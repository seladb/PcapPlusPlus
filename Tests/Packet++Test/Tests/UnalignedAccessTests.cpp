#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "GreLayer.h"
#include "GtpLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PPPoELayer.h"
#include "RawPacket.h"

// Multi-byte fields of packets sit at arbitrary byte offsets, and so do the header structs that contain them. These
// tests copy each packet to an address with an odd offset, so that the fields are misaligned for their type. Reading or
// writing a misaligned field through a cast is undefined behaviour, which UBSan reports. The tests check that the
// parsed values, the checksums and the written bytes are the same as for aligned packets. Run them in a sanitizer build
// (-fsanitize=undefined) to see the undefined accesses.

using pcpp_tests::utils::createPacketAndBufferFromHexResource;

namespace
{

	// A copy of a packet at an odd address. The storage must outlive the packet.
	struct OddAddressPacket
	{
		std::vector<uint8_t> storage;
		std::unique_ptr<pcpp::RawPacket> packet;
	};

	OddAddressPacket copyToOddAddress(const pcpp::RawPacket& source)
	{
		OddAddressPacket copy;
		const auto length = static_cast<std::size_t>(source.getRawDataLen());
		copy.storage.assign(length + 1, 0);
		std::memcpy(copy.storage.data() + 1, source.getRawData(), length);
		copy.packet = std::unique_ptr<pcpp::RawPacket>(
		    new pcpp::RawPacket(copy.storage.data() + 1, static_cast<int>(length), source.getPacketTimeStamp(), false,
		                        source.getLinkLayerType()));
		return copy;
	}

	// The text of every layer, in order: two packets with the same description have the same layers and fields.
	std::string describeLayers(pcpp::Packet& packet)
	{
		std::string description;
		for (auto* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer())
		{
			description += layer->toString();
			description += '\n';
		}
		return description;
	}

	std::vector<uint8_t> bytesOf(const pcpp::RawPacket& packet)
	{
		return std::vector<uint8_t>(packet.getRawData(), packet.getRawData() + packet.getRawDataLen());
	}

}  // namespace

PTF_TEST_CASE(UnalignedPacketsParseLikeAlignedOnes)
{
	// One packet per protocol whose fields were read through casts, or through header structs that were not packed.
	const std::vector<std::string> resources = {
		"PacketExamples/SSL-ClientHello1.dat",
		"PacketExamples/SSL-MultipleRecords1.dat",
		"PacketExamples/SSL-NewSessionTicket.dat",
		"PacketExamples/tls_server_hello.dat",
		"PacketExamples/tls_zero_size_ext.dat",
		"PacketExamples/tls_grease.dat",
		"PacketExamples/tls1_3_client_hello1.dat",
		"PacketExamples/tls1_3_server_hello1.dat",
		"PacketExamples/ssl-malformed1.dat",
		"PacketExamples/Bgp_open.dat",
		"PacketExamples/Bgp_update1.dat",
		"PacketExamples/Bgp_notification.dat",
		"PacketExamples/Bgp_keepalive.dat",
		"PacketExamples/DnsEdit1.dat",
		"PacketExamples/Dns1.dat",
		"PacketExamples/postgres_backend_messages.dat",
		"PacketExamples/postgres_frontend_messages.dat",
		"PacketExamples/mysql_client.dat",
		"PacketExamples/mysql_server.dat",
		"PacketExamples/SSHKexInit.dat",
		"PacketExamples/SSHIdentification.dat",
		"PacketExamples/SSHEncryptedMessage.dat",
		"PacketExamples/gtp-c1.dat",
		"PacketExamples/gtp-u1.dat",
		"PacketExamples/gtpv2-with-teid.dat",
		"PacketExamples/someip.dat",
		"PacketExamples/SomeIpSdOffer.dat",
		"PacketExamples/VRRP-V2.dat",
		"PacketExamples/VRRP-V3-IPv4.dat",
		"PacketExamples/VRRP-V3-IPv6.dat",
		"PacketExamples/PPPoEDiscovery1.dat",
		"PacketExamples/PPPoESession1.dat",
		"PacketExamples/NullLoopback1.dat",
		"PacketExamples/GREv0_1.dat",
		"PacketExamples/GREv1_1.dat",
		"PacketExamples/IGMPv1_1.dat",
		"PacketExamples/IGMPv2_1.dat",
		"PacketExamples/IcmpEchoReply.dat",
		"PacketExamples/IcmpDestUnreachableUdp.dat",
		"PacketExamples/IcmpRedirect.dat",
		"PacketExamples/IPv4-NoOptions1.dat",
		"PacketExamples/EthDot3.dat",
	};

	for (const auto& resource : resources)
	{
		auto loaded = createPacketAndBufferFromHexResource(resource);
		PTF_ASSERT_NOT_NULL(loaded.packet);

		pcpp::Packet alignedPacket(loaded.packet.get());
		const auto alignedDescription = describeLayers(alignedPacket);

		auto odd = copyToOddAddress(*loaded.packet);
		pcpp::Packet oddPacket(odd.packet.get());
		PTF_ASSERT_EQUAL(describeLayers(oddPacket), alignedDescription);
	}
}  // UnalignedPacketsParseLikeAlignedOnes

PTF_TEST_CASE(UnalignedChecksumsMatchAlignedOnes)
{
	// IPv4 and ICMP checksums are computed over the header words: the same packet at an odd address must get the same
	// checksum.
	const std::vector<std::string> resources = {
		"PacketExamples/IPv4-NoOptions1.dat",
		"PacketExamples/IcmpEchoReply.dat",
		"PacketExamples/IcmpRedirect.dat",
	};

	for (const auto& resource : resources)
	{
		auto loaded = createPacketAndBufferFromHexResource(resource);
		PTF_ASSERT_NOT_NULL(loaded.packet);

		pcpp::RawPacket alignedRaw(loaded.packet->getRawData(), loaded.packet->getRawDataLen(),
		                           loaded.packet->getPacketTimeStamp(), false, loaded.packet->getLinkLayerType());
		pcpp::Packet alignedPacket(&alignedRaw);
		auto odd = copyToOddAddress(*loaded.packet);
		pcpp::Packet oddPacket(odd.packet.get());

		alignedPacket.computeCalculateFields();
		oddPacket.computeCalculateFields();

		PTF_ASSERT_TRUE(bytesOf(alignedRaw) == bytesOf(*odd.packet));
	}
}  // UnalignedChecksumsMatchAlignedOnes

PTF_TEST_CASE(UnalignedFieldsWriteAndReadBack)
{
	// PPPoE session protocol: 16-bit big-endian field.
	{
		auto loaded = createPacketAndBufferFromHexResource("PacketExamples/PPPoESession1.dat");
		auto odd = copyToOddAddress(*loaded.packet);
		pcpp::Packet packet(odd.packet.get());
		auto* layer = packet.getLayerOfType<pcpp::PPPoESessionLayer>();
		PTF_ASSERT_NOT_NULL(layer);
		layer->setPPPNextProtocol(0x0021);
		PTF_ASSERT_EQUAL(layer->getPPPNextProtocol(), 0x0021);
	}

	// GTPv2: 32-bit big-endian tunnel endpoint identifier.
	{
		auto loaded = createPacketAndBufferFromHexResource("PacketExamples/gtpv2-with-teid.dat");
		auto odd = copyToOddAddress(*loaded.packet);
		pcpp::Packet packet(odd.packet.get());
		auto* layer = packet.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(layer);
		layer->setTeid(0xDEADBEEF);
		const auto teid = layer->getTeid();
		PTF_ASSERT_TRUE(teid.first);
		PTF_ASSERT_EQUAL(teid.second, 0xDEADBEEFU);
	}

	// GRE version 0: 32-bit big-endian key.
	{
		auto loaded = createPacketAndBufferFromHexResource("PacketExamples/GREv0_1.dat");
		auto odd = copyToOddAddress(*loaded.packet);
		pcpp::Packet packet(odd.packet.get());
		auto* layer = packet.getLayerOfType<pcpp::GREv0Layer>();
		PTF_ASSERT_NOT_NULL(layer);
		PTF_ASSERT_TRUE(layer->setKey(0x01020304));
		uint32_t key = 0;
		PTF_ASSERT_TRUE(layer->getKey(key));
		PTF_ASSERT_EQUAL(key, 0x01020304U);
	}
}  // UnalignedFieldsWriteAndReadBack
