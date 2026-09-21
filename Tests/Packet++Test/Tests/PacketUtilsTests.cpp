#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"
#include "PacketUtils.h"
#include "PayloadLayer.h"
#include <sstream>

PTF_TEST_CASE(PacketUtilsHash5TupleUdp)
{
	pcpp::IPv4Address dstIP("10.0.0.6");
	pcpp::IPv4Address srcIP("212.199.202.9");

	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&udpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv4Layer ipLayer2(dstIP, srcIP);
	ipLayer2.getIPv4Header()->ipId = htobe16(20300);
	ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer2.getIPv4Header()->timeToLive = 59;
	pcpp::UdpLayer udpLayer2(1900, 63628);

	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&udpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 683027169);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 926590153);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 683027169);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 683027169);

}  // PacketUtilsHash5TupleUdp

PTF_TEST_CASE(PacketUtilsHash5TupleTcp)
{
	pcpp::IPv4Address dstIP("10.0.0.6");
	pcpp::IPv4Address srcIP("212.199.202.9");

	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	pcpp::TcpLayer tcpLayer((uint16_t)60388, (uint16_t)80);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(0xe9771586);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(20178);
	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&tcpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv4Layer ipLayer2(dstIP, srcIP);
	ipLayer2.getIPv4Header()->ipId = htobe16(20300);
	ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer2.getIPv4Header()->timeToLive = 59;
	pcpp::TcpLayer tcpLayer2((uint16_t)80, (uint16_t)60388);
	tcpLayer2.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
	tcpLayer2.getTcpHeader()->ackNumber = htobe32(0xe9771586);
	tcpLayer2.getTcpHeader()->ackFlag = 1;
	tcpLayer2.getTcpHeader()->pshFlag = 1;
	tcpLayer2.getTcpHeader()->windowSize = htobe16(20178);
	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&tcpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 1576639238);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 2243556734);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 1576639238);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 1576639238);

	tcpLayer.getTcpHeader()->portDst = 80;
	tcpLayer.getTcpHeader()->portSrc = 80;

	tcpLayer2.getTcpHeader()->portDst = 80;
	tcpLayer2.getTcpHeader()->portSrc = 80;

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

}  // PacketUtilsHash5TupleTcp

PTF_TEST_CASE(PacketUtilsHash5TupleIPv6)
{
	pcpp::IPv6Address dstIP("fe80::4dc7:f593:1f7b:dc11");
	pcpp::IPv6Address srcIP("ff02::c");

	pcpp::IPv6Layer ipLayer(srcIP, dstIP);
	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&udpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv6Layer ipLayer2(dstIP, srcIP);
	pcpp::UdpLayer udpLayer2(1900, 63628);

	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&udpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 4288746927);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 2229527039);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 4288746927);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 4288746927);

	udpLayer.getUdpHeader()->portDst = 80;
	udpLayer.getUdpHeader()->portSrc = 80;

	udpLayer2.getUdpHeader()->portDst = 80;
	udpLayer2.getUdpHeader()->portSrc = 80;

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

}  // PacketUtilsHash5TupleIPv6

PTF_TEST_CASE(PacketSerializerTest)
{
	auto expectedPacket = [](int sec, size_t length) {
		return R"({"timestamp":{"sec":)" + std::to_string(sec) + R"(,"nsec":0},"frameLength":)" +
		       std::to_string(length) + R"(,"linkLayer":1,"linkLayerName":"Ethernet","layers":[)" +
		       R"({"protocolName":"GenericPayload","protocolId":25,"length":)" + std::to_string(length) + "}]}";
	};

	auto buildPacket = [](pcpp::PayloadLayer& layer, pcpp::Packet& packet, int sec) {
		packet.addLayer(&layer);
		packet.computeCalculateFields();
		timespec ts{};
		ts.tv_sec = sec;
		packet.getRawPacket()->setPacketTimeStamp(ts);
	};

	// An empty PacketSerializer (no packets added) still writes a valid, empty array
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			pcpp::PacketSerializer packetSerializer(serializer);
		}
		PTF_ASSERT_EQUAL(oss.str(), "[]");
	}

	// Multiple addPacket() calls, mixing both overloads
	{
		uint8_t payload1[] = { 1, 2, 3 };
		uint8_t payload2[] = { 4, 5 };
		uint8_t payload3[] = { 6, 7, 8, 9 };
		pcpp::PayloadLayer layer1(payload1, sizeof(payload1));
		pcpp::PayloadLayer layer2(payload2, sizeof(payload2));
		pcpp::PayloadLayer layer3(payload3, sizeof(payload3));
		pcpp::Packet packet1(1), packet2(1), packet3(1);
		buildPacket(layer1, packet1, 100);
		buildPacket(layer2, packet2, 200);
		buildPacket(layer3, packet3, 300);

		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			pcpp::PacketSerializer packetSerializer(serializer);
			packetSerializer.addPacket(packet1);
			packetSerializer.addPacket(&packet2);
			packetSerializer.addPacket(packet3);
		}
		std::string expected =
		    "[" + expectedPacket(100, 3) + "," + expectedPacket(200, 2) + "," + expectedPacket(300, 4) + "]";
		PTF_ASSERT_EQUAL(oss.str(), expected);
	}

	// addPackets(const std::vector<Packet>&): bulk-adds every packet in the vector, in order
	{
		uint8_t payload1[] = { 1 };
		uint8_t payload2[] = { 2, 2 };
		pcpp::PayloadLayer layer1(payload1, sizeof(payload1));
		pcpp::PayloadLayer layer2(payload2, sizeof(payload2));

		std::vector<pcpp::Packet> packets;
		packets.reserve(2);
		packets.emplace_back(1);
		packets.emplace_back(1);
		buildPacket(layer1, packets[0], 10);
		buildPacket(layer2, packets[1], 20);

		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			pcpp::PacketSerializer packetSerializer(serializer);
			packetSerializer.addPackets(packets);
		}
		std::string expected = "[" + expectedPacket(10, 1) + "," + expectedPacket(20, 2) + "]";
		PTF_ASSERT_EQUAL(oss.str(), expected);
	}

	// addPackets(const PointerVector<Packet>&): bulk-adds every packet in the vector, in order
	{
		uint8_t payload1[] = { 9, 9, 9 };
		uint8_t payload2[] = { 8 };
		pcpp::PayloadLayer layer1(payload1, sizeof(payload1));
		pcpp::PayloadLayer layer2(payload2, sizeof(payload2));

		pcpp::PointerVector<pcpp::Packet> packets;
		auto* p1 = new pcpp::Packet(1);
		auto* p2 = new pcpp::Packet(1);
		buildPacket(layer1, *p1, 30);
		buildPacket(layer2, *p2, 40);
		packets.pushBack(p1);
		packets.pushBack(p2);

		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			pcpp::PacketSerializer packetSerializer(serializer);
			packetSerializer.addPackets(packets);
		}
		std::string expected = "[" + expectedPacket(30, 3) + "," + expectedPacket(40, 1) + "]";
		PTF_ASSERT_EQUAL(oss.str(), expected);
	}

	// PacketSerializer composes correctly when used to write a NAMED field
	// inside an already-open object, rather than as the top-level root: the
	// "packets" key appears (unlike the top-level cases above, where the
	// root container's own name is always dropped), and sibling fields on
	// either side are comma-separated correctly around it.
	{
		uint8_t payload[] = { 7 };
		pcpp::PayloadLayer layer(payload, sizeof(payload));
		pcpp::Packet packet(1);
		buildPacket(layer, packet, 500);

		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "before" }, int64_t(1));
			{
				pcpp::PacketSerializer packetSerializer(obj);
				packetSerializer.addPacket(packet);
			}
			obj.writeField(pcpp::FieldDescriptor{ 3, "after" }, int64_t(2));
		}
		std::string expected = R"({"before":1,"packets":[)" + expectedPacket(500, 1) + R"(],"after":2})";
		PTF_ASSERT_EQUAL(oss.str(), expected);
	}
}  // PacketSerializerTest
