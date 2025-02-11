#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "IpAddress.h"
#include "EthLayer.h"
#include "EthDot3Layer.h"
#include "ArpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "OUILookup.h"
#include "SystemUtils.h"

PTF_TEST_CASE(OUILookup)
{
	pcpp::OUILookup lookupEngineJson;
	PTF_ASSERT_GREATER_THAN(lookupEngineJson.initOUIDatabaseFromJson("../../3rdParty/OUIDataset/PCPP_OUIDataset.json"),
	                        0);

	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("aa:aa:aa:aa:aa:aa"), "Unknown");
	// CIDR 36
	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("70:B3:D5:2A:B0:00"), "NASA Johnson Space Center");
	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("70:B3:D5:2A:BF:FF"), "NASA Johnson Space Center");
	// CIDR 28
	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("68:79:12:40:00:00"), "McDonald's Corporation");
	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("68:79:12:4f:ff:ff"), "McDonald's Corporation");
	// Short
	PTF_ASSERT_EQUAL(lookupEngineJson.getVendorName("00:08:55:01:01:01"), "NASA-Goddard Space Flight Center");
}

PTF_TEST_CASE(EthPacketCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	pcpp::PayloadLayer payloadLayer(payload, 4);

	pcpp::Packet ethPacket(1);
	PTF_ASSERT_TRUE(ethPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(ethPacket.addLayer(&payloadLayer));

	PTF_ASSERT_TRUE(ethPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>(), &ethLayer, ptr);
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac);
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac);
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_IP));

	pcpp::RawPacket* rawPacket = ethPacket.getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 18);

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa,
		                           0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PTF_ASSERT_BUF_COMPARE(rawPacket->getRawData(), expectedBuffer, 18);
}  // EthPacketCreation

PTF_TEST_CASE(EthPacketPointerCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, 4);

	pcpp::Packet* ethPacket = new pcpp::Packet(1);
	PTF_ASSERT_TRUE(ethPacket->addLayer(ethLayer, true));
	PTF_ASSERT_TRUE(ethPacket->addLayer(payloadLayer, true));

	PTF_ASSERT_TRUE(ethPacket->isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket->getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>(), ethLayer, ptr);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType,
	                 be16toh(PCPP_ETHERTYPE_IP));

	pcpp::RawPacket* rawPacket = ethPacket->getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 18);

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa,
		                           0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PTF_ASSERT_BUF_COMPARE(rawPacket->getRawData(), expectedBuffer, 18);
	delete (ethPacket);
}  // EthPacketPointerCreation

PTF_TEST_CASE(EthAndArpPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ArpResponsePacket.dat");

	pcpp::Packet ethPacket(&rawPacket1);
	PTF_ASSERT_TRUE(ethPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket.getLayerOfType<pcpp::EthLayer>());

	pcpp::MacAddress expectedSrcMac(0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa);
	pcpp::MacAddress expectedDstMac(0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e);
	pcpp::EthLayer* ethLayer = ethPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_EQUAL(ethLayer->getDestMac(), expectedDstMac);
	PTF_ASSERT_EQUAL(ethLayer->getSourceMac(), expectedSrcMac);
	PTF_ASSERT_EQUAL(ethLayer->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_ARP), hex);

	PTF_ASSERT_EQUAL(ethLayer->getNextLayer()->getProtocol(), pcpp::ARP, enum);
	pcpp::ArpLayer* arpLayer = (pcpp::ArpLayer*)ethLayer->getNextLayer();
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareType, htobe16(1));
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP), hex);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareSize, 6);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolSize, 4);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->opcode, htobe16(pcpp::ARP_REPLY));
	PTF_ASSERT_EQUAL(arpLayer->isReply(), true);
	PTF_ASSERT_EQUAL(arpLayer->isRequest(), false);
	PTF_ASSERT_EQUAL(arpLayer->getSenderIpAddr(), pcpp::IPv4Address("10.0.0.138"));
	PTF_ASSERT_EQUAL(arpLayer->getTargetMacAddress(), pcpp::MacAddress("6c:f0:49:b2:de:6e"));
}  // EthAndArpPacketParsing

PTF_TEST_CASE(ArpPacketCreation)
{
	{
		auto const buffer = pcpp_tests::readFileIntoBuffer("PacketExamples/ArpRequestPacket.dat");

		{
			pcpp::MacAddress srcMac("6c:f0:49:b2:de:6e");
			pcpp::MacAddress dstMac("ff:ff:ff:ff:ff:ff");
			pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP);
			pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, srcMac, srcMac, pcpp::IPv4Address("10.0.0.1"),
			                        pcpp::IPv4Address("10.0.0.138"));

			PTF_ASSERT_TRUE(arpLayer.getMessageType() == pcpp::ArpMessageType::Request);

			pcpp::Packet arpRequestPacket(1);

			PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&ethLayer));
			PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&arpLayer));
			arpRequestPacket.computeCalculateFields();
			PTF_ASSERT_EQUAL(arpRequestPacket.getRawPacket()->getRawDataLen(), 42);

			pcpp::ArpLayer* pArpLayer = arpRequestPacket.getLayerOfType<pcpp::ArpLayer>();
			PTF_ASSERT_NOT_NULL(pArpLayer);

			pcpp::arphdr* arpHeader = pArpLayer->getArpHeader();
			PTF_ASSERT_EQUAL(arpHeader->hardwareSize, 6);
			PTF_ASSERT_EQUAL(arpHeader->protocolType, htobe16(PCPP_ETHERTYPE_IP));

			PTF_ASSERT_EQUAL(arpRequestPacket.getRawPacket()->getRawDataLen(), buffer.size());
			PTF_ASSERT_BUF_COMPARE(arpRequestPacket.getRawPacket()->getRawData(), buffer.data(), buffer.size());
		}

		{
			pcpp::MacAddress srcMac("6c:f0:49:b2:de:6e");
			pcpp::IPv4Address srcIp("10.0.0.1");
			pcpp::IPv4Address dstIp("10.0.0.138");

			pcpp::EthLayer ethLayer(srcMac, pcpp::MacAddress::Broadcast, PCPP_ETHERTYPE_ARP);
			pcpp::ArpLayer arpLayer(pcpp::ArpRequest(srcMac, srcIp, dstIp));

			PTF_ASSERT_TRUE(arpLayer.getMessageType() == pcpp::ArpMessageType::Request);

			pcpp::Packet argRequestPacket(1);
			PTF_ASSERT_TRUE(argRequestPacket.addLayer(&ethLayer));
			PTF_ASSERT_TRUE(argRequestPacket.addLayer(&arpLayer));

			argRequestPacket.computeCalculateFields();
			PTF_ASSERT_EQUAL(argRequestPacket.getRawPacket()->getRawDataLen(), 42);

			pcpp::ArpLayer* pArpLayer = argRequestPacket.getLayerOfType<pcpp::ArpLayer>();
			PTF_ASSERT_NOT_NULL(pArpLayer);

			pcpp::arphdr* arpHeader = pArpLayer->getArpHeader();
			PTF_ASSERT_EQUAL(arpHeader->hardwareSize, 6);
			PTF_ASSERT_EQUAL(arpHeader->protocolType, htobe16(PCPP_ETHERTYPE_IP));

			PTF_ASSERT_EQUAL(argRequestPacket.getRawPacket()->getRawDataLen(), buffer.size());
			PTF_ASSERT_BUF_COMPARE(argRequestPacket.getRawPacket()->getRawData(), buffer.data(), buffer.size());
		}
	}

	{
		auto buffer = pcpp_tests::readFileIntoBuffer("PacketExamples/ArpResponsePacket.dat");

		pcpp::MacAddress srcMac("30:46:9a:23:fb:fa");
		pcpp::IPv4Address srcIp("10.0.0.138");
		pcpp::MacAddress dstMac("6c:f0:49:b2:de:6e");
		pcpp::IPv4Address dstIp("10.0.0.1");

		pcpp::EthLayer ethLayer(pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP));
		pcpp::ArpLayer arpLayer(pcpp::ArpReply(srcMac, srcIp, dstMac, dstIp));

		pcpp::Packet packet(1);
		PTF_ASSERT_TRUE(packet.addLayer(&ethLayer));
		PTF_ASSERT_TRUE(packet.addLayer(&arpLayer));

		packet.computeCalculateFields();

		PTF_ASSERT_EQUAL(arpLayer.getHeaderLen(), 28);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareSize, 6);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolSize, 4);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareType, htobe16(1));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->opcode, htobe16(pcpp::ARP_REPLY));
		PTF_ASSERT_TRUE(arpLayer.getMessageType() == pcpp::ArpMessageType::Reply);
		PTF_ASSERT_EQUAL(arpLayer.getSenderMacAddress(), srcMac);
		PTF_ASSERT_EQUAL(arpLayer.getSenderIpAddr(), srcIp);
		PTF_ASSERT_EQUAL(arpLayer.getTargetMacAddress(), dstMac);
		PTF_ASSERT_EQUAL(arpLayer.getTargetIpAddr(), dstIp);

		PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), 42);

		pcpp::ArpLayer* pArpLayer = packet.getLayerOfType<pcpp::ArpLayer>();
		PTF_ASSERT_NOT_NULL(pArpLayer);

		PTF_ASSERT_EQUAL(buffer.size(), packet.getRawPacket()->getRawDataLen() + 18 /* ethernet trailer */);
		PTF_ASSERT_BUF_COMPARE(packet.getRawPacket()->getRawData(), buffer.data(),
		                       packet.getRawPacket()->getRawDataLen());
	}

	{
		// TODO: Add an actual packet to test against.
		pcpp::MacAddress srcMac("02:00:00:00:00:01");
		pcpp::IPv4Address srcIp("10.0.0.1");

		pcpp::ArpLayer arpLayer(pcpp::GratuitousArpRequest(srcMac, srcIp));
		arpLayer.computeCalculateFields();

		PTF_ASSERT_EQUAL(arpLayer.getHeaderLen(), 28);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareSize, 6);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolSize, 4);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareType, htobe16(1));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->opcode, htobe16(pcpp::ARP_REQUEST));
		PTF_ASSERT_TRUE(arpLayer.getMessageType() == pcpp::ArpMessageType::GratuitousRequest);
		PTF_ASSERT_EQUAL(arpLayer.getSenderMacAddress(), srcMac);
		PTF_ASSERT_EQUAL(arpLayer.getSenderIpAddr(), srcIp);
		PTF_ASSERT_EQUAL(arpLayer.getTargetMacAddress(), pcpp::MacAddress::Broadcast);
		PTF_ASSERT_EQUAL(arpLayer.getTargetIpAddr(), srcIp);
	}

	{
		// TODO: Add an actual packet to test against.
		pcpp::MacAddress srcMac("02:00:00:00:00:01");
		pcpp::IPv4Address srcIp("10.0.0.1");

		pcpp::ArpLayer arpLayer(pcpp::GratuitousArpReply(srcMac, srcIp));
		arpLayer.computeCalculateFields();

		PTF_ASSERT_EQUAL(arpLayer.getHeaderLen(), 28);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareSize, 6);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolSize, 4);
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->hardwareType, htobe16(1));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP));
		PTF_ASSERT_EQUAL(arpLayer.getArpHeader()->opcode, htobe16(pcpp::ARP_REPLY));
		PTF_ASSERT_TRUE(arpLayer.getMessageType() == pcpp::ArpMessageType::GratuitousReply);
		PTF_ASSERT_EQUAL(arpLayer.getSenderMacAddress(), srcMac);
		PTF_ASSERT_EQUAL(arpLayer.getSenderIpAddr(), srcIp);
		PTF_ASSERT_EQUAL(arpLayer.getTargetMacAddress(), pcpp::MacAddress::Broadcast);
		PTF_ASSERT_EQUAL(arpLayer.getTargetIpAddr(), srcIp);
	}
}  // ArpPacketCreation

PTF_TEST_CASE(EthDot3LayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/EthDot3.dat");
	pcpp::Packet ethDot3Packet(&rawPacket1);

	PTF_ASSERT_TRUE(ethDot3Packet.isPacketOfType(pcpp::EthernetDot3));
	pcpp::EthDot3Layer* ethDot3Layer = ethDot3Packet.getLayerOfType<pcpp::EthDot3Layer>();
	PTF_ASSERT_NOT_NULL(ethDot3Layer);
	PTF_ASSERT_EQUAL(ethDot3Layer->getHeaderLen(), 14);
	PTF_ASSERT_EQUAL(ethDot3Layer->getSourceMac(), pcpp::MacAddress("00:13:f7:11:5e:db"));
	PTF_ASSERT_EQUAL(ethDot3Layer->getDestMac(), pcpp::MacAddress("01:80:c2:00:00:00"));
	PTF_ASSERT_EQUAL(be16toh(ethDot3Layer->getEthHeader()->length), 38);

	PTF_ASSERT_NOT_NULL(ethDot3Layer->getNextLayer());
	PTF_ASSERT_EQUAL(ethDot3Layer->getNextLayer()->getProtocol(), pcpp::LLC, enum);
}  // EthDot3LayerParsingTest

PTF_TEST_CASE(EthDot3LayerCreateEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/EthDot3.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/EthDot3_2.dat");

	// create a new EthDot3 packet

	pcpp::MacAddress srcAddr("00:13:f7:11:5e:db");
	pcpp::MacAddress dstAddr("01:80:c2:00:00:00");
	pcpp::EthDot3Layer ethDot3NewLayer(srcAddr, dstAddr, 38);

	pcpp::PayloadLayer newPayloadLayer(
	    "424203000000000000000013f71edff00000271080000013f7115ec0801b0100140002000f000000000000000000");
	PTF_ASSERT_EQUAL(newPayloadLayer.getDataLen(), 46);

	pcpp::Packet newEthDot3Packet;
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(&ethDot3NewLayer));
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(&newPayloadLayer));
	newEthDot3Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(newEthDot3Packet.getRawPacket()->getRawData(), buffer1, bufferLength1);

	// edit an EthDot3 packet

	ethDot3NewLayer.setSourceMac(pcpp::MacAddress("00:1a:a1:97:d1:85"));
	ethDot3NewLayer.getEthHeader()->length = htobe16(121);

	auto newPayloadLayer2 = new pcpp::PayloadLayer(
	    "424203000003027c8000000c305dd100000000008000000c305dd10080050000140002000f00000050000000000000000000000000000000000000000000000000000000000000000000000055bf4e8a44b25d442868549c1bf7720f00030d408000001aa197d180137c8005000c305dd10000030d40808013");

	PTF_ASSERT_TRUE(newEthDot3Packet.detachLayer(&newPayloadLayer));
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(newPayloadLayer2, true));
	newEthDot3Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(newEthDot3Packet.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer1;
	delete[] buffer2;

}  // EthDot3LayerCreateEditTest
