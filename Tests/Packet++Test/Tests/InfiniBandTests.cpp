#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include <sstream>
#include "EndianPortable.h"
#include "Logger.h"
#include "MacAddress.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "InfiniBandLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
	case pcpp::Ethernet:
		return "Ethernet";
	case pcpp::VLAN:
		return "Vlan";
	case pcpp::IPv4:
		return "IPv4";
	case pcpp::UDP:
		return "UDP";
	case pcpp::TCP:
		return "TCP";
	case pcpp::Infiniband:
		return "Infiniband";
	case pcpp::HTTPRequest:
	case pcpp::HTTPResponse:
		return "HTTP";
	case pcpp::GenericPayload:
		return "Payload";
	default:
		return "Unknown";
	}
}

PTF_TEST_CASE(InfiniBandPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/InfinibandPacket.dat");

	pcpp::Packet ip4Packet(&rawPacket1);

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket1);

	// first let's go over the layers one by one and find out its type, its total length,
	// its header length and its payload length
	for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
	{
		switch (curLayer->getProtocol())
		{
		case pcpp::Ethernet:
		{
			// now let's get the Ethernet layer
			auto* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
			PTF_ASSERT_NOT_NULL(ethernetLayer);
			break;
		}
		case pcpp::VLAN:
		{
			// now let's get the Vlan layer
			auto* vlanLayer = parsedPacket.getLayerOfType<pcpp::VlanLayer>();
			PTF_ASSERT_NOT_NULL(vlanLayer);
			break;
		}
		case pcpp::IPv4:
		{
			// let's get the IPv4 layer
			auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			PTF_ASSERT_NOT_NULL(ipLayer);
			break;
		}
		case pcpp::UDP:
		{
			// let's get the UDP layer
			auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
			PTF_ASSERT_NOT_NULL(udpLayer);
			PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 57236);
			PTF_ASSERT_EQUAL(udpLayer->getDstPort(), 4791);
			break;
		}
		case pcpp::Infiniband:
		{
			// let's get the Infiniband layer
			auto* ibLayer = parsedPacket.getLayerOfType<pcpp::InfiniBandLayer>();
			PTF_ASSERT_NOT_NULL(ibLayer);
			PTF_ASSERT_EQUAL(ibLayer->getOpcode(), 12);
			PTF_ASSERT_EQUAL(ibLayer->getSe(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getMig(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getPad(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getTver(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getPkey(), 65535);
			PTF_ASSERT_EQUAL(ibLayer->getQpn(), 17);
			PTF_ASSERT_EQUAL(ibLayer->getFecn(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getBecn(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getResv6a(), 0);
			PTF_ASSERT_EQUAL(ibLayer->getAck(), 1);
			PTF_ASSERT_EQUAL(ibLayer->getPsn(), 5557091);
			break;
		}
		case pcpp::GenericPayload:
		{
			break;
		}
		default:
		{
			std::cerr << "Something went wrong, couldn't find this layer" << std::endl;
			break;
		}
		}
	}

}  // InfiniBandPacketParsing