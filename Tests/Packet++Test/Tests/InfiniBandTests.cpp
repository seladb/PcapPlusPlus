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

	/*
	uint8_t buffer1[] = {
	    0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa, 0x6c, 0xf0,
	    0x49, 0xb2, 0xde, 0x6e, 0x08, 0x00, 0x45, 0x00,
	    0x00, 0x3c, 0x1a, 0x57, 0x00, 0x00, 0x80, 0x01,
	    0x14, 0x65, 0x0a, 0x00, 0x00, 0x04, 0x01, 0x01,
	    0x01, 0x01, 0x08, 0x00, 0x4d, 0x5a, 0x00, 0x01,
	    0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
	    0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
	    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	    0x68, 0x69,
	};
	*/

	
	// RRoce
	uint8_t buffer1[] = {
		0x00, 0x0c, 0x29, 0xae, 0x1c, 0xa4, 0x00, 0x0c, 0x29, 0x89, 0xa2, 0xe5, 0x08, 0x00, 0x45,
		0x00, 0x00, 0x3c, 0xbe, 0x10, 0x40, 0x00, 0x40, 0x11, 0x8a, 0x4b, 0xc0, 0xa8, 0x38, 0x81,
		0xc0, 0xa8, 0x38, 0x83, 0xdf, 0x94, 0x12, 0xb7, 0x00, 0x28, 0x00, 0x00, 0x0c, 0x00, 0xff,
		0xff, 0x00, 0x00, 0x00, 0x11, 0x80, 0x54, 0xcb, 0x63, 0x00, 0x00, 0x7f, 0xee, 0x26, 0x0f,
		0xb0, 0x00, 0x00, 0x00, 0x02, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x08, 0xc6, 0x15, 0x4a,
	};

	/*
	// eth + vlan + ipv4 + ICMP
	uint8_t buffer1[] = {
	    0x00, 0x1b, 0xd4, 0x1b, 0xa4, 0xd8, 0x00, 0x13,
	    0xc3, 0xdf, 0xae, 0x18, 0x81, 0x00, 0x00, 0x76,
	    0x81, 0x00, 0x00, 0x0a, 0x08, 0x00, 0x45, 0x00,
	    0x00, 0x64, 0x00, 0x0f, 0x00, 0x00, 0xff, 0x01,
	    0x92, 0x9b, 0x0a, 0x76, 0x0a, 0x01, 0x0a, 0x76,
	    0x0a, 0x02, 0x08, 0x00, 0xce, 0xb7, 0x00, 0x03,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
	    0xaf, 0x70, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
	    0xab, 0xcd
	};
	*/

	int bufferLength1 = sizeof(buffer1);

	uint8_t* result = new uint8_t[bufferLength1];
	memcpy(result, buffer1, bufferLength1);

	pcpp::RawPacket rawPacket1(static_cast<const uint8_t*>(result), bufferLength1, time, true);

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket1);

	// first let's go over the layers one by one and find out its type, its total length,
	// its header length and its payload length
	for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
	{
		std::cout << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; "  // get layer type
		          << "Total data: " << curLayer->getDataLen() << " [bytes]; "    // get total length of the layer
		          << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "  // get the header length of the layer
		          << "Layer payload: " << curLayer->getLayerPayloadSize()
		          << " [bytes]"  // get the payload length of the layer (equals total length minus header length)
		          << std::endl;

		switch (curLayer->getProtocol())
		{
		case pcpp::Ethernet:
		{
			// now let's get the Ethernet layer
			auto* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
			if (ethernetLayer == nullptr)
 			{
				std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
			}
			else
			{
				// print the source and dest MAC addresses and the Ether type
				std::cout << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
						  << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
						  << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType)
						  << std::endl;
			}
			break;
		}
		case pcpp::VLAN:
		{
			// now let's get the Vlan layer
			auto* vlanLayer = parsedPacket.getLayerOfType<pcpp::VlanLayer>();
			if (vlanLayer == nullptr)
			{
				std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
			}
			else
			{
				std::cout << vlanLayer->toString() << std::endl
			              << "vlan type = 0x" << std::hex << pcpp::netToHost16(vlanLayer->getVlanHeader()->etherType)
			              << std::endl;
			}			
			break;
		}
		case pcpp::IPv4:
		{
			// let's get the IPv4 layer
			auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipLayer == nullptr)
			{
				std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
			}
			else
			{
				// print source and dest IP addresses, IP ID and TTL
				std::cout << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
						  << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
						  << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
						  << "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;
			}			
			break;
		}
		case pcpp::UDP:
		{
			// let's get the UDP layer
			auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
			if (udpLayer == nullptr)
			{
				std::cerr << "Something went wrong, couldn't find UDP layer" << std::endl;
			}
			else
			{
				// print source and dest port
				std::cout << "Source port: " << udpLayer->getSrcPort() << std::endl
						  << "Destination port: " << udpLayer->getDstPort() << std::endl;
			}
			break;
		}
		case pcpp::Infiniband:
		{
			// let's get the Infiniband layer
			auto* ibLayer = parsedPacket.getLayerOfType<pcpp::InfiniBandLayer>();
			if (ibLayer == nullptr)
			{
				std::cerr << "Something went wrong, couldn't find Infiniband layer" << std::endl;
			}
			else
			{
				// print opcode
				std::cout << "Opcode: " << std::dec << (int)ibLayer->getOpcode() << std::endl
						  << "Se: " << (int)ibLayer->getSe() << std::endl
						  << "Mig: " << (int)ibLayer->getMig() << std::endl
						  << "Pad: " << (int)ibLayer->getPad() << std::endl
						  << "Tver: " << (int)ibLayer->getTver() << std::endl
						  << "Pkey: " << (int)ibLayer->getPkey() << std::endl
						  << "Qpn: " << (int)ibLayer->getQpn() << std::endl
						  << "Fecn: " << (int)ibLayer->getFecn() << std::endl
						  << "Becn: " << (int)ibLayer->getBecn() << std::endl
						  << "Resv6a: " << (int)ibLayer->getResv6a() << std::endl
						  << "Ack: " << (int)ibLayer->getAck() << std::endl
						  << "Psn: " << (int)ibLayer->getPsn() << std::endl;
			}
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