#define LOG_MODULE PacketLogModuleSllLayer

#include "SllLayer.h"
#include "Logger.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include <string.h>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#elif MAC_OS_X
#include <arpa/inet.h>
#endif

namespace pcpp
{

SllLayer::SllLayer(uint16_t packetType, uint16_t ARPHRDType)
{
	m_DataLen = sizeof(sll_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	sll_header* sllHdr = (sll_header*)m_Data;
	sllHdr->packet_type = htons(packetType);
	sllHdr->ARPHRD_type = htons(ARPHRDType);
	m_Protocol = SLL;
}

bool SllLayer::setLinkLayerAddr(uint8_t* addr, size_t addrLength)
{
	if (addrLength == 0 || addrLength > 8)
	{
		LOG_ERROR("Address length is out of bounds, it must be between 1 and 8");
		return false;
	}

	sll_header* sllHdr = (sll_header*)m_Data;
	memcpy(sllHdr->link_layer_addr, addr, addrLength);
	sllHdr->link_layer_addr_len = htons(addrLength);

	return true;
}

bool SllLayer::setMacAddressAsLinkLayer(MacAddress macAddr)
{
	if (!macAddr.isValid())
	{
		LOG_ERROR("MAC address is not valid");
		return false;
	}

	uint8_t macAddrAsArr[6];
	macAddr.copyTo(macAddrAsArr);
	return setLinkLayerAddr(macAddrAsArr, 6);
}

void SllLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(sll_header))
		return;

	sll_header* hdr = getSllHeader();
	switch (ntohs(hdr->protocol_type))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(sll_header), m_DataLen - sizeof(sll_header), this, m_Packet);
	}

}

void SllLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	sll_header* hdr = getSllHeader();
	switch (m_NextLayer->getProtocol())
	{
		case IPv4:
			hdr->protocol_type = htons(PCPP_ETHERTYPE_IP);
			break;
		case IPv6:
			hdr->protocol_type = htons(PCPP_ETHERTYPE_IPV6);
			break;
		case ARP:
			hdr->protocol_type = htons(PCPP_ETHERTYPE_ARP);
			break;
		case VLAN:
			hdr->protocol_type = htons(PCPP_ETHERTYPE_VLAN);
			break;
		default:
			return;
	}
}

std::string SllLayer::toString()
{
	return "Linux cooked header";
}

} // namespace pcpp

