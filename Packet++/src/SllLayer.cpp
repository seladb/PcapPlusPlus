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
#include "EndianPortable.h"

namespace pcpp
{

SllLayer::SllLayer(uint16_t packetType, uint16_t ARPHRDType)
{
	const size_t headerLen = sizeof(sll_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	sll_header* sllHdr = (sll_header*)m_Data;
	sllHdr->packet_type = htobe16(packetType);
	sllHdr->ARPHRD_type = htobe16(ARPHRDType);
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
	sllHdr->link_layer_addr_len = htobe16(addrLength);

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

	uint8_t* payload = m_Data + sizeof(sll_header);
	size_t payloadLen = m_DataLen - sizeof(sll_header);

	sll_header* hdr = getSllHeader();
	switch (be16toh(hdr->protocol_type))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(payload, payloadLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
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
			hdr->protocol_type = htobe16(PCPP_ETHERTYPE_IP);
			break;
		case IPv6:
			hdr->protocol_type = htobe16(PCPP_ETHERTYPE_IPV6);
			break;
		case ARP:
			hdr->protocol_type = htobe16(PCPP_ETHERTYPE_ARP);
			break;
		case VLAN:
			hdr->protocol_type = htobe16(PCPP_ETHERTYPE_VLAN);
			break;
		default:
			return;
	}
}

std::string SllLayer::toString() const
{
	return "Linux cooked header";
}

} // namespace pcpp

