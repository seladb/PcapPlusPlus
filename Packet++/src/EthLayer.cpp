#define LOG_MODULE PacketLogModuleEthLayer

#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include "EndianPortable.h"
#include <string.h>

namespace pcpp
{


EthLayer::EthLayer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t etherType) : Layer()
{
	const size_t headerLen = sizeof(ether_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);

	ether_header* ethHdr = (ether_header*)m_Data;
	destMac.copyTo(ethHdr->dstMac);
	sourceMac.copyTo(ethHdr->srcMac);
	ethHdr->etherType = htobe16(etherType);
	m_Protocol = Ethernet;
}

void EthLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(ether_header))
		return;

	ether_header* hdr = getEthHeader();
	uint8_t* payload = m_Data + sizeof(ether_header);
	size_t payloadLen = m_DataLen - sizeof(ether_header);

	switch (be16toh(hdr->etherType))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
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

void EthLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	switch (m_NextLayer->getProtocol())
	{
	case IPv4:
		getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_IP);
		break;
	case IPv6:
		getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_IPV6);
		break;
	case ARP:
		getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_ARP);
		break;
	case VLAN:
		getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_VLAN);
		break;
	default:
		return;
	}
}

std::string EthLayer::toString() const
{
	return "Ethernet II Layer, Src: " + getSourceMac().toString() + ", Dst: " + getDestMac().toString();
}

} // namespace pcpp
