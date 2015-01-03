#define LOG_MODULE PacketLogModuleEthLayer

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <ArpLayer.h>
#include <VlanLayer.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <in.h>
#endif

EthLayer::EthLayer(MacAddress& sourceMac, MacAddress& destMac, uint16_t etherType) : Layer()
{
	m_DataLen = sizeof(ether_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	ether_header* ethHdr = (ether_header*)m_Data;
	destMac.copyTo(ethHdr->dstMac);
	sourceMac.copyTo(ethHdr->srcMac);
	ethHdr->etherType = htons(etherType);
	m_Protocol = Ethernet;
}

void EthLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(ether_header))
		return;

	ether_header* hdr = getEthHeader();
	switch (ntohs(hdr->etherType))
	{
	case ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(ether_header), m_DataLen - sizeof(ether_header), this, m_Packet);
		break;
	case ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(ether_header), m_DataLen - sizeof(ether_header), this, m_Packet);
		break;
	case ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(ether_header), m_DataLen - sizeof(ether_header), this, m_Packet);
		break;
	case ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(ether_header), m_DataLen - sizeof(ether_header), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(ether_header), m_DataLen - sizeof(ether_header), this, m_Packet);
	}

}

void EthLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	switch (m_NextLayer->getProtocol())
	{
		case IPv4:
			getEthHeader()->etherType = htons(ETHERTYPE_IP);
			break;
		case IPv6:
			getEthHeader()->etherType = htons(ETHERTYPE_IPV6);
			break;
		case ARP:
			getEthHeader()->etherType = htons(ETHERTYPE_ARP);
			break;
		case VLAN:
			getEthHeader()->etherType = htons(ETHERTYPE_VLAN);
			break;
		default:
			return;
	}
}

string EthLayer::toString()
{
	return "Ethernet II Layer, Src: " + getSourceMac().toString() + ", Dst: " + getDestMac().toString();
}
