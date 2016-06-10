#define LOG_MODULE PacketLogModuleSllLayer

#include <SllLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <ArpLayer.h>
#include <VlanLayer.h>
#include <PPPoELayer.h>
#include <MplsLayer.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#elif LINUX
#include <in.h>
#elif MAC_OS_X
#include <arpa/inet.h>
#endif

namespace pcpp
{

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

