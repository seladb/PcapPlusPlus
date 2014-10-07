#define LOG_MODULE eVlanLayer

#include <VlanLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <ArpLayer.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <in.h>
#endif


VlanLayer::VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType)
{
	m_DataLen = sizeof(vlan_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, sizeof(m_DataLen));
	m_Protocol = VLAN;

	vlan_header* vlanHeader = getVlanHeader();
	setVlanID(vlanID);
	vlanHeader->cfi = cfi;
	vlanHeader->priority = 0x07 & priority;
	vlanHeader->etherType = htons(etherType);
}

void VlanLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(vlan_header))
		return;

	vlan_header* hdr = getVlanHeader();
	switch (ntohs(hdr->etherType))
	{
	case ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this);
		break;
	case ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this);
		break;
	case ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this);
		break;
	case ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this);
	}
}
