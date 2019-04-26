#define LOG_MODULE PacketLogModuleVlanLayer

#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include <string.h>
#include <sstream>
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif
#include "EndianPortable.h"

namespace pcpp
{

VlanLayer::VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType)
{
	m_DataLen = sizeof(vlan_header);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = VLAN;

	vlan_header* vlanHeader = getVlanHeader();
	setVlanID(vlanID);
	setCFI(cfi);
	setPriority(priority);
	vlanHeader->etherType = htons(etherType);
}

uint16_t VlanLayer::getVlanID() const {
	return htobe16(getVlanHeader()->vlan) & 0xFFF;
}

uint8_t VlanLayer::getCFI() const {
	return ((htobe16(getVlanHeader()->vlan) >> 12) & 1);
}

uint8_t VlanLayer::getPriority() const {
	return (htobe16(getVlanHeader()->vlan) >> 13) & 7;
}

void VlanLayer::setVlanID(uint16_t id) {
	getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~0xFFF)) | (id & 0xFFF));
}

void VlanLayer::setCFI(bool cfi) {
	getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~(1 << 12))) | ((cfi & 1) << 12));
}

void VlanLayer::setPriority(uint8_t priority) {
	getVlanHeader()->vlan = htobe16((be16toh(getVlanHeader()->vlan) & (~(7 << 13))) | ((priority & 7) << 13));
}

void VlanLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(vlan_header))
		return;

	vlan_header* hdr = getVlanHeader();
	switch (ntohs(hdr->etherType))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(vlan_header), m_DataLen - sizeof(vlan_header), this, m_Packet);
	}
}

std::string VlanLayer::toString()
{
	std::ostringstream cfiStream;
	cfiStream << (int)getCFI();
	std::ostringstream priStream;
	priStream << (int)getPriority();
	std::ostringstream idStream;
	idStream << getVlanID();

	return "VLAN Layer, Priority: " + priStream.str() + ", Vlan ID: " + idStream.str() + ", CFI: " + cfiStream.str();
}

} // namespace pcpp
