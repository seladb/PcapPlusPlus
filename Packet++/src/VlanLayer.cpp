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
#include "EndianPortable.h"

namespace pcpp
{

VlanLayer::VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType)
{
	const size_t headerLen = sizeof(vlan_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	m_Protocol = VLAN;

	vlan_header* vlanHeader = getVlanHeader();
	setVlanID(vlanID);
	setCFI(cfi);
	setPriority(priority);
	vlanHeader->etherType = htobe16(etherType);
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
	
	uint8_t* payload = m_Data + sizeof(vlan_header);
	size_t payloadLen = m_DataLen - sizeof(vlan_header);

	vlan_header* hdr = getVlanHeader();
	switch (be16toh(hdr->etherType))
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

std::string VlanLayer::toString() const
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
