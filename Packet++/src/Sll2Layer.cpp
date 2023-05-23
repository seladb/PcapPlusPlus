#define LOG_MODULE PacketLogModuleSll2Layer

#include "Sll2Layer.h"
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
bool Sll2Layer::setLinkLayerAddr(uint8_t* addr, size_t addrLength)
{
	if (addrLength == 0 || addrLength > 8)
	{
		PCPP_LOG_ERROR("Address length is out of bounds, it must be between 1 and 8");
		return false;
	}

	sll2_header* sll2Hdr = (sll2_header*)m_Data;
	memcpy(sll2Hdr->link_layer_addr, addr, addrLength);
	sll2Hdr->link_layer_addr_len = htobe16(addrLength);
	return true;
}

bool Sll2Layer::setMacAddressAsLinkLayer(MacAddress macAddr)
{
	if (!macAddr.isValid())
	{
		PCPP_LOG_ERROR("MAC address is not valid");
		return false;
	}

	uint8_t macAddrAsArr[6];
	macAddr.copyTo(macAddrAsArr);
	return setLinkLayerAddr(macAddrAsArr, 6);
}

void Sll2Layer::parseNextLayer()
{
	if (m_DataLen <= sizeof(sll2_header))
		return;

	uint8_t* payload = m_Data + sizeof(sll2_header);
	size_t payloadLen = m_DataLen - sizeof(sll2_header);

	sll2_header* hdr = getSll2Header();
	switch (be16toh(hdr->protocol_type))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
	case PCPP_ETHERTYPE_IEEE_802_1AD:
		m_NextLayer = new VlanLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = PPPoESessionLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new PPPoESessionLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = PPPoEDiscoveryLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new PPPoEDiscoveryLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(payload, payloadLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

}

void Sll2Layer::computeCalculateFields()
{
	if (m_NextLayer == nullptr)
		return;

	sll2_header* hdr = getSll2Header();
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

std::string Sll2Layer::toString() const
{
	return "Linux cooked header v2";
}

} // namespace pcpp
