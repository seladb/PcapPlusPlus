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
#include "EndianPortable.h"

namespace pcpp
{
	Sll2Layer::Sll2Layer(uint32_t interfaceIndex, uint16_t ARPHRDType, uint8_t packetType)
	{
		const size_t headerLen = sizeof(sll2_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setPacketType(packetType);
		setArphrdType(ARPHRDType);
		setInterfaceIndex(interfaceIndex);
		m_Protocol = SLL2;
	}

	bool Sll2Layer::setLinkLayerAddr(const uint8_t* addr, size_t addrLength)
	{
		if (addr == nullptr || addrLength == 0 || addrLength > 8)
		{
			PCPP_LOG_ERROR("Address length is out of bounds, it must be between 1 and 8");
			return false;
		}

		getSll2Header()->link_layer_addr_len = addrLength;
		memcpy(getSll2Header()->link_layer_addr, addr, addrLength);
		return true;
	}

	MacAddress Sll2Layer::getLinkLayerAsMacAddress()
	{
		const uint8_t* data = getLinkLayerAddr();
		uint8_t dataLen = getLinkLayerAddrLen();
		if (data == nullptr || dataLen == 0 || dataLen > 8)
		{
			return MacAddress::Zero;
		}
		return MacAddress(data);
	}

	bool Sll2Layer::setMacAddressAsLinkLayer(const MacAddress& macAddr)
	{
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

	bool Sll2Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(sll2_header);
	}

	std::string Sll2Layer::toString() const
	{
		return "Linux cooked header v2";
	}

	uint16_t Sll2Layer::getProtocolType() const
	{
		return be16toh(getSll2Header()->protocol_type);
	}

	void Sll2Layer::setProtocolType(uint16_t protocolType)
	{
		getSll2Header()->protocol_type = htobe16(protocolType);
	}

	uint32_t Sll2Layer::getInterfaceIndex() const
	{
		return be32toh(getSll2Header()->interface_index);
	}

	void Sll2Layer::setInterfaceIndex(uint32_t interfaceIndex)
	{
		getSll2Header()->interface_index = htobe32(interfaceIndex);
	}

	uint16_t Sll2Layer::getArphrdType() const
	{
		return be16toh(getSll2Header()->ARPHRD_type);
	}

	void Sll2Layer::setArphrdType(uint16_t arphrdType)
	{
		getSll2Header()->ARPHRD_type = htobe16(arphrdType);
	}

	uint8_t Sll2Layer::getPacketType() const
	{
		return getSll2Header()->packet_type;
	}

	void Sll2Layer::setPacketType(uint8_t packetType)
	{
		getSll2Header()->packet_type = packetType;
	}

	uint8_t Sll2Layer::getLinkLayerAddrLen() const
	{
		return getSll2Header()->link_layer_addr_len;
	}

	const uint8_t* Sll2Layer::getLinkLayerAddr() const
	{
		return getSll2Header()->link_layer_addr;
	}

}  // namespace pcpp
