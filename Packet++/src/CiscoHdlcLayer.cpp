#include "CiscoHdlcLayer.h"
#include "Layer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include <string.h>

namespace pcpp
{

// Protocol types for Cisco HDLC
#define CISCO_HDLC_TYPE_IP 0x0800
#define CISCO_HDLC_TYPE_IPV6 0x86DD

	CiscoHdlcLayer::CiscoHdlcLayer(AddressType address)
	{
		m_DataLen = sizeof(cisco_hdlc_header);
		m_Data = new uint8_t[m_DataLen]{};

		cisco_hdlc_header* hdlcHdr = getCiscoHdlcHeader();
		hdlcHdr->address = static_cast<uint8_t>(address == AddressType::Unknown ? AddressType::Unicast : address);
		hdlcHdr->control = 0;  // Always 0 for Cisco HDLC
	}

	void CiscoHdlcLayer::computeCalculateFields()
	{
		if (m_NextLayer != nullptr)
		{
			switch (m_NextLayer->getProtocol())
			{
			case IPv4:
			{
				setNextProtocol(CISCO_HDLC_TYPE_IP);
				break;
			}
			case IPv6:
			{
				setNextProtocol(CISCO_HDLC_TYPE_IPV6);
				break;
			}
			}
		}
	}

	void CiscoHdlcLayer::parseNextLayer()
	{
		auto payload = m_Data + sizeof(cisco_hdlc_header);
		auto payloadLen = m_DataLen - sizeof(cisco_hdlc_header);

		auto nextProtocol = be16toh(getCiscoHdlcHeader()->protocol);

		switch (nextProtocol)
		{
		case CISCO_HDLC_TYPE_IP:
		{
			m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		}
		case CISCO_HDLC_TYPE_IPV6:
		{
			m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		}
		default:
		{
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
			break;
		}
		}
	}

	std::string CiscoHdlcLayer::toString() const
	{
		return "Cisco HDLC Layer";
	}

	CiscoHdlcLayer::AddressType CiscoHdlcLayer::getAddress() const
	{
		switch (static_cast<AddressType>(getAddressValue()))
		{
		case AddressType::Unicast:
		case AddressType::Multicast:
		{
			return static_cast<AddressType>(getAddressValue());
		}
		default:
		{
			return AddressType::Unknown;
		}
		}
	}

	uint8_t CiscoHdlcLayer::getAddressValue() const
	{
		return getCiscoHdlcHeader()->address;
	}

	void CiscoHdlcLayer::setAddress(AddressType address)
	{
		if (address == AddressType::Unknown)
		{
			throw std::invalid_argument("Cannot set the address to Address::Unknown");
		}

		setAddressValue(static_cast<uint8_t>(address));
	}

	void CiscoHdlcLayer::setAddressValue(uint8_t address)
	{
		getCiscoHdlcHeader()->address = address;
	}

	uint16_t CiscoHdlcLayer::getNextProtocol() const
	{
		return be16toh(getCiscoHdlcHeader()->protocol);
	}

	void CiscoHdlcLayer::setNextProtocol(uint16_t protocol)
	{
		getCiscoHdlcHeader()->protocol = htobe16(protocol);
	}
}  // namespace pcpp
