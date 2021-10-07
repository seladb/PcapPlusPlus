#include "DhcpV6Layer.h"
#include "GeneralUtils.h"

namespace pcpp
{

DhcpV6OptionType DhcpV6Option::getType() const
{
	uint16_t optionType = be16toh(m_Data->recordType);
	if (optionType <= 62 && optionType != 10 && optionType != 35 && optionType != 57 && optionType != 58)
	{
		return static_cast<DhcpV6OptionType>(optionType);
	}
	if (optionType == 65 || optionType == 66 || optionType == 68 || optionType == 79 || optionType == 112)
	{
		return static_cast<DhcpV6OptionType>(optionType);
	}

	return DhcpV6OptionType::DHCPV6_OPT_UNKNOWN;
}

std::string DhcpV6Option::getValueAsHexString() const
{
	return byteArrayToHexString(m_Data->recordValue, getDataSize());
}

size_t DhcpV6Option::getTotalSize() const
{
	return 2*sizeof(uint16_t) + be16toh(m_Data->recordLen);
}

size_t DhcpV6Option::getDataSize() const
{
	return static_cast<size_t>(be16toh(m_Data->recordLen));
}

DhcpV6Layer::DhcpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = DHCPv6;
}

DhcpV6MessageType DhcpV6Layer::getMessageType() const
{
	uint8_t messageType = getDhcpHeader()->messageType;
	if (messageType > 13)
	{
		return DHCPV6_UNKNOWN_MSG_TYPE;
	}

	return static_cast<DhcpV6MessageType>(messageType);
}

std::string DhcpV6Layer::getMessageTypeAsString() const
{
	DhcpV6MessageType messageType = getMessageType();
	switch (messageType)
	{
		case DHCPV6_SOLICIT:
			return "Solicit";
		case DHCPV6_ADVERTISE:
			return "Advertise";
		case DHCPV6_REQUEST:
			return "Request";
		case DHCPV6_CONFIRM:
			return "Confirm";
		case DHCPV6_RENEW:
			return "Renew";
		case DHCPV6_REBIND:
			return "Rebind";
		case DHCPV6_REPLY:
			return "Reply";
		case DHCPV6_RELEASE:
			return "Release";
		case DHCPV6_DECLINE:
			return "Decline";
		case DHCPV6_RECONFIGURE:
			return "Reconfigure";
		case DHCPV6_INFORMATION_REQUEST:
			return "Information-Request";
		case DHCPV6_RELAY_FORWARD:
			return "Relay-Forward";
		case DHCPV6_RELAY_REPLY:
			return "Relay-Reply";
		default:
			return "Unknown";
	}
}

uint32_t DhcpV6Layer::getTransactionID() const
{
	dhcpv6_header* hdr = getDhcpHeader();
	uint32_t result = hdr->transactionId1 << 16 | hdr->transactionId2 << 8 | hdr->transactionId3;
	return result;
}

DhcpV6Option DhcpV6Layer::getFirstOptionData() const
{
	return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
}

DhcpV6Option DhcpV6Layer::getNextOptionData(DhcpV6Option dhcpv6Option) const
{
	return m_OptionReader.getNextTLVRecord(dhcpv6Option, getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
}

DhcpV6Option DhcpV6Layer::getOptionData(DhcpV6OptionType option) const
{
	return m_OptionReader.getTLVRecord(static_cast<uint32_t>(option), getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
}

size_t DhcpV6Layer::getOptionCount() const
{
	return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
}

std::string DhcpV6Layer::toString() const
{
	return "DHCPv6 Layer, " + getMessageTypeAsString() + " message";
}

}
