#define LOG_MODULE PacketLogModuleDhcpV6Layer

#include "DhcpV6Layer.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"

namespace pcpp
{

	DhcpV6OptionType DhcpV6Option::getType() const
	{
		if (m_Data == nullptr)
			return DhcpV6OptionType::DHCPV6_OPT_UNKNOWN;

		uint16_t optionType = be16toh(m_Data->recordType);
		if (optionType <= 62 && optionType != 10 && optionType != 35 && optionType != 57 && optionType != 58)
		{
			return static_cast<DhcpV6OptionType>(optionType);
		}
		if (optionType == 65 || optionType == 66 || optionType == 68 || optionType == 79 || optionType == 112)
		{
			return static_cast<DhcpV6OptionType>(optionType);
		}

		return DHCPV6_OPT_UNKNOWN;
	}

	std::string DhcpV6Option::getValueAsHexString() const
	{
		if (m_Data == nullptr)
			return "";

		return byteArrayToHexString(m_Data->recordValue, getDataSize());
	}

	size_t DhcpV6Option::getTotalSize() const
	{
		if (m_Data == nullptr)
			return 0;

		return 2 * sizeof(uint16_t) + be16toh(m_Data->recordLen);
	}

	size_t DhcpV6Option::getDataSize() const
	{
		if (m_Data == nullptr)
			return 0;

		return static_cast<size_t>(be16toh(m_Data->recordLen));
	}

	DhcpV6Option DhcpV6OptionBuilder::build() const
	{
		if (m_RecType == 0)
			return DhcpV6Option(nullptr);

		size_t optionSize = 2 * sizeof(uint16_t) + m_RecValueLen;
		uint8_t* recordBuffer = new uint8_t[optionSize];
		uint16_t optionTypeVal = htobe16(static_cast<uint16_t>(m_RecType));
		uint16_t optionLength = htobe16(static_cast<uint16_t>(m_RecValueLen));
		memcpy(recordBuffer, &optionTypeVal, sizeof(uint16_t));
		memcpy(recordBuffer + sizeof(uint16_t), &optionLength, sizeof(uint16_t));
		if (optionSize > 0 && m_RecValue != nullptr)
			memcpy(recordBuffer + 2 * sizeof(uint16_t), m_RecValue, m_RecValueLen);

		return DhcpV6Option(recordBuffer);
	}

	DhcpV6Layer::DhcpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, DHCPv6)
	{}

	DhcpV6Layer::DhcpV6Layer(DhcpV6MessageType messageType, uint32_t transactionId)
	{
		m_DataLen = sizeof(dhcpv6_header);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = DHCPv6;

		setMessageType(messageType);
		setTransactionID(transactionId);
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

	void DhcpV6Layer::setMessageType(DhcpV6MessageType messageType)
	{
		getDhcpHeader()->messageType = static_cast<uint8_t>(messageType);
	}

	uint32_t DhcpV6Layer::getTransactionID() const
	{
		dhcpv6_header* hdr = getDhcpHeader();
		uint32_t result = hdr->transactionId1 << 16 | hdr->transactionId2 << 8 | hdr->transactionId3;
		return result;
	}

	void DhcpV6Layer::setTransactionID(uint32_t transactionId) const
	{
		dhcpv6_header* hdr = getDhcpHeader();
		hdr->transactionId1 = (transactionId >> 16) & 0xff;
		hdr->transactionId2 = (transactionId >> 8) & 0xff;
		hdr->transactionId3 = transactionId & 0xff;
	}

	DhcpV6Option DhcpV6Layer::getFirstOptionData() const
	{
		return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
	}

	DhcpV6Option DhcpV6Layer::getNextOptionData(DhcpV6Option dhcpv6Option) const
	{
		return m_OptionReader.getNextTLVRecord(dhcpv6Option, getOptionsBasePtr(),
		                                       getHeaderLen() - sizeof(dhcpv6_header));
	}

	DhcpV6Option DhcpV6Layer::getOptionData(DhcpV6OptionType option) const
	{
		return m_OptionReader.getTLVRecord(static_cast<uint32_t>(option), getOptionsBasePtr(),
		                                   getHeaderLen() - sizeof(dhcpv6_header));
	}

	size_t DhcpV6Layer::getOptionCount() const
	{
		return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcpv6_header));
	}

	DhcpV6Option DhcpV6Layer::addOptionAt(const DhcpV6OptionBuilder& optionBuilder, int offset)
	{
		DhcpV6Option newOpt = optionBuilder.build();
		if (newOpt.isNull())
		{
			PCPP_LOG_ERROR("Cannot build new option");
			return DhcpV6Option(nullptr);
		}

		size_t sizeToExtend = newOpt.getTotalSize();

		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend DhcpLayer in [" << newOpt.getTotalSize() << "] bytes");
			newOpt.purgeRecordData();
			return DhcpV6Option(nullptr);
		}

		memcpy(m_Data + offset, newOpt.getRecordBasePtr(), newOpt.getTotalSize());

		uint8_t* newOptPtr = m_Data + offset;

		m_OptionReader.changeTLVRecordCount(1);

		newOpt.purgeRecordData();

		return DhcpV6Option(newOptPtr);
	}

	DhcpV6Option DhcpV6Layer::addOption(const DhcpV6OptionBuilder& optionBuilder)
	{
		return addOptionAt(optionBuilder, getHeaderLen());
	}

	DhcpV6Option DhcpV6Layer::addOptionAfter(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType)
	{
		int offset = 0;

		DhcpV6Option prevOpt = getOptionData(optionType);

		if (prevOpt.isNull())
		{
			PCPP_LOG_ERROR("Option type " << optionType << " doesn't exist in layer");
			return DhcpV6Option(nullptr);
		}
		offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
		return addOptionAt(optionBuilder, offset);
	}

	DhcpV6Option DhcpV6Layer::addOptionBefore(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType)
	{
		int offset = 0;

		DhcpV6Option nextOpt = getOptionData(optionType);

		if (nextOpt.isNull())
		{
			PCPP_LOG_ERROR("Option type " << optionType << " doesn't exist in layer");
			return DhcpV6Option(nullptr);
		}

		offset = nextOpt.getRecordBasePtr() - m_Data;
		return addOptionAt(optionBuilder, offset);
	}

	bool DhcpV6Layer::removeOption(DhcpV6OptionType optionType)
	{
		DhcpV6Option optToRemove = getOptionData(optionType);
		if (optToRemove.isNull())
		{
			return false;
		}

		int offset = optToRemove.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, optToRemove.getTotalSize()))
		{
			return false;
		}

		m_OptionReader.changeTLVRecordCount(-1);
		return true;
	}

	bool DhcpV6Layer::removeAllOptions()
	{
		int offset = sizeof(dhcpv6_header);

		if (!shortenLayer(offset, getHeaderLen() - offset))
			return false;

		m_OptionReader.changeTLVRecordCount(0 - getOptionCount());
		return true;
	}

	std::string DhcpV6Layer::toString() const
	{
		return "DHCPv6 Layer, " + getMessageTypeAsString() + " message";
	}

}  // namespace pcpp
