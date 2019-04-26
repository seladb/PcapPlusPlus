#define LOG_MODULE PacketLogModuleDhcpLayer

#include "DhcpLayer.h"
#include "Logger.h"

namespace pcpp
{

#define DHCP_MAGIC_NUMBER 0x63538263


DhcpOption DhcpOptionBuilder::build() const
{
	size_t recSize = 2*sizeof(uint8_t) + m_RecValueLen;

	if ((m_RecType == DHCPOPT_END || m_RecType == DHCPOPT_PAD))
	{
		if (m_RecValueLen != 0)
		{
			LOG_ERROR("Can't set DHCP END option or DHCP PAD option with size different than 0, tried to set size %d", m_RecValueLen);
			return DhcpOption(NULL);
		}

		recSize = sizeof(uint8_t);
	}

	uint8_t* recordBuffer = new uint8_t[recSize];
	memset(recordBuffer, 0, recSize);
	recordBuffer[0] = m_RecType;
	if (recSize > 1)
	{
		recordBuffer[1] = m_RecValueLen;
		if (m_RecValue != NULL)
			memcpy(recordBuffer+2, m_RecValue, m_RecValueLen);
		else
			memset(recordBuffer+2, 0, m_RecValueLen);
	}

	return DhcpOption(recordBuffer);
}

DhcpLayer::DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	 m_Protocol = DHCP;
}

void DhcpLayer::initDhcpLayer(size_t numOfBytesToAllocate)
{
	m_DataLen = numOfBytesToAllocate;
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = DHCP;
}

DhcpLayer::DhcpLayer() : Layer()
{
	initDhcpLayer(sizeof(dhcp_header));
}

DhcpLayer::DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr) : Layer()
{
	initDhcpLayer(sizeof(dhcp_header) + 4*sizeof(uint8_t));

	setClientHardwareAddress(clientMacAddr);

	uint8_t* msgTypeOptionPtr = m_Data + sizeof(dhcp_header);
	msgTypeOptionPtr[0] = (uint8_t)DHCPOPT_DHCP_MESSAGE_TYPE; // option code
	msgTypeOptionPtr[1] = 1; // option len
	msgTypeOptionPtr[2] = (uint8_t)msgType; // option data - message type

	msgTypeOptionPtr[3] =  (uint8_t)DHCPOPT_END;
}

IPv4Address DhcpLayer::getClientIpAddress() const
{
	return IPv4Address(getDhcpHeader()->clientIpAddress);
}

void DhcpLayer::setClientIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->clientIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getServerIpAddress() const
{
	return IPv4Address(getDhcpHeader()->serverIpAddress);
}

void DhcpLayer::setServerIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->serverIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getYourIpAddress() const
{
	return IPv4Address(getDhcpHeader()->yourIpAddress);
}

void DhcpLayer::setYourIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->yourIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getGatewayIpAddress() const
{
	return IPv4Address(getDhcpHeader()->gatewayIpAddress);
}

void DhcpLayer::setGatewayIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->gatewayIpAddress = addr.toInt();
}

MacAddress DhcpLayer::getClientHardwareAddress() const
{
	dhcp_header* hdr = getDhcpHeader();
	if (hdr != NULL && hdr->hardwareType == 1 && hdr->hardwareAddressLength == 6)
		return MacAddress(hdr->clientHardwareAddress);

	LOG_DEBUG("Hardware type isn't Ethernet or hardware addr len != 6, returning MacAddress:Zero");

	return MacAddress::Zero;
}

void DhcpLayer::setClientHardwareAddress(const MacAddress& addr)
{
	dhcp_header* hdr = getDhcpHeader();
	hdr->hardwareType = 1; // Ethernet
	hdr->hardwareAddressLength = 6; // MAC address length
	addr.copyTo(hdr->clientHardwareAddress);
}

size_t DhcpLayer::getHeaderLen()
{
	// assuming no more layers DHCP
	return m_DataLen;
}

void DhcpLayer::computeCalculateFields()
{
	dhcp_header* hdr = getDhcpHeader();

	hdr->magicNumber = DHCP_MAGIC_NUMBER;

	DhcpMessageType msgType = getMesageType();
	switch(msgType)
	{
	case DHCP_DISCOVER:
	case DHCP_REQUEST:
	case DHCP_DECLINE:
	case DHCP_RELEASE:
	case DHCP_INFORM:
	case DHCP_UNKNOWN_MSG_TYPE:
		hdr->opCode = DHCP_BOOTREQUEST;
		break;
	case DHCP_OFFER:
	case DHCP_ACK:
	case DHCP_NAK:
		hdr->opCode = DHCP_BOOTREPLY;
		break;
	default:
		break;
	}

	hdr->hardwareType = 1; //Ethernet
	hdr->hardwareAddressLength = 6; // MAC address length
}

std::string DhcpLayer::toString()
{
	std::string msgType = "Unknown";
	switch (getMesageType())
	{
	case DHCP_DISCOVER:
	{
		msgType = "Discover";
		break;
	}
	case DHCP_OFFER:
	{
		msgType = "Offer";
		break;
	}
	case DHCP_REQUEST:
	{
		msgType = "Request";
		break;
	}
	case DHCP_DECLINE:
	{
		msgType = "Decline";
		break;
	}
	case DHCP_ACK:
	{
		msgType = "Acknowledge";
		break;
	}
	case DHCP_NAK:
	{
		msgType = "Negative Acknowledge";
		break;
	}
	case DHCP_RELEASE:
	{
		msgType = "Release";
		break;
	}
	case DHCP_INFORM:
	{
		msgType = "Inform";
		break;
	}
	default:
		break;

	}

	return "DHCP layer (" + msgType + ")";
}

DhcpMessageType DhcpLayer::getMesageType()
{
	DhcpOption opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
	if (opt.isNull())
		return DHCP_UNKNOWN_MSG_TYPE;

	return (DhcpMessageType)opt.getValueAs<uint8_t>();
}

bool DhcpLayer::setMesageType(DhcpMessageType msgType)
{
	if (msgType == DHCP_UNKNOWN_MSG_TYPE)
		return false;

	DhcpOption opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
	if (opt.isNull())
	{
		opt = addOptionAfter(DhcpOptionBuilder(DHCPOPT_DHCP_MESSAGE_TYPE, (uint8_t)msgType), DHCPOPT_UNKNOWN);
		if (opt.isNull())
			return false;
	}

	opt.setValue<uint8_t>((uint8_t)msgType);
	return true;
}

DhcpOption DhcpLayer::getOptionData(DhcpOptionTypes option)
{
	return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
}

DhcpOption DhcpLayer::getFirstOptionData()
{
	return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
}

DhcpOption DhcpLayer::getNextOptionData(DhcpOption dhcpOption)
{
	return m_OptionReader.getNextTLVRecord(dhcpOption, getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
}

size_t DhcpLayer::getOptionsCount()
{
	return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
}

DhcpOption DhcpLayer::addOptionAt(const DhcpOptionBuilder& optionBuilder, int offset)
{
	DhcpOption newOpt = optionBuilder.build();

	if (newOpt.isNull())
	{
		LOG_ERROR("Cannot build new option of type %d", (int)newOpt.getType());
		return DhcpOption(NULL);
	}

	size_t sizeToExtend = newOpt.getTotalSize();

	if (!extendLayer(offset, sizeToExtend))
	{
		LOG_ERROR("Could not extend DhcpLayer in [%d] bytes", (int)newOpt.getTotalSize());
		return DhcpOption(NULL);
	}

	memcpy(m_Data + offset, newOpt.getRecordBasePtr(), newOpt.getTotalSize());

	uint8_t* newOptPtr = m_Data + offset;

	m_OptionReader.changeTLVRecordCount(1);

	newOpt.purgeRecordData();

	return DhcpOption(newOptPtr);
}

DhcpOption DhcpLayer::addOption(const DhcpOptionBuilder& optionBuilder)
{
	int offset = 0;
	DhcpOption endOpt = getOptionData(DHCPOPT_END);
	if (!endOpt.isNull())
		offset = endOpt.getRecordBasePtr() - m_Data;
	else
		offset = getHeaderLen();

	return addOptionAt(optionBuilder, offset);
}

DhcpOption DhcpLayer::addOptionAfter(const DhcpOptionBuilder& optionBuilder, DhcpOptionTypes prevOption)
{
	int offset = 0;

	DhcpOption prevOpt = getOptionData(prevOption);

	if (prevOpt.isNull())
	{
		offset = sizeof(dhcp_header);
	}
	else
	{
		offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
	}

	return addOptionAt(optionBuilder, offset);
}

bool DhcpLayer::removeOption(DhcpOptionTypes optionType)
{
	DhcpOption optToRemove = getOptionData(optionType);
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

bool DhcpLayer::removeAllOptions()
{
	int offset = sizeof(dhcp_header);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	m_OptionReader.changeTLVRecordCount(0-getOptionsCount());
	return true;
}


}
