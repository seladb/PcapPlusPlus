#define LOG_MODULE PacketLogModuleDhcpLayer

#include "DhcpLayer.h"
#include "Logger.h"

namespace pcpp
{

#define DHCP_MAGIC_NUMBER 0x63538263

DhcpLayer::DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	 m_Protocol = DHCP;
	 m_DhcpOptionsCount = -1;
}

void DhcpLayer::initDhcpLayer(size_t numOfBytesToAllocate)
{
	m_DataLen = numOfBytesToAllocate;
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = DHCP;
	m_DhcpOptionsCount = -1;
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

IPv4Address DhcpLayer::getClientIpAddress()
{
	return IPv4Address(getDhcpHeader()->clientIpAddress);
}

void DhcpLayer::setClientIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->clientIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getServerIpAddress()
{
	return IPv4Address(getDhcpHeader()->serverIpAddress);
}

void DhcpLayer::setServerIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->serverIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getYourIpAddress()
{
	return IPv4Address(getDhcpHeader()->yourIpAddress);
}

void DhcpLayer::setYourIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->yourIpAddress = addr.toInt();
}

IPv4Address DhcpLayer::getGatewayIpAddress()
{
	return IPv4Address(getDhcpHeader()->gatewayIpAddress);
}

void DhcpLayer::setGatewayIpAddress(const IPv4Address& addr)
{
	getDhcpHeader()->gatewayIpAddress = addr.toInt();
}

MacAddress DhcpLayer::getClientHardwareAddress()
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
	DhcpOptionData* opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
	if (opt == NULL)
		return DHCP_UNKNOWN_MSG_TYPE;

	return (DhcpMessageType)opt->getValueAs<uint8_t>();
}

bool DhcpLayer::setMesageType(DhcpMessageType msgType)
{
	if (msgType == DHCP_UNKNOWN_MSG_TYPE)
		return false;

	DhcpOptionData* opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
	if (opt == NULL)
	{
		opt = addOptionAfter(DHCPOPT_DHCP_MESSAGE_TYPE, 1, NULL, DHCPOPT_UNKNOWN);
		if (opt == NULL)
			return false;
	}

	opt->setValue<uint8_t>((uint8_t)msgType);
	return true;
}

DhcpOptionData* DhcpLayer::castPtrToOptionData(uint8_t* ptr)
{
	return (DhcpOptionData*)ptr;
}

DhcpOptionData* DhcpLayer::getOptionData(DhcpOptionTypes option)
{
	// check if there are DHCP options at all
	if (m_DataLen <= sizeof(dhcp_header))
		return NULL;

	if (option == DHCPOPT_UNKNOWN)
		return NULL;

	uint8_t* curOptPtr = m_Data + sizeof(dhcp_header);
	while ((curOptPtr - m_Data) < (int)m_DataLen)
	{
		DhcpOptionData* curOpt = castPtrToOptionData(curOptPtr);
		if ((int)curOpt->opCode == option)
			return curOpt;

		curOptPtr += curOpt->getTotalSize();
	}

	return NULL;
}

DhcpOptionData* DhcpLayer::getFirstOptionData()
{
	// check if there are DHCP options at all
	if (getHeaderLen() <= sizeof(dhcp_header))
		return NULL;

	uint8_t* curOptPtr = m_Data + sizeof(dhcp_header);
	return castPtrToOptionData(curOptPtr);
}

DhcpOptionData* DhcpLayer::getNextOptionData(DhcpOptionData* dhcpOption)
{
	if (dhcpOption == NULL)
		return NULL;

	// prev opt was the last opt
	if ((uint8_t*)dhcpOption + dhcpOption->getTotalSize() - m_Data >= (int)getHeaderLen())
		return NULL;

	DhcpOptionData* nextOption = castPtrToOptionData((uint8_t*)dhcpOption + dhcpOption->getTotalSize());

	// TOOD: see if this is necessary
	//	if (nextOption->option == TCPOPT_DUMMY)
	//		return NULL;

	return nextOption;
}

size_t DhcpLayer::getOptionsCount()
{
	if (m_DhcpOptionsCount != (size_t)-1)
		return m_DhcpOptionsCount;

	m_DhcpOptionsCount = 0;
	DhcpOptionData* curOpt = getFirstOptionData();
	while (curOpt != NULL)
	{
		m_DhcpOptionsCount++;
		curOpt = getNextOptionData(curOpt);
	}

	return m_DhcpOptionsCount;
}

DhcpOptionData* DhcpLayer::addOptionAt(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, int offset)
{
	size_t sizeToExtend = optionLen + 2*sizeof(uint8_t);

	if ((optionType == DHCPOPT_END || optionType == DHCPOPT_PAD))
	{
		if (optionLen != 0)
		{
			LOG_ERROR("Can't set DHCP END option or DHCP PAD option with size different than 0, tried to set size %d", optionLen);
			return NULL;
		}

		sizeToExtend = sizeof(uint8_t);
	}

	if (!extendLayer(offset, sizeToExtend))
	{
		LOG_ERROR("Could not extend DhcpLayer in [%d] bytes", optionLen);
		return NULL;
	}

	uint8_t optionTypeVal = (uint8_t)optionType;
	memcpy(m_Data + offset, &optionTypeVal, sizeof(uint8_t));

	if (optionLen > 0)
	{
		memcpy(m_Data + offset + sizeof(uint8_t), &optionLen, sizeof(uint8_t));
		if (optionLen > 1 && optionData != NULL)
			memcpy(m_Data + offset + 2*sizeof(uint8_t), optionData, optionLen);
	}

	uint8_t* newOptPtr = m_Data + offset;

	m_DhcpOptionsCount++;

	return castPtrToOptionData(newOptPtr);
}

DhcpOptionData* DhcpLayer::addOption(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData)
{
	int offset = 0;
	DhcpOptionData* endOpt = getOptionData(DHCPOPT_END);
	if (endOpt != NULL)
		offset = ((uint8_t*)endOpt) - m_Data;
	else
		offset = getHeaderLen();

	return addOptionAt(optionType, optionLen, optionData, offset);
}

DhcpOptionData* DhcpLayer::addOptionAfter(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, DhcpOptionTypes prevOption)
{
	int offset = 0;

	DhcpOptionData* prevOpt = getOptionData(prevOption);

	if (prevOpt == NULL)
	{
		offset = sizeof(dhcp_header);
	}
	else
	{
		offset = (uint8_t*)prevOpt + prevOpt->getTotalSize() - m_Data;
	}

	return addOptionAt(optionType, optionLen, optionData, offset);
}

bool DhcpLayer::removeOption(DhcpOptionTypes optionType)
{
	DhcpOptionData* opt = getOptionData(optionType);
	if (opt == NULL)
	{
		return false;
	}

	int offset = (uint8_t*)opt - m_Data;

	if (!shortenLayer(offset, opt->getTotalSize()))
	{
		return false;
	}

	m_DhcpOptionsCount--;

	return true;
}

bool DhcpLayer::removeAllOptions()
{
	int offset = sizeof(dhcp_header);

	if (!shortenLayer(offset, getHeaderLen()-offset))
		return false;

	m_DhcpOptionsCount = 0;
	return true;
}


}
