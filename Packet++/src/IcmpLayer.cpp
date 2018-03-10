#define LOG_MODULE PacketLogModuleIcmpLayer

#include "IcmpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "IpUtils.h"
#include "Logger.h"
#include <sstream>
#include <string.h>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace pcpp
{

icmp_router_address_structure* icmp_router_advertisement::getRouterAddress(int index)
{
	if (index < 0 || index >= header->advertisementCount)
		return NULL;

	uint8_t* headerAsByteArr = (uint8_t*)header;
	return (icmp_router_address_structure*)(headerAsByteArr + sizeof(icmp_router_advertisement_hdr) + index*sizeof(icmp_router_address_structure));
}

void icmp_router_address_structure::setRouterAddress(IPv4Address addr, uint32_t preference)
{
	routerAddress = addr.toInt();
	preferenceLevel = htonl(preference);
}

IPv4Address icmp_router_address_structure::getAddress()
{
	return IPv4Address(routerAddress);
}

IcmpLayer::IcmpLayer() : Layer()
{
	m_DataLen = sizeof(icmphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMP;
}

IcmpMessageType IcmpLayer::getMessageType()
{
	uint8_t type = getIcmpHeader()->type;
	if (type > 18)
		return ICMP_UNSUPPORTED;

	return (IcmpMessageType)type;
}

bool IcmpLayer::isMessageOfType(IcmpMessageType type)
{
	return (getMessageType() == type);
}

bool IcmpLayer::cleanIcmpLayer()
{
	// remove all layers after

	if (m_Packet != NULL)
	{
		Layer* layerToRemove = this->getNextLayer();
		while (layerToRemove != NULL)
		{
			Layer* temp = layerToRemove->getNextLayer();
			if (!m_Packet->removeLayer(layerToRemove))
				return false;
			layerToRemove = temp;
		}
	}


	// shorten layer to size of icmphdr

	size_t headerLen = this->getHeaderLen();
	if (headerLen > sizeof(icmphdr))
	{
		if (!this->shortenLayer(sizeof(icmphdr), headerLen - sizeof(icmphdr)))
			return false;
	}

	return true;
}

bool IcmpLayer::setEchoData(IcmpMessageType echoType, uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen)
{
	if (!cleanIcmpLayer())
		return false;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_echo_hdr) - sizeof(icmphdr) + dataLen))
		return false;

	getIcmpHeader()->type = (uint8_t)echoType;

	icmp_echo_request* header = NULL;
	if (echoType == ICMP_ECHO_REQUEST)
		header = getEchoRequestData();
	else if (echoType == ICMP_ECHO_REPLY)
		header = (icmp_echo_request*)getEchoReplyData();
	else
		return false;

	header->header->code = 0;
	header->header->checksum = 0;
	header->header->id = htons(id);
	header->header->sequence = htons(sequence);
	header->header->timestamp = timestamp;
	if (data != NULL && dataLen > 0)
		memcpy(header->data, data, dataLen);

	return true;
}

bool IcmpLayer::setIpAndL4Layers(IPv4Layer* ipLayer, Layer* l4Layer)
{
	if (m_Packet == NULL)
	{
		LOG_ERROR("Cannot set ICMP data that involves IP and L4 layers on a layer not attached to a packet. "
				"Please add the ICMP layer to a packet and try again");
		return false;
	}

	if (ipLayer != NULL && !m_Packet->addLayer(ipLayer))
	{
		LOG_ERROR("Couldn't add IP layer to ICMP packet");
		return false;
	}

	if (l4Layer != NULL && !m_Packet->addLayer(l4Layer))
	{
		LOG_ERROR("Couldn't add L4 layer to ICMP packet");
		return false;
	}

	return true;
}

icmp_echo_request* IcmpLayer::getEchoRequestData()
{
	if (!isMessageOfType(ICMP_ECHO_REQUEST))
		return NULL;

	m_EchoData.header = (icmp_echo_hdr*)m_Data;
	m_EchoData.data = (uint8_t*)(m_Data + sizeof(icmp_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmp_echo_hdr);

	return &m_EchoData;
}

icmp_echo_request* IcmpLayer::setEchoRequestData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen)
{
	if (setEchoData(ICMP_ECHO_REQUEST, id, sequence, timestamp, data, dataLen))
		return getEchoRequestData();
	else
		return NULL;
}

icmp_echo_reply* IcmpLayer::getEchoReplyData()
{
	if (!isMessageOfType(ICMP_ECHO_REPLY))
		return NULL;

	m_EchoData.header = (icmp_echo_hdr*)m_Data;
	m_EchoData.data = (uint8_t*)(m_Data + sizeof(icmp_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmp_echo_hdr);

	return &m_EchoData;
}

icmp_echo_reply* IcmpLayer::setEchoReplyData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen)
{
	if (setEchoData(ICMP_ECHO_REPLY, id, sequence, timestamp, data, dataLen))
		return getEchoReplyData();
	else
		return NULL;
}


icmp_timestamp_request* IcmpLayer::getTimestampRequestData()
{
	if (!isMessageOfType(ICMP_TIMESTAMP_REQUEST))
		return NULL;

	return (icmp_timestamp_request*)m_Data;
}

icmp_timestamp_request* IcmpLayer::setTimestampRequestData(uint16_t id, uint16_t sequence, timeval originateTimestamp)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_timestamp_request) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_TIMESTAMP_REQUEST;

	icmp_timestamp_request* header = getTimestampRequestData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);
	header->originateTimestamp = htonl(originateTimestamp.tv_sec*1000 + originateTimestamp.tv_usec/1000);
	header->receiveTimestamp = 0;
	header->transmitTimestamp = 0;

	return header;
}

icmp_timestamp_reply* IcmpLayer::getTimestampReplyData()
{
	if (!isMessageOfType(ICMP_TIMESTAMP_REPLY))
		return NULL;

	return (icmp_timestamp_reply*)m_Data;
}

icmp_timestamp_reply* IcmpLayer::setTimestampReplyData(uint16_t id, uint16_t sequence,
		timeval originateTimestamp, timeval receiveTimestamp, timeval transmitTimestamp)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_timestamp_reply) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_TIMESTAMP_REPLY;

	icmp_timestamp_reply* header = getTimestampReplyData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);
	header->originateTimestamp = htonl(originateTimestamp.tv_sec*1000 + originateTimestamp.tv_usec/1000);
	header->receiveTimestamp = htonl(receiveTimestamp.tv_sec*1000 + receiveTimestamp.tv_usec/1000);
	header->transmitTimestamp = htonl(transmitTimestamp.tv_sec*1000 + transmitTimestamp.tv_usec/1000);

	return header;
}

icmp_destination_unreachable* IcmpLayer::getDestUnreachableData()
{
	if (!isMessageOfType(ICMP_DEST_UNREACHABLE))
		return NULL;

	return (icmp_destination_unreachable*)m_Data;
}

icmp_destination_unreachable* IcmpLayer::setDestUnreachableData(IcmpDestUnreachableCodes code, uint16_t nextHopMTU, IPv4Layer* ipHeader, Layer* l4Header)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_destination_unreachable) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_DEST_UNREACHABLE;

	icmp_destination_unreachable* header = getDestUnreachableData();
	header->code = code;
	header->nextHopMTU = htons(nextHopMTU);
	header->unused = 0;

	if (!setIpAndL4Layers(ipHeader, l4Header))
		return NULL;

	return header;
}

icmp_source_quench* IcmpLayer::getSourceQuenchdata()
{
	if (!isMessageOfType(ICMP_SOURCE_QUENCH))
		return NULL;

	return (icmp_source_quench*)m_Data;

}

icmp_source_quench* IcmpLayer::setSourceQuenchdata(IPv4Layer* ipHeader, Layer* l4Header)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_source_quench) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_SOURCE_QUENCH;

	icmp_source_quench* header = getSourceQuenchdata();
	header->unused = 0;

	if (!setIpAndL4Layers(ipHeader, l4Header))
		return NULL;

	return header;
}

icmp_redirect* IcmpLayer::getRedirectData()
{
	if (!isMessageOfType(ICMP_REDIRECT))
		return NULL;

	return (icmp_redirect*)m_Data;
}

icmp_redirect* IcmpLayer::setRedirectData(uint8_t code, IPv4Address gatewayAddress, IPv4Layer* ipHeader, Layer* l4Header)
{
	if (code > 3)
	{
		LOG_ERROR("Unknown code %d for ICMP redirect data", (int)code);
		return NULL;
	}

	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_redirect) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_REDIRECT;

	icmp_redirect* header = getRedirectData();
	header->code = code;
	header->gatewayAddress = gatewayAddress.toInt();

	if (!setIpAndL4Layers(ipHeader, l4Header))
		return NULL;

	return header;
}

icmp_router_advertisement* IcmpLayer::getRouterAdvertisementData()
{
	if (!isMessageOfType(ICMP_ROUTER_ADV))
		return NULL;

	m_RouterAdvData.header = (icmp_router_advertisement_hdr*)m_Data;

	return &m_RouterAdvData;
}

icmp_router_advertisement* IcmpLayer::setRouterAdvertisementData(uint8_t code, uint16_t lifetimeInSeconds, const std::vector<icmp_router_address_structure>& routerAddresses)
{
	if (code != 0 && code != 16)
	{
		LOG_ERROR("Unknown code %d for ICMP router advertisement data (only codes 0 and 16 are legal)", (int)code);
		return NULL;
	}

	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_router_advertisement_hdr) + (routerAddresses.size()*sizeof(icmp_router_address_structure)) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_ROUTER_ADV;

	icmp_router_advertisement* header = getRouterAdvertisementData();
	header->header->code = code;
	header->header->lifetime = htons(lifetimeInSeconds);
	header->header->advertisementCount = (uint8_t)routerAddresses.size();
	header->header->addressEntrySize = 2;

	icmp_router_address_structure* curPos = (icmp_router_address_structure*)((uint8_t*)header->header + sizeof(icmp_router_advertisement_hdr));
	for (std::vector<icmp_router_address_structure>::const_iterator iter = routerAddresses.begin(); iter != routerAddresses.end(); iter++)
	{
		curPos->routerAddress = iter->routerAddress;
		curPos->preferenceLevel = iter->preferenceLevel;
		curPos += 1;
	}

	return header;
}

icmp_router_solicitation* IcmpLayer::getRouterSolicitationData()
{
	if (!isMessageOfType(ICMP_ROUTER_SOL))
		return NULL;

	return (icmp_router_solicitation*)m_Data;
}

icmp_router_solicitation* IcmpLayer::setRouterSolicitationData()
{
	if (!cleanIcmpLayer())
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_ROUTER_SOL;

	icmp_router_solicitation* header = getRouterSolicitationData();
	header->code = 0;

	return header;
}

icmp_time_exceeded* IcmpLayer::getTimeExceededData()
{
	if (!isMessageOfType(ICMP_TIME_EXCEEDED))
		return NULL;

	return (icmp_time_exceeded*)m_Data;
}

icmp_time_exceeded* IcmpLayer::setTimeExceededData(uint8_t code, IPv4Layer* ipHeader, Layer* l4Header)
{
	if (code > 1)
	{
		LOG_ERROR("Unknown code %d for ICMP time exceeded data", (int)code);
		return NULL;
	}

	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_time_exceeded) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_TIME_EXCEEDED;

	icmp_time_exceeded* header = getTimeExceededData();
	header->code = code;
	header->unused = 0;

	if (!setIpAndL4Layers(ipHeader, l4Header))
		return NULL;

	return header;
}

icmp_param_problem* IcmpLayer::getParamProblemData()
{
	if (!isMessageOfType(ICMP_PARAM_PROBLEM))
		return NULL;

	return (icmp_param_problem*)m_Data;
}

icmp_param_problem* IcmpLayer::setParamProblemData(uint8_t code, uint8_t errorOctetPointer, IPv4Layer* ipHeader, Layer* l4Header)
{
	if (code > 2)
	{
		LOG_ERROR("Unknown code %d for ICMP parameter problem data", (int)code);
		return NULL;
	}

	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_param_problem) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_PARAM_PROBLEM;

	icmp_param_problem* header = getParamProblemData();
	header->code = code;
	header->unused1 = 0;
	header->unused2 = 0;
	header->pointer = errorOctetPointer;

	if (!setIpAndL4Layers(ipHeader, l4Header))
		return NULL;

	return header;
}

icmp_address_mask_request* IcmpLayer::getAddressMaskRequestData()
{
	if (!isMessageOfType(ICMP_ADDRESS_MASK_REQUEST))
		return NULL;

	return (icmp_address_mask_request*)m_Data;
}

icmp_address_mask_request* IcmpLayer::setAddressMaskRequestData(uint16_t id, uint16_t sequence, IPv4Address mask)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_address_mask_request) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_ADDRESS_MASK_REQUEST;

	icmp_address_mask_request* header = getAddressMaskRequestData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);
	header->addressMask = mask.toInt();

	return header;
}

icmp_address_mask_reply* IcmpLayer::getAddressMaskReplyData()
{
	if (!isMessageOfType(ICMP_ADDRESS_MASK_REPLY))
		return NULL;

	return (icmp_address_mask_reply*)m_Data;
}

icmp_address_mask_reply* IcmpLayer::setAddressMaskReplyData(uint16_t id, uint16_t sequence, IPv4Address mask)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_address_mask_reply) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_ADDRESS_MASK_REPLY;

	icmp_address_mask_reply* header = getAddressMaskReplyData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);
	header->addressMask = htonl(mask.toInt());

	return header;
}

icmp_info_request* IcmpLayer::getInfoRequestData()
{
	if (!isMessageOfType(ICMP_INFO_REQUEST))
		return NULL;

	return (icmp_info_request*)m_Data;
}

icmp_info_request* IcmpLayer::setInfoRequestData(uint16_t id, uint16_t sequence)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_info_request) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_INFO_REQUEST;

	icmp_info_request* header = getInfoRequestData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);

	return header;
}

icmp_info_reply* IcmpLayer::getInfoReplyData()
{
	if (!isMessageOfType(ICMP_INFO_REPLY))
		return NULL;

	return (icmp_info_reply*)m_Data;
}

icmp_info_reply* IcmpLayer::setInfoReplyData(uint16_t id, uint16_t sequence)
{
	if (!cleanIcmpLayer())
		return NULL;

	if (!this->extendLayer(m_DataLen, sizeof(icmp_info_reply) - sizeof(icmphdr)))
		return NULL;

	getIcmpHeader()->type = (uint8_t)ICMP_INFO_REPLY;

	icmp_info_reply* header = getInfoReplyData();
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);

	return header;
}


void IcmpLayer::parseNextLayer()
{
	IcmpMessageType type = getMessageType();
	size_t headerLen = 0;

	switch (type)
	{
	case ICMP_DEST_UNREACHABLE:
	case ICMP_SOURCE_QUENCH:
	case ICMP_TIME_EXCEEDED:
	case ICMP_REDIRECT:
	case ICMP_PARAM_PROBLEM:
		headerLen = getHeaderLen();
		if (m_DataLen - headerLen >= sizeof(iphdr))
			m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet, false);
		return;
	default:
		headerLen = getHeaderLen();
		if (m_DataLen > headerLen)
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		return;
	}
}

size_t IcmpLayer::getHeaderLen()
{
	IcmpMessageType type = getMessageType();
	size_t routerAdvSize = 0;
	switch (type)
	{
	case ICMP_ECHO_REQUEST:
	case ICMP_ECHO_REPLY:
		return m_DataLen;
	case ICMP_TIMESTAMP_REQUEST:
	case ICMP_TIMESTAMP_REPLY:
		return sizeof(icmp_timestamp_request);
	case ICMP_ROUTER_SOL:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_UNSUPPORTED:
		return sizeof(icmphdr);
	case ICMP_ADDRESS_MASK_REPLY:
	case ICMP_ADDRESS_MASK_REQUEST:
		return sizeof(icmp_address_mask_request);
	case ICMP_DEST_UNREACHABLE:
		return sizeof(icmp_destination_unreachable);
	case ICMP_REDIRECT:
		return sizeof(icmp_redirect);
	case ICMP_TIME_EXCEEDED:
	case ICMP_SOURCE_QUENCH:
		return sizeof(icmp_time_exceeded);
	case ICMP_PARAM_PROBLEM:
		return sizeof(icmp_param_problem);
	case ICMP_ROUTER_ADV:
		routerAdvSize = sizeof(icmp_router_advertisement_hdr) + (getRouterAdvertisementData()->header->advertisementCount*sizeof(icmp_router_address_structure));
		return routerAdvSize;
	default:
		return sizeof(icmphdr);
	}
}

void IcmpLayer::computeCalculateFields()
{
	// calculate checksum
	getIcmpHeader()->checksum = 0;

	size_t icmpLen = 0;
	Layer* curLayer = this;
	while (curLayer != NULL)
	{
		icmpLen += curLayer->getHeaderLen();
		curLayer = curLayer->getNextLayer();
	}

	ScalarBuffer<uint16_t> buffer;
	buffer.buffer = (uint16_t*)getIcmpHeader();
	buffer.len = icmpLen;
	size_t checksum = compute_checksum(&buffer, 1);

	getIcmpHeader()->checksum = htons(checksum);
}

std::string IcmpLayer::toString()
{
	std::string messageTypeAsString;
	IcmpMessageType type = getMessageType();
	switch (type)
	{
	case ICMP_ECHO_REPLY:
		messageTypeAsString = "Echo (ping) reply";
		break;
	case ICMP_DEST_UNREACHABLE:
		messageTypeAsString = "Destination unreachable";
		break;
	case ICMP_SOURCE_QUENCH:
		messageTypeAsString = "Source quench (flow control)";
		break;
	case ICMP_REDIRECT:
		messageTypeAsString = "Redirect";
		break;
	case ICMP_ECHO_REQUEST:
		messageTypeAsString = "Echo (ping) request";
		break;
	case ICMP_ROUTER_ADV:
		messageTypeAsString = "Router advertisement";
		break;
	case ICMP_ROUTER_SOL:
		messageTypeAsString = "Router solicitation";
		break;
	case ICMP_TIME_EXCEEDED:
		messageTypeAsString = "Time-to-live exceeded";
		break;
	case ICMP_PARAM_PROBLEM:
		messageTypeAsString = "Parameter problem: bad IP header";
		break;
	case ICMP_TIMESTAMP_REQUEST:
		messageTypeAsString = "Timestamp request";
		break;
	case ICMP_TIMESTAMP_REPLY:
		messageTypeAsString = "Timestamp reply";
		break;
	case ICMP_INFO_REQUEST:
		messageTypeAsString = "Information request";
		break;
	case ICMP_INFO_REPLY:
		messageTypeAsString = "Information reply";
		break;
	case ICMP_ADDRESS_MASK_REQUEST:
		messageTypeAsString = "Address mask request";
		break;
	case ICMP_ADDRESS_MASK_REPLY:
		messageTypeAsString = "Address mask reply";
		break;
	default:
		messageTypeAsString = "Unknown";
		break;
	}

	std::ostringstream typeStream;
	typeStream << (int)getIcmpHeader()->type;

	return "ICMP Layer, " + messageTypeAsString + " (type: " + typeStream.str() + ")";
}

} // namespace pcpp
