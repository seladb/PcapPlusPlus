#define LOG_MODULE PacketLogModuleIcmpV6Layer

#include "IcmpV6Layer.h"
#include "EndianPortable.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "NdpLayer.h"
#include "PacketUtils.h"
#include "PayloadLayer.h"
#include <memory>
#include <sstream>

// IcmpV6Layer

namespace pcpp
{

ICMPv6MessageType IcmpV6Layer::getMessageType() const
{
	return (ICMPv6MessageType)getIcmpv6Header()->type;
}

uint8_t IcmpV6Layer::getCode() const
{
	return getIcmpv6Header()->code;
}

uint16_t IcmpV6Layer::getChecksum() const
{
	return be16toh(getIcmpv6Header()->checksum);
}

bool IcmpV6Layer::cleanIcmpLayer()
{
	// remove all layers after

	if (m_Packet != NULL)
	{
		bool res = m_Packet->removeAllLayersAfter(this);
		if (!res)
			return false;
	}

	// shorten layer to size of icmpv6hdr

	size_t headerLen = this->getHeaderLen();
	if (headerLen > sizeof(icmpv6hdr))
	{
		if (!this->shortenLayer(sizeof(icmpv6hdr), headerLen - sizeof(icmpv6hdr)))
			return false;
	}

	return true;
}

bool IcmpV6Layer::isDataValid(const uint8_t *data, size_t dataLen)
{
	if (dataLen < sizeof(icmpv6hdr))
		return false;

	/* Currently checks if the type equals an already implemented type. If not, return false. */
	icmpv6hdr *hdr = (icmpv6hdr *)data;

	switch (hdr->type)
	{
	case ICMPv6_ECHO_REQUEST:
	case ICMPv6_ECHO_REPLY:
	case ICMPv6_NEIGHBOR_SOLICITATION:
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return true;
	}

	return false;
}

void IcmpV6Layer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	uint8_t *payload = m_Data + getHeaderLen();
	size_t payloadLen = m_DataLen - getHeaderLen();

	switch (getMessageType())
	{
	case ICMPv6_NEIGHBOR_SOLICITATION:
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		break;
	default:
		if (m_DataLen > headerLen)
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	}
}

size_t IcmpV6Layer::getHeaderLen() const
{
	switch (getMessageType())
	{
	case ICMPv6_ECHO_REQUEST:
	case ICMPv6_ECHO_REPLY:
	case ICMPv6_NEIGHBOR_SOLICITATION:
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return m_DataLen;
	default:
		return sizeof(icmpv6hdr);
	}
}

void IcmpV6Layer::computeCalculateFields()
{
	calculateChecksum();
}

void IcmpV6Layer::calculateChecksum()
{
	/* Pseudo header of 40 bytes which is composed as follows(in order):
	- 16 bytes for the source address
	- 16 bytes for the destination address
	- 4 bytes big endian payload length(the same value as in the IPv6 header)
	- 3 bytes zero + 1 byte nextheader( 58 decimal) big endian
	*/

	if (m_PrevLayer != NULL)
	{
		ScalarBuffer<uint16_t> vec[2];

		vec[0].buffer = (uint16_t *)m_Data;
		vec[0].len = m_DataLen;

		const unsigned int pseudoHeaderLen = 40;
		const unsigned int bigEndianLen = htobe32(m_DataLen);
		const unsigned int bigEndianNextHeader = htobe32(PACKETPP_IPPROTO_ICMPV6);

		uint16_t pseudoHeader[pseudoHeaderLen / 2];
		((IPv6Layer *)m_PrevLayer)->getSrcIPv6Address().copyTo((uint8_t *)pseudoHeader);
		((IPv6Layer *)m_PrevLayer)->getDstIPv6Address().copyTo((uint8_t *)(pseudoHeader + 8));
		memcpy(&pseudoHeader[16], &bigEndianLen, sizeof(uint32_t));
		memcpy(&pseudoHeader[18], &bigEndianNextHeader, sizeof(uint32_t));
		vec[1].buffer = pseudoHeader;
		vec[1].len = pseudoHeaderLen;

		/* Calculate and write checksum */
		getIcmpv6Header()->checksum = htobe16(computeChecksum(vec, 2));
	}
}

std::string IcmpV6Layer::toString() const
{
	std::string messageTypeAsString;
	ICMPv6MessageType type = getMessageType();
	switch (type)
	{
	case ICMPv6_ECHO_REQUEST:
		messageTypeAsString = "Echo Request";
		break;
	case ICMPv6_ECHO_REPLY:
		messageTypeAsString = "Echo Reply";
		break;
	case ICMPv6_NEIGHBOR_SOLICITATION:
		messageTypeAsString = "Neighbor Solicitation";
		break;
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		messageTypeAsString = "Neighbor Advertisement";
		break;
	default:
		messageTypeAsString = "Unknown";
		break;
	}

	std::ostringstream typeStream;
	typeStream << (int)type;

	return "ICMPv6 Layer, " + messageTypeAsString + " (type: " + typeStream.str() + ")";
}

ProtocolType IcmpV6Layer::getIcmpv6Version(uint8_t* data, size_t dataLen)
{
	if (dataLen < sizeof(icmpv6hdr))
		return UnknownProtocol;

	icmpv6hdr *hdr = (icmpv6hdr *)data;

	switch (hdr->type)
	{
	case ICMPv6_ECHO_REQUEST:
		return ICMPv6EchoRequest;
	case ICMPv6_ECHO_REPLY:
		return ICMPv6EchoReply;
	case ICMPv6_NEIGHBOR_SOLICITATION:
		return NDPNeighborSolicitation;
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return NDPNeighborAdvertisement;
	}

	return UnknownProtocol;
}

// ICMPv6EchoRequestLayer

ICMPv6EchoRequestLayer::ICMPv6EchoRequestLayer()
{
	m_DataLen = sizeof(icmpv6hdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6EchoRequest;
	getIcmpv6Header()->type = ICMPv6_ECHO_REPLY;
}

icmpv6_echo_request *ICMPv6EchoRequestLayer::getEchoRequestData()
{
	if (!isMessageOfType(ICMPv6_ECHO_REQUEST))
		return NULL;

	m_EchoData.header = (icmpv6_echo_hdr *)m_Data;
	m_EchoData.data = (uint8_t *)(m_Data + sizeof(icmpv6_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmpv6_echo_hdr);

	return &m_EchoData;
}

icmpv6_echo_request *ICMPv6EchoRequestLayer::setEchoRequestData(uint16_t id, uint16_t sequence, const uint8_t *data,
													 size_t dataLen)
{
	if (setEchoData(ICMPv6_ECHO_REQUEST, id, sequence, data, dataLen))
		return getEchoRequestData();
	else
		return NULL;
}

bool ICMPv6EchoRequestLayer::setEchoData(ICMPv6MessageType echoType, uint16_t id, uint16_t sequence, const uint8_t *data,
							  size_t dataLen)
{
	if (!cleanIcmpLayer())
		return false;

	if (!this->extendLayer(m_DataLen, sizeof(icmpv6_echo_hdr) - sizeof(icmpv6hdr) + dataLen))
		return false;

	getIcmpv6Header()->type = (uint8_t)echoType;

	icmpv6_echo_request *header = NULL;
	if (echoType == ICMPv6_ECHO_REQUEST)
		header = getEchoRequestData();
	else
		return false;

	header->header->code = 0;
	header->header->checksum = 0;
	header->header->id = htobe16(id);
	header->header->sequence = htobe16(sequence);
	if (data != NULL && dataLen > 0)
		memcpy(header->data, data, dataLen);

	return true;
}


// ICMPv6EchoReplyLayer

ICMPv6EchoReplyLayer::ICMPv6EchoReplyLayer()
{
	m_DataLen = sizeof(icmpv6hdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6EchoReply;
	getIcmpv6Header()->type = ICMPv6_ECHO_REPLY;
}

icmpv6_echo_reply *ICMPv6EchoReplyLayer::getEchoReplyData()
{
	if (!isMessageOfType(ICMPv6_ECHO_REPLY))
		return NULL;

	m_EchoData.header = (icmpv6_echo_hdr *)m_Data;
	m_EchoData.data = (uint8_t *)(m_Data + sizeof(icmpv6_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmpv6_echo_hdr);

	return &m_EchoData;
}

icmpv6_echo_reply *ICMPv6EchoReplyLayer::setEchoReplyData(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen)
{
	if (setEchoData(ICMPv6_ECHO_REPLY, id, sequence, data, dataLen))
		return getEchoReplyData();
	else
		return NULL;
}

bool ICMPv6EchoReplyLayer::setEchoData(ICMPv6MessageType echoType, uint16_t id, uint16_t sequence, const uint8_t *data,
							  size_t dataLen)
{
	if (!cleanIcmpLayer())
		return false;

	if (!this->extendLayer(m_DataLen, sizeof(icmpv6_echo_hdr) - sizeof(icmpv6hdr) + dataLen))
		return false;

	getIcmpv6Header()->type = (uint8_t)echoType;

	icmpv6_echo_request *header = NULL;
	if (echoType == ICMPv6_ECHO_REPLY)
		header = (icmpv6_echo_request *)getEchoReplyData();
	else
		return false;

	header->header->code = 0;
	header->header->checksum = 0;
	header->header->id = htobe16(id);
	header->header->sequence = htobe16(sequence);
	if (data != NULL && dataLen > 0)
		memcpy(header->data, data, dataLen);

	return true;
}

} // namespace pcpp
