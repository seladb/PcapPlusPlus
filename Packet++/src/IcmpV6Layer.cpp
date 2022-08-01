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

ProtocolType IcmpV6Layer::getIcmpv6Version(uint8_t *data, size_t dataLen)
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

//
// ICMPv6EchoRequestLayer
//

ICMPv6EchoRequestLayer::ICMPv6EchoRequestLayer(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen)
{
	m_DataLen = sizeof(icmpv6_echo_hdr) + dataLen;
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6EchoRequest;

	icmpv6_echo_request *header = getEchoRequestData();
	header->header->type = ICMPv6_ECHO_REQUEST;
	header->header->code = 0;
	header->header->checksum = 0;
	header->header->id = htobe16(id);
	header->header->sequence = htobe16(sequence);
	if (data != NULL && dataLen > 0)
		memcpy(header->data, data, dataLen);
}

icmpv6_echo_request *ICMPv6EchoRequestLayer::getEchoRequestData()
{
	m_EchoData.header = (icmpv6_echo_hdr *)m_Data;
	m_EchoData.data = (uint8_t *)(m_Data + sizeof(icmpv6_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmpv6_echo_hdr);

	return &m_EchoData;
}

std::string ICMPv6EchoRequestLayer::toString() const
{
	std::ostringstream typeStream;
	typeStream << (int)getMessageType();
	return "ICMPv6 Layer, Echo Request (type: " + typeStream.str() + ")";
}

//
// ICMPv6EchoReplyLayer
//

ICMPv6EchoReplyLayer::ICMPv6EchoReplyLayer(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen)
{
	m_DataLen = sizeof(icmpv6_echo_hdr) + dataLen;
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6EchoReply;

	icmpv6_echo_reply *header = getEchoReplyData();
	header->header->type = ICMPv6_ECHO_REPLY;
	header->header->code = 0;
	header->header->checksum = 0;
	header->header->id = htobe16(id);
	header->header->sequence = htobe16(sequence);
	if (data != NULL && dataLen > 0)
		memcpy(header->data, data, dataLen);
}

icmpv6_echo_reply *ICMPv6EchoReplyLayer::getEchoReplyData()
{
	m_EchoData.header = (icmpv6_echo_hdr *)m_Data;
	m_EchoData.data = (uint8_t *)(m_Data + sizeof(icmpv6_echo_hdr));
	m_EchoData.dataLength = m_DataLen - sizeof(icmpv6_echo_hdr);

	return &m_EchoData;
}

std::string ICMPv6EchoReplyLayer::toString() const
{
	std::ostringstream typeStream;
	typeStream << (int)getMessageType();
	return "ICMPv6 Layer, Echo Reply (type: " + typeStream.str() + ")";
}

} // namespace pcpp
