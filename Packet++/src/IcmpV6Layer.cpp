#define LOG_MODULE PacketLogModuleIcmpV6Layer

#include <EndianPortable.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IcmpV6Layer.h>
#include <NdpLayer.h>
#include <PacketUtils.h>
#include <memory>
#include <sstream>

namespace pcpp
{
IcmpV6Layer::IcmpV6Layer(ICMPv6MessageTypes type, uint8_t code) : Layer()
{
	m_DataLen = sizeof(icmpv6hdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6;

	icmpv6hdr *hdr = getIcmpv6Header();
	hdr->type = type;
	hdr->code = code;
}

void IcmpV6Layer::parseNextLayer()
{
	uint8_t *payload = m_Data + getHeaderLen();
	size_t payloadLen = m_DataLen - getHeaderLen();

	switch (getMessageType())
	{
	case ICMPv6_NEIGHBOR_SOLICITATION: {
		m_NextLayer = new NDPNeighborSolicitationLayer(payload, payloadLen, this, m_Packet);
		break;
	}
	case ICMPv6_NEIGHBOR_ADVERTISEMENT: {
		m_NextLayer = new NDPNeighborAdvertisementLayer(payload, payloadLen, this, m_Packet);
		break;
	}
	}
}

ICMPv6MessageTypes IcmpV6Layer::getMessageType() const
{
	return (ICMPv6MessageTypes)getIcmpv6Header()->type;
}

uint16_t IcmpV6Layer::getChecksum() const
{
	return be16toh(getIcmpv6Header()->checksum);
}

uint8_t IcmpV6Layer::getCode() const
{
	return getIcmpv6Header()->code;
}

void IcmpV6Layer::computeCalculateFields()
{
	calculateChecksum();
}

std::string IcmpV6Layer::toString() const
{
	std::string messageTypeAsString;
	ICMPv6MessageTypes type = getMessageType();
	switch (type)
	{
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

bool IcmpV6Layer::isDataValid(const uint8_t *data, size_t dataLen)
{
	if (dataLen < sizeof(icmpv6hdr))
		return false;

	/* Currently checks if the type equals an already implemented type. If not, return false.*/
	icmpv6hdr *hdr = (icmpv6hdr *)data;

	switch (hdr->type)
	{
	case ICMPv6_NEIGHBOR_SOLICITATION:
	case ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return true;
	}

	return false;
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

} // namespace pcpp
