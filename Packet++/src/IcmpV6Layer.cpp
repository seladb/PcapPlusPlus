#define LOG_MODULE PacketLogModuleIcmpV6Layer

#include "IcmpV6Layer.h"
#include "EndianPortable.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "NdpLayer.h"
#include "PacketUtils.h"
#include "PayloadLayer.h"
#include <sstream>

// IcmpV6Layer

namespace pcpp
{

	Layer* IcmpV6Layer::parseIcmpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (dataLen < sizeof(icmpv6hdr))
			return new PayloadLayer(data, dataLen, prevLayer, packet);

		icmpv6hdr* hdr = (icmpv6hdr*)data;
		ICMPv6MessageType messageType = static_cast<ICMPv6MessageType>(hdr->type);

		switch (messageType)
		{
		case ICMPv6MessageType::ICMPv6_ECHO_REQUEST:
		case ICMPv6MessageType::ICMPv6_ECHO_REPLY:
			return new ICMPv6EchoLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION:
			return new NDPNeighborSolicitationLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT:
			return new NDPNeighborAdvertisementLayer(data, dataLen, prevLayer, packet);
		case ICMPv6MessageType::ICMPv6_UNKNOWN_MESSAGE:
			return new PayloadLayer(data, dataLen, prevLayer, packet);
		default:
			return new IcmpV6Layer(data, dataLen, prevLayer, packet);
		}
	}

	IcmpV6Layer::IcmpV6Layer(ICMPv6MessageType msgType, uint8_t code, const uint8_t* data, size_t dataLen)
	{
		m_DataLen = sizeof(icmpv6hdr) + dataLen;
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = ICMPv6;

		icmpv6hdr* hdr = (icmpv6hdr*)m_Data;
		hdr->type = static_cast<uint8_t>(msgType);
		hdr->code = code;

		if (data != nullptr && dataLen > 0)
			memcpy(m_Data + sizeof(icmpv6hdr), data, dataLen);
	}

	ICMPv6MessageType IcmpV6Layer::getMessageType() const
	{
		return static_cast<ICMPv6MessageType>(getIcmpv6Header()->type);
	}

	uint8_t IcmpV6Layer::getCode() const
	{
		return getIcmpv6Header()->code;
	}

	uint16_t IcmpV6Layer::getChecksum() const
	{
		return be16toh(getIcmpv6Header()->checksum);
	}

	void IcmpV6Layer::computeCalculateFields()
	{
		calculateChecksum();
	}

	void IcmpV6Layer::calculateChecksum()
	{
		// Pseudo header of 40 bytes which is composed as follows(in order):
		// - 16 bytes for the source address
		// - 16 bytes for the destination address
		// - 4 bytes big endian payload length(the same value as in the IPv6 header)
		// - 3 bytes zero + 1 byte nextheader( 58 decimal) big endian

		getIcmpv6Header()->checksum = 0;

		if (m_PrevLayer != nullptr)
		{
			ScalarBuffer<uint16_t> vec[2];

			vec[0].buffer = (uint16_t*)m_Data;
			vec[0].len = m_DataLen;

			const unsigned int pseudoHeaderLen = 40;
			const unsigned int bigEndianLen = htobe32(m_DataLen);
			const unsigned int bigEndianNextHeader = htobe32(PACKETPP_IPPROTO_ICMPV6);

			uint16_t pseudoHeader[pseudoHeaderLen / 2];
			((IPv6Layer*)m_PrevLayer)->getSrcIPv6Address().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIPv6Address().copyTo((uint8_t*)(pseudoHeader + 8));
			memcpy(&pseudoHeader[16], &bigEndianLen, sizeof(uint32_t));
			memcpy(&pseudoHeader[18], &bigEndianNextHeader, sizeof(uint32_t));
			vec[1].buffer = pseudoHeader;
			vec[1].len = pseudoHeaderLen;

			// Calculate and write checksum
			getIcmpv6Header()->checksum = htobe16(computeChecksum(vec, 2));
		}
	}

	std::string IcmpV6Layer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << (int)getMessageType();
		return "ICMPv6 Layer, Message type: " + typeStream.str();
	}

	//
	// ICMPv6EchoLayer
	//

	ICMPv6EchoLayer::ICMPv6EchoLayer(ICMPv6EchoType echoType, uint16_t id, uint16_t sequence, const uint8_t* data,
	                                 size_t dataLen)
	{
		m_DataLen = sizeof(icmpv6_echo_hdr) + dataLen;
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = ICMPv6;

		icmpv6_echo_hdr* header = getEchoHeader();

		switch (echoType)
		{
		case REPLY:
			header->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_ECHO_REPLY);
			break;
		case REQUEST:
		default:
			header->type = static_cast<uint8_t>(ICMPv6MessageType::ICMPv6_ECHO_REQUEST);
			break;
		}

		header->code = 0;
		header->checksum = 0;
		header->id = htobe16(id);
		header->sequence = htobe16(sequence);

		if (data != nullptr && dataLen > 0)
			memcpy(getEchoDataPtr(), data, dataLen);
	}

	uint16_t ICMPv6EchoLayer::getIdentifier() const
	{
		return be16toh(getEchoHeader()->id);
	}

	uint16_t ICMPv6EchoLayer::getSequenceNr() const
	{
		return be16toh(getEchoHeader()->sequence);
	}

	std::string ICMPv6EchoLayer::toString() const
	{
		std::ostringstream typeStream;
		typeStream << (int)getMessageType();
		return "ICMPv6 Layer, Echo Request/Reply Message (type: " + typeStream.str() + ")";
	}

}  // namespace pcpp
