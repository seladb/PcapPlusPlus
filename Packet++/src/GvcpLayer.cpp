#define LOG_MODULE PacketLogModuleGvcpLayer

#include "GvcpLayer.h"
#include <cstring>
#include <sstream>

namespace pcpp
{
	std::ostream& operator<<(std::ostream& os, GvcpCommand command)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(command) << std::dec;
		return os;
	}

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(status) << std::dec;
		return os;
	}

	/*---------------------- Class GvcpLayer ----------------------------*/

	GvcpLayer::GvcpLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataSize, prevLayer, packet, GVCP)
	{}

	GvcpLayer* GvcpLayer::parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (GvcpLayer::verifyRequest(data))
		{
			auto* header = reinterpret_cast<GvcpRequestHeader*>(data);
			if (header->getCommand() == GvcpCommand::DiscoveredCmd)
			{
				return new GvcpDiscoveryRequestLayer(data, dataLen, prevLayer, packet);
			}
			else if (header->getCommand() == GvcpCommand::ForceIpCmd)
			{
				return new GvcpForceIpRequestLayer(data, dataLen, prevLayer, packet);
			}
			else
			{
				return new GvcpRequestLayer(data, dataLen, prevLayer, packet);
			}
		}
		else
		{
			auto* header = reinterpret_cast<GvcpAckHeader*>(data);
			if (header->getCommand() == GvcpCommand::DiscoveredAck)
			{
				return new GvcpDiscoveryAcknowledgeLayer(data, dataLen);
			}
			else if (header->getCommand() == GvcpCommand::ForceIpAck)
			{
				return new GvcpForceIpAcknowledgeLayer(data, dataLen);
			}
			else
			{
				return new GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet);
			}
		}
	}

	/*---------------------- Class GvcpRequestLayer ----------------------------*/
	GvcpRequestLayer::GvcpRequestLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : GvcpLayer(data, dataSize, prevLayer, packet)
	{}

	GvcpRequestLayer::GvcpRequestLayer(GvcpCommand command, const uint8_t* payloadData, uint16_t payloadDataSize,
	                                   GvcpFlag flag, uint16_t requestId)
	{
		m_Protocol = GVCP;

		m_DataLen = getHeaderLen() + payloadDataSize;
		m_Data = new uint8_t[m_DataLen];

		// copy the payload data
		memcpy(m_Data + getHeaderLen(), payloadData, payloadDataSize);

		// set the header fields
		auto header = reinterpret_cast<GvcpRequestHeader*>(m_Data);
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->flag = flag;
		header->requestId = hostToNet16(requestId);
		header->dataSize = hostToNet16(payloadDataSize);
	}

	GvcpRequestLayer::GvcpRequestLayer(const uint8_t* data, size_t dataSize)
	{
		m_Protocol = GVCP;

		m_DataLen = dataSize;
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data, m_DataLen);
	}

	std::string GvcpRequestLayer::toString() const
	{
		std::stringstream ss;
		ss << "GVCP Request Layer, Command: " << getCommand() << ", Request ID: " << getRequestId();
		return ss.str();
	}

	/*---------------------- Class GvcpAcknowledgeLayer ----------------------------*/
	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(uint8_t* data, size_t dataSize, Layer* prevLayer, Packet* packet)
	    : GvcpLayer(data, dataSize, prevLayer, packet)
	{}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command,
	                                           const uint8_t* payloadData, uint16_t payloadDataSize, uint16_t ackId)
	{
		m_Protocol = GVCP;

		m_DataLen = getHeaderLen() + payloadDataSize;
		m_Data = new uint8_t[m_DataLen];

		// copy the payload data
		memcpy(m_Data + getHeaderLen(), payloadData, payloadDataSize);

		// set the header fields
		auto header = reinterpret_cast<GvcpAckHeader*>(m_Data);
		header->status = hostToNet16(static_cast<uint16_t>(status));
		header->command = hostToNet16(static_cast<uint16_t>(command));
		header->dataSize = hostToNet16(payloadDataSize);
		header->ackId = hostToNet16(ackId);
	}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(const uint8_t* data, size_t dataSize)
	{
		m_Protocol = GVCP;

		m_DataLen = dataSize;
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data, m_DataLen);
	}

	std::string GvcpAcknowledgeLayer::toString() const
	{
		std::stringstream ss;
		ss << "GVCP Acknowledge Layer, Command: " << getCommand() << ", Acknowledge ID: " << getAckId()
		   << ", Status: " << getStatus();
		return ss.str();
	}
}  // namespace pcpp
