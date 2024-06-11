#define LOG_MODULE PacketLogModuleGvcpLayer

#include "GvcpLayer.h"
#include <cstring>

/**
 * @file GvcpLayer.cpp
 * @author An-Chi Liu (phy.tiger@gmail.com)
 */

namespace pcpp
{

	std::ostream &operator<<(std::ostream &os, GvcpCommand command)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(command) << std::dec;
		return os;
	}

	std::ostream &operator<<(std::ostream &os, GvcpResponseStatus status)
	{
		os << "0x" << std::hex << static_cast<uint16_t>(status) << std::dec;
		return os;
	}

	/*---------------------- Class GvcpLayer ----------------------------*/

	GvcpLayer::GvcpLayer(uint8_t *data, size_t dataSize, Layer *prevLayer, Packet *packet)
		: Layer(data, dataSize, prevLayer, packet)
	{
		m_Protocol = Gvcp;
	}

	/*---------------------- Class GvcpRequestLayer ----------------------------*/
	GvcpRequestLayer::GvcpRequestLayer(uint8_t *data, size_t dataSize, Layer *prevLayer, Packet *packet)
		: GvcpLayer(data, dataSize, prevLayer, packet)
	{
		m_Header = reinterpret_cast<GvcpRequestHeader *>(data);
		m_DataLen = dataSize - sizeof(GvcpRequestHeader);
		m_Data = data + sizeof(GvcpRequestHeader);
	}

	GvcpRequestLayer::GvcpRequestLayer(GvcpCommand command, const uint8_t *data, uint16_t dataSize, GvcpFlag flag,
									   uint16_t requestId)
	{
		m_Protocol = Gvcp;
		m_Header = new GvcpRequestHeader(flag, command, dataSize, requestId);

		m_DataLen = dataSize;
		m_Data = new uint8_t[sizeof(GvcpRequestHeader)];
		memcpy(m_Data, data + sizeof(GvcpRequestHeader), m_DataLen);
	}

	GvcpRequestLayer::GvcpRequestLayer(const uint8_t *data, uint16_t dataSize)
	{
		m_Protocol = Gvcp;
		m_Header = new GvcpRequestHeader();
		std::memcpy(m_Header, data, sizeof(GvcpRequestHeader));

		m_DataLen = dataSize - sizeof(GvcpRequestHeader);
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data + sizeof(GvcpRequestHeader), m_DataLen);
	}

	/*---------------------- Class GvcpAcknowledgeLayer ----------------------------*/
	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(uint8_t *data, size_t dataSize, Layer *prevLayer, Packet *packet)
		: GvcpLayer(data, dataSize, prevLayer, packet)
	{
		m_Protocol = Gvcp;
		m_Header = reinterpret_cast<GvcpAckHeader *>(const_cast<uint8_t *>(data));
		m_DataLen = dataSize - sizeof(GvcpAckHeader);
		m_Data = data + sizeof(GvcpAckHeader);
	}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command,
											   const uint8_t *payloadData, uint16_t payloadDataSize, uint16_t ackId)
	{
		m_Protocol = Gvcp;
		m_Header = new GvcpAckHeader(status, command, payloadDataSize, ackId);
		m_DataLen = payloadDataSize;
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, payloadData, m_DataLen);
	}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(const uint8_t *data, uint16_t dataSize)
	{
		m_Protocol = Gvcp;
		m_Header = new GvcpAckHeader();
		std::memcpy(m_Header, data, sizeof(GvcpAckHeader));

		m_DataLen = dataSize - sizeof(GvcpAckHeader);
		m_Data = new uint8_t[m_DataLen];
		memcpy(m_Data, data + sizeof(GvcpAckHeader), m_DataLen);
	}
} // namespace pcpp
