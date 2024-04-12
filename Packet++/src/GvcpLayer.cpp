#define LOG_MODULE PacketLogModuleGvcpLayer

#include "GvcpLayer.h"
#include <cstring>

namespace pcpp
{
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
		m_Header = new GvcpRequestHeader();
		memcpy(m_Header, data, sizeof(GvcpRequestHeader));
		m_DataLen = dataSize - sizeof(GvcpRequestHeader);
		m_Data = new uint8_t[sizeof(GvcpRequestHeader)];

		m_Header->command = command;
		m_Header->flag = flag;
		m_Header->requestId = requestId;
		m_Header->dataSize = dataSize;
	}

	/*---------------------- Class GvcpAcknowledgeLayer ----------------------------*/
	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(uint8_t *data, size_t dataSize, Layer *prevLayer, Packet *packet)
		: GvcpLayer(data, dataSize, prevLayer, packet)
	{
		m_Header = reinterpret_cast<GvcpAckHeader *>(data);
		m_DataLen = dataSize - sizeof(GvcpAckHeader);
		m_Data = data + sizeof(GvcpAckHeader);
	}

	GvcpAcknowledgeLayer::GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command, const uint8_t *data,
											   uint16_t dataSize, uint16_t ackId)
	{
		m_Protocol = Gvcp;
		m_Header = new GvcpAckHeader();
		memcpy(m_Header, data, sizeof(GvcpAckHeader));
		m_DataLen = dataSize - sizeof(GvcpAckHeader);
		m_Data = new uint8_t[sizeof(GvcpAckHeader)];

		m_Header->status = status;
		m_Header->command = command;
		m_Header->ackId = ackId;
		m_Header->dataSize = dataSize;
	}

} // namespace pcpp
