#define LOG_MODULE PacketLogModuleLayer

#include "Layer.h"
#include "Logger.h"
#include "Packet.h"
#include <cstring>

namespace pcpp
{

	Layer::~Layer()
	{
		if (!isAllocatedToPacket())
			delete[] m_Data;
	}

	Layer::Layer(const Layer& other)
	    : m_Packet(nullptr), m_Protocol(other.m_Protocol), m_NextLayer(nullptr), m_PrevLayer(nullptr),
	      m_IsAllocatedInPacket(false)
	{
		m_DataLen = other.getHeaderLen();
		m_Data = new uint8_t[other.m_DataLen];
		memcpy(m_Data, other.m_Data, other.m_DataLen);
	}

	Layer& Layer::operator=(const Layer& other)
	{
		if (this == &other)
			return *this;

		if (m_Data != nullptr)
			delete[] m_Data;

		m_DataLen = other.getHeaderLen();
		m_Packet = nullptr;
		m_Protocol = other.m_Protocol;
		m_NextLayer = nullptr;
		m_PrevLayer = nullptr;
		m_Data = new uint8_t[other.m_DataLen];
		m_IsAllocatedInPacket = false;
		memcpy(m_Data, other.m_Data, other.m_DataLen);

		return *this;
	}

	bool Layer::isMemberOfProtocolFamily(ProtocolTypeFamily protocolTypeFamily) const
	{
		auto protocolToFamily = static_cast<ProtocolTypeFamily>(m_Protocol);
		return (m_Protocol != UnknownProtocol && (protocolToFamily == (protocolTypeFamily & 0xff) ||
		                                          protocolToFamily << 8 == (protocolTypeFamily & 0xff00) ||
		                                          protocolToFamily << 16 == (protocolTypeFamily & 0xff0000) ||
		                                          protocolToFamily << 24 == (protocolTypeFamily & 0xff000000)));
	}

	void Layer::copyData(uint8_t* toArr) const
	{
		memcpy(toArr, m_Data, m_DataLen);
	}

	bool Layer::extendLayer(int offsetInLayer, size_t numOfBytesToExtend)
	{
		if (m_Data == nullptr)
		{
			PCPP_LOG_ERROR("Layer's data is nullptr");
			return false;
		}

		if (m_Packet == nullptr)
		{
			if ((size_t)offsetInLayer > m_DataLen)
			{
				PCPP_LOG_ERROR("Requested offset is larger than data length");
				return false;
			}

			uint8_t* newData = new uint8_t[m_DataLen + numOfBytesToExtend];
			memcpy(newData, m_Data, offsetInLayer);
			memcpy(newData + offsetInLayer + numOfBytesToExtend, m_Data + offsetInLayer, m_DataLen - offsetInLayer);
			delete[] m_Data;
			m_Data = newData;
			m_DataLen += numOfBytesToExtend;
			return true;
		}

		return m_Packet->extendLayer(this, offsetInLayer, numOfBytesToExtend);
	}

	bool Layer::shortenLayer(int offsetInLayer, size_t numOfBytesToShorten)
	{
		if (m_Data == nullptr)
		{
			PCPP_LOG_ERROR("Layer's data is nullptr");
			return false;
		}

		if (m_Packet == nullptr)
		{
			if ((size_t)offsetInLayer >= m_DataLen)
			{
				PCPP_LOG_ERROR("Requested offset is larger than data length");
				return false;
			}

			uint8_t* newData = new uint8_t[m_DataLen - numOfBytesToShorten];
			memcpy(newData, m_Data, offsetInLayer);
			memcpy(newData + offsetInLayer, m_Data + offsetInLayer + numOfBytesToShorten,
			       m_DataLen - offsetInLayer - numOfBytesToShorten);
			delete[] m_Data;
			m_Data = newData;
			m_DataLen -= numOfBytesToShorten;
			return true;
		}

		return m_Packet->shortenLayer(this, offsetInLayer, numOfBytesToShorten);
	}

}  // namespace pcpp
