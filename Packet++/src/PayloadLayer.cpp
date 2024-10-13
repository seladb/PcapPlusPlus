#define LOG_MODULE PacketLogModulePayloadLayer

#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include <sstream>
#include <cstring>

namespace pcpp
{

	PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen) : Layer()
	{
		m_Data = new uint8_t[dataLen];
		memcpy(m_Data, data, dataLen);
		m_DataLen = dataLen;
		m_Protocol = GenericPayload;
	}

	PayloadLayer::PayloadLayer(const std::string& payloadAsHexStream)
	{
		m_DataLen = payloadAsHexStream.length() / 2;
		m_Data = new uint8_t[m_DataLen];
		m_Protocol = GenericPayload;
		if (hexStringToByteArray(payloadAsHexStream, m_Data, m_DataLen) == 0)
		{
			delete[] m_Data;
			m_Data = nullptr;
			m_DataLen = 0;
		}
	}

	void PayloadLayer::setPayload(const uint8_t* newPayload, size_t newPayloadLength)
	{
		if (newPayloadLength < m_DataLen)
		{
			// shorten payload layer
			shortenLayer(newPayloadLength, m_DataLen - newPayloadLength);
		}
		else if (newPayloadLength > m_DataLen)
		{
			// extend payload layer
			extendLayer(m_DataLen, newPayloadLength - m_DataLen);
		}

		// and copy data to layer
		// this is also executed if the newPayloadLength == m_DataLen
		memcpy(m_Data, newPayload, newPayloadLength);
	}

	std::string PayloadLayer::toString() const
	{
		std::ostringstream dataLenStream;
		dataLenStream << m_DataLen;

		return "Payload Layer, Data length: " + dataLenStream.str() + " [Bytes]";
	}

}  // namespace pcpp
