#define LOG_MODULE PacketLogModulePayloadLayer

#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen, bool dummy) : Layer()
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
		delete [] m_Data;
		m_Data = NULL;
		m_DataLen = 0;
	}
}

std::string PayloadLayer::toString() const
{
	std::ostringstream dataLenStream;
	dataLenStream << m_DataLen;

	return "Payload Layer, Data length: " + dataLenStream.str() + " [Bytes]";
}

} // namespace pcpp
