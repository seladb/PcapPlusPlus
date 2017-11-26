#define LOG_MODULE PacketLogModulePayloadLayer

#include "PayloadLayer.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen, bool dummy) : Layer()
{
	m_Data = new uint8_t[dataLen];
	memcpy(m_Data, data, dataLen);
	m_DataLen = dataLen;
	m_Protocol = GenericPayolad;
}

std::string PayloadLayer::toString()
{
	std::ostringstream dataLenStream;
	dataLenStream << m_DataLen;

	return "Payload Layer, Data length: " + dataLenStream.str() + " [Bytes]";
}

} // namespace pcpp
