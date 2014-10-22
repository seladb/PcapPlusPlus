#define LOG_MODULE PacketLogModulePayloadLayer

#include <PayloadLayer.h>
#include <string.h>

PayloadLayer::PayloadLayer(const uint8_t* data, size_t dataLen, bool selfAllocated) : Layer()
{
	m_Data = new uint8_t[dataLen];
	memcpy(m_Data, data, dataLen);
	m_DataLen = dataLen;
}
