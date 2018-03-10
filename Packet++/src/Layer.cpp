#define LOG_MODULE PacketLogModuleLayer

#include "Layer.h"
#include <string.h>
#include "Logger.h"
#include "Packet.h"

namespace pcpp
{

Layer::~Layer()
{
	if (!isAllocatedToPacket())
		delete [] m_Data;
}

Layer::Layer(const Layer& other) : m_Packet(NULL), m_Protocol(other.m_Protocol), m_NextLayer(NULL), m_PrevLayer(NULL), m_IsAllocatedInPacket(false)
{
	m_DataLen = ((Layer&)other).getHeaderLen();
	m_Data = new uint8_t[other.m_DataLen];
	memcpy(m_Data, other.m_Data, other.m_DataLen);
}

Layer& Layer::operator=(const Layer& other)
{
	if (this == &other)
		return *this;

	if (m_Data != NULL)
		delete [] m_Data;

	m_DataLen = ((Layer&)other).getHeaderLen();
	m_Packet = NULL;
	m_Protocol = other.m_Protocol;
	m_NextLayer = NULL;
	m_PrevLayer = NULL;
	m_Data = new uint8_t[other.m_DataLen];
	m_IsAllocatedInPacket = false;
	memcpy(m_Data, other.m_Data, other.m_DataLen);

	return *this;
}

void Layer::copyData(uint8_t* toArr)
{
	memcpy(toArr, m_Data, m_DataLen);
}

bool Layer::extendLayer(int offsetInLayer, size_t numOfBytesToExtend)
{
	if (m_Data == NULL)
	{
		LOG_ERROR("Layer's data is NULL");
		return false;
	}

	if (m_Packet == NULL)
	{
		if ((size_t)offsetInLayer > m_DataLen)
		{
			LOG_ERROR("Requested offset is larger than data length");
			return false;
		}

		uint8_t* newData = new uint8_t[m_DataLen + numOfBytesToExtend];
		memcpy(newData, m_Data, offsetInLayer);
		memcpy(newData + offsetInLayer + numOfBytesToExtend, m_Data + offsetInLayer, m_DataLen - offsetInLayer);
		delete [] m_Data;
		m_Data = newData;
		m_DataLen += numOfBytesToExtend;
		return true;
	}

	return m_Packet->extendLayer(this, offsetInLayer, numOfBytesToExtend);
}

bool Layer::shortenLayer(int offsetInLayer, size_t numOfBytesToShorten)
{
	if (m_Data == NULL)
	{
		LOG_ERROR("Layer's data is NULL");
		return false;
	}

	if (m_Packet == NULL)
	{
		if ((size_t)offsetInLayer >= m_DataLen)
		{
			LOG_ERROR("Requested offset is larget than data length");
			return false;
		}

		uint8_t* newData = new uint8_t[m_DataLen - numOfBytesToShorten];
		memcpy(newData, m_Data, offsetInLayer);
		memcpy(newData + offsetInLayer, m_Data + offsetInLayer + numOfBytesToShorten, m_DataLen - offsetInLayer - numOfBytesToShorten);
		delete [] m_Data;
		m_Data = newData;
		m_DataLen -= numOfBytesToShorten;
		return true;
	}

	return m_Packet->shortenLayer(this, offsetInLayer, numOfBytesToShorten);
}

} // namespace pcpp
