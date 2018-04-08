#define LOG_MODULE PacketLogModuleRawPacket

#include "RawPacket.h"
#include <string.h>
#include "Logger.h"

namespace pcpp
{

void RawPacket::Init()
{
	m_pRawData = 0;
	m_RawDataLen = 0;
	m_DeleteRawDataAtDestructor = true;
	m_RawPacketSet = false;
	m_linkLayerType = LINKTYPE_ETHERNET;
}

RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, LinkLayerType layerType)
{
	Init();
	m_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
	setRawData(pRawData, rawDataLen, timestamp, layerType);
}

RawPacket::RawPacket()
{
	Init();
}

RawPacket::~RawPacket()
{
	if (m_DeleteRawDataAtDestructor)
	{
		delete[] m_pRawData;
	}
}

RawPacket::RawPacket(const RawPacket& other)
{
	copyDataFrom(other, true);
}

RawPacket& RawPacket::operator=(const RawPacket& other)
{
	if (m_pRawData != NULL)
		delete [] m_pRawData;

	m_RawPacketSet = false;

	copyDataFrom(other, true);

	return *this;
}


void RawPacket::copyDataFrom(const RawPacket& other, bool allocateData)
{
	if (!other.m_RawPacketSet)
		return;

	m_TimeStamp = other.m_TimeStamp;

	if (allocateData)
	{
		m_DeleteRawDataAtDestructor = true;
		m_pRawData = new uint8_t[other.m_RawDataLen];
		m_RawDataLen = other.m_RawDataLen;
	}

	memcpy(m_pRawData, other.m_pRawData, other.m_RawDataLen);
	m_linkLayerType = other.m_linkLayerType;
	m_FrameLength = other.m_FrameLength;
	m_RawPacketSet = true;
}

bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	if(frameLength == -1)
		frameLength = rawDataLen;
	m_FrameLength = frameLength;
	if (m_pRawData != 0 && m_DeleteRawDataAtDestructor)
	{
		delete[] m_pRawData;
	}

	m_pRawData = (uint8_t*)pRawData;
	m_RawDataLen = rawDataLen;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_linkLayerType = layerType;
	return true;
}

const uint8_t* RawPacket::getRawData()
{
	return m_pRawData;
}

const uint8_t* RawPacket::getRawDataReadOnly() const
{
	return m_pRawData;
}
		
LinkLayerType RawPacket::getLinkLayerType() const
{
	return m_linkLayerType;
}

int RawPacket::getRawDataLen() const
{
	return m_RawDataLen;
}

int RawPacket::getFrameLength() const
{
	return m_FrameLength;
}

timeval RawPacket::getPacketTimeStamp()
{
	return m_TimeStamp;
}

void RawPacket::clear()
{
	if (m_pRawData != 0)
		delete[] m_pRawData;

	m_pRawData = 0;
	m_RawDataLen = 0;
	m_FrameLength = 0;
	m_RawPacketSet = false;
}

void RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	memcpy((uint8_t*)m_pRawData+m_RawDataLen, dataToAppend, dataToAppendLen);
	m_RawDataLen += dataToAppendLen;
	m_FrameLength = m_RawDataLen;
}

void RawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
	int index = m_RawDataLen-1;
	while (index >= atIndex)
	{
		m_pRawData[index+dataToInsertLen] = m_pRawData[index];
		index--;
	}

	memcpy((uint8_t*)m_pRawData+atIndex, dataToInsert, dataToInsertLen);
	m_RawDataLen += dataToInsertLen;
	m_FrameLength = m_RawDataLen;
}

bool RawPacket::reallocateData(size_t newBufferLength)
{
	if ((int)newBufferLength == m_RawDataLen)
		return true;

	if ((int)newBufferLength < m_RawDataLen)
	{
		LOG_ERROR("Cannot reallocate raw packet to a smaller size. Current data length: %d; requested length: %d", m_RawDataLen, (int)newBufferLength);
		return false;
	}

	uint8_t* newBuffer = new uint8_t[newBufferLength];
	memset(newBuffer, 0, newBufferLength);
	memcpy(newBuffer, m_pRawData, m_RawDataLen);
	if (m_DeleteRawDataAtDestructor)
		delete [] m_pRawData;

	m_DeleteRawDataAtDestructor = true;
	m_pRawData = newBuffer;

	return true;
}

bool RawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if ((atIndex + (int)numOfBytesToRemove) > m_RawDataLen)
	{
		LOG_ERROR("Remove section is out of raw packet bound");
		return false;
	}

	int index = atIndex;
	while (index < (m_RawDataLen - (int)numOfBytesToRemove))
	{
		m_pRawData[index] = m_pRawData[index+numOfBytesToRemove];
		index++;
	}

	m_RawDataLen -= numOfBytesToRemove;
	m_FrameLength = m_RawDataLen;
	return true;
}

} // namespace pcpp
