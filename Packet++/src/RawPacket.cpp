#define LOG_MODULE PacketLogModuleRawPacket

#include "RawPacket.h"
#include <string.h>
#include "Logger.h"
#include "TimespecTimeval.h"

namespace pcpp
{

void RawPacket::init(bool deleteRawDataAtDestructor)
{
	m_RawData = 0;
	m_StartOfBuffer = 0;
	m_RawDataLen = 0;
	m_FrameLength = 0;
	m_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
	m_RawPacketSet = false;
	m_LinkLayerType = LINKTYPE_ETHERNET;
}

RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor, LinkLayerType layerType)
{
	timespec nsec_time;
	TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
	init(deleteRawDataAtDestructor);
	setRawData(pRawData, rawDataLen, nsec_time, layerType);
}

RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor, LinkLayerType layerType)
{
	init(deleteRawDataAtDestructor);
	setRawData(pRawData, rawDataLen, timestamp, layerType);
}

RawPacket::RawPacket()
{
	init();
}

RawPacket::~RawPacket()
{
	if (m_DeleteRawDataAtDestructor)
	{
		delete[] m_StartOfBuffer;
	}
}

RawPacket::RawPacket(const RawPacket& other)
{
	m_StartOfBuffer = m_RawData = NULL;
	copyDataFrom(other, true);
}

RawPacket& RawPacket::operator=(const RawPacket& other)
{
	if (this != &other)
	{
		if (m_StartOfBuffer != NULL)
			delete [] m_StartOfBuffer;

		m_RawPacketSet = false;

		copyDataFrom(other, true);
	}
	
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
		m_StartOfBuffer = m_RawData = new uint8_t[other.m_RawDataLen];
		m_RawDataLen = other.m_RawDataLen;
	}

	memcpy(m_StartOfBuffer, other.m_StartOfBuffer, other.m_RawDataLen);
	m_LinkLayerType = other.m_LinkLayerType;
	m_FrameLength = other.m_FrameLength;
	m_RawPacketSet = true;
}

bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	timespec nsec_time;
	TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
	return setRawData(pRawData, rawDataLen, nsec_time, layerType, frameLength);
}

bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType, int frameLength)
{
	if(frameLength == -1)
		frameLength = rawDataLen;
	m_FrameLength = frameLength;
	if (m_StartOfBuffer != 0 && m_DeleteRawDataAtDestructor)
	{
		delete[] m_StartOfBuffer;
	}

	m_StartOfBuffer = m_RawData = (uint8_t*)pRawData;
	m_RawDataLen = rawDataLen;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_LinkLayerType = layerType;
	return true;
}

void RawPacket::clear()
{
	if (m_StartOfBuffer != 0)
		delete[] m_StartOfBuffer;

	m_StartOfBuffer = m_RawData = 0;
	m_RawDataLen = 0;
	m_FrameLength = 0;
	m_RawPacketSet = false;
}

void RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	writeData(m_RawDataLen, dataToAppend, dataToAppendLen);
	m_RawDataLen += dataToAppendLen;
	m_FrameLength = m_RawDataLen;
}

void RawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
	// memmove copies data as if there was an intermediate buffer inbetween - so it allows for copying processes on overlapping src/dest ptrs
	// if insertData is called with atIndex == m_RawDataLen, then no data is being moved. The data of the raw packet is still extended by dataToInsertLen
	// TODO: use moveData here?
	memmove((uint8_t*)m_RawData + atIndex + dataToInsertLen, (uint8_t*)m_RawData + atIndex, m_RawDataLen - atIndex);

	if (dataToInsert != NULL)
	{
		// insert data
		writeData(atIndex, dataToInsert, dataToInsertLen);
	}
	
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
	memcpy(newBuffer, m_StartOfBuffer, m_RawDataLen);
	if (m_DeleteRawDataAtDestructor)
		delete [] m_StartOfBuffer;

	m_DeleteRawDataAtDestructor = true;
	// m_RawData points to start of data, which does not have to be at the start of the buffer (e.g. when the packet is created from pre-filled packet)
	// set m_RawData to old offset but in new buffer
	m_RawData = newBuffer + (m_RawData - m_StartOfBuffer);
	m_StartOfBuffer = m_RawData = newBuffer;

	return true;
}

bool RawPacket::relocateStartOfPacket(size_t offsetFromStart)
{
	if (offsetFromStart > m_RawDataLen)
		return false;

	m_RawData = m_StartOfBuffer + offsetFromStart;
	m_FrameLength = m_RawDataLen - offsetFromStart;

	return true;
}

void RawPacket::writeData(size_t index, const uint8_t* data, size_t dataLen)
{
	memcpy(m_StartOfBuffer + index, data, dataLen);
}

void RawPacket::moveData(size_t indexFrom, size_t length, size_t indexTo)
{
	uint8_t* insertPosition = m_StartOfBuffer + indexTo;

	if (insertPosition < m_RawData)
	{
		// extend frame towards the start of the buffer
		m_RawData = insertPosition;
		m_FrameLength += m_RawData - insertPosition;
	}
	// if the move exceeds the back of the buffer
	else if ((insertPosition + length) > (m_RawData + m_RawDataLen))
	{
		// need to realloc
	}
	else if ((insertPosition + length) > (m_RawData + m_FrameLength))
	{
		// set m_FrameLength to difference between start of frame (m_RawData) and new end of frame (insertPosition + length)
		m_FrameLength = (insertPosition + length) - m_RawData;
	}

	memmove(insertPosition, m_StartOfBuffer + indexFrom, length);
}

bool RawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if ((atIndex + (int)numOfBytesToRemove) > m_RawDataLen)
	{
		LOG_ERROR("Remove section is out of raw packet bound");
		return false;
	}

	// only move data if we are removing data somewhere in the layer, not at the end of the last layer
	// this is so that resizing of the last layer can occur fast by just reducing the fictional length of the packet (m_RawDataLen) by the given amount
	if((atIndex + (int)numOfBytesToRemove) != m_RawDataLen)
		// memmove copies data as if there was an intermediate buffer inbetween - so it allows for copying processes on overlapping src/dest ptrs
		memmove((uint8_t*)m_RawData + atIndex, (uint8_t*)m_RawData + atIndex + numOfBytesToRemove, m_RawDataLen - (atIndex + numOfBytesToRemove));
	
	m_RawDataLen -= numOfBytesToRemove;
	m_FrameLength = m_RawDataLen;
	return true;
}

bool RawPacket::setPacketTimeStamp(timeval timestamp)
{
	timespec nsec_time;
	TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
	return setPacketTimeStamp(nsec_time);
}

bool RawPacket::setPacketTimeStamp(timespec timestamp)
{
	m_TimeStamp = timestamp;
	return true;
}

} // namespace pcpp
