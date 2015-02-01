#define LOG_MODULE PacketLogModuleRawPacket

#include <RawPacket.h>
#include <string.h>
#include <Logger.h>

void RawPacket::Init()
{
	m_pRawData = 0;
	m_RawDataLen = 0;
	m_DeleteRawDataAtDestructor = true;
	m_RawPacketSet = false;
}

RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor)
{
	Init();
	m_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
	setRawData(pRawData, rawDataLen, timestamp);
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
	copyDataFrom(other);
}

RawPacket& RawPacket::operator=(const RawPacket& other)
{
	if (m_pRawData != NULL)
		delete [] m_pRawData;

	m_RawPacketSet = false;

	copyDataFrom(other);

	return *this;
}


void RawPacket::copyDataFrom(const RawPacket& other)
{
	if (!other.m_RawPacketSet)
		return;

	m_DeleteRawDataAtDestructor = true;
	m_RawDataLen = other.m_RawDataLen;
	m_TimeStamp = other.m_TimeStamp;
	m_pRawData = new uint8_t[other.m_RawDataLen];
	memcpy(m_pRawData, other.m_pRawData, other.m_RawDataLen);
	m_RawPacketSet = true;
}

void RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp)
{
	if (m_pRawData != 0 && m_DeleteRawDataAtDestructor)
	{
		delete[] m_pRawData;
	}

	m_pRawData = (uint8_t*)pRawData;
	m_RawDataLen = rawDataLen;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
}

const uint8_t* RawPacket::getRawData()
{
	return m_pRawData;
}

int RawPacket::getRawDataLen()
{
	return m_RawDataLen;
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
	m_RawPacketSet = false;
}

void RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	memcpy((uint8_t*)m_pRawData+m_RawDataLen, dataToAppend, dataToAppendLen);
	m_RawDataLen += dataToAppendLen;
}

void RawPacket::insertData(int atIndex, const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	int index = m_RawDataLen;
	while (index >= atIndex)
	{
		m_pRawData[index+dataToAppendLen] = m_pRawData[index];
		index--;
	}

	memcpy((uint8_t*)m_pRawData+atIndex, dataToAppend, dataToAppendLen);
	m_RawDataLen += dataToAppendLen;
}

void RawPacket::reallocateData(uint8_t* newBuffer)
{
	memcpy(newBuffer, m_pRawData, m_RawDataLen);
	if (m_DeleteRawDataAtDestructor)
		delete [] m_pRawData;
	m_pRawData = newBuffer;
}

bool RawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if ((atIndex + numOfBytesToRemove) > m_RawDataLen)
	{
		LOG_ERROR("Remove section is out of raw packet bound");
		return false;
	}

	int index = atIndex;
	while (index < (m_RawDataLen-numOfBytesToRemove))
	{
		m_pRawData[index] = m_pRawData[index+numOfBytesToRemove];
		index++;
	}

	m_RawDataLen -= numOfBytesToRemove;
	return true;
}
