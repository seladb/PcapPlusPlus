#include "TLVData.h"

#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace pcpp
{

TLVRecordBuilder::TLVRecordBuilder()
{
	m_RecType = 0;
	m_RecValueLen = 0;
	m_RecValue = NULL;
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, const uint8_t* recValue, uint8_t recValueLen)
{
	init(recType, recValue, recValueLen);
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, uint8_t recValue)
{
	init(recType, &recValue, sizeof(uint8_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, uint16_t recValue)
{
	recValue = htons(recValue);
	init(recType, (uint8_t*)&recValue, sizeof(uint16_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, uint32_t recValue)
{
	recValue = htonl(recValue);
	init(recType, (uint8_t*)&recValue, sizeof(uint32_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, const IPv4Address& recValue)
{
	uint32_t recIntValue = recValue.toInt();
	init(recType, (uint8_t*)&recIntValue, sizeof(uint32_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint8_t recType, const std::string& recValue)
{
	uint8_t* recValueByteArr = (uint8_t*)recValue.c_str();
	init(recType, recValueByteArr, recValue.length());
}

TLVRecordBuilder::TLVRecordBuilder(const TLVRecordBuilder& other)
{
	m_RecType = other.m_RecType;
	m_RecValueLen = other.m_RecValueLen;
	m_RecValue = NULL;
	if (other.m_RecValue != NULL)
	{
		m_RecValue = new uint8_t[m_RecValueLen];
		memcpy(m_RecValue, other.m_RecValue, m_RecValueLen);
	}
}

TLVRecordBuilder::~TLVRecordBuilder()
{
	if (m_RecValue != NULL) delete [] m_RecValue;
}

void TLVRecordBuilder::init(uint8_t recType, const uint8_t* recValue, uint8_t recValueLen)
{
	m_RecType = recType;
	m_RecValueLen = recValueLen;
	m_RecValue = new uint8_t[recValueLen];
	if (recValue != NULL)
		memcpy(m_RecValue, recValue, recValueLen);
	else
		memset(m_RecValue, 0, recValueLen);
}



}
