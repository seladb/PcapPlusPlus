#include "TLVData.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"

namespace pcpp
{

	TLVRecordBuilder::TLVRecordBuilder()
	{
		m_RecType = 0;
		m_RecValueLen = 0;
		m_RecValue = nullptr;
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const uint8_t* recValue, uint8_t recValueLen)
	{
		init(recType, recValue, recValueLen);
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint8_t recValue)
	{
		init(recType, &recValue, sizeof(uint8_t));
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint16_t recValue)
	{
		recValue = htobe16(recValue);
		init(recType, reinterpret_cast<uint8_t*>(&recValue), sizeof(uint16_t));
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint32_t recValue)
	{
		recValue = htobe32(recValue);
		init(recType, reinterpret_cast<uint8_t*>(&recValue), sizeof(uint32_t));
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const IPv4Address& recValue)
	{
		uint32_t recIntValue = recValue.toInt();
		init(recType, reinterpret_cast<uint8_t*>(&recIntValue), sizeof(uint32_t));
	}

	TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const std::string& recValue, bool valueIsHexString)
	{
		m_RecType = 0;
		m_RecValueLen = 0;
		m_RecValue = nullptr;

		if (valueIsHexString)
		{
			uint8_t recValueByteArr[512];
			size_t byteArraySize = hexStringToByteArray(recValue, recValueByteArr, 512);
			if (byteArraySize > 0)
			{
				init(recType, recValueByteArr, byteArraySize);
			}
		}
		else
		{
			const uint8_t* recValueByteArr = reinterpret_cast<const uint8_t*>(recValue.c_str());
			init(recType, recValueByteArr, recValue.length());
		}
	}

	void TLVRecordBuilder::copyData(const TLVRecordBuilder& other)
	{
		m_RecType = other.m_RecType;
		m_RecValueLen = other.m_RecValueLen;
		m_RecValue = nullptr;
		if (other.m_RecValue != nullptr)
		{
			m_RecValue = new uint8_t[m_RecValueLen];
			memcpy(m_RecValue, other.m_RecValue, m_RecValueLen);
		}
	}

	TLVRecordBuilder::TLVRecordBuilder(const TLVRecordBuilder& other)
	{
		copyData(other);
	}

	TLVRecordBuilder& TLVRecordBuilder::operator=(const TLVRecordBuilder& other)
	{
		if (m_RecValue != nullptr)
		{
			delete[] m_RecValue;
			m_RecValue = nullptr;
		}

		copyData(other);

		return *this;
	}

	TLVRecordBuilder::~TLVRecordBuilder()
	{
		if (m_RecValue != nullptr)
			delete[] m_RecValue;
	}

	void TLVRecordBuilder::init(uint32_t recType, const uint8_t* recValue, size_t recValueLen)
	{
		m_RecType = recType;
		m_RecValueLen = recValueLen;
		m_RecValue = new uint8_t[recValueLen];
		if (recValue != nullptr)
			memcpy(m_RecValue, recValue, recValueLen);
		else
			memset(m_RecValue, 0, recValueLen);
	}

}  // namespace pcpp
