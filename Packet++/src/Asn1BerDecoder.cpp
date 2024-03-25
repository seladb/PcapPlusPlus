#include "Asn1BerDecoder.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"
#include <iostream>
#include <cmath>

namespace pcpp {
	std::unique_ptr<Asn1BerRecord> Asn1BerRecord::decode(const uint8_t* data, size_t dataLen, bool lazy)
	{
		auto record = decodeInternal(data, dataLen ,lazy);
		return std::unique_ptr<Asn1BerRecord>(record);
	}

	uint8_t Asn1BerRecord::encodeTag()
	{
		uint8_t tagByte;

		switch (m_TagClass)
		{
			case BerTagClass::Private:
			{
				tagByte = 0xc0;
				break;
			}
			case BerTagClass::ContextSpecific:
			{
				tagByte = 0x80;
				break;
			}
			case BerTagClass::Application:
			{
				tagByte = 0x40;
				break;
			}
			default:
			{
				tagByte = 0;
				break;
			}
		}

		if (m_BerTagType == BerTagType::Constructed)
		{
			tagByte |= 0x20;
		}

		auto tagType = m_TagType & 0x1f;
		tagByte |= tagType;

		return tagByte;
	}

	std::vector<uint8_t> Asn1BerRecord::encodeLength() const
	{
		std::vector<uint8_t> result;

		if (m_ValueLength < 128)
		{
			result.push_back(static_cast<uint8_t>(m_ValueLength));
			return result;
		}

		// Assuming the size is always 4 bytes
		uint8_t firstByte = 0x80 | sizeof(uint32_t);
		result.push_back(firstByte);

		result.push_back((m_ValueLength >> 24) & 0xff);
		result.push_back((m_ValueLength >> 16) & 0xff);
		result.push_back((m_ValueLength >> 8) & 0xff);
		result.push_back(m_ValueLength & 0xff);

		return result;
	}

	std::vector<uint8_t> Asn1BerRecord::encode()
	{
		std::vector<uint8_t> result;

		result.push_back(encodeTag());

		auto lengthBytes = encodeLength();
		result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());

		auto encodedValue = encodeValue();
		result.insert(result.end(), encodedValue.begin(), encodedValue.end());

		return result;
	}

	Asn1BerRecord* Asn1BerRecord::decodeInternal(const uint8_t* data, size_t dataLen, bool lazy)
	{
		int tagLen = 1;
		if (dataLen < static_cast<size_t>(tagLen))
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data is shorter than tag len");
		}

		auto decodedRecord = decodeTagAndCreateRecord(data, dataLen);

		auto lengthLen = decodedRecord->decodeLength(data + tagLen, dataLen - tagLen);

		if (dataLen - tagLen - lengthLen - decodedRecord->m_ValueLength < 0)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data doesn't contain the entire record");
		}

		decodedRecord->m_TotalLength = tagLen + lengthLen + decodedRecord->m_ValueLength;

		if (!lazy)
		{
			try
			{
				decodedRecord->decodeValue((uint8_t*)data + tagLen + lengthLen, lazy);
			}
			catch (...)
			{
				delete decodedRecord;
				throw;
			}

		}
		else
		{
			decodedRecord->m_EncodedValue = (uint8_t*)data + tagLen + lengthLen;
		}

		return decodedRecord;

		// TODO

//		else if (!isValidTlv) {
//			if (allowConstructedIfMultipleTlvs)
//			{
//				if (currentReadIndex != tlv.size() && currentReadIndex != tlv.size() + 2)
//				{
//					const int lengthInt = tlv.size();
//					if (lengthInt > 0)
//					{
//						isValidTlv = true;
//
//						// this is a group of tags, so we add them as children and consider this a constructed tag
//						children.push_back(*this);
//
//						int currentReadIndexChildren = currentReadIndex;
//						while (currentReadIndexChildren < lengthInt)
//						{
//							Asn1BerRecord nextTag;
//							nextTag.decode(tlv.substr(currentReadIndexChildren), false);
//							if (nextTag.isValidTlv)
//							{
//								children.push_back(nextTag);
//							}
//							currentReadIndexChildren += nextTag.currentReadIndex;
//						}
//
//						// If nothing else in the TLV was considered valid, we go back to having the first valid TLV as the only one
//						if (children.size() > 1)
//						{
//							tagType = BerTagType::CONSTRUCTED;
//
//							tag.clear();
//							value = tlv;
//							length.clear();
//							tagClass = BerTagClass::UNIVERSAL;
//						}
//						else
//						{
//							children.clear();
//							isValidTlv = false;
//						}
//					}
//				}
//			}
//			else if (hasMoreAfterValue)
//			{
//				isValidTlv = true; // this is part of a group of tags not inside a constructed tag, so we consider this as valid and will continue to evalute the rest of the tlv
//			}
//		}
	}

	Asn1UniversalTagType Asn1BerRecord::getAsn1UniversalTagType() const
	{
		if (m_TagClass == BerTagClass::Universal)
		{
			return static_cast<Asn1UniversalTagType>(m_TagType);
		}

		return Asn1UniversalTagType::NotApplicable;
	}

	Asn1BerRecord* Asn1BerRecord::decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record tag");
		}

		BerTagClass tagClass = BerTagClass::Universal;

		// Check first 2 bits
		auto tagClassBits = data[0] & 0xc0;
		if (tagClassBits == 0)
		{
			tagClass = BerTagClass::Universal;
		}
		else if ((tagClassBits & 0xc0) == 0xc0)
		{
			tagClass = BerTagClass::Private;
		}
		else if ((tagClassBits & 0x80) == 0x80)
		{
			tagClass = BerTagClass::ContextSpecific;
		}
		else if ((tagClassBits & 0x40) == 0x40)
		{
			tagClass = BerTagClass::Application;
		}

		// Check bit 6
		auto tagTypeBits = data[0] & 0x20;
		BerTagType berTagType = (tagTypeBits == 0 ? BerTagType::Primitive : BerTagType::Constructed);

		// Check last 5 bits
		auto tagType = data[0] & 0x1f;

		Asn1BerRecord* newRecord;

		if (berTagType == BerTagType::Constructed)
		{
			if (tagClass == BerTagClass::Universal)
			{
				switch (static_cast<Asn1UniversalTagType>(tagType))
				{
					case Asn1UniversalTagType::Sequence:
					{
						newRecord = new Asn1SequenceRecord();
						break;
					}
					case Asn1UniversalTagType::Set:
					{
						newRecord = new Asn1SetRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1BerConstructedRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1BerConstructedRecord();
			}
		}
		else
		{
			if (tagClass == BerTagClass::Universal)
			{
				auto asn1UniversalTagType = static_cast<Asn1UniversalTagType>(tagType);
				switch (asn1UniversalTagType)
				{
					case Asn1UniversalTagType::Integer:
					{
						newRecord = new Asn1IntegerRecord();
						break;
					}
					case Asn1UniversalTagType::Enumerated:
					{
						newRecord = new Asn1EnumeratedRecord();
						break;
					}
					case Asn1UniversalTagType::OctetString:
					{
						newRecord = new Asn1OctetStringRecord();
						break;
					}
					case Asn1UniversalTagType::Boolean:
					{
						newRecord = new Asn1BooleanRecord();
						break;
					}
					case Asn1UniversalTagType::Null:
					{
						newRecord = new Asn1NullRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1GenericRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1GenericRecord();
			}
		}

		newRecord->m_TagClass = tagClass;
		newRecord->m_BerTagType = berTagType;
		newRecord->m_TagType = tagType;

		return newRecord;
		// TODO
//		// Check if the tag is using more than one byte
//		if (tagNumber >= 31)
//		{
//			for (auto i = 1; i < 1000; i++)
//				// Check first bit
//				const bool hasNextByte = data[i] & 0x80;
//				if (!hasNextByte)
//				{
//					break;
//				}
//			}
//		}
	}

	int Asn1BerRecord::decodeLength(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record length");
		}

		// Check 8th bit
		auto lengthForm = data[0] & 0x80;

		auto numberLengthBytes = 1;

		// Check if the tag is using more than one byte
		// 8th bit at 0 means the length only uses one byte
		// 8th bit at 1 means the length uses more than one byte. The number of bytes is encoded in the other 7 bits
		if (lengthForm != 0)
		{
			auto additionalLengthBytes = data[0] & 0x7F;
			if (static_cast<int>(dataLen) < additionalLengthBytes + 1)
			{
				throw std::invalid_argument("Cannot decode ASN.1 BER record length");
			}
			for (auto index = additionalLengthBytes; index > 0; --index)
			{
				m_ValueLength += data[index] * static_cast<int>(std::pow(256, (additionalLengthBytes - index)));
			}
			numberLengthBytes += additionalLengthBytes;
		}
		else
		{
			m_ValueLength = data[0];
		}

		return numberLengthBytes;
	}

	void Asn1BerRecord::decodeValueIfNeeded()
	{
		if (m_EncodedValue != nullptr)
		{
			decodeValue(m_EncodedValue, true);
			m_EncodedValue = nullptr;
		}
	}

	Asn1GenericRecord::Asn1GenericRecord(BerTagClass tagClass, BerTagType berTagType, uint8_t tagType, const uint8_t* value, size_t valueLen)
	{
		m_TagType = tagType;
		m_TagClass = tagClass;
		m_BerTagType = berTagType;
		m_Value = new uint8_t[valueLen];
		m_FreeValueOnDestruction = true;
		memcpy(m_Value, value, valueLen);
		m_ValueLength = valueLen;
		m_TotalLength = m_ValueLength + 2;
	}

	Asn1GenericRecord::~Asn1GenericRecord()
	{
		if (m_Value && m_FreeValueOnDestruction)
		{
			delete m_Value;
		}
	}

	void Asn1GenericRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = data;
	}

	std::vector<uint8_t> Asn1GenericRecord::encodeValue() const
	{
		return {m_Value, m_Value + m_ValueLength};
	}

	Asn1BerConstructedRecord::Asn1BerConstructedRecord(BerTagClass tagClass, uint8_t tagType, const std::vector<Asn1BerRecord*>& subRecords)
	{
		m_TagType = tagType;
		m_TagClass = tagClass;
		m_BerTagType = BerTagType::Constructed;

		size_t recordValueLength = 0;
		for (auto record : subRecords)
		{
			auto encodedRecord = record->encode();
			auto copyRecord = Asn1BerRecord::decode(encodedRecord.data(), encodedRecord.size(), false);
			m_SubRecords.pushBack(copyRecord.release());
			recordValueLength += encodedRecord.size();
		}

		m_ValueLength = recordValueLength;
		m_TotalLength = recordValueLength + 2;
	}

	void Asn1BerConstructedRecord::decodeValue(uint8_t* data, bool lazy)
	{
		if (!(data || m_ValueLength))
		{
			return;
		}

		auto value = data;
		auto valueLen = m_ValueLength;

		while (valueLen > 0)
		{
			auto subRecord = Asn1BerRecord::decodeInternal(value, valueLen, lazy);
			value += subRecord->getTotalLength();
			valueLen -= subRecord->getTotalLength();

			m_SubRecords.pushBack(subRecord);
		}
	}

	std::vector<uint8_t> Asn1BerConstructedRecord::encodeValue() const
	{
		std::vector<uint8_t> result;
		result.reserve(m_ValueLength);

		for (auto record : m_SubRecords)
		{
			auto encodedRecord = record->encode();
			result.insert(result.end(), std::make_move_iterator(encodedRecord.begin()), std::make_move_iterator(encodedRecord.end()));
		}
		return result;
	}

	Asn1SequenceRecord::Asn1SequenceRecord(const std::vector<Asn1BerRecord*>& subRecords)
		: Asn1BerConstructedRecord(BerTagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const std::vector<Asn1BerRecord*>& subRecords)
			: Asn1BerConstructedRecord(BerTagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1PrimitiveRecord::Asn1PrimitiveRecord(uint8_t tagType) : Asn1BerRecord()
	{
		m_TagType = tagType;
		m_TagClass = BerTagClass::Universal;
		m_BerTagType = BerTagType::Primitive;
	}

	Asn1IntegerRecord::Asn1IntegerRecord(uint32_t value) : Asn1PrimitiveRecord(static_cast<uint8_t>(Asn1UniversalTagType::Integer))
	{
		m_Value = value;

		if (m_Value <= std::pow(2, sizeof(uint8_t) * 8))
		{
			m_ValueLength = sizeof(uint8_t);
		}
		else if (value <= std::pow(2, sizeof(uint16_t) * 8))
		{
			m_ValueLength = sizeof(uint16_t);
		}
		else if (value <= std::pow(2, 3 * 8))
		{
			m_ValueLength = 3;
		}
		else
		{
			m_ValueLength = sizeof(uint32_t);
		}

		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1IntegerRecord::decodeValue(uint8_t* data, bool lazy)
	{
		switch (m_ValueLength)
		{
			case 1:
			{
				m_Value = *(uint8_t*)data;
				break;
			}
			case 2:
			{
				m_Value = be16toh(*(uint16_t*)data);
				break;
			}
			case 3:
			{
				uint8_t tempData[4] = {0};
				memcpy(tempData + 1, data, 3);
				m_Value = be32toh(*(uint32_t*)tempData);
				break;
			}
			case 4:
			{
				m_Value = be32toh(*(uint32_t*)data);
				break;
			}
			default:
			{
				throw std::runtime_error("An integer ASN.1 record of more than 4 bytes is not supported");
			}
		}
	}

	std::vector<uint8_t> Asn1IntegerRecord::encodeValue() const
	{
		std::vector<uint8_t> result;
		result.reserve(m_ValueLength);

		switch (m_ValueLength)
		{
			case 1:
			{
				result.push_back(static_cast<uint8_t>(m_Value));
				break;
			}
			case 2:
			{
				uint8_t tempArr[sizeof(uint16_t)];
				auto hostValue = htobe16(static_cast<uint16_t>(m_Value));
				memcpy(tempArr, &hostValue, m_ValueLength);
				std::copy(tempArr, tempArr + m_ValueLength, std::back_inserter(result));
				break;
			}
			case 3:
			{
				uint8_t tempArr[sizeof(uint32_t)];
				auto hostValue = htobe32(static_cast<uint32_t>(m_Value));
				memcpy(tempArr, &hostValue, sizeof(uint32_t));
				std::copy(tempArr + 1, tempArr + m_ValueLength + 1, std::back_inserter(result));
				break;
			}
			case 4:
			{
				uint8_t tempArr[sizeof(uint32_t)];
				auto hostValue = htobe32(static_cast<uint32_t>(m_Value));
				memcpy(tempArr, &hostValue, m_ValueLength);
				std::copy(tempArr, tempArr + m_ValueLength, std::back_inserter(result));
				break;
			}
			default:
			{
				throw std::runtime_error("Integer value of more than 4 bytes is not supported");
			}
		}

		return result;
	}

	Asn1EnumeratedRecord::Asn1EnumeratedRecord(uint32_t value) : Asn1IntegerRecord(value)
	{
		m_TagType = static_cast<uint8_t>(Asn1UniversalTagType::Enumerated);
	}

	Asn1OctetStringRecord::Asn1OctetStringRecord(const std::string& value) : Asn1PrimitiveRecord(static_cast<uint8_t>(Asn1UniversalTagType::OctetString))
	{
		m_Value = value;
		m_ValueLength = value.size();
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1OctetStringRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = std::string(reinterpret_cast<char*>(data), m_ValueLength);
	}

	std::vector<uint8_t> Asn1OctetStringRecord::encodeValue() const
	{
		return {m_Value.begin(), m_Value.end()};
	}

	Asn1BooleanRecord::Asn1BooleanRecord(bool value) : Asn1PrimitiveRecord(static_cast<uint8_t>(Asn1UniversalTagType::Boolean))
	{
		m_Value = value;
		m_ValueLength = 1;
		m_TotalLength = 3;
	}

	void Asn1BooleanRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = data[0] != 0;
	}

	std::vector<uint8_t> Asn1BooleanRecord::encodeValue() const
	{
		uint8_t byte = (m_Value ? 0xff : 0x00);
		return { byte };
	}

	Asn1NullRecord::Asn1NullRecord() : Asn1PrimitiveRecord(static_cast<uint8_t>(Asn1UniversalTagType::Null))
	{
		m_ValueLength = 0;
		m_TotalLength = 2;
	}
}