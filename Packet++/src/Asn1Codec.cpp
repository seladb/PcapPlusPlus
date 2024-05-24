#define LOG_MODULE PacketLogModuleAsn1Codec

#include "Asn1Codec.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"
#include <numeric>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <cstring>
#include <cmath>
#include <limits>

#if defined(_WIN32)
#undef max
#endif

namespace pcpp
{
	std::string toString(Asn1TagClass tagClass)
	{
		switch (tagClass)
		{
			case Asn1TagClass::Universal:
				return "Universal";
			case Asn1TagClass::ContextSpecific:
				return "ContextSpecific";
			case Asn1TagClass::Application:
				return "Application";
			default:
				return "Private";
		}
	}

	std::string toString(Asn1UniversalTagType tagType)
	{
		switch (tagType)
		{
			case Asn1UniversalTagType::EndOfContent:
				return "EndOfContent";
			case Asn1UniversalTagType::Boolean:
				return "Boolean";
			case Asn1UniversalTagType::Integer:
				return "Integer";
			case Asn1UniversalTagType::BitString:
				return "BitString";
			case Asn1UniversalTagType::OctetString:
				return "OctetString";
			case Asn1UniversalTagType::Null:
				return "Null";
			case Asn1UniversalTagType::ObjectIdentifier:
				return "ObjectIdentifier";
			case Asn1UniversalTagType::ObjectDescriptor:
				return "ObjectDescriptor";
			case Asn1UniversalTagType::External:
				return "External";
			case Asn1UniversalTagType::Real:
				return "Real";
			case Asn1UniversalTagType::Enumerated:
				return "Enumerated";
			case Asn1UniversalTagType::EmbeddedPDV:
				return "EmbeddedPDV";
			case Asn1UniversalTagType::UTF8String:
				return "UTF8String";
			case Asn1UniversalTagType::RelativeObjectIdentifier:
				return "RelativeObjectIdentifier";
			case Asn1UniversalTagType::Time:
				return "Time";
			case Asn1UniversalTagType::Reserved:
				return "Reserved";
			case Asn1UniversalTagType::Sequence:
				return "Sequence";
			case Asn1UniversalTagType::Set:
				return "Set";
			case Asn1UniversalTagType::NumericString:
				return "NumericString";
			case Asn1UniversalTagType::PrintableString:
				return "PrintableString";
			case Asn1UniversalTagType::T61String:
				return "T61String";
			case Asn1UniversalTagType::VideotexString:
				return "VideotexString";
			case Asn1UniversalTagType::IA5String:
				return "IA5String";
			case Asn1UniversalTagType::UTCTime:
				return "UTCTime";
			case Asn1UniversalTagType::GeneralizedTime:
				return "GeneralizedTime";
			case Asn1UniversalTagType::GraphicString:
				return "GraphicString";
			case Asn1UniversalTagType::VisibleString:
				return "VisibleString";
			case Asn1UniversalTagType::GeneralString:
				return "GeneralString";
			case Asn1UniversalTagType::UniversalString:
				return "UniversalString";
			case Asn1UniversalTagType::CharacterString:
				return "CharacterString";
			case Asn1UniversalTagType::BMPString:
				return "BMPString";
			case Asn1UniversalTagType::Date:
				return "Date";
			case Asn1UniversalTagType::TimeOfDay:
				return "TimeOfDay";
			case Asn1UniversalTagType::DateTime:
				return "DateTime";
			case Asn1UniversalTagType::Duration:
				return "Duration";
			case Asn1UniversalTagType::ObjectIdentifierIRI:
				return "ObjectIdentifierIRI";
			case Asn1UniversalTagType::RelativeObjectIdentifierIRI:
				return "RelativeObjectIdentifierIRI";
			default:
				return "Unknown";
		}
	}

	std::unique_ptr<Asn1Record> Asn1Record::decode(const uint8_t* data, size_t dataLen, bool lazy)
	{
		auto record = decodeInternal(data, dataLen ,lazy);
		return std::unique_ptr<Asn1Record>(record);
	}

	uint8_t Asn1Record::encodeTag()
	{
		uint8_t tagByte;

		switch (m_TagClass)
		{
			case Asn1TagClass::Private:
			{
				tagByte = 0xc0;
				break;
			}
			case Asn1TagClass::ContextSpecific:
			{
				tagByte = 0x80;
				break;
			}
			case Asn1TagClass::Application:
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

		if (m_IsConstructed)
		{
			tagByte |= 0x20;
		}

		auto tagType = m_TagType & 0x1f;
		tagByte |= tagType;

		return tagByte;
	}

	std::vector<uint8_t> Asn1Record::encodeLength() const
	{
		std::vector<uint8_t> result;

		if (m_ValueLength < 128)
		{
			result.push_back(static_cast<uint8_t>(m_ValueLength));
			return result;
		}

		// Assuming the size is always less than 256
		uint8_t firstByte = 0x80 | 0x01;
		result.push_back(firstByte);
		result.push_back(m_ValueLength);

		return result;
	}

	std::vector<uint8_t> Asn1Record::encode()
	{
		std::vector<uint8_t> result;

		result.push_back(encodeTag());

		auto lengthBytes = encodeLength();
		result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());

		auto encodedValue = encodeValue();
		result.insert(result.end(), encodedValue.begin(), encodedValue.end());

		return result;
	}

	Asn1Record* Asn1Record::decodeInternal(const uint8_t* data, size_t dataLen, bool lazy)
	{
		int tagLen;
		auto decodedRecord = decodeTagAndCreateRecord(data, dataLen, tagLen);

		int lengthLen;
		try
		{
			lengthLen = decodedRecord->decodeLength(data + tagLen, dataLen - tagLen);
		}
		catch (...)
		{
			delete decodedRecord;
			throw;
		}

		if (static_cast<int>(dataLen) - tagLen - lengthLen - static_cast<int>(decodedRecord->m_ValueLength) < 0)
		{
			delete decodedRecord;
			throw std::invalid_argument("Cannot decode ASN.1 record, data doesn't contain the entire record");
		}

		decodedRecord->m_TotalLength = tagLen + lengthLen + decodedRecord->m_ValueLength;

		if (!lazy)
		{
			try
			{
				decodedRecord->decodeValue(const_cast<uint8_t*>(data) + tagLen + lengthLen, lazy);
			}
			catch (...)
			{
				delete decodedRecord;
				throw;
			}

		}
		else
		{
			decodedRecord->m_EncodedValue = const_cast<uint8_t*>(data) + tagLen + lengthLen;
		}

		return decodedRecord;
	}

	Asn1UniversalTagType Asn1Record::getUniversalTagType() const
	{
		if (m_TagClass == Asn1TagClass::Universal)
		{
			return static_cast<Asn1UniversalTagType>(m_TagType);
		}

		return Asn1UniversalTagType::NotApplicable;
	}

	Asn1Record* Asn1Record::decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, int& tagLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record tag");
		}

		tagLen = 1;

		Asn1TagClass tagClass = Asn1TagClass::Universal;

		// Check first 2 bits
		auto tagClassBits = data[0] & 0xc0;
		if (tagClassBits == 0)
		{
			tagClass = Asn1TagClass::Universal;
		}
		else if ((tagClassBits & 0xc0) == 0xc0)
		{
			tagClass = Asn1TagClass::Private;
		}
		else if ((tagClassBits & 0x80) == 0x80)
		{
			tagClass = Asn1TagClass::ContextSpecific;
		}
		else if ((tagClassBits & 0x40) == 0x40)
		{
			tagClass = Asn1TagClass::Application;
		}

		// Check bit 6
		auto tagTypeBits = data[0] & 0x20;
		bool isConstructed = (tagTypeBits != 0);

		// Check last 5 bits
		auto tagType = data[0] & 0x1f;
		if (tagType == 0x1f)
		{
			if (dataLen < 2)
			{
				throw std::invalid_argument("Cannot decode ASN.1 record tag");
			}

			if ((data[1] & 0x80) != 0)
			{
				throw std::invalid_argument("ASN.1 tags with value larger than 127 are not supported");
			}

			tagType = data[1] & 0x7f;
			tagLen = 2;
		}

		Asn1Record* newRecord;

		if (isConstructed)
		{
			if (tagClass == Asn1TagClass::Universal)
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
						newRecord = new Asn1ConstructedRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1ConstructedRecord();
			}
		}
		else
		{
			if (tagClass == Asn1TagClass::Universal)
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
		newRecord->m_IsConstructed = isConstructed;
		newRecord->m_TagType = tagType;

		return newRecord;
	}

	int Asn1Record::decodeLength(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record length");
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
				throw std::invalid_argument("Cannot decode ASN.1 record length");
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

	void Asn1Record::decodeValueIfNeeded()
	{
		if (m_EncodedValue != nullptr)
		{
			decodeValue(m_EncodedValue, true);
			m_EncodedValue = nullptr;
		}
	}

	std::string Asn1Record::toString()
	{
		auto lines = toStringList();

		auto commaSeparated = [](std::string str1, std::string str2)
		{
			return std::move(str1) + '\n' + std::move(str2);
		};

		return std::accumulate(std::next(lines.begin()), lines.end(),lines[0], commaSeparated);
	}

	std::vector<std::string> Asn1Record::toStringList()
	{
		std::ostringstream stream;

		auto universalType = getUniversalTagType();
		if (universalType == Asn1UniversalTagType::NotApplicable)
		{
			stream << pcpp::toString(m_TagClass) << " (" << static_cast<int>(m_TagType) << ")";
		}
		else
		{
			stream << pcpp::toString(universalType);
		}

		if (m_IsConstructed)
		{
			stream << " (constructed)";
		}

		stream << ", Length: " << m_TotalLength - m_ValueLength << "+" << m_ValueLength;

		return {stream.str()};
	}

	Asn1GenericRecord::Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value, size_t valueLen)
	{
		m_TagType = tagType;
		m_TagClass = tagClass;
		m_IsConstructed = isConstructed;
		m_Value = new uint8_t[valueLen];
		memcpy(m_Value, value, valueLen);
		m_ValueLength = valueLen;
		m_TotalLength = m_ValueLength + 2;
	}

	Asn1GenericRecord::~Asn1GenericRecord()
	{
		delete m_Value;
	}

	void Asn1GenericRecord::decodeValue(uint8_t* data, bool lazy)
	{
		delete m_Value;

		m_Value = new uint8_t[m_ValueLength];
		memcpy(m_Value, data, m_ValueLength);
	}

	std::vector<uint8_t> Asn1GenericRecord::encodeValue() const
	{
		return {m_Value, m_Value + m_ValueLength};
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType, const std::vector<Asn1Record*>& subRecords)
	{
		init(tagClass, tagType, subRecords.begin(), subRecords.end());
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType, const PointerVector<Asn1Record>& subRecords)
	{
		init(tagClass, tagType, subRecords.begin(), subRecords.end());
	}

	void Asn1ConstructedRecord::decodeValue(uint8_t* data, bool lazy)
	{
		if (!(data || m_ValueLength))
		{
			return;
		}

		auto value = data;
		auto valueLen = m_ValueLength;

		while (valueLen > 0)
		{
			auto subRecord = Asn1Record::decodeInternal(value, valueLen, lazy);
			value += subRecord->getTotalLength();
			valueLen -= subRecord->getTotalLength();

			m_SubRecords.pushBack(subRecord);
		}
	}

	std::vector<uint8_t> Asn1ConstructedRecord::encodeValue() const
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

	std::vector<std::string> Asn1ConstructedRecord::toStringList()
	{
		decodeValueIfNeeded();
		std::vector<std::string> result = {Asn1Record::toStringList().front()};
		for (auto subRecord : m_SubRecords)
		{
			for (const auto& line : subRecord->toStringList())
			{
				result.push_back("  " + line);
			}
		}
		return result;
	}

	Asn1SequenceRecord::Asn1SequenceRecord(const std::vector<Asn1Record*>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence), subRecords)
	{}

	Asn1SequenceRecord::Asn1SequenceRecord(const PointerVector<Asn1Record>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const std::vector<Asn1Record*>& subRecords)
			: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const PointerVector<Asn1Record>& subRecords)
		: Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1PrimitiveRecord::Asn1PrimitiveRecord(Asn1UniversalTagType tagType) : Asn1Record()
	{
		m_TagType = static_cast<uint8_t >(tagType);
		m_TagClass = Asn1TagClass::Universal;
		m_IsConstructed = false;
	}

	Asn1IntegerRecord::Asn1IntegerRecord(uint32_t value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Integer)
	{
		m_Value = value;

		if (m_Value <= std::numeric_limits<uint8_t>::max())
		{
			m_ValueLength = sizeof(uint8_t);
		}
		else if (value <= std::numeric_limits<uint16_t>::max())
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
				m_Value = *data;
				break;
			}
			case 2:
			{
				m_Value = be16toh(*reinterpret_cast<uint16_t*>(data));
				break;
			}
			case 3:
			{
				uint8_t tempData[4] = {0};
				memcpy(tempData + 1, data, 3);
				m_Value = be32toh(*reinterpret_cast<uint32_t*>(tempData));
				break;
			}
			case 4:
			{
				m_Value = be32toh(*reinterpret_cast<uint32_t*>(data));
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
				memcpy(tempArr, &hostValue, m_ValueLength + 1);
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

	std::vector<std::string> Asn1IntegerRecord::toStringList()
	{
		return std::vector<std::string>({Asn1Record::toStringList().front() + ", Value: " + std::to_string(getValue())});
	}

	Asn1EnumeratedRecord::Asn1EnumeratedRecord(uint32_t value) : Asn1IntegerRecord(value)
	{
		m_TagType = static_cast<uint8_t>(Asn1UniversalTagType::Enumerated);
	}

	Asn1OctetStringRecord::Asn1OctetStringRecord(const std::string& value) : Asn1PrimitiveRecord(Asn1UniversalTagType::OctetString)
	{
		m_Value = value;
		m_ValueLength = value.size();
		m_TotalLength = m_ValueLength + 2;
		m_IsPrintable = true;
	}

	Asn1OctetStringRecord::Asn1OctetStringRecord(const uint8_t* value, size_t valueLength) : Asn1PrimitiveRecord(Asn1UniversalTagType::OctetString)
	{
		m_Value = byteArrayToHexString(value, valueLength);
		m_ValueLength = valueLength;
		m_TotalLength = m_ValueLength + 2;
		m_IsPrintable = false;
	}

	void Asn1OctetStringRecord::decodeValue(uint8_t* data, bool lazy)
	{
		auto value = reinterpret_cast<char*>(data);

		m_IsPrintable = std::all_of(value, value + m_ValueLength, [](char c) {
			return isprint(c);
		});

		if (m_IsPrintable)
		{
			m_Value = std::string(value, m_ValueLength);
		}
		else
		{
			m_Value = byteArrayToHexString(data, m_ValueLength);
		}
	}

	std::vector<uint8_t> Asn1OctetStringRecord::encodeValue() const
	{
		if (m_IsPrintable)
		{
			return {m_Value.begin(), m_Value.end()};
		}

		auto rawValueSize = static_cast<size_t>(m_Value.size() / 2);
		std::vector<uint8_t> rawValue;
		rawValue.resize(rawValueSize);
		hexStringToByteArray(m_Value, rawValue.data(), rawValueSize);
		return rawValue;
	}

	std::vector<std::string> Asn1OctetStringRecord::toStringList()
	{
		return {Asn1Record::toStringList().front() + ", Value: " + getValue()};
	}

	Asn1BooleanRecord::Asn1BooleanRecord(bool value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Boolean)
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

	std::vector<std::string> Asn1BooleanRecord::toStringList()
	{
		return {Asn1Record::toStringList().front() + ", Value: " + (getValue() ? "true" : "false")};
	}

	Asn1NullRecord::Asn1NullRecord() : Asn1PrimitiveRecord(Asn1UniversalTagType::Null)
	{
		m_ValueLength = 0;
		m_TotalLength = 2;
	}
}
