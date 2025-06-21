#define LOG_MODULE PacketLogModuleAsn1Codec

#include "Asn1Codec.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"
#include "SystemUtils.h"
#include <unordered_map>
#include <numeric>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <limits>
#include <cstring>

#if defined(_WIN32)
#	undef max
#endif

namespace pcpp
{
	const std::unordered_map<Asn1TagClass, std::string, EnumClassHash<Asn1TagClass>> Asn1TagClassToString{
		{ Asn1TagClass::Universal,       "Universal"       },
		{ Asn1TagClass::ContextSpecific, "ContextSpecific" },
		{ Asn1TagClass::Application,     "Application"     },
		{ Asn1TagClass::Private,         "Private"         }
	};

	std::string toString(Asn1TagClass tagClass)
	{
		if (Asn1TagClassToString.find(tagClass) != Asn1TagClassToString.end())
		{
			return Asn1TagClassToString.at(tagClass);
		}

		return "Unknown";
	}

	const std::unordered_map<Asn1UniversalTagType, std::string, EnumClassHash<Asn1UniversalTagType>>
	    Asn1UniversalTagTypeToString{
		    { Asn1UniversalTagType::EndOfContent,                "EndOfContent"                },
		    { Asn1UniversalTagType::Boolean,                     "Boolean"                     },
		    { Asn1UniversalTagType::Integer,                     "Integer"                     },
		    { Asn1UniversalTagType::BitString,                   "BitString"                   },
		    { Asn1UniversalTagType::OctetString,                 "OctetString"                 },
		    { Asn1UniversalTagType::Null,                        "Null"                        },
		    { Asn1UniversalTagType::ObjectIdentifier,            "ObjectIdentifier"            },
		    { Asn1UniversalTagType::ObjectDescriptor,            "ObjectDescriptor"            },
		    { Asn1UniversalTagType::External,                    "External"                    },
		    { Asn1UniversalTagType::Real,                        "Real"                        },
		    { Asn1UniversalTagType::Enumerated,                  "Enumerated"                  },
		    { Asn1UniversalTagType::EmbeddedPDV,                 "EmbeddedPDV"                 },
		    { Asn1UniversalTagType::UTF8String,                  "UTF8String"                  },
		    { Asn1UniversalTagType::RelativeObjectIdentifier,    "RelativeObjectIdentifier"    },
		    { Asn1UniversalTagType::Time,                        "Time"                        },
		    { Asn1UniversalTagType::Reserved,                    "Reserved"                    },
		    { Asn1UniversalTagType::Sequence,                    "Sequence"                    },
		    { Asn1UniversalTagType::Set,                         "Set"                         },
		    { Asn1UniversalTagType::NumericString,               "NumericString"               },
		    { Asn1UniversalTagType::PrintableString,             "PrintableString"             },
		    { Asn1UniversalTagType::T61String,                   "T61String"                   },
		    { Asn1UniversalTagType::VideotexString,              "VideotexString"              },
		    { Asn1UniversalTagType::IA5String,                   "IA5String"                   },
		    { Asn1UniversalTagType::UTCTime,                     "UTCTime"                     },
		    { Asn1UniversalTagType::GeneralizedTime,             "GeneralizedTime"             },
		    { Asn1UniversalTagType::GraphicString,               "GraphicString"               },
		    { Asn1UniversalTagType::VisibleString,               "VisibleString"               },
		    { Asn1UniversalTagType::GeneralString,               "GeneralString"               },
		    { Asn1UniversalTagType::UniversalString,             "UniversalString"             },
		    { Asn1UniversalTagType::CharacterString,             "CharacterString"             },
		    { Asn1UniversalTagType::BMPString,                   "BMPString"                   },
		    { Asn1UniversalTagType::Date,                        "Date"                        },
		    { Asn1UniversalTagType::TimeOfDay,                   "TimeOfDay"                   },
		    { Asn1UniversalTagType::DateTime,                    "DateTime"                    },
		    { Asn1UniversalTagType::Duration,                    "Duration"                    },
		    { Asn1UniversalTagType::ObjectIdentifierIRI,         "ObjectIdentifierIRI"         },
		    { Asn1UniversalTagType::RelativeObjectIdentifierIRI, "RelativeObjectIdentifierIRI" },
		    { Asn1UniversalTagType::NotApplicable,               "Unknown"                     }
    };

	std::string toString(Asn1UniversalTagType tagType)
	{
		if (Asn1UniversalTagTypeToString.find(tagType) != Asn1UniversalTagTypeToString.end())
		{
			return Asn1UniversalTagTypeToString.at(tagType);
		}

		return "Unknown";
	}

	std::unique_ptr<Asn1Record> Asn1Record::decode(const uint8_t* data, size_t dataLen, bool lazy)
	{
		auto record = decodeInternal(data, dataLen, lazy);
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

		auto tempValueLength = m_ValueLength;
		do
		{
			uint8_t byte = tempValueLength & 0xff;
			result.push_back(byte);  // Inserts the bytes in reverse order
			tempValueLength >>= 8;
		} while (tempValueLength != 0);

		uint8_t firstByte = 0x80 | static_cast<uint8_t>(result.size());
		result.push_back(firstByte);

		// Reverses the bytes to get forward ordering
		std::reverse(result.begin(), result.end());

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
		uint8_t tagLen;
		auto decodedRecord = decodeTagAndCreateRecord(data, dataLen, tagLen);

		uint8_t lengthLen;
		try
		{
			lengthLen = decodedRecord->decodeLength(data + tagLen, dataLen - tagLen);
		}
		catch (...)
		{
			delete decodedRecord;
			throw;
		}

		decodedRecord->m_TotalLength = tagLen + lengthLen + decodedRecord->m_ValueLength;
		if (decodedRecord->m_TotalLength < decodedRecord->m_ValueLength ||  // check for overflow
		    decodedRecord->m_TotalLength > dataLen)
		{
			delete decodedRecord;
			throw std::invalid_argument("Cannot decode ASN.1 record, data doesn't contain the entire record");
		}

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

	Asn1Record* Asn1Record::decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, uint8_t& tagLen)
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
				case Asn1UniversalTagType::UTF8String:
				{
					newRecord = new Asn1UTF8StringRecord();
					break;
				}
				case Asn1UniversalTagType::PrintableString:
				{
					newRecord = new Asn1PrintableStringRecord();
					break;
				}
				case Asn1UniversalTagType::IA5String:
				{
					newRecord = new Asn1IA5StringRecord();
					break;
				}
				case Asn1UniversalTagType::Boolean:
				{
					newRecord = new Asn1BooleanRecord();
					break;
				}
				case Asn1UniversalTagType::BitString:
				{
					newRecord = new Asn1BitStringRecord();
					break;
				}
				case Asn1UniversalTagType::Null:
				{
					newRecord = new Asn1NullRecord();
					break;
				}
				case Asn1UniversalTagType::ObjectIdentifier:
				{
					newRecord = new Asn1ObjectIdentifierRecord();
					break;
				}
				case Asn1UniversalTagType::UTCTime:
				{
					newRecord = new Asn1UtcTimeRecord();
					break;
				}
				case Asn1UniversalTagType::GeneralizedTime:
				{
					newRecord = new Asn1GeneralizedTimeRecord();
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

	uint8_t Asn1Record::decodeLength(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record length");
		}

		// Check 8th bit
		auto lengthForm = data[0] & 0x80;

		// Check if the tag is using more than one byte
		// 8th bit at 0 means the length only uses one byte
		// 8th bit at 1 means the length uses more than one byte. The number of bytes is encoded in the other 7 bits
		if (lengthForm == 0)
		{
			m_ValueLength = data[0];
			return 1;
		}

		uint8_t actualLengthBytes = data[0] & 0x7F;
		const uint8_t* actualLengthData = data + 1;

		if (dataLen < static_cast<size_t>(actualLengthBytes) + 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 record length");
		}

		for (int i = 0; i < actualLengthBytes; i++)
		{
			size_t partialValueLength = m_ValueLength << 8;
			if (partialValueLength < m_ValueLength)  // check for overflow
			{
				throw std::invalid_argument("Cannot decode ASN.1 record length");
			}

			m_ValueLength = partialValueLength | actualLengthData[i];
		}

		return 1 + actualLengthBytes;
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

		auto commaSeparated = [](std::string str1, std::string str2) {
			return std::move(str1) + '\n' + std::move(str2);
		};

		return std::accumulate(std::next(lines.begin()), lines.end(), lines[0], commaSeparated);
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

		return { stream.str() };
	}

	Asn1GenericRecord::Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType,
	                                     const uint8_t* value, size_t valueLen)
	{
		init(tagClass, isConstructed, tagType, value, valueLen);
	}

	Asn1GenericRecord::Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType,
	                                     const std::string& value)
	{
		init(tagClass, isConstructed, tagType, reinterpret_cast<const uint8_t*>(value.c_str()), value.size());
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
		return { m_Value, m_Value + m_ValueLength };
	}

	void Asn1GenericRecord::init(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value,
	                             size_t valueLen)
	{
		m_TagType = tagType;
		m_TagClass = tagClass;
		m_IsConstructed = isConstructed;
		m_Value = new uint8_t[valueLen];
		memcpy(m_Value, value, valueLen);
		m_ValueLength = valueLen;
		m_TotalLength = m_ValueLength + 2;
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
	                                             const std::vector<Asn1Record*>& subRecords)
	{
		init(tagClass, tagType, subRecords.begin(), subRecords.end());
	}

	Asn1ConstructedRecord::Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
	                                             const PointerVector<Asn1Record>& subRecords)
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
			result.insert(result.end(), std::make_move_iterator(encodedRecord.begin()),
			              std::make_move_iterator(encodedRecord.end()));
		}
		return result;
	}

	std::vector<std::string> Asn1ConstructedRecord::toStringList()
	{
		decodeValueIfNeeded();
		std::vector<std::string> result = { Asn1Record::toStringList().front() };
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
	    : Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence),
	                            subRecords)
	{}

	Asn1SequenceRecord::Asn1SequenceRecord(const PointerVector<Asn1Record>& subRecords)
	    : Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Sequence),
	                            subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const std::vector<Asn1Record*>& subRecords)
	    : Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1SetRecord::Asn1SetRecord(const PointerVector<Asn1Record>& subRecords)
	    : Asn1ConstructedRecord(Asn1TagClass::Universal, static_cast<uint8_t>(Asn1UniversalTagType::Set), subRecords)
	{}

	Asn1PrimitiveRecord::Asn1PrimitiveRecord(Asn1UniversalTagType tagType) : Asn1Record()
	{
		m_TagType = static_cast<uint8_t>(tagType);
		m_TagClass = Asn1TagClass::Universal;
		m_IsConstructed = false;
	}

	Asn1IntegerRecord::BigInt::BigInt(const std::string& value)
	{
		m_Value = initFromString(value);
	}

	Asn1IntegerRecord::BigInt::BigInt(const BigInt& other)
	{
		m_Value = other.m_Value;
	}

	std::string Asn1IntegerRecord::BigInt::initFromString(const std::string& value)
	{
		std::string valueStr = value;

		// Optional 0x or 0X prefix
		if (value.size() >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
		{
			valueStr = value.substr(2);
		}

		if (valueStr.empty())
		{
			throw std::invalid_argument("Value is not a valid hex stream");
		}

		for (const char i : valueStr)
		{
			if (!std::isxdigit(i))
			{
				throw std::invalid_argument("Value is not a valid hex stream");
			}
		}

		return valueStr;
	}

	Asn1IntegerRecord::BigInt& Asn1IntegerRecord::BigInt::operator=(const std::string& value)
	{
		m_Value = initFromString(value);
		return *this;
	}

	size_t Asn1IntegerRecord::BigInt::size() const
	{
		return m_Value.size() / 2;
	}

	std::string Asn1IntegerRecord::BigInt::toString() const
	{
		return m_Value;
	}

	std::vector<uint8_t> Asn1IntegerRecord::BigInt::toBytes() const
	{
		std::string value = m_Value;
		if (m_Value.size() % 2 != 0)
		{
			value.insert(0, 1, '0');
		}

		std::vector<uint8_t> result;
		for (std::size_t i = 0; i < value.size(); i += 2)
		{
			std::string byteStr = value.substr(i, 2);
			auto byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
			result.push_back(byte);
		}

		return result;
	}

	Asn1IntegerRecord::Asn1IntegerRecord(uint64_t value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Integer)
	{
		m_Value = value;

		std::size_t length = 0;
		while (value != 0)
		{
			++length;
			value >>= 8;
		}
		m_ValueLength = length == 0 ? 1 : length;

		m_TotalLength = m_ValueLength + 2;
	}

	Asn1IntegerRecord::Asn1IntegerRecord(const std::string& value) : Asn1PrimitiveRecord(Asn1UniversalTagType::Integer)
	{
		m_Value = value;
		m_ValueLength = m_Value.size();
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1IntegerRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = pcpp::byteArrayToHexString(data, m_ValueLength);
	}

	std::vector<uint8_t> Asn1IntegerRecord::encodeValue() const
	{
		return m_Value.toBytes();
	}

	std::vector<std::string> Asn1IntegerRecord::toStringList()
	{
		auto valueAsString =
		    m_Value.canFit<uint64_t>() ? std::to_string(getIntValue<uint64_t>()) : "0x" + getValueAsString();
		return std::vector<std::string>({ Asn1Record::toStringList().front() + ", Value: " + valueAsString });
	}

	Asn1EnumeratedRecord::Asn1EnumeratedRecord(uint32_t value) : Asn1IntegerRecord(value)
	{
		m_TagType = static_cast<uint8_t>(Asn1UniversalTagType::Enumerated);
	}

	Asn1OctetStringRecord::Asn1OctetStringRecord(const uint8_t* value, size_t valueLength) : m_IsPrintable(false)
	{
		m_Value = byteArrayToHexString(value, valueLength);
		m_ValueLength = valueLength;
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1OctetStringRecord::decodeValue(uint8_t* data, bool lazy)
	{
		auto value = reinterpret_cast<char*>(data);

		m_IsPrintable = std::all_of(value, value + m_ValueLength, [](char c) { return isprint(0xff & c); });

		if (m_IsPrintable)
		{
			Asn1StringRecord::decodeValue(data, lazy);
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
			return Asn1StringRecord::encodeValue();
		}

		// converting the hex stream to a byte array.
		// The byte array size is half the size of the string
		// i.e "1a2b" (length == 4)  becomes {0x1a, 0x2b} (length == 2)
		auto rawValueSize = static_cast<size_t>(m_Value.size() / 2);
		std::vector<uint8_t> rawValue;
		rawValue.resize(rawValueSize);
		hexStringToByteArray(m_Value, rawValue.data(), rawValueSize);
		return rawValue;
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
		return { Asn1Record::toStringList().front() + ", Value: " + (getValue() ? "true" : "false") };
	}

	Asn1NullRecord::Asn1NullRecord() : Asn1PrimitiveRecord(Asn1UniversalTagType::Null)
	{
		m_ValueLength = 0;
		m_TotalLength = 2;
	}

	Asn1ObjectIdentifier::Asn1ObjectIdentifier(const uint8_t* data, size_t dataLen)
	{
		// A description of OID encoding can be found here:
		// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN

		if (!data || dataLen == 0)
		{
			throw std::invalid_argument("Malformed OID: Not enough bytes for the first component");
		}

		size_t currentByteIndex = 0;
		std::vector<uint32_t> components;

		uint8_t firstByte = data[currentByteIndex++];
		// Decode the first byte: first_component * 40 + second_component
		components.push_back(static_cast<uint32_t>(firstByte / 40));
		components.push_back(static_cast<uint32_t>(firstByte % 40));

		uint32_t currentComponentValue = 0;
		bool componentStarted = false;

		// Process remaining bytes using base-128 encoding
		while (currentByteIndex < dataLen)
		{
			uint8_t byte = data[currentByteIndex++];

			// Shift previous bits left by 7 and append lower 7 bits
			currentComponentValue = (currentComponentValue << 7) | (byte & 0x7f);
			componentStarted = true;

			// If the MSB is 0, this is the final byte of the current value
			if ((byte & 0x80) == 0)
			{
				components.push_back(currentComponentValue);
				currentComponentValue = 0;
				componentStarted = false;
			}
		}

		if (componentStarted)
		{
			throw std::invalid_argument("Malformed OID: Incomplete component at end of data");
		}

		m_Components = components;
	}

	Asn1ObjectIdentifier::Asn1ObjectIdentifier(const std::string& oidString)
	{
		std::vector<uint32_t> components;
		std::istringstream stream(oidString);
		std::string token;

		while (std::getline(stream, token, '.'))
		{
			if (token.empty())
			{
				throw std::invalid_argument("Malformed OID: empty component");
			}

			unsigned long long value;
			try
			{
				value = std::stoull(token);
			}
			catch (const std::exception&)
			{
				throw std::invalid_argument("Malformed OID: invalid component");
			}

			if (value > std::numeric_limits<uint32_t>::max())
			{
				throw std::invalid_argument("Malformed OID: component out of uint32_t range");
			}

			components.push_back(static_cast<uint32_t>(value));
		}

		if (components.size() < 2)
		{
			throw std::invalid_argument("Malformed OID: an OID must have at least two components");
		}

		if (components[0] > 2)
		{
			throw std::invalid_argument("Malformed OID: first component must be 0, 1, or 2");
		}

		if ((components[0] == 0 || components[0] == 1) && components[1] >= 40)
		{
			throw std::invalid_argument(
			    "Malformed OID: second component must be less than 40 when first component is 0 or 1");
		}

		m_Components = components;
	}

	std::string Asn1ObjectIdentifier::toString() const
	{
		if (m_Components.empty())
		{
			return "";
		}

		std::ostringstream stream;
		stream << m_Components[0];

		for (size_t i = 1; i < m_Components.size(); ++i)
		{
			stream << "." << m_Components[i];
		}
		return stream.str();
	}

	std::vector<uint8_t> Asn1ObjectIdentifier::toBytes() const
	{
		// A description of OID encoding can be found here:
		// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN

		if (m_Components.size() < 2)
		{
			throw std::runtime_error("OID must have at least two components to encode.");
		}

		std::vector<uint8_t> encoded;

		// Encode the first two components into one byte
		uint32_t firstComponent = m_Components[0];
		uint32_t secondComponent = m_Components[1];
		encoded.push_back(static_cast<uint8_t>(firstComponent * 40 + secondComponent));

		// Encode remaining components using base-128 encoding
		for (size_t i = 2; i < m_Components.size(); ++i)
		{
			uint32_t currentComponent = m_Components[i];
			std::vector<uint8_t> temp;

			// At least one byte must be generated even if value is 0
			do
			{
				temp.push_back(static_cast<uint8_t>(currentComponent & 0x7F));
				currentComponent >>= 7;
			} while (currentComponent > 0);

			// Set continuation bits (MSB) for all but the last byte
			for (size_t j = temp.size(); j-- > 0;)
			{
				uint8_t byte = temp[j];
				if (j != 0)
				{
					byte |= 0x80;
				}
				encoded.push_back(byte);
			}
		}

		return encoded;
	}

	Asn1ObjectIdentifierRecord::Asn1ObjectIdentifierRecord(const Asn1ObjectIdentifier& value)
	    : Asn1PrimitiveRecord(Asn1UniversalTagType::ObjectIdentifier)
	{
		m_Value = value;
		m_ValueLength = value.toBytes().size();
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1ObjectIdentifierRecord::decodeValue(uint8_t* data, bool lazy)
	{
		m_Value = Asn1ObjectIdentifier(data, m_ValueLength);
	}

	std::vector<uint8_t> Asn1ObjectIdentifierRecord::encodeValue() const
	{
		return m_Value.toBytes();
	}

	std::vector<std::string> Asn1ObjectIdentifierRecord::toStringList()
	{
		return { Asn1Record::toStringList().front() + ", Value: " + getValue().toString() };
	}

	Asn1TimeRecord::Asn1TimeRecord(Asn1UniversalTagType tagType, const std::chrono::system_clock::time_point& value,
	                               const std::string& timezone)
	    : Asn1PrimitiveRecord(tagType)
	{
		validateTimezone(timezone);
		m_Value = adjustTimezones(value, timezone, "Z");
	}

	std::string Asn1TimeRecord::getValueAsString(const std::string& format, const std::string& timezone,
	                                             bool includeMilliseconds)
	{
		auto value = getValue(timezone);
		auto timeValue = std::chrono::system_clock::to_time_t(value);
		auto tmValue = *std::gmtime(&timeValue);

		std::ostringstream osstream;
		osstream << std::put_time(&tmValue, format.c_str());

		if (includeMilliseconds)
		{
			auto milliseconds =
			    std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count() % 1000;
			if (milliseconds != 0)
			{
				osstream << "." << std::setw(3) << std::setfill('0') << milliseconds;
			}
		}

		if (timezone != "Z")
		{
			osstream << " UTC" << timezone;
		}

		return osstream.str();
	}

	std::vector<std::string> Asn1TimeRecord::toStringList()
	{
		return { Asn1Record::toStringList().front() + ", Value: " + getValueAsString("%Y-%m-%d %H:%M:%S", "Z", true) };
	}

	void Asn1TimeRecord::validateTimezone(const std::string& timezone)
	{
		if (timezone == "Z")
		{
			return;
		}

		if (timezone.length() != 5 || (timezone[0] != '+' && timezone[0] != '-') || !std::isdigit(timezone[1]) ||
		    !std::isdigit(timezone[2]) || !std::isdigit(timezone[3]) || !std::isdigit(timezone[4]))
		{
			throw std::invalid_argument("Invalid timezone format. Use 'Z' or '+/-HHMM'.");
		}
	}

	std::chrono::system_clock::time_point Asn1TimeRecord::adjustTimezones(
	    const std::chrono::system_clock::time_point& value, const std::string& fromTimezone,
	    const std::string& toTimezone)
	{
		validateTimezone(fromTimezone);
		validateTimezone(toTimezone);

		int fromOffsetSeconds = 0;
		if (fromTimezone != "Z")
		{
			int fromSign = (fromTimezone[0] == '+') ? 1 : -1;
			auto fromHours = std::stoi(fromTimezone.substr(1, 2));
			auto fromMinutes = std::stoi(fromTimezone.substr(3, 2));
			fromOffsetSeconds = fromSign * (fromHours * 3600 + fromMinutes * 60);
		}

		int toOffsetSeconds = 0;
		if (toTimezone != "Z")
		{
			int toSign = (toTimezone[0] == '+') ? 1 : -1;
			auto toHours = std::stoi(toTimezone.substr(1, 2));
			auto toMinutes = std::stoi(toTimezone.substr(3, 2));
			toOffsetSeconds = toSign * (toHours * 3600 + toMinutes * 60);
		}

		return value + std::chrono::seconds(toOffsetSeconds - fromOffsetSeconds);
	}

	Asn1UtcTimeRecord::Asn1UtcTimeRecord(const std::chrono::system_clock::time_point& value, bool withSeconds)
	    : Asn1TimeRecord(Asn1UniversalTagType::UTCTime, value, "Z"), m_WithSeconds(withSeconds)
	{
		m_ValueLength = 11;
		if (withSeconds)
		{
			m_ValueLength += 2;
		}

		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1UtcTimeRecord::decodeValue(uint8_t* data, bool lazy)
	{
		std::string timeString(reinterpret_cast<const char*>(data), m_ValueLength);

		if (timeString.back() == 'Z')
		{
			timeString.pop_back();
		}

		m_WithSeconds = true;
		if (timeString.size() == 10)
		{
			m_WithSeconds = false;
			timeString.append("00");
		}

		auto year = std::stoi(timeString.substr(0, 2));
		if (year <= 50)
		{
			timeString.insert(0, "20");
		}
		else
		{
			timeString.insert(0, "19");
		}

		std::tm tm = {};
		std::istringstream sstream(timeString);
		sstream >> std::get_time(&tm, "%Y%m%d%H%M%S");

		if (sstream.fail())
		{
			throw std::runtime_error("Failed to parse ASN.1 UTC time");
		}

		std::time_t timeValue = mkUtcTime(tm);
		m_Value = std::chrono::system_clock::from_time_t(timeValue);
	}

	std::vector<uint8_t> Asn1UtcTimeRecord::encodeValue() const
	{
		auto timeValue = std::chrono::system_clock::to_time_t(m_Value);

		auto tm = *std::gmtime(&timeValue);

		auto pattern = std::string("%y%m%d%H%M") + (m_WithSeconds ? "%S" : "");
		std::ostringstream osstream;
		osstream << std::put_time(&tm, pattern.c_str()) << 'Z';

		auto timeString = osstream.str();
		return { timeString.begin(), timeString.end() };
	}

	Asn1GeneralizedTimeRecord::Asn1GeneralizedTimeRecord(const std::chrono::system_clock::time_point& value,
	                                                     const std::string& timezone)
	    : Asn1TimeRecord(Asn1UniversalTagType::GeneralizedTime, value, timezone), m_Timezone(timezone)
	{
		m_ValueLength = 14 + (timezone == "Z" ? 1 : 5);

		auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
		if (milliseconds % 1000 != 0)
		{
			m_ValueLength += 4;
		}

		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1GeneralizedTimeRecord::decodeValue(uint8_t* data, bool lazy)
	{
		std::string timeString(reinterpret_cast<const char*>(data), m_ValueLength);

		std::string timezone = "Z";
		auto timezonePos = timeString.find_first_of("+-");
		if (timeString.back() == 'Z')
		{
			timeString.pop_back();
		}
		else if (timezonePos != std::string::npos)
		{
			timezone = timeString.substr(timezonePos);
			timeString.erase(timezonePos);
		}

		std::tm tm = {};
		std::istringstream sstream(timeString);
		sstream >> std::get_time(&tm, "%Y%m%d%H%M%S");

		if (sstream.fail())
		{
			throw std::runtime_error("Failed to parse ASN.1 generalized time");
		}

		size_t dotPos = timeString.find('.');
		int milliseconds = 0;
		if (dotPos != std::string::npos)
		{
			std::string millisecondsStr = timeString.substr(dotPos + 1);
			// Limit the milliseconds to 3 digits
			if (millisecondsStr.length() > 3)
			{
				timeString.erase(timezonePos);
				millisecondsStr.resize(3);
			}
			milliseconds = std::stoi(millisecondsStr);
		}

		auto timeValue = mkUtcTime(tm);

		m_Timezone = timezone;
		m_Value = adjustTimezones(
		    std::chrono::system_clock::from_time_t(timeValue) + std::chrono::milliseconds(milliseconds), timezone, "Z");
	}

	std::vector<uint8_t> Asn1GeneralizedTimeRecord::encodeValue() const
	{
		auto value = adjustTimezones(m_Value, "Z", m_Timezone);
		auto timeValue = std::chrono::system_clock::to_time_t(value);

		auto tm = *std::gmtime(&timeValue);

		auto pattern = std::string("%Y%m%d%H%M%S");
		std::ostringstream osstream;
		osstream << std::put_time(&tm, pattern.c_str());

		auto milliseconds =
		    std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count() % 1000;
		if (milliseconds != 0)
		{
			osstream << "." << std::setw(3) << std::setfill('0') << milliseconds;
		}

		osstream << m_Timezone;

		auto timeString = osstream.str();
		return { timeString.begin(), timeString.end() };
	}

	void Asn1BitStringRecord::BitSet::initFromString(const std::string& value)
	{
		m_NumBits = value.length();

		size_t numBytes = (m_NumBits + 7) / 8;
		m_Data.clear();
		m_Data.reserve(numBytes);

		size_t i = 0;
		while (i < value.length())
		{
			std::string curByteString = value.substr(i, 8);
			curByteString.append(8 - curByteString.length(), '0');
			try
			{
				std::bitset<8> bs(curByteString);
				m_Data.push_back(bs);
				i += 8;
			}
			catch (const std::invalid_argument&)
			{
				throw std::invalid_argument("Invalid bit string");
			}
		}
	}

	Asn1BitStringRecord::BitSet::BitSet(const std::string& value)
	{
		initFromString(value);
	}

	Asn1BitStringRecord::BitSet::BitSet(const uint8_t* data, size_t numBits) : m_NumBits(numBits)
	{
		if (!data || !numBits)
		{
			throw std::invalid_argument("Provided data is null or num of bits is 0");
		}

		size_t requiredBytes = (m_NumBits + 7) / 8;
		m_Data.resize(requiredBytes);
		std::copy_n(data, requiredBytes, m_Data.begin());
	}

	Asn1BitStringRecord::BitSet& Asn1BitStringRecord::BitSet::operator=(const std::string& value)
	{
		initFromString(value);
		return *this;
	}

	std::string Asn1BitStringRecord::BitSet::toString() const
	{
		std::string result;
		result.reserve(m_Data.size() * 8);
		for (const auto bs : m_Data)
		{
			result += bs.to_string();
		}
		result.resize(m_NumBits);
		return result;
	}

	std::vector<uint8_t> Asn1BitStringRecord::BitSet::toBytes() const
	{
		std::vector<uint8_t> result;
		result.reserve(m_Data.size());
		for (const auto& bs : m_Data)
		{
			result.push_back(static_cast<uint8_t>(bs.to_ulong()));
		}

		return result;
	}

	size_t Asn1BitStringRecord::BitSet::sizeInBytes() const
	{
		return m_Data.size();
	}

	Asn1BitStringRecord::Asn1BitStringRecord(const std::string& value)
	    : Asn1PrimitiveRecord(Asn1UniversalTagType::BitString)
	{
		m_Value = value;
		m_ValueLength = m_Value.sizeInBytes() + 1;
		m_TotalLength = m_ValueLength + 2;
	}

	void Asn1BitStringRecord::decodeValue(uint8_t* data, bool lazy)
	{
		auto numBits = (m_ValueLength - 1) * 8 - static_cast<size_t>(data[0]);
		m_Value = BitSet(data + 1, numBits);
	}

	std::vector<uint8_t> Asn1BitStringRecord::encodeValue() const
	{
		auto result = m_Value.toBytes();
		size_t unusedBits = m_Value.sizeInBytes() * 8 - m_Value.getNumBits();
		result.insert(result.begin(), static_cast<uint8_t>(unusedBits));
		return result;
	}

	std::vector<std::string> Asn1BitStringRecord::toStringList()
	{
		return { Asn1Record::toStringList().front() + ", Value: " + m_Value.toString() };
	}

}  // namespace pcpp
