#include "../TestDefinition.h"
#include "Asn1Codec.h"
#include "RawPacket.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <functional>
#include <cstring>
#include <sstream>

PTF_TEST_CASE(Asn1DecodingTest)
{
	// Context specific
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("870b6f626a656374636c617373", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::ContextSpecific, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record->getValueLength(), 11);
		PTF_ASSERT_EQUAL(record->toString(), "ContextSpecific (7), Length: 2+11");
		auto genericRecord = record->castAs<pcpp::Asn1GenericRecord>();
		auto recordValue =
		    std::string(genericRecord->getValue(), genericRecord->getValue() + genericRecord->getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "objectclass");
	};

	// Integer 1 byte
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020106", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint8_t>(), 6);
		PTF_ASSERT_EQUAL(record->toString(), "Integer, Length: 2+1, Value: 6");
	}

	// Integer 2 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020203e8", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record->getValueLength(), 2);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);
		PTF_ASSERT_EQUAL(record->toString(), "Integer, Length: 2+2, Value: 1000");
	}

	// Integer 3 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("02030186a0", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 5);
		PTF_ASSERT_EQUAL(record->getValueLength(), 3);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint32_t>(), 100000);
		PTF_ASSERT_EQUAL(record->toString(), "Integer, Length: 2+3, Value: 100000");
	}

	// Integer 4 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020400989680", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 6);
		PTF_ASSERT_EQUAL(record->getValueLength(), 4);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint32_t>(), 10000000);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 10000000);
		PTF_ASSERT_EQUAL(record->toString(), "Integer, Length: 2+4, Value: 10000000");
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint8_t>(), std::overflow_error,
		                  "Value cannot fit into requested int type");
	}

	// Big Integer
	{
		uint8_t data[22];
		std::string bigIntValue = "21c28a1bff4aa8400226fc73409b54bbc1f06c5f";
		auto dataLen = pcpp::hexStringToByteArray("0214" + bigIntValue, data, 22);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 22);
		PTF_ASSERT_EQUAL(record->getValueLength(), 20);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValueAsString(), bigIntValue);
		std::ostringstream oss;
		oss << "Integer, Length: 2+20, Value: 0x" << bigIntValue;
		PTF_ASSERT_EQUAL(record->toString(), oss.str());
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint32_t>(), std::overflow_error,
		                  "Value cannot fit into requested int type");
	}

	// Enumerated
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0a022000", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Enumerated, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record->getValueLength(), 2);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1EnumeratedRecord>()->getIntValue<uint16_t>(), 8192);
		PTF_ASSERT_EQUAL(record->toString(), "Enumerated, Length: 2+2, Value: 8192");
	}

	// Boolean - true
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0101ff", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_TRUE(record->castAs<pcpp::Asn1BooleanRecord>()->getValue());
		PTF_ASSERT_EQUAL(record->toString(), "Boolean, Length: 2+1, Value: true");
	}

	// Boolean - false
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("010100", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_FALSE(record->castAs<pcpp::Asn1BooleanRecord>()->getValue());
		PTF_ASSERT_EQUAL(record->toString(), "Boolean, Length: 2+1, Value: false");
	}

	// OctetString with printable value
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0411737562736368656d61537562656e747279", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 19);
		PTF_ASSERT_EQUAL(record->getValueLength(), 17);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "subschemaSubentry");
		PTF_ASSERT_EQUAL(record->toString(), "OctetString, Length: 2+17, Value: subschemaSubentry");
	}

	// OctetString with non-printable value
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("04083006020201f40400", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 10);
		PTF_ASSERT_EQUAL(record->getValueLength(), 8);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "3006020201f40400");
		PTF_ASSERT_EQUAL(record->toString(), "OctetString, Length: 2+8, Value: 3006020201f40400");
	}

	// UTF8String
	{
		uint8_t data[30];
		auto dataLen = pcpp::hexStringToByteArray("0c1ae697a5ed959ce0b8aae0a48541cea9d0afd7a9e4bda0f09f8c8d", data, 30);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::UTF8String, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 28);
		PTF_ASSERT_EQUAL(record->getValueLength(), 26);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1UTF8StringRecord>()->getValue(), "日한สअAΩЯש你🌍");
		PTF_ASSERT_EQUAL(record->toString(), "UTF8String, Length: 2+26, Value: 日한สअAΩЯש你🌍");
	}

	// PrintableString
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("13027573", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::PrintableString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record->getValueLength(), 2);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1PrintableStringRecord>()->getValue(), "us");
		PTF_ASSERT_EQUAL(record->toString(), "PrintableString, Length: 2+2, Value: us");
	}

	// IA5String
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("1609414243313233402324", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::IA5String, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 11);
		PTF_ASSERT_EQUAL(record->getValueLength(), 9);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IA5StringRecord>()->getValue(), "ABC123@#$");
		PTF_ASSERT_EQUAL(record->toString(), "IA5String, Length: 2+9, Value: ABC123@#$");
	}

	// Null
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0500", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Null, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 2);
		PTF_ASSERT_EQUAL(record->getValueLength(), 0);
		PTF_ASSERT_NOT_NULL(record->castAs<pcpp::Asn1NullRecord>());
		PTF_ASSERT_EQUAL(record->toString(), "Null, Length: 2+0");
	}

	// ObjectIdentifier (OID)
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("06092a864886f70d01010b", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::ObjectIdentifier, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 11);
		PTF_ASSERT_EQUAL(record->getValueLength(), 9);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1ObjectIdentifierRecord>()->getValue(), "1.2.840.113549.1.1.11");
	}

	// UTC time
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170d3235303532343135333034355a", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::UTCTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 15);
		PTF_ASSERT_EQUAL(record->getValueLength(), 13);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1UtcTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 1748100645000000);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1UtcTimeRecord>()->getValueAsString("%Y%m%d"), "20250524");
		PTF_ASSERT_EQUAL(record->toString(), "UTCTime, Length: 2+13, Value: 2025-05-24 15:30:45");
	}

	// UTC time - without seconds
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170b323530353234313533305a", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::UTCTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record->getValueLength(), 11);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1UtcTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 1748100600000000);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1UtcTimeRecord>()->getValueAsString("%Y%m%d"), "20250524");
		PTF_ASSERT_EQUAL(record->toString(), "UTCTime, Length: 2+11, Value: 2025-05-24 15:30:00");
	}

	// UTC time - before year 2000
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170d3835303332333035333030305a", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::UTCTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 15);
		PTF_ASSERT_EQUAL(record->getValueLength(), 13);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1UtcTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 480403800000000);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1UtcTimeRecord>()->getValueAsString("%Y%m%d"), "19850323");
		PTF_ASSERT_EQUAL(record->toString(), "UTCTime, Length: 2+13, Value: 1985-03-23 05:30:00");
	}

	// UTC time - invalid data
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170d3835303332333035333037305a", data, 20);

		auto record = pcpp::Asn1Record::decode(data, dataLen);
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1UtcTimeRecord>()->getValue(), std::runtime_error,
		                  "Failed to parse ASN.1 UTC time");
	}

	// Generalized time - UTC
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("180f32303235303533313134333030305a", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 17);
		PTF_ASSERT_EQUAL(record->getValueLength(), 15);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1GeneralizedTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 1748701800000000);
		PTF_ASSERT_EQUAL(record->toString(), "GeneralizedTime, Length: 2+15, Value: 2025-05-31 14:30:00");
	}

	// Generalized time - non-UTC
	{
		uint8_t data[22];
		auto dataLen = pcpp::hexStringToByteArray("181332303235303533313134333030302D30343030", data, 22);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 21);
		PTF_ASSERT_EQUAL(record->getValueLength(), 19);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1GeneralizedTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 1748716200000000);
		PTF_ASSERT_EQUAL(record->toString(), "GeneralizedTime, Length: 2+19, Value: 2025-05-31 18:30:00");
	}

	// Generalized time - with milliseconds
	{
		uint8_t data[22];
		auto dataLen = pcpp::hexStringToByteArray("181332303235303533313134333030302e3132335a", data, 22);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 21);
		PTF_ASSERT_EQUAL(record->getValueLength(), 19);
		PTF_ASSERT_EQUAL(std::chrono::duration_cast<std::chrono::microseconds>(
		                     record->castAs<pcpp::Asn1GeneralizedTimeRecord>()->getValue().time_since_epoch())
		                     .count(),
		                 1748701800123000);
		PTF_ASSERT_EQUAL(record->toString(), "GeneralizedTime, Length: 2+19, Value: 2025-05-31 14:30:00.123");
	}

	// Generalized time - invalid data
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("180f32303235303533313134333037305a", data, 20);

		auto record = pcpp::Asn1Record::decode(data, dataLen);
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1GeneralizedTimeRecord>()->getValue(), std::runtime_error,
		                  "Failed to parse ASN.1 generalized time");
	}

	// Timezone conversions
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170d3235303532343135333034355a", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);
		auto utcTimeRecord = record->castAs<pcpp::Asn1UtcTimeRecord>();

		std::vector<std::pair<std::string, std::string>> timezonesAndValues = {
			{ "Z",     "2025-05-24 15:30:45"          },
			{ "+1000", "2025-05-25 01:30:45 UTC+1000" },
			{ "-1030", "2025-05-24 05:00:45 UTC-1030" }
		};
		for (const auto& timezonesAndValue : timezonesAndValues)
		{
			PTF_ASSERT_EQUAL(utcTimeRecord->getValueAsString("%Y-%m-%d %H:%M:%S", timezonesAndValue.first),
			                 timezonesAndValue.second);
		}

		std::vector<std::string> invalidTimezones = { "invalid", "abcde", "-a100", "+1a00", "-10a0", "+100a" };
		for (const auto& invalidTimezone : invalidTimezones)
		{
			PTF_ASSERT_RAISES(utcTimeRecord->getValueAsString("%Y%m%d", invalidTimezone), std::invalid_argument,
			                  "Invalid timezone format. Use 'Z' or '+/-HHMM'.");
		}
	}

	// BitString with 0 unused bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("030300a3b5", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::BitString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 5);
		PTF_ASSERT_EQUAL(record->getValueLength(), 3);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1BitStringRecord>()->getValue(), "1010001110110101");
		PTF_ASSERT_EQUAL(record->toString(), "BitString, Length: 2+3, Value: 1010001110110101");
	}

	// BitString with unused bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("030306b2c0", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::BitString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 5);
		PTF_ASSERT_EQUAL(record->getValueLength(), 3);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1BitStringRecord>()->getValue(), "1011001011");
		PTF_ASSERT_EQUAL(record->toString(), "BitString, Length: 2+3, Value: 1011001011");
	}

	// Sequence
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("300a040461626364020203e8", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_TRUE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Sequence, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& subRecords = record->castAs<pcpp::Asn1SequenceRecord>()->getSubRecords();
		PTF_ASSERT_EQUAL(subRecords.size(), 2);
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);

		std::ostringstream expectedString;
		expectedString << "Sequence (constructed), Length: 2+10" << std::endl
		               << "  OctetString, Length: 2+4, Value: abcd" << std::endl
		               << "  Integer, Length: 2+2, Value: 1000";

		PTF_ASSERT_EQUAL(record->toString(), expectedString.str());
	}

	// Set
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("310a020203e8040461626364", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_TRUE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::Set, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& subRecords = record->castAs<pcpp::Asn1SetRecord>()->getSubRecords();
		PTF_ASSERT_EQUAL(subRecords.size(), 2);
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");

		std::ostringstream expectedString;
		expectedString << "Set (constructed), Length: 2+10" << std::endl
		               << "  Integer, Length: 2+2, Value: 1000" << std::endl
		               << "  OctetString, Length: 2+4, Value: abcd";

		PTF_ASSERT_EQUAL(record->toString(), expectedString.str());
	}

	// Application constructed
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("630a040461626364020203e8", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Application, enumclass);
		PTF_ASSERT_TRUE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& subRecords = record->castAs<pcpp::Asn1ConstructedRecord>()->getSubRecords();
		PTF_ASSERT_EQUAL(subRecords.size(), 2);
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);

		std::ostringstream expectedString;
		expectedString << "Application (3) (constructed), Length: 2+10" << std::endl
		               << "  OctetString, Length: 2+4, Value: abcd" << std::endl
		               << "  Integer, Length: 2+2, Value: 1000";

		PTF_ASSERT_EQUAL(record->toString(), expectedString.str());
	}

	// Tag > 30
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("1f23076d7976616c7565", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getUniversalTagType(), pcpp::Asn1UniversalTagType::ObjectIdentifierIRI, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 10);
		PTF_ASSERT_EQUAL(record->getValueLength(), 7);
		PTF_ASSERT_EQUAL(record->toString(), "ObjectIdentifierIRI, Length: 3+7");
		auto genericRecord = record->castAs<pcpp::Asn1GenericRecord>();
		auto recordValue =
		    std::string(genericRecord->getValue(), genericRecord->getValue() + genericRecord->getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "myvalue");
	}

	// Unknown tag
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("1f28076d7976616c7565", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record->isConstructed());
		PTF_ASSERT_EQUAL(record->getTagType(), 40);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 10);
		PTF_ASSERT_EQUAL(record->getValueLength(), 7);
		PTF_ASSERT_EQUAL(record->toString(), "Unknown, Length: 3+7");
		auto genericRecord = record->castAs<pcpp::Asn1GenericRecord>();
		auto recordValue =
		    std::string(genericRecord->getValue(), genericRecord->getValue() + genericRecord->getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "myvalue");
	}

	// Tag > 127
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("1f8100076d7976616c7565", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, dataLen), std::invalid_argument,
		                  "ASN.1 tags with value larger than 127 are not supported");
	}

	// Not enough data to parse tag
	{
		uint8_t data[20];
		pcpp::hexStringToByteArray("1f8100076d7976616c7565", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, 0), std::invalid_argument, "Cannot decode ASN.1 record tag");
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, 1), std::invalid_argument, "Cannot decode ASN.1 record tag");
	}

	// Not enough data to parse length
	{
		uint8_t data[20];
		pcpp::hexStringToByteArray("0500", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, 1), std::invalid_argument,
		                  "Cannot decode ASN.1 record length");
	}

	// Incomplete record - doesn't contain the entire value
	{
		uint8_t data[20];
		pcpp::hexStringToByteArray("0a022000", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, 3), std::invalid_argument,
		                  "Cannot decode ASN.1 record, data doesn't contain the entire record");
	}

	// Cast as the wrong type
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0a022000", data, 20);
		auto record = pcpp::Asn1Record::decode(data, dataLen);
#ifdef _MSC_VER
		auto expectedMessage = "bad cast";
#else
		auto expectedMessage = "std::bad_cast";
#endif
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1BooleanRecord>(), std::bad_cast, expectedMessage);
	}
};  // Asn1DecodingTest

PTF_TEST_CASE(Asn1EncodingTest)
{
	// Generic record with byte array value
	{
		uint8_t value[] = { 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73 };
		pcpp::Asn1GenericRecord record(pcpp::Asn1TagClass::ContextSpecific, false, 7, value, 11);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::ContextSpecific, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record.getValueLength(), 11);
		auto recordValue = std::string(record.getValue(), record.getValue() + record.getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "objectclass");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("870b6f626a656374636c617373", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Generic record with string value
	{
		pcpp::Asn1GenericRecord record(pcpp::Asn1TagClass::ContextSpecific, false, 7, "objectclass");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::ContextSpecific, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record.getValueLength(), 11);
		auto recordValue = std::string(record.getValue(), record.getValue() + record.getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "objectclass");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("870b6f626a656374636c617373", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Record length > 128
	{
		pcpp::Asn1OctetStringRecord record(
		    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456"
		    "7890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");

		uint8_t data[203];
		auto dataLen = pcpp::hexStringToByteArray(
		    "0481c83132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930"
		    "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233"
		    "3435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536"
		    "3738393031323334353637383930313233343536373839303132333435363738393031323334353637383930",
		    data, 203);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Record length > 256
	{
		pcpp::Asn1OctetStringRecord record(
		    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"
		    "6789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
		    "2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");

		uint8_t data[304];
		auto dataLen = pcpp::hexStringToByteArray(
		    "0482012c30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738"
		    "3930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031"
		    "3233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
		    "3536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637"
		    "3839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930"
		    "313233343536373839303132333435363738393031323334353637383930313233343536373839",
		    data, 304);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Integer 1 byte
	{
		pcpp::Asn1IntegerRecord record(6);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record.getValueLength(), 1);
		PTF_ASSERT_EQUAL(record.getIntValue<uint8_t>(), 6);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020106", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Integer 2 bytes
	{
		pcpp::Asn1IntegerRecord record(1000);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record.getValueLength(), 2);
		PTF_ASSERT_EQUAL(record.getIntValue<uint16_t>(), 1000);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020203e8", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Integer 3 bytes
	{
		pcpp::Asn1IntegerRecord record(100000);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 5);
		PTF_ASSERT_EQUAL(record.getValueLength(), 3);
		PTF_ASSERT_EQUAL(record.getIntValue<uint32_t>(), 100000);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("02030186a0", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Integer 4 bytes
	{
		pcpp::Asn1IntegerRecord record(100000000);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 6);
		PTF_ASSERT_EQUAL(record.getValueLength(), 4);
		PTF_ASSERT_EQUAL(record.getIntValue<uint32_t>(), 100000000);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020405f5e100", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Big Integer
	{
		std::vector<std::string> recordValues = { "21c28a1bff4aa8400226fc73409b54bbc1f06c5f",
			                                      "0x21c28a1bff4aa8400226fc73409b54bbc1f06c5f",
			                                      "0X21c28a1bff4aa8400226fc73409b54bbc1f06c5f" };

		for (const auto& recordValue : recordValues)
		{
			pcpp::Asn1IntegerRecord record(recordValue);

			PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
			PTF_ASSERT_FALSE(record.isConstructed());
			PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
			PTF_ASSERT_EQUAL(record.getTotalLength(), 22);
			PTF_ASSERT_EQUAL(record.getValueLength(), 20);
			PTF_ASSERT_EQUAL(record.getValueAsString(), "21c28a1bff4aa8400226fc73409b54bbc1f06c5f");

			uint8_t data[22];
			auto dataLen = pcpp::hexStringToByteArray("021421c28a1bff4aa8400226fc73409b54bbc1f06c5f", data, 22);

			auto encodedValue = record.encode();
			PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
			PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
		}
	}

	// Invalid big integer
	{
		PTF_ASSERT_RAISES(pcpp::Asn1IntegerRecord("invalid"), std::invalid_argument, "Value is not a valid hex stream");
		PTF_ASSERT_RAISES(pcpp::Asn1IntegerRecord(""), std::invalid_argument, "Value is not a valid hex stream");
	}

	// Enumerated
	{
		pcpp::Asn1EnumeratedRecord record(8192);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Enumerated, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record.getValueLength(), 2);
		PTF_ASSERT_EQUAL(record.getIntValue<uint16_t>(), 8192);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0a022000", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// OctetString with printable value
	{
		pcpp::Asn1OctetStringRecord record("subschemaSubentry");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 19);
		PTF_ASSERT_EQUAL(record.getValueLength(), 17);
		PTF_ASSERT_EQUAL(record.getValue(), "subschemaSubentry");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0411737562736368656d61537562656e747279", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// OctetString with non-printable value
	{
		constexpr size_t valueSize = 8;
		uint8_t value[valueSize] = { 0x30, 0x06, 0x02, 0x02, 0x01, 0xf4, 0x04, 0x00 };
		pcpp::Asn1OctetStringRecord record(value, valueSize);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), valueSize + 2);
		PTF_ASSERT_EQUAL(record.getValueLength(), valueSize);
		PTF_ASSERT_EQUAL(record.getValue(), "3006020201f40400");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("04083006020201f40400", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// UTF8String
	{
		pcpp::Asn1UTF8StringRecord record("日한สअAΩЯש你🌍");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::UTF8String, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 28);
		PTF_ASSERT_EQUAL(record.getValueLength(), 26);
		PTF_ASSERT_EQUAL(record.getValue(), "日한สअAΩЯש你🌍");

		uint8_t data[30];
		auto dataLen = pcpp::hexStringToByteArray("0c1ae697a5ed959ce0b8aae0a48541cea9d0afd7a9e4bda0f09f8c8d", data, 30);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// PrintableString
	{
		pcpp::Asn1PrintableStringRecord record("us");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::PrintableString, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record.getValueLength(), 2);
		PTF_ASSERT_EQUAL(record.getValue(), "us");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("13027573", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// IA5String
	{
		pcpp::Asn1IA5StringRecord record("ABC123@#$");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::IA5String, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 11);
		PTF_ASSERT_EQUAL(record.getValueLength(), 9);
		PTF_ASSERT_EQUAL(record.getValue(), "ABC123@#$");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("1609414243313233402324", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Boolean - true
	{
		pcpp::Asn1BooleanRecord record(true);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record.getValueLength(), 1);
		PTF_ASSERT_TRUE(record.getValue());

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0101ff", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Boolean - false
	{
		pcpp::Asn1BooleanRecord record(false);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("010100", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Null
	{
		pcpp::Asn1NullRecord record;

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Null, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 2);
		PTF_ASSERT_EQUAL(record.getValueLength(), 0);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0500", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// ObjectIdentifier (OID)
	{
		pcpp::Asn1ObjectIdentifier oid("1.2.840.113549.1.1.11");
		pcpp::Asn1ObjectIdentifierRecord record(oid);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("06092a864886f70d01010b", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// UTC time
	{
		std::tm tm{ 45, 30, 15, 24, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm));

		pcpp::Asn1UtcTimeRecord record(timePoint);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::UTCTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 15);
		PTF_ASSERT_EQUAL(record.getValueLength(), 13);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170d3235303532343135333034355a", data, 20);

		record.getValue();
		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// UTC time - without seconds
	{
		std::tm tm{ 45, 30, 15, 24, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm));

		pcpp::Asn1UtcTimeRecord record(timePoint, false);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::UTCTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record.getValueLength(), 11);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("170b323530353234313533305a", data, 20);

		record.getValue();
		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Generalized time - UTC
	{
		std::tm tm{ 0, 30, 14, 31, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm));

		pcpp::Asn1GeneralizedTimeRecord record(timePoint);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 17);
		PTF_ASSERT_EQUAL(record.getValueLength(), 15);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("180f32303235303533313134333030305a", data, 20);

		record.getValue();
		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Generalized time - non-UTC
	{
		std::tm tm{ 0, 30, 14, 31, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm));

		pcpp::Asn1GeneralizedTimeRecord record(timePoint, "-0400");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 21);
		PTF_ASSERT_EQUAL(record.getValueLength(), 19);

		uint8_t data[22];
		auto dataLen = pcpp::hexStringToByteArray("181332303235303533313134333030302D30343030", data, 22);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Generalized time - with milliseconds
	{
		std::tm tm{ 0, 30, 14, 31, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm)) + std::chrono::milliseconds(123);

		pcpp::Asn1GeneralizedTimeRecord record(timePoint, "Z");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 21);
		PTF_ASSERT_EQUAL(record.getValueLength(), 19);

		uint8_t data[22];
		auto dataLen = pcpp::hexStringToByteArray("181332303235303533313134333030302e3132335a", data, 22);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Generalized time - non-UTC + milliseconds
	{
		std::tm tm{ 45, 30, 2, 31, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm)) + std::chrono::milliseconds(123);

		pcpp::Asn1GeneralizedTimeRecord record(timePoint, "+1000");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::GeneralizedTime, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 25);
		PTF_ASSERT_EQUAL(record.getValueLength(), 23);

		uint8_t data[25];
		auto dataLen = pcpp::hexStringToByteArray("181732303235303533313032333034352e3132332b31303030", data, 25);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Generalized time - invalid timezone
	{
		std::tm tm{ 0, 30, 14, 31, 5 - 1, 2025 - 1900, 0 };
		auto timePoint = std::chrono::system_clock::from_time_t(pcpp::mkUtcTime(tm));
		PTF_ASSERT_RAISES(pcpp::Asn1GeneralizedTimeRecord(timePoint, "invalid"), std::invalid_argument,
		                  "Invalid timezone format. Use 'Z' or '+/-HHMM'.");
	}

	// BitString with 0 unused bytes
	{
		pcpp::Asn1BitStringRecord record("1010001110110101");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("030300a3b5", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// BitString with unused bytes
	{
		pcpp::Asn1BitStringRecord record("1011001011");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("030306b2c0", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// BitString invalid value
	{
		PTF_ASSERT_RAISES(pcpp::Asn1BitStringRecord record("0011invalid"), std::invalid_argument, "Invalid bit string");
	}

	// Sequence
	{
		pcpp::Asn1OctetStringRecord octestStringRecord("abcd");
		pcpp::Asn1IntegerRecord integerRecord(1000);
		pcpp::Asn1SequenceRecord record({ &octestStringRecord, &integerRecord });

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_TRUE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Sequence, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record.getValueLength(), 10);

		auto& subRecords = record.getSubRecords();
		PTF_ASSERT_EQUAL(subRecords.size(), 2);
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("300a040461626364020203e8", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Sequence initialized with a PointerVector
	{
		pcpp::PointerVector<pcpp::Asn1Record> subRecords;
		subRecords.pushBack(new pcpp::Asn1OctetStringRecord("abcd"));
		subRecords.pushBack(new pcpp::Asn1IntegerRecord(1000));
		pcpp::Asn1SequenceRecord record(subRecords);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("300a040461626364020203e8", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Set
	{
		pcpp::Asn1OctetStringRecord octestStringRecord("abcd");
		pcpp::Asn1IntegerRecord integerRecord(1000);
		pcpp::Asn1SetRecord record({ &integerRecord, &octestStringRecord });

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_TRUE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Set, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record.getValueLength(), 10);

		auto& subRecords = record.getSubRecords();
		PTF_ASSERT_EQUAL(subRecords.size(), 2);
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1IntegerRecord>()->getIntValue<uint16_t>(), 1000);
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("310a020203e8040461626364", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}

	// Set initialized with a PointerVector
	{
		pcpp::PointerVector<pcpp::Asn1Record> subRecords;
		subRecords.pushBack(new pcpp::Asn1IntegerRecord(1000));
		subRecords.pushBack(new pcpp::Asn1OctetStringRecord("abcd"));
		pcpp::Asn1SetRecord record(subRecords);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("310a020203e8040461626364", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen);
	}
}  // Asn1EncodingTest

PTF_TEST_CASE(Asn1ObjectIdentifierTest)
{
	// Generate from byte array - First byte
	{
		std::vector<std::pair<std::vector<uint8_t>, std::string>> encodedDataAndExpectedStrings = {
			{ { 0x16 }, "0.22" },
			{ { 0x35 }, "1.13" },
			{ { 0x76 }, "2.38" },
		};

		for (auto encodedDataAndExpectedString : encodedDataAndExpectedStrings)
		{
			pcpp::Asn1ObjectIdentifier oid(encodedDataAndExpectedString.first.data(),
			                               encodedDataAndExpectedString.first.size());
			PTF_ASSERT_EQUAL(oid.toString(), encodedDataAndExpectedString.second);
		}
	}

	// Generate from byte array - Small and large value components
	{
		std::vector<std::pair<std::vector<uint8_t>, std::string>> encodedDataAndExpectedStrings = {
			{ { 0x2a, 0x26, 0x7f },                         "1.2.38.127"        },
			{ { 0x2a, 0x95, 0x8c, 0x4e },                   "1.2.345678"        },
			{ { 0x2a, 0x95, 0x8c, 0x4e, 0x01, 0xcd, 0x14 }, "1.2.345678.1.9876" },
		};

		for (auto encodedDataAndExpectedString : encodedDataAndExpectedStrings)
		{
			pcpp::Asn1ObjectIdentifier oid(encodedDataAndExpectedString.first.data(),
			                               encodedDataAndExpectedString.first.size());
			PTF_ASSERT_EQUAL(oid.toString(), encodedDataAndExpectedString.second);
		}
	}

	// Generate from byte array - Invalid values
	{
		PTF_ASSERT_RAISES(pcpp::Asn1ObjectIdentifier(nullptr, 2), std::invalid_argument,
		                  "Malformed OID: Not enough bytes for the first component");
		PTF_ASSERT_RAISES(pcpp::Asn1ObjectIdentifier(std::vector<uint8_t>({ 0x85 }).data(), 0), std::invalid_argument,
		                  "Malformed OID: Not enough bytes for the first component");
		PTF_ASSERT_RAISES(pcpp::Asn1ObjectIdentifier(std::vector<uint8_t>({ 0x2a, 0x95 }).data(), 2),
		                  std::invalid_argument, "Malformed OID: Incomplete component at end of data");
	}

	// Generate from string - Valid values
	{
		std::vector<std::pair<std::string, std::vector<uint32_t>>> inputAndExpectedComponents = {
			{ "0.9.2342.19200300.100.1.1", { 0x0, 0x9, 0x926, 0x124F92C, 0x64, 0x1, 0x1 } },
			{ "1.3.6.1.4.1.12345",         { 0x1, 0x3, 0x6, 0x1, 0x4, 0x1, 0x3039 }       },
			{ "2.5.4.3",                   { 0x2, 0x5, 0x4, 0x3 }                         }
		};

		for (auto inputAndExpectedComponent : inputAndExpectedComponents)
		{
			pcpp::Asn1ObjectIdentifier oid(inputAndExpectedComponent.first);
			PTF_ASSERT_VECTORS_EQUAL(oid.getComponents(), inputAndExpectedComponent.second);
			PTF_ASSERT_EQUAL(oid.toString(), inputAndExpectedComponent.first)
		}
	}

	// Generate from string - Invalid values
	{
		std::vector<std::pair<std::string, std::string>> malformedValuesAndExceptions = {
			{ "invalid",          "Malformed OID: invalid component"                                                    },
			{ "1.invalid",        "Malformed OID: invalid component"                                                    },
			{ "1..1",             "Malformed OID: empty component"                                                      },
			{ "1.2.999999999999", "Malformed OID: component out of uint32_t range"                                      },
			{ "1",                "Malformed OID: an OID must have at least two components"                             },
			{ "3.2",              "Malformed OID: first component must be 0, 1, or 2"                                   },
			{ "0.40",             "Malformed OID: second component must be less than 40 when first component is 0 or 1" },
			{ "1.40",             "Malformed OID: second component must be less than 40 when first component is 0 or 1" }
		};

		for (auto malformedValuesAndException : malformedValuesAndExceptions)
		{
			PTF_ASSERT_RAISES(pcpp::Asn1ObjectIdentifier oid(malformedValuesAndException.first), std::invalid_argument,
			                  malformedValuesAndException.second);
		}
	}

	// Encode
	{
		pcpp::Asn1ObjectIdentifier oid("1.2.840.113549.1.1.11");
		PTF_ASSERT_VECTORS_EQUAL(oid.toBytes(),
		                         std::vector<uint8_t>({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }));
	}

}  // Asn1ObjectIdentifierTest
