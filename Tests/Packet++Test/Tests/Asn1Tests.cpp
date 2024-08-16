#include "../TestDefinition.h"
#include "Asn1Codec.h"
#include "RawPacket.h"
#include "GeneralUtils.h"
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
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 6);
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
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
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
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 100000);
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
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 10000000);
		PTF_ASSERT_EQUAL(record->toString(), "Integer, Length: 2+4, Value: 10000000");
	}

	// Integer more than 4 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020502540be400", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1Record::decode(data, dataLen, false), std::runtime_error,
		                  "An integer ASN.1 record of more than 4 bytes is not supported");
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
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1EnumeratedRecord>()->getValue(), 8192);
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
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);

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
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
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
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);

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
		PTF_ASSERT_EQUAL(record.getValue(), 6);

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
		PTF_ASSERT_EQUAL(record.getValue(), 1000);

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
		PTF_ASSERT_EQUAL(record.getValue(), 100000);

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
		PTF_ASSERT_EQUAL(record.getValue(), 100000000);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020405f5e100", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Enumerated
	{
		pcpp::Asn1EnumeratedRecord record(8192);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::Asn1TagClass::Universal, enumclass);
		PTF_ASSERT_FALSE(record.isConstructed());
		PTF_ASSERT_EQUAL(record.getUniversalTagType(), pcpp::Asn1UniversalTagType::Enumerated, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record.getValueLength(), 2);
		PTF_ASSERT_EQUAL(record.getValue(), 8192);

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
		PTF_ASSERT_EQUAL(subRecords.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);

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
		PTF_ASSERT_EQUAL(subRecords.at(0)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
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
