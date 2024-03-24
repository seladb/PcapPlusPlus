#include "../TestDefinition.h"
#include "Asn1BerDecoder.h"
#include "RawPacket.h"
#include "GeneralUtils.h"
#include <functional>

PTF_TEST_CASE(Asn1BerDecodingTest)
{
	// Context specific
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("870b6f626a656374636c617373", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::ContextSpecific, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 13);
		PTF_ASSERT_EQUAL(record->getValueLength(), 11);
		auto genericRecord = record->castAs<pcpp::Asn1GenericRecord>();
		auto recordValue = std::string(genericRecord->getValue(), genericRecord->getValue() + genericRecord->getValueLength());
		PTF_ASSERT_EQUAL(recordValue, "objectclass");
	}

	// Integer 1 byte
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020106", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 6);
	}

	// Integer 2 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020203e8", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record->getValueLength(), 2);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
	}

	// Integer 3 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("02030186a0", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 5);
		PTF_ASSERT_EQUAL(record->getValueLength(), 3);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 100000);
	}

	// Integer 4 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020400989680", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 6);
		PTF_ASSERT_EQUAL(record->getValueLength(), 4);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 10000000);
	}

	// Integer more than 4 bytes
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("020502540be400", data, 20);
		PTF_ASSERT_RAISES(pcpp::Asn1BerRecord::decode(data, dataLen), std::runtime_error, "An integer ASN.1 record of more than 4 bytes is not supported");
	}

	// Enumerated
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0a022000", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Enumerated, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record->getValueLength(), 2);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1EnumeratedRecord>()->getValue(), 8192);
	}

	// Boolean - true
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0101ff", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_TRUE(record->castAs<pcpp::Asn1BooleanRecord>()->getValue());
	}

	// Boolean - false
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("010100", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 3);
		PTF_ASSERT_EQUAL(record->getValueLength(), 1);
		PTF_ASSERT_FALSE(record->castAs<pcpp::Asn1BooleanRecord>()->getValue());
	}

	// OctetString
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0411737562736368656d61537562656e747279", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 19);
		PTF_ASSERT_EQUAL(record->getValueLength(), 17);
		PTF_ASSERT_EQUAL(record->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "subschemaSubentry");
	}

	// Null
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0500", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Null, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 2);
		PTF_ASSERT_EQUAL(record->getValueLength(), 0);
		PTF_ASSERT_NOT_NULL(record->castAs<pcpp::Asn1NullRecord>());
	}

	// Sequence
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("300a040461626364020203e8", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Constructed, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Sequence, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& children = record->castAs<pcpp::Asn1SequenceRecord>()->getChildren();
		PTF_ASSERT_EQUAL(children.size(), 2);
		PTF_ASSERT_EQUAL(children.at(0)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
		PTF_ASSERT_EQUAL(children.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
	}

	// Set
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("310a020203e8040461626364", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Constructed, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Set, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& children = record->castAs<pcpp::Asn1SetRecord>()->getChildren();
		PTF_ASSERT_EQUAL(children.size(), 2);
		PTF_ASSERT_EQUAL(children.at(0)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
		PTF_ASSERT_EQUAL(children.at(1)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
	}

	// Application constructed
	{
		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("630a040461626364020203e8", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Application, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Constructed, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 12);
		PTF_ASSERT_EQUAL(record->getValueLength(), 10);

		auto& children = record->castAs<pcpp::Asn1BerConstructedRecord>()->getChildren();
		PTF_ASSERT_EQUAL(children.size(), 2);
		PTF_ASSERT_EQUAL(children.at(0)->castAs<pcpp::Asn1OctetStringRecord>()->getValue(), "abcd");
		PTF_ASSERT_EQUAL(children.at(1)->castAs<pcpp::Asn1IntegerRecord>()->getValue(), 1000);
	}
}; // Asn1BerDecodingTest


PTF_TEST_CASE(Asn1BerEncodingTest)
{
	// Generic record
	{
		uint8_t value[] = {0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73};
		pcpp::Asn1GenericRecord record(pcpp::BerTagClass::ContextSpecific, pcpp::BerTagType::Primitive, 7, value, 11);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::ContextSpecific, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::NotApplicable, enumclass);
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

	// Integer 1 byte
	{
		pcpp::Asn1IntegerRecord record(6);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
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

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
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

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
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

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
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

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Enumerated, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 4);
		PTF_ASSERT_EQUAL(record.getValueLength(), 2);
		PTF_ASSERT_EQUAL(record.getValue(), 8192);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0a022000", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// OctetString
	{
		pcpp::Asn1OctetStringRecord record("subschemaSubentry");

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::OctetString, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 19);
		PTF_ASSERT_EQUAL(record.getValueLength(), 17);
		PTF_ASSERT_EQUAL(record.getValue(), "subschemaSubentry");

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0411737562736368656d61537562656e747279", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}

	// Boolean - true
	{
		pcpp::Asn1BooleanRecord record(true);

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Boolean, enumclass);
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

		PTF_ASSERT_EQUAL(record.getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record.getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record.getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Null, enumclass);
		PTF_ASSERT_EQUAL(record.getTotalLength(), 2);
		PTF_ASSERT_EQUAL(record.getValueLength(), 0);

		uint8_t data[20];
		auto dataLen = pcpp::hexStringToByteArray("0500", data, 20);

		auto encodedValue = record.encode();
		PTF_ASSERT_EQUAL(encodedValue.size(), dataLen);
		PTF_ASSERT_BUF_COMPARE(encodedValue.data(), data, dataLen)
	}
}