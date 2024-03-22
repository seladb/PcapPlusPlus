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
		auto recordValue = std::string(record->getRawValue(), record->getRawValue() + record->getValueLength());
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
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Integer, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 7);
		PTF_ASSERT_EQUAL(record->getValueLength(), 5);
		PTF_ASSERT_RAISES(record->castAs<pcpp::Asn1IntegerRecord>()->getValue(), std::runtime_error, "An integer ASN.1 record of more than 4 bytes is not supported");
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
		auto dataLen = pcpp::hexStringToByteArray("0500", data, 20);
		auto record = pcpp::Asn1BerRecord::decode(data, dataLen);

		PTF_ASSERT_EQUAL(record->getTagClass(), pcpp::BerTagClass::Universal, enumclass);
		PTF_ASSERT_EQUAL(record->getBerTagType(), pcpp::BerTagType::Primitive, enumclass);
		PTF_ASSERT_EQUAL(record->getAsn1UniversalTagType(), pcpp::Asn1UniversalTagType::Null, enumclass);
		PTF_ASSERT_EQUAL(record->getTotalLength(), 2);
		PTF_ASSERT_EQUAL(record->getValueLength(), 0);
		PTF_ASSERT_NOT_NULL(record->castAs<pcpp::Asn1NullRecord>());
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
