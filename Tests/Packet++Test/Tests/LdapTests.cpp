#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "LdapLayer.h"
#include <sstream>
#include <cstring>

PTF_TEST_CASE(LdapParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// LDAP packet
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_add_response.dat");
		pcpp::Packet ldapPacket(&rawPacket1);

		auto ldapLayer = ldapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		PTF_ASSERT_EQUAL(ldapLayer->getMessageID(), 27);
		PTF_ASSERT_EQUAL(ldapLayer->getLdapOperationType(), pcpp::LdapOperationType::AddResponse, enum);
		PTF_ASSERT_EQUAL(ldapLayer->getProtocol(), pcpp::LDAP);
		PTF_ASSERT_EQUAL(ldapLayer->getHeaderLen(), 14);
		PTF_ASSERT_TRUE(ldapLayer->getControls().empty());
		PTF_ASSERT_EQUAL(ldapLayer->toString(), "LDAP Layer, AddResponse");

		pcpp::Asn1IntegerRecord messageIdRecord(27);

		pcpp::Asn1EnumeratedRecord enumeratedRecord(0);
		pcpp::Asn1OctetStringRecord stringRecord1("");
		pcpp::Asn1OctetStringRecord stringRecord2("");
		pcpp::Asn1ConstructedRecord expectedOperationRecord(pcpp::Asn1TagClass::Application, 9, {&enumeratedRecord, &stringRecord1, &stringRecord2});

		pcpp::Asn1SequenceRecord expectedRootRecord({&messageIdRecord, &expectedOperationRecord});

		PTF_ASSERT_EQUAL(ldapLayer->getRootAsn1Record()->toString(), expectedRootRecord.toString());
		PTF_ASSERT_EQUAL(ldapLayer->getLdapOperationAsn1Record()->toString(), expectedOperationRecord.toString());
	}

	// LDAP with multiple controls
	{
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_search_request1.dat", pcpp::LINKTYPE_LINUX_SLL);
		pcpp::Packet ldapWithControlsPacket(&rawPacket1);

		auto ldapLayer = ldapWithControlsPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		auto controls = ldapLayer->getControls();
		std::vector<pcpp::LdapControl> expectedControls = {
				{"1.2.840.113556.1.4.801", "3003020107"},
				{"1.2.840.113556.1.4.319", "3006020201f40400"}
		};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// LDAP with partial controls
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet ldapWithControlsPacket(&rawPacket1);

		auto ldapLayer = ldapWithControlsPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		auto controls = ldapLayer->getControls();
		std::vector<pcpp::LdapControl> expectedControls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// LdapLayer tryGet
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		buffer1[68] = 0x04;
		pcpp::Packet malformedLdapPacket(&rawPacket1);

		auto malformedLdapLayer = malformedLdapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(malformedLdapLayer);

		uint16_t messageId;
		PTF_ASSERT_FALSE(malformedLdapLayer->tryGet(&pcpp::LdapLayer::getMessageID, messageId));

		std::vector<pcpp::LdapControl> controls;
		PTF_ASSERT_TRUE(malformedLdapLayer->tryGet(&pcpp::LdapLayer::getControls, controls));
		std::vector<pcpp::LdapControl> expectedControls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};
		PTF_ASSERT_VECTORS_EQUAL(controls, expectedControls);
	}

	// Multiple LDAP messages in the same packet
	{
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_multiple_messages.dat", pcpp::LINKTYPE_LINUX_SLL);
		pcpp::Packet multipleLdapPacket(&rawPacket1);

		auto ldapLayer = multipleLdapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(ldapLayer);

		for (int i = 0; i < 3; i++)
		{
			PTF_ASSERT_EQUAL(ldapLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultReference, enum);
			ldapLayer = dynamic_cast<pcpp::LdapLayer*>(ldapLayer->getNextLayer());
			PTF_ASSERT_NOT_NULL(ldapLayer);
		}

		PTF_ASSERT_EQUAL(ldapLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultDone, enum);
		PTF_ASSERT_NULL(ldapLayer->getNextLayer());
	}
} // LdapParsingTest


PTF_TEST_CASE(LdapCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// LDAP packet with multiple controls
	{
		READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/ldap_search_request1.dat", pcpp::LINKTYPE_LINUX_SLL);
		pcpp::Packet ldapPacket(&rawPacket1);

		pcpp::Asn1OctetStringRecord stringRecord("DC=matrix,DC=local");
		pcpp::Asn1EnumeratedRecord enumeratedRecord1(2);
		pcpp::Asn1EnumeratedRecord enumeratedRecord2(3);
		pcpp::Asn1IntegerRecord integerRecord1(0);
		pcpp::Asn1IntegerRecord integerRecord2(0);
		pcpp::Asn1BooleanRecord booleanRecord(false);

		pcpp::Asn1GenericRecord subRecord1(pcpp::Asn1TagClass::ContextSpecific, false, 1, "2.16.840.1.113730.3.3.2.46.1");
		pcpp::Asn1GenericRecord subRecord2(pcpp::Asn1TagClass::ContextSpecific, false, 2, "departmentNumber");
		pcpp::Asn1GenericRecord subRecord3(pcpp::Asn1TagClass::ContextSpecific, false, 3, ">=N4709");
		pcpp::Asn1ConstructedRecord constructedRecord1(pcpp::Asn1TagClass::ContextSpecific, 9, {&subRecord1, &subRecord2, &subRecord3});

		pcpp::Asn1OctetStringRecord stringSubRecord1("*");
		pcpp::Asn1OctetStringRecord stringSubRecord2("ntsecuritydescriptor");
		pcpp::Asn1SequenceRecord sequenceRecord({&stringSubRecord1, &stringSubRecord2});

		std::vector<pcpp::LdapControl> controls = {
			{"1.2.840.113556.1.4.801", "3003020107"},
			{"1.2.840.113556.1.4.319", "3006020201f40400"}
		};

		pcpp::LdapLayer ldapLayer(6, pcpp::LdapOperationType::SearchRequest,
			{&stringRecord, &enumeratedRecord1, &enumeratedRecord2, &integerRecord1, &integerRecord2, &booleanRecord, &constructedRecord1, &sequenceRecord},
			controls);

		auto expectedLdapLayer = ldapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(expectedLdapLayer);

		PTF_ASSERT_BUF_COMPARE(ldapLayer.getData(), expectedLdapLayer->getData(), expectedLdapLayer->getDataLen());
	}

	// LDAP packet with partial controls
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_bind_request1.dat");
		pcpp::Packet ldapPacket(&rawPacket1);

		pcpp::Asn1IntegerRecord integerRecord(3);
		pcpp::Asn1OctetStringRecord stringRecord("cn=Administrator,cn=Users,dc=cloudshark-a,dc=example,dc=com");
		uint8_t contextSpecificData[14] = {0x63, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x68, 0x61, 0x72, 0x6b, 0x31, 0x32, 0x33, 0x21};
		pcpp::Asn1GenericRecord contextSpecificRecord(pcpp::Asn1TagClass::ContextSpecific, false, 0, contextSpecificData, 14);
		std::vector<pcpp::LdapControl> controls = {{"1.3.6.1.4.1.42.2.27.8.5.1"}};

		pcpp::LdapLayer ldapLayer(2, pcpp::LdapOperationType::BindRequest, {&integerRecord, &stringRecord, &contextSpecificRecord}, controls);

		auto expectedLdapLayer = ldapPacket.getLayerOfType<pcpp::LdapLayer>();
		PTF_ASSERT_NOT_NULL(expectedLdapLayer);

		PTF_ASSERT_BUF_COMPARE(ldapLayer.getData(), expectedLdapLayer->getData(), expectedLdapLayer->getDataLen());
	}
} // LdapCreationTest
