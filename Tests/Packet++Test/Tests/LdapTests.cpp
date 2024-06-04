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

	// SearchRequest
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request2.dat");
		pcpp::Packet searchRequestPacket(&rawPacket1);

		auto searchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(searchRequestLayer);
		PTF_ASSERT_EQUAL(searchRequestLayer->getMessageID(), 9);
		PTF_ASSERT_EQUAL(searchRequestLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchRequest, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getBaseObject(), "cn=schema");
		PTF_ASSERT_EQUAL(searchRequestLayer->getScope(), pcpp::LdapSearchRequestLayer::SearchRequestScope::BaseObject, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getDerefAlias(), pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways, enum);
		PTF_ASSERT_EQUAL(searchRequestLayer->getSizeLimit(), 0);
		PTF_ASSERT_EQUAL(searchRequestLayer->getTimeLimit(), 0);
		PTF_ASSERT_FALSE(searchRequestLayer->getTypesOnly());
		std::ostringstream expectedFilter;
		expectedFilter
			<< "ContextSpecific (3) (constructed), Length: 2+24" << std::endl
			<< "  OctetString, Length: 2+11, Value: objectClass" << std::endl
			<< "  OctetString, Length: 2+9, Value: subschema";
		PTF_ASSERT_EQUAL(searchRequestLayer->getFilter()->toString(), expectedFilter.str());
		PTF_ASSERT_EQUAL(searchRequestLayer->toString(), "LDAP Layer, SearchRequest, \"cn=schema\", BaseObject");
		auto attributes = searchRequestLayer->getAttributes();
		std::vector<std::string> expectedAttributes = {
			"objectClasses",
			"attributeTypes",
			"ldapSyntaxes",
			"matchingRules",
			"matchingRuleUse",
			"dITContentRules",
			"dITStructureRules",
			"nameForms",
			"createTimestamp",
			"modifyTimestamp",
			"*",
			"+"
		};
		PTF_ASSERT_VECTORS_EQUAL(attributes, expectedAttributes);
	}

	// SearchResultEntry
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_result_entry.dat");
		pcpp::Packet searchResEntryPacket(&rawPacket1);

		auto searchResultEntryLayer = searchResEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
		PTF_ASSERT_NOT_NULL(searchResultEntryLayer);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getMessageID(), 16);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultEntry, enum);
		PTF_ASSERT_EQUAL(searchResultEntryLayer->getObjectName(), "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org");
		std::vector<pcpp::LdapAttribute> expectedAttributes = {
			{"objectclass", {"inetOrgPerson", "organizationalPerson", "person", "top"}},
			{"sn",          {"Young"}},
			{"cn",          {"b.smith"}},
			{"givenname",   {"Beatrix"}}
		};
		PTF_ASSERT_VECTORS_EQUAL(searchResultEntryLayer->getAttributes(), expectedAttributes);
	}

	// LdapSearchResultDoneLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_result_done.dat");
		pcpp::Packet searchResultDonePacket(&rawPacket1);

		auto searchResultDoneLayer = searchResultDonePacket.getLayerOfType<pcpp::LdapSearchResultDoneLayer>();
		PTF_ASSERT_NOT_NULL(searchResultDoneLayer);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getMessageID(), 8);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getLdapOperationType(), pcpp::LdapOperationType::SearchResultDone, enum);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getResultCode(), pcpp::LdapResultCode::Success, enum);
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(searchResultDoneLayer->getDiagnosticMessage(), "");
		PTF_ASSERT_VECTORS_EQUAL(searchResultDoneLayer->getReferral(), std::vector<std::string>());
	}

	// LdapModifyResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_response.dat");
		pcpp::Packet modifyResponsePacket(&rawPacket1);

		auto modifyResponseLayer = modifyResponsePacket.getLayerOfType<pcpp::LdapModifyResponseLayer>();
		PTF_ASSERT_NOT_NULL(modifyResponseLayer);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getMessageID(), 14);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getLdapOperationType(), pcpp::LdapOperationType::ModifyResponse, enum);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getResultCode(), pcpp::LdapResultCode::NoSuchObject, enum);
		PTF_ASSERT_EQUAL(modifyResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(modifyResponseLayer->getDiagnosticMessage(), "");
		PTF_ASSERT_VECTORS_EQUAL(modifyResponseLayer->getReferral(), std::vector<std::string>());
	}

	// LdapAddResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_add_response.dat");
		pcpp::Packet addResponsePacket(&rawPacket1);

		auto addResponseLayer = addResponsePacket.getLayerOfType<pcpp::LdapAddResponseLayer>();
		PTF_ASSERT_NOT_NULL(addResponseLayer);
		PTF_ASSERT_EQUAL(addResponseLayer->getMessageID(), 27);
		PTF_ASSERT_EQUAL(addResponseLayer->getLdapOperationType(), pcpp::LdapOperationType::AddResponse, enum);
		PTF_ASSERT_EQUAL(addResponseLayer->getResultCode(), pcpp::LdapResultCode::Success, enum);
		PTF_ASSERT_EQUAL(addResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(addResponseLayer->getDiagnosticMessage(), "");
		PTF_ASSERT_VECTORS_EQUAL(addResponseLayer->getReferral(), std::vector<std::string>());
	}

	// LdapDeleteResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_delete_response.dat");
		pcpp::Packet deleteResponsePacket(&rawPacket1);

		auto deleteResponseLayer = deleteResponsePacket.getLayerOfType<pcpp::LdapDeleteResponseLayer>();
		PTF_ASSERT_NOT_NULL(deleteResponseLayer);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getMessageID(), 27);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getLdapOperationType(), pcpp::LdapOperationType::DelResponse, enum);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getResultCode(), pcpp::LdapResultCode::NoSuchObject, enum);
		PTF_ASSERT_EQUAL(deleteResponseLayer->getMatchedDN(), "ou=People,dc=example,dc=com");
		PTF_ASSERT_EQUAL(deleteResponseLayer->getDiagnosticMessage(), "LDAP: error code 32 - No such object");

		std::vector<std::string> expectedReferral = {
			"ldap://ldap.example.com/dc=example,dc=com",
			"ldap://ldap.example.com/dc=example,dc=com?objectClass?one"
		};
		PTF_ASSERT_VECTORS_EQUAL(deleteResponseLayer->getReferral(), expectedReferral);
	}

	// LdapModifyDNResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_dn_response.dat");
		pcpp::Packet modifyDNResponsePacket(&rawPacket1);

		auto modifyDNResponseLayer = modifyDNResponsePacket.getLayerOfType<pcpp::LdapModifyDNResponseLayer>();
		PTF_ASSERT_NOT_NULL(modifyDNResponseLayer);
		PTF_ASSERT_EQUAL(modifyDNResponseLayer->getMessageID(), 15);
		PTF_ASSERT_EQUAL(modifyDNResponseLayer->getLdapOperationType(), pcpp::LdapOperationType::ModifyDNResponse, enum);
		PTF_ASSERT_EQUAL(modifyDNResponseLayer->getResultCode(), pcpp::LdapResultCode::NoSuchObject, enum);
		PTF_ASSERT_EQUAL(modifyDNResponseLayer->getMatchedDN(), "ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org");
		PTF_ASSERT_EQUAL(modifyDNResponseLayer->getDiagnosticMessage(), "");
		PTF_ASSERT_VECTORS_EQUAL(modifyDNResponseLayer->getReferral(), std::vector<std::string>());
	}

	// LdapCompareResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_compare_response.dat");
		pcpp::Packet compareResponsePacket(&rawPacket1);

		auto compareResponseLayer = compareResponsePacket.getLayerOfType<pcpp::LdapCompareResponseLayer>();
		PTF_ASSERT_NOT_NULL(compareResponseLayer);
		PTF_ASSERT_EQUAL(compareResponseLayer->getMessageID(), 28);
		PTF_ASSERT_EQUAL(compareResponseLayer->getLdapOperationType(), pcpp::LdapOperationType::CompareResponse, enum);
		PTF_ASSERT_EQUAL(compareResponseLayer->getResultCode(), pcpp::LdapResultCode::CompareFalse, enum);
		PTF_ASSERT_EQUAL(compareResponseLayer->getMatchedDN(), "");
		PTF_ASSERT_EQUAL(compareResponseLayer->getDiagnosticMessage(), "");
		PTF_ASSERT_VECTORS_EQUAL(compareResponseLayer->getReferral(), std::vector<std::string>());
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

	// SearchRequest
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_request2.dat");
		pcpp::Packet searchRequestPacket(&rawPacket1);

		pcpp::Asn1OctetStringRecord filterSubRecord1("objectClass");
		pcpp::Asn1OctetStringRecord filterSubRecord2("subschema");
		pcpp::Asn1ConstructedRecord filterRecord(pcpp::Asn1TagClass::ContextSpecific, 3, {&filterSubRecord1, &filterSubRecord2});

		std::vector<std::string> attributes = {
			"objectClasses",
			"attributeTypes",
			"ldapSyntaxes",
			"matchingRules",
			"matchingRuleUse",
			"dITContentRules",
			"dITStructureRules",
			"nameForms",
			"createTimestamp",
			"modifyTimestamp",
			"*",
			"+"
		};

		pcpp::LdapSearchRequestLayer searchRequestLayer(
			9, "cn=schema", pcpp::LdapSearchRequestLayer::SearchRequestScope::BaseObject,
			pcpp::LdapSearchRequestLayer::DerefAliases::DerefAlways,
			0, 0, false, &filterRecord, attributes);

		auto expectedSearchRequestLayer = searchRequestPacket.getLayerOfType<pcpp::LdapSearchRequestLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchRequestLayer);

		PTF_ASSERT_BUF_COMPARE(searchRequestLayer.getData(), expectedSearchRequestLayer->getData(),
			expectedSearchRequestLayer->getDataLen());
	}

	// SearchResultEntry
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_result_entry.dat");
		pcpp::Packet searchResultEntryPacket(&rawPacket1);

		std::vector<pcpp::LdapAttribute> attributes = {
			{"objectclass", {"inetOrgPerson", "organizationalPerson", "person", "top"}},
			{"sn",          {"Young"}},
			{"cn",          {"b.smith"}},
			{"givenname",   {"Beatrix"}}
		};

		pcpp::LdapSearchResultEntryLayer searchResultEntryLayer(16, "cn=b.smith,ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org", attributes);

		auto expectedSearchResultEntryLayer = searchResultEntryPacket.getLayerOfType<pcpp::LdapSearchResultEntryLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchResultEntryLayer);

		PTF_ASSERT_BUF_COMPARE(searchResultEntryLayer.getData(), expectedSearchResultEntryLayer->getData(),
			expectedSearchResultEntryLayer->getDataLen());
	}

	// LdapSearchResultDoneLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_search_result_done.dat");
		pcpp::Packet searchResultDonePacket(&rawPacket1);

		pcpp::LdapSearchResultDoneLayer searchResultDoneLayer(8, pcpp::LdapResultCode::Success, "", "");

		auto expectedSearchResultDoneLayer = searchResultDonePacket.getLayerOfType<pcpp::LdapSearchResultDoneLayer>();
		PTF_ASSERT_NOT_NULL(expectedSearchResultDoneLayer);

		PTF_ASSERT_BUF_COMPARE(searchResultDoneLayer.getData(), expectedSearchResultDoneLayer->getData(),
			expectedSearchResultDoneLayer->getDataLen());
	}

	// LdapModifyResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_response.dat");
		pcpp::Packet modifyResponsePacket(&rawPacket1);

		pcpp::LdapModifyResponseLayer modifyResponseLayer(14, pcpp::LdapResultCode::NoSuchObject, "", "");

		auto expectedModifyResponseLayer = modifyResponsePacket.getLayerOfType<pcpp::LdapModifyResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedModifyResponseLayer);

		PTF_ASSERT_BUF_COMPARE(modifyResponseLayer.getData(), expectedModifyResponseLayer->getData(),
			expectedModifyResponseLayer->getDataLen());
	}

	// LdapAddResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_add_response.dat");
		pcpp::Packet addResponsePacket(&rawPacket1);

		pcpp::LdapAddResponseLayer addResponseLayer(27, pcpp::LdapResultCode::Success, "", "");

		auto expectedAddResponseLayer = addResponsePacket.getLayerOfType<pcpp::LdapAddResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedAddResponseLayer);

		PTF_ASSERT_BUF_COMPARE(addResponseLayer.getData(), expectedAddResponseLayer->getData(),
			expectedAddResponseLayer->getDataLen());
	}

	// LdapDeleteResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_delete_response.dat");
		pcpp::Packet deleteResponsePacket(&rawPacket1);

		std::vector<std::string> referral = {
			"ldap://ldap.example.com/dc=example,dc=com",
			"ldap://ldap.example.com/dc=example,dc=com?objectClass?one"
		};

		pcpp::LdapDeleteResponseLayer deleteResponseLayer(27, pcpp::LdapResultCode::NoSuchObject, "ou=People,dc=example,dc=com",
			"LDAP: error code 32 - No such object", referral);

		auto expectedDeleteResponseLayer = deleteResponsePacket.getLayerOfType<pcpp::LdapDeleteResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedDeleteResponseLayer);

		PTF_ASSERT_BUF_COMPARE(deleteResponseLayer.getData(), expectedDeleteResponseLayer->getData(),
			expectedDeleteResponseLayer->getDataLen());
	}

	// LdapModifyDNResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_modify_dn_response.dat");
		pcpp::Packet modifyDNResponsePacket(&rawPacket1);

		pcpp::LdapModifyDNResponseLayer modifyDNResponseLayer(15, pcpp::LdapResultCode::NoSuchObject, "ou=ldap3-tutorial,dc=demo1,dc=freeipa,dc=org", "");

		auto expectedModifyDNResponseLayer = modifyDNResponsePacket.getLayerOfType<pcpp::LdapModifyDNResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedModifyDNResponseLayer);

		PTF_ASSERT_BUF_COMPARE(modifyDNResponseLayer.getData(), expectedModifyDNResponseLayer->getData(),
			expectedModifyDNResponseLayer->getDataLen());
	}

	// LdapCompareResponseLayer
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ldap_compare_response.dat");
		pcpp::Packet compareResponsePacket(&rawPacket1);

		pcpp::LdapCompareResponseLayer compareResponseLayer(28, pcpp::LdapResultCode::CompareFalse, "", "");

		auto expectedCompareResponseLayer = compareResponsePacket.getLayerOfType<pcpp::LdapCompareResponseLayer>();
		PTF_ASSERT_NOT_NULL(expectedCompareResponseLayer);

		PTF_ASSERT_BUF_COMPARE(compareResponseLayer.getData(), expectedCompareResponseLayer->getData(),
			expectedCompareResponseLayer->getDataLen());
	}
} // LdapCreationTest
