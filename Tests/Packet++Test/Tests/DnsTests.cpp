#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include <limits>
#include <sstream>
#include <vector>
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketAndBufferFromHexResource;
using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(DnsLayerParsingTest)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/Dns3.dat");

	pcpp::Packet dnsPacket(rawPacket1.get());

	pcpp::DnsLayer* dnsLayer = dnsPacket.getLayerOfType<pcpp::DnsLayer>();

	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 2);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswerCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAuthorityCount(), 2);
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecordCount(), 1);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->queryOrResponse, 0);

	pcpp::DnsQuery* firstQuery = dnsLayer->getFirstQuery();
	PTF_ASSERT_NOT_NULL(firstQuery);
	PTF_ASSERT_EQUAL(firstQuery->getName(), "Yaels-iPhone.local");
	PTF_ASSERT_EQUAL(firstQuery->getDnsType(), pcpp::DNS_TYPE_ALL, enum);
	PTF_ASSERT_EQUAL(firstQuery->getDnsClass(), pcpp::DNS_CLASS_IN, enum);

	pcpp::DnsQuery* secondQuery = dnsLayer->getNextQuery(firstQuery);
	PTF_ASSERT_NOT_NULL(secondQuery);
	PTF_ASSERT_EQUAL(secondQuery->getName(), "Yaels-iPhone.local");
	PTF_ASSERT_EQUAL(secondQuery->getDnsType(), pcpp::DNS_TYPE_ALL, enum);
	PTF_ASSERT_EQUAL(secondQuery->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_NULL(dnsLayer->getNextQuery(secondQuery));

	pcpp::DnsQuery* queryByName = dnsLayer->getQuery(std::string("Yaels-iPhone.local"), true);
	PTF_ASSERT_NOT_NULL(queryByName);
	PTF_ASSERT_EQUAL(queryByName, firstQuery, ptr);
	PTF_ASSERT_NULL(dnsLayer->getQuery(std::string("www.seladb.com"), true));

	pcpp::DnsResource* firstAuthority = dnsLayer->getFirstAuthority();
	PTF_ASSERT_NOT_NULL(firstAuthority);
	PTF_ASSERT_EQUAL(firstAuthority->getDnsType(), pcpp::DNS_TYPE_A, enum);
	PTF_ASSERT_EQUAL(firstAuthority->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(firstAuthority->getTTL(), 120);
	PTF_ASSERT_EQUAL(firstAuthority->getName(), "Yaels-iPhone.local");
	PTF_ASSERT_EQUAL(firstAuthority->getDataLength(), 4);
	PTF_ASSERT_EQUAL(firstAuthority->getData()->toString(), "10.0.0.2");
	PTF_ASSERT_EQUAL(firstAuthority->getData().castAs<pcpp::IPv4DnsResourceData>()->getIpAddress(),
	                 pcpp::IPv4Address("10.0.0.2"));
	PTF_ASSERT_EQUAL(firstAuthority->getSize(), 16);

	pcpp::DnsResource* secondAuthority = dnsLayer->getNextAuthority(firstAuthority);
	PTF_ASSERT_NOT_NULL(secondAuthority);
	PTF_ASSERT_EQUAL(secondAuthority->getDnsType(), pcpp::DNS_TYPE_AAAA, enum);
	PTF_ASSERT_EQUAL(secondAuthority->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(secondAuthority->getTTL(), 120);
	PTF_ASSERT_EQUAL(secondAuthority->getName(), "Yaels-iPhone.local");
	PTF_ASSERT_EQUAL(secondAuthority->getDataLength(), 16);
	PTF_ASSERT_EQUAL(secondAuthority->getData()->toString(), "fe80::5a1f:aaff:fe4f:3f9d");
	PTF_ASSERT_EQUAL(secondAuthority->getData().castAs<pcpp::IPv6DnsResourceData>()->getIpAddress(),
	                 pcpp::IPv6Address("fe80::5a1f:aaff:fe4f:3f9d"));
	PTF_ASSERT_EQUAL(secondAuthority->getSize(), 28);

	pcpp::DnsResource* thirdAuthority = dnsLayer->getNextAuthority(secondAuthority);
	PTF_ASSERT_NULL(thirdAuthority);

	PTF_ASSERT_EQUAL(dnsLayer->getAuthority("Yaels-iPhon", false), firstAuthority, ptr);
	PTF_ASSERT_NULL(dnsLayer->getAuthority("www.google.com", false));

	pcpp::DnsResource* additionalRecord = dnsLayer->getFirstAdditionalRecord();
	PTF_ASSERT_NOT_NULL(additionalRecord);
	PTF_ASSERT_EQUAL(additionalRecord->getDnsType(), pcpp::DNS_TYPE_OPT, enum);
	PTF_ASSERT_EQUAL(additionalRecord->getDnsClass(), 0x05a0);
	PTF_ASSERT_EQUAL(additionalRecord->getTTL(), 0x1194);
	PTF_ASSERT_EQUAL(additionalRecord->getName(), "");
	PTF_ASSERT_EQUAL(additionalRecord->getDataLength(), 12);
	PTF_ASSERT_EQUAL(additionalRecord->getData()->toString(), "0004000800df581faa4f3f9d");
	PTF_ASSERT_EQUAL(additionalRecord->getSize(), 23);
	PTF_ASSERT_NULL(dnsLayer->getNextAdditionalRecord(additionalRecord));
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecord("", true), additionalRecord, ptr);

	PTF_ASSERT_EQUAL(dnsLayer->toString(),
	                 "DNS query, ID: 0; queries: 2, answers: 0, authorities: 2, additional record: 1");

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(), R"({"protocolName":"DNS","protocolId":13,"length":109,"transactionID":"0x0","isResponse":false,)"
		               R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":false,)"
		               R"("recursionAvailable":false,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		               R"("queries":[{"name":"Yaels-iPhone.local","type":255,"typeName":"ANY","class":1},)"
		               R"({"name":"Yaels-iPhone.local","type":255,"typeName":"ANY","class":1}],"answers":[],)"
		               R"("authorities":[{"name":"Yaels-iPhone.local","type":1,"typeName":"A","class":1,"ttl":120,)"
		               R"("dataLength":4,"data":"10.0.0.2"},{"name":"Yaels-iPhone.local","type":28,"typeName":"AAAA",)"
		               R"("class":1,"ttl":120,"dataLength":16,"data":"fe80::5a1f:aaff:fe4f:3f9d"}],)"
		               R"("additionalRecords":[{"name":"","type":41,"typeName":"OPT","class":1440,"ttl":4500,)"
		               R"("dataLength":12}]})");
	}

	auto rawPacket2 = createPacketFromHexResource("PacketExamples/Dns1.dat");

	pcpp::Packet dnsPacket2(rawPacket2.get());

	dnsLayer = dnsPacket2.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0x2d6d);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->queryOrResponse, 1);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->recursionAvailable, 1);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->recursionDesired, 1);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->opcode, 0);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->authoritativeAnswer, 0);
	PTF_ASSERT_EQUAL(dnsLayer->getDnsHeader()->checkingDisabled, 0);
	firstQuery = dnsLayer->getFirstQuery();
	PTF_ASSERT_NOT_NULL(firstQuery);
	PTF_ASSERT_EQUAL(firstQuery->getName(), "www.google-analytics.com");
	PTF_ASSERT_EQUAL(firstQuery->getDnsType(), pcpp::DNS_TYPE_A, enum);

	pcpp::DnsResource* curAnswer = dnsLayer->getFirstAnswer();
	PTF_ASSERT_NOT_NULL(curAnswer);
	PTF_ASSERT_EQUAL(curAnswer->getDnsType(), pcpp::DNS_TYPE_CNAME, enum);
	PTF_ASSERT_EQUAL(curAnswer->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(curAnswer->getTTL(), 57008);
	PTF_ASSERT_EQUAL(curAnswer->getName(), "www.google-analytics.com");
	PTF_ASSERT_EQUAL(curAnswer->getDataLength(), 32);
	PTF_ASSERT_EQUAL(curAnswer->getData()->toString(), "www-google-analytics.l.google.com");
	PTF_ASSERT_EQUAL(curAnswer->getSize(), 44);

	curAnswer = dnsLayer->getNextAnswer(curAnswer);
	int answerCount = 2;
	while (curAnswer != nullptr)
	{
		PTF_ASSERT_EQUAL(curAnswer->getDnsType(), pcpp::DNS_TYPE_A, enum);
		PTF_ASSERT_EQUAL(curAnswer->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
		PTF_ASSERT_EQUAL(curAnswer->getTTL(), 117);
		PTF_ASSERT_EQUAL(curAnswer->getName(), "www-google-analytics.L.google.com");
		PTF_ASSERT_EQUAL(curAnswer->getDataLength(), 4);
		PTF_ASSERT_TRUE(curAnswer->getData().castAs<pcpp::IPv4DnsResourceData>()->getIpAddress().matchNetwork(
		    std::string("212.199.219.0/255.255.255.0")));

		curAnswer = dnsLayer->getNextAnswer(curAnswer);
		answerCount++;
	}

	PTF_ASSERT_EQUAL(answerCount, 18);

	PTF_ASSERT_EQUAL(dnsLayer->getAnswer("www.google-analytics.com", false), dnsLayer->getFirstAnswer(), ptr);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswer("www-google-analytics.L.google.com", true),
	                 dnsLayer->getNextAnswer(dnsLayer->getFirstAnswer()), ptr);

	PTF_ASSERT_EQUAL(dnsLayer->toString(),
	                 "DNS query response, ID: 11629; queries: 1, answers: 17, authorities: 0, additional record: 0");

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":365,"transactionID":"0x2d6d","isResponse":true,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":true,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		    R"("queries":[{"name":"www.google-analytics.com","type":1,"typeName":"A","class":1}],)"
		    R"("answers":[{"name":"www.google-analytics.com","type":5,"typeName":"CNAME","class":1,"ttl":57008,)"
		    R"("dataLength":32,"data":"www-google-analytics.l.google.com"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.237"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.227"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.246"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.241"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.222"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.251"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.212"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.247"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.232"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.242"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.216"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.221"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.217"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.226"},)"
		    R"({"name":"www-google-analytics.L.google.com","type":1,"typeName":"A","class":1,"ttl":117,)"
		    R"("dataLength":4,"data":"212.199.219.231"},{"name":"www-google-analytics.L.google.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":117,"dataLength":4,"data":"212.199.219.236"}],"authorities":[],)"
		    R"("additionalRecords":[]})");
	}

	auto rawPacket3 = createPacketFromHexResource("PacketExamples/Dns2.dat");

	pcpp::Packet dnsPacket3(rawPacket3.get());

	dnsLayer = dnsPacket3.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	queryByName = dnsLayer->getQuery(std::string("Yaels-iPhone.loca"), false);
	PTF_ASSERT_NOT_NULL(queryByName);
	PTF_ASSERT_EQUAL(queryByName->getDnsClass(), pcpp::DNS_CLASS_IN_QU, enum);

	PTF_ASSERT_EQUAL(dnsLayer->toString(),
	                 "DNS query, ID: 0; queries: 2, answers: 0, authorities: 2, additional record: 1");

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(), R"({"protocolName":"DNS","protocolId":13,"length":109,"transactionID":"0x0","isResponse":false,)"
		               R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":false,)"
		               R"("recursionAvailable":false,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		               R"("queries":[{"name":"Yaels-iPhone.local","type":255,"typeName":"ANY","class":32769},)"
		               R"({"name":"Yaels-iPhone.local","type":255,"typeName":"ANY","class":32769}],"answers":[],)"
		               R"("authorities":[{"name":"Yaels-iPhone.local","type":1,"typeName":"A","class":1,"ttl":120,)"
		               R"("dataLength":4,"data":"10.0.0.2"},{"name":"Yaels-iPhone.local","type":28,"typeName":"AAAA",)"
		               R"("class":1,"ttl":120,"dataLength":16,"data":"fe80::5a1f:aaff:fe4f:3f9d"}],)"
		               R"("additionalRecords":[{"name":"","type":41,"typeName":"OPT","class":1440,"ttl":4500,)"
		               R"("dataLength":12}]})");
	}

	auto rawPacket4 = createPacketFromHexResource("PacketExamples/Dns4.dat");

	pcpp::Packet dnsPacket4(rawPacket4.get());
	dnsLayer = dnsPacket4.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);

	curAnswer = dnsLayer->getFirstAnswer();
	PTF_ASSERT_NOT_NULL(curAnswer);
	PTF_ASSERT_EQUAL(curAnswer->getDnsType(), pcpp::DNS_TYPE_MX, enum);
	PTF_ASSERT_EQUAL(curAnswer->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(curAnswer->getData()->toString(), "pref: 1; mx: mta5.am0.yahoodns.net");
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().preference, 1);
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().mailExchange,
	                 "mta5.am0.yahoodns.net");

	curAnswer = dnsLayer->getNextAnswer(curAnswer);
	PTF_ASSERT_NOT_NULL(curAnswer);
	PTF_ASSERT_EQUAL(curAnswer->getDnsType(), pcpp::DNS_TYPE_MX, enum);
	PTF_ASSERT_EQUAL(curAnswer->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(curAnswer->getData()->toString(), "pref: 1; mx: mta7.am0.yahoodns.net");
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().preference, 1);
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().mailExchange,
	                 "mta7.am0.yahoodns.net");

	curAnswer = dnsLayer->getNextAnswer(curAnswer);
	PTF_ASSERT_NOT_NULL(curAnswer);
	PTF_ASSERT_EQUAL(curAnswer->getDnsType(), pcpp::DNS_TYPE_MX, enum);
	PTF_ASSERT_EQUAL(curAnswer->getDnsClass(), pcpp::DNS_CLASS_IN, enum);
	PTF_ASSERT_EQUAL(curAnswer->getData()->toString(), "pref: 1; mx: mta6.am0.yahoodns.net");
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().preference, 1);
	PTF_ASSERT_EQUAL(curAnswer->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().mailExchange,
	                 "mta6.am0.yahoodns.net");

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":394,"transactionID":"0x264","isResponse":true,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":true,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		    R"("queries":[{"name":"yahoo.com","type":15,"typeName":"MX","class":1}],"answers":[{"name":"yahoo.com",)"
		    R"("type":15,"typeName":"MX","class":1,"ttl":187,"dataLength":25,)"
		    R"("data":"pref: 1; mx: mta5.am0.yahoodns.net"},{"name":"yahoo.com","type":15,"typeName":"MX",)"
		    R"("class":1,"ttl":187,"dataLength":9,"data":"pref: 1; mx: mta7.am0.yahoodns.net"},{"name":"yahoo.com",)"
		    R"("type":15,"typeName":"MX","class":1,"ttl":187,"dataLength":9,)"
		    R"("data":"pref: 1; mx: mta6.am0.yahoodns.net"}],"authorities":[{"name":"yahoo.com","type":2,)"
		    R"("typeName":"NS","class":1,"ttl":81481,"dataLength":6,"data":"ns4.yahoo.com"},{"name":"yahoo.com",)"
		    R"("type":2,"typeName":"NS","class":1,"ttl":81481,"dataLength":6,"data":"ns6.yahoo.com"},)"
		    R"({"name":"yahoo.com","type":2,"typeName":"NS","class":1,"ttl":81481,"dataLength":6,)"
		    R"("data":"ns2.yahoo.com"},{"name":"yahoo.com","type":2,"typeName":"NS","class":1,"ttl":81481,)"
		    R"("dataLength":6,"data":"ns3.yahoo.com"},{"name":"yahoo.com","type":2,"typeName":"NS","class":1,)"
		    R"("ttl":81481,"dataLength":6,"data":"ns1.yahoo.com"},{"name":"yahoo.com","type":2,"typeName":"NS",)"
		    R"("class":1,"ttl":81481,"dataLength":6,"data":"ns5.yahoo.com"}],)"
		    R"("additionalRecords":[{"name":"ns1.yahoo.com","type":1,"typeName":"A","class":1,"ttl":1137517,)"
		    R"("dataLength":4,"data":"68.180.131.16"},{"name":"ns2.yahoo.com","type":1,"typeName":"A","class":1,)"
		    R"("ttl":1176690,"dataLength":4,"data":"68.142.255.16"},{"name":"ns2.yahoo.com","type":28,)"
		    R"("typeName":"AAAA","class":1,"ttl":602,"dataLength":16,"data":"2001:4998:140::1002"},)"
		    R"({"name":"ns3.yahoo.com","type":1,"typeName":"A","class":1,"ttl":1173959,"dataLength":4,)"
		    R"("data":"203.84.221.53"},{"name":"ns3.yahoo.com","type":28,"typeName":"AAAA","class":1,"ttl":1808,)"
		    R"("dataLength":16,"data":"2406:8600:b8:fe03::1003"},{"name":"ns4.yahoo.com","type":1,"typeName":"A",)"
		    R"("class":1,"ttl":1199585,"dataLength":4,"data":"98.138.11.157"},{"name":"ns5.yahoo.com","type":1,)"
		    R"("typeName":"A","class":1,"ttl":1178335,"dataLength":4,"data":"119.160.247.124"},)"
		    R"({"name":"ns6.yahoo.com","type":1,"typeName":"A","class":1,"ttl":145869,"dataLength":4,)"
		    R"("data":"121.101.144.139"},{"name":"ns6.yahoo.com","type":28,"typeName":"AAAA","class":1,"ttl":187,)"
		    R"("dataLength":16,"data":"2406:2000:108:4::1006"}]})");
	}

	auto rawPacket5 = createPacketFromHexResource("PacketExamples/dns_stack_overflow.dat");

	pcpp::Packet dnsPacket5(rawPacket5.get());

	dnsLayer = dnsPacket5.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);

	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 1);
	firstQuery = dnsLayer->getFirstQuery();
	PTF_ASSERT_NOT_NULL(firstQuery);
	PTF_ASSERT_EQUAL(
	    firstQuery->getName(),
	    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.");
	PTF_ASSERT_EQUAL(firstQuery->getSize(), 134);
	PTF_ASSERT_NULL(dnsLayer->getNextQuery(firstQuery));

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":1068,"transactionID":"0x0","isResponse":true,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":false,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		    R"("queries":[{"name":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)"
		    R"(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.","type":16962,"typeName":"Unknown",)"
		    R"("class":16962}],"answers":[],"authorities":[],"additionalRecords":[]})");
	}

	// a corner case of malformed packet where the total number of resources overflow uint16
	// by less than 300. This fixes the bug: https://github.com/seladb/PcapPlusPlus/issues/441
	auto rawPacket6 = createPacketFromHexResource("PacketExamples/DnsTooManyResources.dat");
	pcpp::Packet dnsPacket6 = [&]() {
		SuppressLogs suppressLogs;
		return pcpp::Packet(rawPacket6.get());
	}();
	dnsLayer = dnsPacket6.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NULL(dnsLayer->getFirstQuery());
	PTF_ASSERT_NULL(dnsLayer->getFirstAnswer());
	PTF_ASSERT_NULL(dnsLayer->getFirstAuthority());
	PTF_ASSERT_NULL(dnsLayer->getFirstAdditionalRecord());

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":706,"transactionID":"0xa04","isResponse":false,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":true,"recursionDesired":false,)"
		    R"("recursionAvailable":true,"authenticData":true,"checkingDisabled":true,"responseCode":8,)"
		    R"("queries":[],"answers":[],"authorities":[],"additionalRecords":[]})");
	}
}  // DnsLayerParsingTest

PTF_TEST_CASE(DnsLayerQueryCreationTest)
{
	auto rawPacketAndBuf2 = createPacketAndBufferFromHexResource("PacketExamples/DnsEdit2.dat");
	auto& resource2 = rawPacketAndBuf2.resourceBuffer;
	auto& rawPacket2 = rawPacketAndBuf2.packet;

	pcpp::Packet dnsEdit2RefPacket(rawPacket2.get());

	pcpp::EthLayer ethLayer2(*dnsEdit2RefPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipLayer2(*dnsEdit2RefPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer2(*dnsEdit2RefPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::DnsLayer dns2Layer;
	dns2Layer.getDnsHeader()->recursionDesired = true;
	dns2Layer.getDnsHeader()->transactionID = htobe16(0xb179);
	pcpp::DnsQuery* newQuery =
	    dns2Layer.addQuery("mail-attachment.googleusercontent.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(newQuery);
	PTF_ASSERT_EQUAL(dns2Layer.getQueryCount(), 1);
	PTF_ASSERT_EQUAL(newQuery->getName(), "mail-attachment.googleusercontent.com");

	pcpp::Packet dnsEdit2Packet(1);
	PTF_ASSERT_TRUE(dnsEdit2Packet.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(dnsEdit2Packet.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(dnsEdit2Packet.addLayer(&udpLayer2));
	PTF_ASSERT_TRUE(dnsEdit2Packet.addLayer(&dns2Layer));

	dnsEdit2Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit2Packet.getRawPacket()->getRawDataLen(), resource2.length);
	PTF_ASSERT_BUF_COMPARE(dnsEdit2Packet.getRawPacket()->getRawData(), resource2.data.get(), resource2.length);

	auto rawPacketAndBuf1 = createPacketAndBufferFromHexResource("PacketExamples/DnsEdit1.dat");
	auto& resource1 = rawPacketAndBuf1.resourceBuffer;
	auto& rawPacket1 = rawPacketAndBuf1.packet;

	pcpp::Packet dnsEdit1RefPacket(rawPacket1.get());

	pcpp::EthLayer ethLayer1(*dnsEdit1RefPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipLayer1(*dnsEdit1RefPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer1(*dnsEdit1RefPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::DnsLayer dns1Layer;

	pcpp::Packet dnsEdit1Packet(1);
	PTF_ASSERT_TRUE(dnsEdit1Packet.addLayer(&ethLayer1));
	PTF_ASSERT_TRUE(dnsEdit1Packet.addLayer(&ipLayer1));
	PTF_ASSERT_TRUE(dnsEdit1Packet.addLayer(&udpLayer1));
	PTF_ASSERT_TRUE(dnsEdit1Packet.addLayer(&dns1Layer));

	newQuery = dns1Layer.addQuery("_apple-mobdev._tcp.local", pcpp::DNS_TYPE_PTR, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(newQuery);
	PTF_ASSERT_EQUAL(dns1Layer.getQueryCount(), 1);

	newQuery = dns1Layer.addQuery(newQuery);
	PTF_ASSERT_NOT_NULL(newQuery);
	PTF_ASSERT_EQUAL(dns1Layer.getQueryCount(), 2);

	PTF_ASSERT_TRUE(newQuery->setName("_sleep-proxy._udp.local"));

	PTF_ASSERT_NULL(dns1Layer.addQuery(nullptr));
	PTF_ASSERT_EQUAL(dns1Layer.getQueryCount(), 2);

	dnsEdit1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit1Packet.getRawPacket()->getRawDataLen(), resource1.length);
	PTF_ASSERT_BUF_COMPARE(dnsEdit1Packet.getRawPacket()->getRawData(), resource1.data.get(), resource1.length);
}  // DnsLayerQueryCreationTest

PTF_TEST_CASE(DnsLayerResourceCreationTest)
{
	auto rawPacketAndBuf4 = createPacketAndBufferFromHexResource("PacketExamples/DnsEdit4.dat");
	auto& resource4 = rawPacketAndBuf4.resourceBuffer;
	auto& rawPacket4 = rawPacketAndBuf4.packet;

	pcpp::Packet dnsEdit4RefPacket(rawPacket4.get());

	pcpp::EthLayer ethLayer4(*dnsEdit4RefPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipLayer4(*dnsEdit4RefPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer4(*dnsEdit4RefPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::DnsLayer dns4Layer;
	dns4Layer.getDnsHeader()->transactionID = htobe16(14627);
	dns4Layer.getDnsHeader()->queryOrResponse = 1;
	dns4Layer.getDnsHeader()->recursionDesired = 1;
	dns4Layer.getDnsHeader()->recursionAvailable = 1;

	pcpp::StringDnsResourceData stringDnsData("assets.pinterest.com.cdngc.net");
	pcpp::DnsResource* firstAnswer =
	    dns4Layer.addAnswer("assets.pinterest.com", pcpp::DNS_TYPE_CNAME, pcpp::DNS_CLASS_IN, 228, &stringDnsData);
	PTF_ASSERT_NOT_NULL(firstAnswer);
	PTF_ASSERT_EQUAL(dns4Layer.getFirstAnswer(), firstAnswer, ptr);
	PTF_ASSERT_EQUAL(firstAnswer->getData()->toString(), "assets.pinterest.com.cdngc.net");

	pcpp::Packet dnsEdit4Packet(1);
	PTF_ASSERT_TRUE(dnsEdit4Packet.addLayer(&ethLayer4));
	PTF_ASSERT_TRUE(dnsEdit4Packet.addLayer(&ipLayer4));
	PTF_ASSERT_TRUE(dnsEdit4Packet.addLayer(&udpLayer4));
	PTF_ASSERT_TRUE(dnsEdit4Packet.addLayer(&dns4Layer));

	PTF_ASSERT_EQUAL(dnsEdit4Packet.getLayerOfType<pcpp::DnsLayer>()->getFirstAnswer(), firstAnswer, ptr);

	pcpp::IPv4DnsResourceData ipv4DnsData(std::string("151.249.90.217"));
	pcpp::DnsResource* secondAnswer =
	    dns4Layer.addAnswer("assets.pinterest.com.cdngc.net", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 3, &ipv4DnsData);
	PTF_ASSERT_NOT_NULL(secondAnswer);
	PTF_ASSERT_EQUAL(secondAnswer->getData()->castAs<pcpp::IPv4DnsResourceData>()->getIpAddress(),
	                 ipv4DnsData.getIpAddress());

	pcpp::DnsQuery* query = dns4Layer.addQuery("assets.pinterest.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(query);

	PTF_ASSERT_EQUAL(dnsEdit4Packet.getLayerOfType<pcpp::DnsLayer>()->getFirstAnswer(), firstAnswer, ptr);
	PTF_ASSERT_EQUAL(dnsEdit4Packet.getLayerOfType<pcpp::DnsLayer>()->getNextAnswer(firstAnswer), secondAnswer, ptr);

	PTF_ASSERT_RAISES(pcpp::IPv4DnsResourceData(std::string("256.249.90.238")), std::invalid_argument,
	                  "Not a valid IPv4 address: 256.249.90.238");

	pcpp::DnsResource* thirdAnswer = dns4Layer.addAnswer(secondAnswer);
	PTF_ASSERT_NOT_NULL(thirdAnswer);
	{
		SuppressLogs suppressLogs;
		PTF_ASSERT_FALSE(thirdAnswer->setData(nullptr));
	}
	ipv4DnsData = pcpp::IPv4DnsResourceData(std::string("151.249.90.238"));
	PTF_ASSERT_TRUE(thirdAnswer->setData(&ipv4DnsData));

	PTF_ASSERT_EQUAL(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", true)->getData()->toString(),
	                 "151.249.90.217");
	PTF_ASSERT_EQUAL(
	    dns4Layer.getNextAnswer(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", false))->getData()->toString(),
	    "151.249.90.238");

	dnsEdit4Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit4Packet.getRawPacket()->getRawDataLen(), resource4.length);
	PTF_ASSERT_BUF_COMPARE(dnsEdit4Packet.getRawPacket()->getRawData(), resource4.data.get(), resource4.length);

	auto rawPacketAndBuf6 = createPacketAndBufferFromHexResource("PacketExamples/DnsEdit6.dat");
	auto& resource6 = rawPacketAndBuf6.resourceBuffer;
	auto& rawPacket6 = rawPacketAndBuf6.packet;

	pcpp::Packet dnsEdit6RefPacket(rawPacket6.get());

	pcpp::EthLayer ethLayer6(*dnsEdit6RefPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv6Layer ipLayer6(*dnsEdit6RefPacket.getLayerOfType<pcpp::IPv6Layer>());
	pcpp::UdpLayer udpLayer6(*dnsEdit6RefPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::DnsLayer dnsLayer6;

	ipv4DnsData = pcpp::IPv4DnsResourceData(std::string("10.0.0.2"));
	pcpp::DnsResource* authority =
	    dnsLayer6.addAuthority("Yaels-iPhone.local", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 120, &ipv4DnsData);
	PTF_ASSERT_NOT_NULL(authority);

	query = dnsLayer6.addQuery(query);
	PTF_ASSERT_TRUE(query->setName("Yaels-iPhone.local"));
	query->setDnsClass(pcpp::DNS_CLASS_CH);
	query->setDnsType(pcpp::DNS_TYPE_ALL);

	pcpp::Packet dnsEdit6Packet(52);
	PTF_ASSERT_TRUE(dnsEdit6Packet.addLayer(&ethLayer6));
	PTF_ASSERT_TRUE(dnsEdit6Packet.addLayer(&ipLayer6));
	PTF_ASSERT_TRUE(dnsEdit6Packet.addLayer(&udpLayer6));
	PTF_ASSERT_TRUE(dnsEdit6Packet.addLayer(&dnsLayer6));

	PTF_ASSERT_EQUAL(dnsLayer6.getAuthority("Yaels-iPhone.local", true)->getData()->toString(), "10.0.0.2");

	PTF_ASSERT_RAISES(pcpp::IPv6DnsResourceData(std::string("##80::5a1f:aaff:fe4f:3f9d")), std::invalid_argument,
	                  "Not a valid IPv6 address: ##80::5a1f:aaff:fe4f:3f9d");

	authority = dnsLayer6.addAuthority(authority);
	{
		SuppressLogs suppressLogs;
		PTF_ASSERT_FALSE(authority->setData(nullptr));
	}
	authority->setDnsType(pcpp::DNS_TYPE_AAAA);
	auto ipv6DnsData = pcpp::IPv6DnsResourceData(std::string("fe80::5a1f:aaff:fe4f:3f9d"));
	PTF_ASSERT_TRUE(authority->setData(&ipv6DnsData));

	query = dnsLayer6.addQuery(query);
	query->setDnsClass(pcpp::DNS_CLASS_ANY);

	PTF_ASSERT_EQUAL(dnsLayer6.getQueryCount(), 2);
	PTF_ASSERT_EQUAL(dnsLayer6.getAuthorityCount(), 2);
	PTF_ASSERT_EQUAL(dnsLayer6.getAnswerCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer6.getAdditionalRecordCount(), 0);

	pcpp::GenericDnsResourceData genericData("0004000800df581faa4f3f9d");
	pcpp::DnsResource* additional = dnsLayer6.addAdditionalRecord("", pcpp::DNS_TYPE_OPT, 0xa005, 0x1194, &genericData);
	PTF_ASSERT_NOT_NULL(additional);
	{
		SuppressLogs suppressLogs;
		genericData = pcpp::GenericDnsResourceData("a0123");
		PTF_ASSERT_FALSE(additional->setData(&genericData));
		genericData = pcpp::GenericDnsResourceData("a01j34");
		PTF_ASSERT_FALSE(additional->setData(&genericData));
	}

	dnsEdit6Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit6Packet.getRawPacket()->getRawDataLen(), resource6.length);
	PTF_ASSERT_BUF_COMPARE(dnsEdit6Packet.getRawPacket()->getRawData(), resource6.data.get(), resource6.length);

	auto rawPacketAndBuf7 = createPacketAndBufferFromHexResource("PacketExamples/DnsEdit7.dat");
	auto& resource7 = rawPacketAndBuf7.resourceBuffer;
	auto& rawPacket7 = rawPacketAndBuf7.packet;

	pcpp::Packet dnsEdit7RefPacket(rawPacket7.get());

	pcpp::EthLayer ethLayer7(*dnsEdit7RefPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipLayer7(*dnsEdit7RefPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer7(*dnsEdit7RefPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::DnsLayer dnsLayer7;
	dnsLayer7.getDnsHeader()->transactionID = htobe16(612);
	dnsLayer7.getDnsHeader()->queryOrResponse = 1;
	dnsLayer7.getDnsHeader()->recursionDesired = 1;
	dnsLayer7.getDnsHeader()->recursionAvailable = 1;

	query = dnsLayer7.addQuery("yahoo.com", pcpp::DNS_TYPE_MX, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(query);

	std::stringstream queryNameOffset;
	queryNameOffset << "#" << query->getNameOffset();

	pcpp::MxDnsResourceData mxDnsData(1, "mta5.am0.yahoodns.net");
	pcpp::DnsResource* answer =
	    dnsLayer7.addAnswer(queryNameOffset.str(), pcpp::DNS_TYPE_MX, pcpp::DNS_CLASS_IN, 187, &mxDnsData);
	PTF_ASSERT_NOT_NULL(answer);

	std::stringstream firsAnswerMxOffset;
	firsAnswerMxOffset << "#" << (answer->getDataOffset() + 2 + 5);

	mxDnsData.setMxData(1, "mta7." + firsAnswerMxOffset.str());
	answer = dnsLayer7.addAnswer(queryNameOffset.str(), pcpp::DNS_TYPE_MX, pcpp::DNS_CLASS_IN, 187, &mxDnsData);
	PTF_ASSERT_NOT_NULL(answer);

	mxDnsData.setMxData(1, "mta6." + firsAnswerMxOffset.str());
	answer = dnsLayer7.addAnswer(queryNameOffset.str(), pcpp::DNS_TYPE_MX, pcpp::DNS_CLASS_IN, 187, &mxDnsData);
	PTF_ASSERT_NOT_NULL(answer);

	pcpp::Packet dnsEdit7Packet(60);
	PTF_ASSERT_TRUE(dnsEdit7Packet.addLayer(&ethLayer7));
	PTF_ASSERT_TRUE(dnsEdit7Packet.addLayer(&ipLayer7));
	PTF_ASSERT_TRUE(dnsEdit7Packet.addLayer(&udpLayer7));
	PTF_ASSERT_TRUE(dnsEdit7Packet.addLayer(&dnsLayer7));

	dnsEdit7Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit7Packet.getRawPacket()->getRawDataLen(), resource7.length);
	PTF_ASSERT_BUF_COMPARE(dnsEdit7Packet.getRawPacket()->getRawData(), resource7.data.get(), resource7.length);

	// Generic RDATA uses a 16-bit wire length and can exceed the old 4096-byte temporary buffer,
	// verify that both adding and copying such a record work
	{
		std::vector<uint8_t> rdata(5000, 0xAB);
		pcpp::GenericDnsResourceData largeGenericData(rdata.data(), rdata.size());

		pcpp::DnsLayer largeDataLayer;
		auto* largeDataAnswer =
		    largeDataLayer.addAnswer("example.com", pcpp::DNS_TYPE_DNSKEY, pcpp::DNS_CLASS_IN, 60, &largeGenericData);
		PTF_ASSERT_NOT_NULL(largeDataAnswer);
		PTF_ASSERT_EQUAL(largeDataAnswer->getDataLength(), static_cast<size_t>(5000));

		auto largeData = largeDataAnswer->getData();
		PTF_ASSERT_TRUE(largeData.isTypeOf<pcpp::GenericDnsResourceData>());
		PTF_ASSERT_TRUE(*largeData.castAs<pcpp::GenericDnsResourceData>() == largeGenericData);

		pcpp::DnsLayer copiedLayer;
		auto* copiedAnswer = copiedLayer.addAnswer(largeDataAnswer);
		PTF_ASSERT_NOT_NULL(copiedAnswer);
		PTF_ASSERT_EQUAL(copiedAnswer->getDataLength(), static_cast<size_t>(5000));
	}

	// A resource whose data can't be serialized must be rolled back from the layer
	{
		pcpp::DnsLayer rollbackLayer;
		pcpp::StringDnsResourceData cnameData("www.example.com");
		PTF_ASSERT_NOT_NULL(
		    rollbackLayer.addAnswer("example.com", pcpp::DNS_TYPE_CNAME, pcpp::DNS_CLASS_IN, 60, &cnameData));

		const size_t layerSizeBefore = rollbackLayer.getDataLen();
		const size_t answerCountBefore = rollbackLayer.getAnswerCount();

		// DNS_TYPE_A requires IPv4DnsResourceData, so setData() fails after the resource was inserted to the layer
		PTF_ASSERT_NULL(rollbackLayer.addAnswer("x", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 60, &cnameData));

		PTF_ASSERT_EQUAL(rollbackLayer.getDataLen(), layerSizeBefore);
		PTF_ASSERT_EQUAL(rollbackLayer.getAnswerCount(), answerCountBefore);
		PTF_ASSERT_EQUAL(rollbackLayer.getAnswerCount(), static_cast<size_t>(1));
		auto* remainingAnswer = rollbackLayer.getFirstAnswer();
		PTF_ASSERT_NOT_NULL(remainingAnswer);
		PTF_ASSERT_EQUAL(remainingAnswer->getName(), "example.com");
		PTF_ASSERT_EQUAL(remainingAnswer->getData()->toString(), "www.example.com");
	}

	// RDATA that doesn't fit the 16-bit length field must be rejected without changing the layer
	{
		// Parentheses around std::numeric_limits<>::max avoid a clash with the Windows max macro
		std::vector<uint8_t> oversizedData(static_cast<size_t>((std::numeric_limits<uint16_t>::max)()) + 1, 0x5A);
		pcpp::GenericDnsResourceData oversizedGenericData(oversizedData.data(), oversizedData.size());

		pcpp::DnsLayer oversizedLayer;
		const size_t layerSizeBefore = oversizedLayer.getDataLen();
		PTF_ASSERT_NULL(
		    oversizedLayer.addAnswer("x", pcpp::DNS_TYPE_DNSKEY, pcpp::DNS_CLASS_IN, 60, &oversizedGenericData));
		PTF_ASSERT_EQUAL(oversizedLayer.getDataLen(), layerSizeBefore);
		PTF_ASSERT_EQUAL(oversizedLayer.getAnswerCount(), static_cast<size_t>(0));
	}

}  // DnsLayerResourceCreationTest

PTF_TEST_CASE(DnsLayerAddDnsKeyTest)
{

	// data length overflow 256
	const std::string dnskey =
	    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQ \
lNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+Sr \
DK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";

	pcpp::DnsLayer dnsLayer;
	pcpp::GenericDnsResourceData genericData(reinterpret_cast<const uint8_t*>(dnskey.c_str()), dnskey.size());
	const auto* additional =
	    dnsLayer.addAnswer("github.com", pcpp::DNS_TYPE_DNSKEY, pcpp::DNS_CLASS_IN, 32, &genericData);
	PTF_ASSERT_NOT_NULL(additional);
}

PTF_TEST_CASE(DnsLayerEditTest)
{
	auto rawPacket3 = createPacketFromHexResource("PacketExamples/DnsEdit3.dat");
	auto rawPacket5 = createPacketFromHexResource("PacketExamples/DnsEdit5.dat");
	pcpp::RawPacket raw3PacketCopy(*rawPacket3);

	pcpp::Packet dnsEdit3(rawPacket3.get());
	pcpp::Packet dnsEdit5(rawPacket5.get());

	pcpp::DnsLayer* dnsLayer3 = dnsEdit3.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer3);

	pcpp::DnsLayer* dnsLayer5 = dnsEdit5.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer5);

	PTF_ASSERT_TRUE(dnsLayer3->getFirstQuery()->setName("www.mora.fr"));
	dnsLayer3->getDnsHeader()->transactionID = htobe16(35240);
	PTF_ASSERT_EQUAL(dnsLayer3->getHeaderLen(), dnsLayer5->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(dnsLayer3->getData(), dnsLayer5->getData(), dnsLayer3->getHeaderLen());

	dnsEdit3 = pcpp::Packet(&raw3PacketCopy);
	dnsLayer3 = dnsEdit3.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer3);

	dnsLayer5->getDnsHeader()->transactionID = htobe16(14627);
	PTF_ASSERT_TRUE(dnsLayer5->getFirstQuery()->setName("assets.pinterest.com"));
	PTF_ASSERT_EQUAL(dnsLayer3->getHeaderLen(), dnsLayer5->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(dnsLayer3->getData(), dnsLayer5->getData(), dnsLayer3->getHeaderLen());
}  // DnsLayerEditTest

PTF_TEST_CASE(DnsLayerRemoveResourceTest)
{
	auto rawPacket6 = createPacketFromHexResource("PacketExamples/DnsEdit6.dat");

	pcpp::Packet dnsEdit6Packet(rawPacket6.get());

	pcpp::DnsLayer* dnsLayer6 = dnsEdit6Packet.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer6);

	pcpp::DnsLayer origDnsLayer6(*dnsLayer6);

	pcpp::DnsQuery* firstQuery = dnsLayer6->getFirstQuery();
	size_t firstQuerySize = firstQuery->getSize();
	pcpp::DnsQuery* secondQuery = dnsLayer6->getNextQuery(firstQuery);
	PTF_ASSERT_NOT_NULL(firstQuery);
	PTF_ASSERT_NOT_NULL(secondQuery);
	PTF_ASSERT_TRUE(dnsLayer6->removeQuery(firstQuery));

	PTF_ASSERT_EQUAL(dnsLayer6->getFirstQuery(), secondQuery, ptr);
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstQuery()->getDnsType(), pcpp::DNS_TYPE_ALL, enum);
	PTF_ASSERT_EQUAL(dnsLayer6->getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAuthority()->getData()->toString(), "10.0.0.2");
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAdditionalRecord()->getDnsType(), pcpp::DNS_TYPE_OPT, enum);

	PTF_ASSERT_EQUAL(dnsLayer6->getHeaderLen(), origDnsLayer6.getHeaderLen() - firstQuerySize);

	PTF_ASSERT_BUF_COMPARE(dnsLayer6->getData() + sizeof(pcpp::dnshdr),
	                       origDnsLayer6.getData() + sizeof(pcpp::dnshdr) + firstQuerySize,
	                       dnsLayer6->getHeaderLen() - sizeof(pcpp::dnshdr));

	pcpp::DnsResource* firstAuthority = dnsLayer6->getFirstAuthority();
	pcpp::DnsResource* secondAuthority = dnsLayer6->getNextAuthority(firstAuthority);
	PTF_ASSERT_NOT_NULL(secondAuthority);
	size_t secondAuthoritySize = secondAuthority->getSize();

	PTF_ASSERT_TRUE(dnsLayer6->removeAuthority(secondAuthority));
	PTF_ASSERT_EQUAL(dnsLayer6->getAuthorityCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAuthority(), firstAuthority, ptr);
	PTF_ASSERT_NULL(dnsLayer6->getNextAuthority(firstAuthority));
	PTF_ASSERT_EQUAL(firstAuthority->getTTL(), 120);
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAdditionalRecord()->getDnsType(), pcpp::DNS_TYPE_OPT, enum);
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAdditionalRecord()->getDataLength(), 12);
	PTF_ASSERT_EQUAL(dnsLayer6->getHeaderLen(), origDnsLayer6.getHeaderLen() - firstQuerySize - secondAuthoritySize);

	PTF_ASSERT_FALSE(dnsLayer6->removeQuery("BlaBla", true));
	PTF_ASSERT_FALSE(dnsLayer6->removeAuthority(secondAuthority));
	PTF_ASSERT_FALSE(dnsLayer6->removeAdditionalRecord(nullptr));

	size_t additionalRecordSize = dnsLayer6->getFirstAdditionalRecord()->getSize();
	PTF_ASSERT_TRUE(dnsLayer6->removeAdditionalRecord(dnsLayer6->getFirstAdditionalRecord()));
	PTF_ASSERT_EQUAL(dnsLayer6->getAdditionalRecordCount(), 0);
	PTF_ASSERT_NULL(dnsLayer6->getFirstAdditionalRecord());
	PTF_ASSERT_EQUAL(dnsLayer6->getFirstAuthority()->getData()->toString(), "10.0.0.2");
	PTF_ASSERT_EQUAL(dnsLayer6->getHeaderLen(),
	                 origDnsLayer6.getHeaderLen() - firstQuerySize - secondAuthoritySize - additionalRecordSize);

	auto rawPacket4 = createPacketFromHexResource("PacketExamples/DnsEdit4.dat");

	pcpp::Packet dnsEdit4Packet(rawPacket4.get());

	pcpp::DnsLayer* dnsLayer4 = dnsEdit4Packet.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer4);

	pcpp::DnsLayer origDnsLayer4(*dnsLayer4);

	firstQuerySize = dnsLayer4->getFirstQuery()->getSize();
	PTF_ASSERT_TRUE(dnsLayer4->removeQuery("pinter", false));
	PTF_ASSERT_EQUAL(dnsLayer4->getQueryCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer4->getHeaderLen(), origDnsLayer4.getHeaderLen() - firstQuerySize);

	pcpp::DnsResource* firstAnswer = dnsLayer4->getFirstAnswer();
	PTF_ASSERT_NOT_NULL(firstAnswer);
	size_t firstAnswerSize = firstAnswer->getSize();
	PTF_ASSERT_EQUAL(dnsLayer4->getFirstAnswer()->getData()->toString(), "assets.pinterest.com.cdngc.net");

	pcpp::DnsResource* secondAnswer = dnsLayer4->getNextAnswer(firstAnswer);
	PTF_ASSERT_NOT_NULL(secondAnswer);
	size_t secondAnswerSize = secondAnswer->getSize();

	pcpp::DnsResource* thirdAnswer = dnsLayer4->getNextAnswer(secondAnswer);
	PTF_ASSERT_NOT_NULL(thirdAnswer);

	PTF_ASSERT_TRUE(dnsLayer4->removeAnswer("assets.pinterest.com.cdngc.net", true));
	PTF_ASSERT_EQUAL(dnsLayer4->getAnswerCount(), 2);
	PTF_ASSERT_EQUAL(dnsLayer4->getFirstAnswer(), firstAnswer, ptr);
	PTF_ASSERT_EQUAL(dnsLayer4->getNextAnswer(dnsLayer4->getFirstAnswer()), thirdAnswer, ptr);
	PTF_ASSERT_EQUAL(dnsLayer4->getHeaderLen(), origDnsLayer4.getHeaderLen() - firstQuerySize - secondAnswerSize);

	PTF_ASSERT_TRUE(dnsLayer4->removeAnswer(firstAnswer));
	PTF_ASSERT_EQUAL(dnsLayer4->getAnswerCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer4->getFirstAnswer(), thirdAnswer, ptr);
	PTF_ASSERT_EQUAL(dnsLayer4->getFirstAnswer()->getData()->toString(), "151.249.90.238");
	PTF_ASSERT_EQUAL(dnsLayer4->getHeaderLen(),
	                 origDnsLayer4.getHeaderLen() - firstQuerySize - secondAnswerSize - firstAnswerSize);

	PTF_ASSERT_TRUE(dnsLayer4->removeAnswer(thirdAnswer));
	PTF_ASSERT_FALSE(dnsLayer4->removeAdditionalRecord("blabla", false));
	PTF_ASSERT_EQUAL(dnsLayer4->getHeaderLen(), sizeof(pcpp::dnshdr));
}  // DnsLayerRemoveResourceTest

PTF_TEST_CASE(DnsLayerAddResourceOutOfOrderTest)
{
	// The resources are added in the opposite order of their place in the packet. Adding a resource that belongs
	// before all the existing ones used to link it back to the first existing resource, so the resource list became
	// circular and removing a resource or adding a query never returned
	pcpp::IPv4DnsResourceData ipData(std::string("10.0.0.1"));
	pcpp::DnsLayer dnsLayer;

	pcpp::DnsResource* additional =
	    dnsLayer.addAdditionalRecord("additional.example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 30, &ipData);
	PTF_ASSERT_NOT_NULL(additional);

	pcpp::DnsResource* authority =
	    dnsLayer.addAuthority("authority.example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 20, &ipData);
	PTF_ASSERT_NOT_NULL(authority);

	pcpp::DnsResource* answer =
	    dnsLayer.addAnswer("answer.example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 10, &ipData);
	PTF_ASSERT_NOT_NULL(answer);

	pcpp::DnsQuery* query = dnsLayer.addQuery("query.example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(query);

	PTF_ASSERT_EQUAL(dnsLayer.getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer.getAnswerCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer.getAuthorityCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer.getAdditionalRecordCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer.getFirstQuery(), query, ptr);
	PTF_ASSERT_EQUAL(dnsLayer.getFirstAnswer(), answer, ptr);
	PTF_ASSERT_EQUAL(dnsLayer.getFirstAuthority(), authority, ptr);
	PTF_ASSERT_EQUAL(dnsLayer.getFirstAdditionalRecord(), additional, ptr);

	// copying the layer parses the layer data again, so this verifies the order of the resources in the packet
	pcpp::DnsLayer parsedLayer(dnsLayer);
	PTF_ASSERT_EQUAL(parsedLayer.getQueryCount(), 1);
	PTF_ASSERT_EQUAL(parsedLayer.getAnswerCount(), 1);
	PTF_ASSERT_EQUAL(parsedLayer.getAuthorityCount(), 1);
	PTF_ASSERT_EQUAL(parsedLayer.getAdditionalRecordCount(), 1);
	PTF_ASSERT_EQUAL(parsedLayer.getFirstQuery()->getName(), "query.example.com");
	PTF_ASSERT_EQUAL(parsedLayer.getFirstAnswer()->getName(), "answer.example.com");
	PTF_ASSERT_EQUAL(parsedLayer.getFirstAuthority()->getName(), "authority.example.com");
	PTF_ASSERT_EQUAL(parsedLayer.getFirstAdditionalRecord()->getName(), "additional.example.com");

	PTF_ASSERT_TRUE(dnsLayer.removeAnswer(answer));
	PTF_ASSERT_TRUE(dnsLayer.removeAuthority(authority));
	PTF_ASSERT_TRUE(dnsLayer.removeAdditionalRecord(additional));
	PTF_ASSERT_TRUE(dnsLayer.removeQuery(query));
	PTF_ASSERT_EQUAL(dnsLayer.getHeaderLen(), sizeof(pcpp::dnshdr));
}  // DnsLayerAddResourceOutOfOrderTest

PTF_TEST_CASE(DnsOverTcpParsingTest)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/dns_over_tcp_query.dat");
	pcpp::Packet dnsPacket(rawPacket1.get());

	pcpp::DnsLayer* dnsLayer = dnsPacket.getLayerOfType<pcpp::DnsLayer>();
	pcpp::DnsOverTcpLayer* dnsOverTcpLayer = dnsPacket.getLayerOfType<pcpp::DnsOverTcpLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswerCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAuthorityCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecordCount(), 1);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0x6165, hex);
	PTF_ASSERT_EQUAL(dnsOverTcpLayer->getTcpMessageLength(), 42);

	pcpp::DnsQuery* query = dnsLayer->getFirstQuery();
	PTF_ASSERT_NOT_NULL(query);
	PTF_ASSERT_EQUAL(query->getName(), "cole-tech.net");
	PTF_ASSERT_EQUAL(query->getDnsType(), pcpp::DNS_TYPE_AAAA, enum);
	PTF_ASSERT_EQUAL(query->getDnsClass(), pcpp::DNS_CLASS_IN, enum);

	pcpp::DnsResource* additionalRecord = dnsLayer->getFirstAdditionalRecord();
	PTF_ASSERT_EQUAL(additionalRecord->getDnsType(), pcpp::DNS_TYPE_OPT, enum);
	PTF_ASSERT_EQUAL(additionalRecord->getName(), "");

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsOverTcpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":44,"transactionID":"0x6165","isResponse":false,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":false,"authenticData":false,"checkingDisabled":true,"responseCode":0,)"
		    R"("queries":[{"name":"cole-tech.net","type":28,"typeName":"AAAA","class":1}],"answers":[],)"
		    R"("authorities":[],"additionalRecords":[{"name":"","type":41,"typeName":"OPT","class":512,"ttl":32768,)"
		    R"("dataLength":0}],"tcpMessageLength":42})");
	}

	auto rawPacket2 = createPacketFromHexResource("PacketExamples/dns_over_tcp_response.dat");
	pcpp::Packet dnsPacket2(rawPacket2.get());

	dnsLayer = dnsPacket2.getLayerOfType<pcpp::DnsLayer>();
	dnsOverTcpLayer = dnsPacket2.getLayerOfType<pcpp::DnsOverTcpLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswerCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAuthorityCount(), 8);
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecordCount(), 1);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0x6165, hex);
	PTF_ASSERT_EQUAL(dnsOverTcpLayer->getTcpMessageLength(), 1133);

	std::string expectedNames[8] = { "net",
		                             "net",
		                             "A1RT98BS5QGC9NFI51S9HCI47ULJG6JH.net",
		                             "A1RT98BS5QGC9NFI51S9HCI47ULJG6JH.net",
		                             "QT8SCE02D5ONC5NBTQUNBEIDMFJE7GL8.net",
		                             "QT8SCE02D5ONC5NBTQUNBEIDMFJE7GL8.net",
		                             "EEQ3CIFFULOPN4J3E5MKEGKVDJKIGVBP.net",
		                             "EEQ3CIFFULOPN4J3E5MKEGKVDJKIGVBP.net" };

	pcpp::DnsType expectedTypes[8] = { pcpp::DNS_TYPE_SOA,   pcpp::DNS_TYPE_RRSIG, pcpp::DNS_TYPE_NSEC3,
		                               pcpp::DNS_TYPE_RRSIG, pcpp::DNS_TYPE_NSEC3, pcpp::DNS_TYPE_RRSIG,
		                               pcpp::DNS_TYPE_NSEC3, pcpp::DNS_TYPE_RRSIG };

	int i = 0;
	for (pcpp::DnsResource* authority = dnsLayer->getFirstAuthority(); authority != nullptr;
	     authority = dnsLayer->getNextAuthority(authority))
	{
		PTF_ASSERT_EQUAL(authority->getName(), expectedNames[i]);
		PTF_ASSERT_EQUAL(authority->getDnsType(), expectedTypes[i], enum);
		i++;
	}

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsOverTcpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":1135,"transactionID":"0x6165","isResponse":true,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":true,"authenticData":false,"checkingDisabled":true,"responseCode":3,)"
		    R"("queries":[{"name":"cole-tech.net","type":28,"typeName":"AAAA","class":1}],"answers":[],)"
		    R"("authorities":[{"name":"net","type":6,"typeName":"SOA","class":1,"ttl":891,"dataLength":61},)"
		    R"({"name":"net","type":46,"typeName":"RRSIG","class":1,"ttl":891,"dataLength":183},)"
		    R"({"name":"A1RT98BS5QGC9NFI51S9HCI47ULJG6JH.net","type":50,"typeName":"NSEC3","class":1,"ttl":3097,)"
		    R"("dataLength":35},{"name":"A1RT98BS5QGC9NFI51S9HCI47ULJG6JH.net","type":46,"typeName":"RRSIG",)"
		    R"("class":1,"ttl":3097,"dataLength":183},{"name":"QT8SCE02D5ONC5NBTQUNBEIDMFJE7GL8.net","type":50,)"
		    R"("typeName":"NSEC3","class":1,"ttl":6232,"dataLength":34},)"
		    R"({"name":"QT8SCE02D5ONC5NBTQUNBEIDMFJE7GL8.net","type":46,"typeName":"RRSIG","class":1,"ttl":6232,)"
		    R"("dataLength":183},{"name":"EEQ3CIFFULOPN4J3E5MKEGKVDJKIGVBP.net","type":50,"typeName":"NSEC3",)"
		    R"("class":1,"ttl":4711,"dataLength":34},{"name":"EEQ3CIFFULOPN4J3E5MKEGKVDJKIGVBP.net","type":46,)"
		    R"("typeName":"RRSIG","class":1,"ttl":4711,"dataLength":183}],"additionalRecords":[{"name":"",)"
		    R"("type":41,"typeName":"OPT","class":4096,"ttl":32768,"dataLength":0}],"tcpMessageLength":1133})");
	}

	auto rawPacket3 = createPacketFromHexResource("PacketExamples/dns_over_tcp_answer.dat");
	pcpp::Packet dnsPacket3(rawPacket3.get());

	dnsLayer = dnsPacket3.getLayerOfType<pcpp::DnsLayer>();
	dnsOverTcpLayer = dnsPacket3.getLayerOfType<pcpp::DnsOverTcpLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswerCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAuthorityCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecordCount(), 0);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0x38, hex);
	PTF_ASSERT_EQUAL(dnsOverTcpLayer->getTcpMessageLength(), 44);

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsOverTcpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(), R"({"protocolName":"DNS","protocolId":13,"length":46,"transactionID":"0x38","isResponse":true,)"
		               R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		               R"("recursionAvailable":true,"authenticData":false,"checkingDisabled":false,"responseCode":0,)"
		               R"("queries":[{"name":"github.com","type":1,"typeName":"A","class":1}],)"
		               R"("answers":[{"name":"github.com","type":1,"typeName":"A","class":1,"ttl":32,"dataLength":4,)"
		               R"("data":"192.30.255.113"}],"authorities":[],"additionalRecords":[],"tcpMessageLength":44})");
	}

	pcpp::DnsResource* answer = dnsLayer->getFirstAnswer();
	PTF_ASSERT_EQUAL(answer->getName(), "github.com");
	PTF_ASSERT_EQUAL(answer->getData().castAs<pcpp::IPv4DnsResourceData>()->getIpAddress().toString(),
	                 "192.30.255.113");
}  // DnsOverTcpParsingTest

PTF_TEST_CASE(DnsOverTcpCreationTest)
{
	auto rawPacketAndBuf = createPacketAndBufferFromHexResource("PacketExamples/dns_over_tcp_answer2.dat");
	auto& resource1 = rawPacketAndBuf.resourceBuffer;
	auto& rawPacket1 = rawPacketAndBuf.packet;

	pcpp::DnsOverTcpLayer newDnsLayer;
	newDnsLayer.getDnsHeader()->transactionID = htobe16(0x38);
	newDnsLayer.getDnsHeader()->queryOrResponse = 1;
	newDnsLayer.getDnsHeader()->recursionDesired = 1;
	newDnsLayer.getDnsHeader()->recursionAvailable = 1;
	newDnsLayer.addQuery("github.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	pcpp::IPv4DnsResourceData ipv4Answer("192.30.255.113");
	newDnsLayer.addAnswer("github.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 32, &ipv4Answer);

	pcpp::Packet dnsPacket(rawPacket1.get());
	dnsPacket.removeLayer(pcpp::DNS);

	dnsPacket.addLayer(&newDnsLayer);
	dnsPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(resource1.length, dnsPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(dnsPacket.getRawPacket()->getRawData(), resource1.data.get(), resource1.length);
}  // DnsOverTcpCreationTest

PTF_TEST_CASE(DnsNXDomainTest)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/DNS_NXDomain.dat");
	pcpp::Packet dnsPacket(rawPacket1.get());

	pcpp::DnsLayer* dnsLayer = dnsPacket.getLayerOfType<pcpp::DnsLayer>();

	PTF_ASSERT_EQUAL(1, dnsLayer->getDnsHeader()->queryOrResponse);

	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		dnsLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"DNS","protocolId":13,"length":27,"transactionID":"0x7e51","isResponse":true,)"
		    R"("opcode":0,"authoritativeAnswer":false,"truncation":false,"recursionDesired":true,)"
		    R"("recursionAvailable":true,"authenticData":false,"checkingDisabled":false,"responseCode":3,)"
		    R"("queries":[{"name":"htb.local","type":1,"typeName":"A","class":1}],"answers":[],"authorities":[],)"
		    R"("additionalRecords":[]})");
	}
}  // DnsNXDomainTest
