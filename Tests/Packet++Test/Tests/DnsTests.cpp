#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include <sstream>
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(DnsLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Dns3.dat");

	pcpp::Packet dnsPacket(&rawPacket1);

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

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Dns1.dat");

	pcpp::Packet dnsPacket2(&rawPacket2);

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

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/Dns2.dat");

	pcpp::Packet dnsPacket3(&rawPacket3);

	dnsLayer = dnsPacket3.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	queryByName = dnsLayer->getQuery(std::string("Yaels-iPhone.loca"), false);
	PTF_ASSERT_NOT_NULL(queryByName);
	PTF_ASSERT_EQUAL(queryByName->getDnsClass(), pcpp::DNS_CLASS_IN_QU, enum);

	PTF_ASSERT_EQUAL(dnsLayer->toString(),
	                 "DNS query, ID: 0; queries: 2, answers: 0, authorities: 2, additional record: 1");

	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/Dns4.dat");

	pcpp::Packet dnsPacket4(&rawPacket4);
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

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/dns_stack_overflow.dat");

	pcpp::Packet dnsPacket5(&rawPacket5);

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

	// a corner case of malformed packet where the total number of resources overflow uint16
	// by less than 300. This fixes the bug: https://github.com/seladb/PcapPlusPlus/issues/441
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/DnsTooManyResources.dat");
	pcpp::Logger::getInstance().suppressLogs();
	pcpp::Packet dnsPacket6(&rawPacket6);
	pcpp::Logger::getInstance().enableLogs();
	dnsLayer = dnsPacket6.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NULL(dnsLayer->getFirstQuery());
	PTF_ASSERT_NULL(dnsLayer->getFirstAnswer());
	PTF_ASSERT_NULL(dnsLayer->getFirstAuthority());
	PTF_ASSERT_NULL(dnsLayer->getFirstAdditionalRecord());
}  // DnsLayerParsingTest

PTF_TEST_CASE(DnsLayerQueryCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/DnsEdit2.dat");

	pcpp::Packet dnsEdit2RefPacket(&rawPacket2);

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

	PTF_ASSERT_EQUAL(bufferLength2, dnsEdit2Packet.getRawPacket()->getRawDataLen());

	PTF_ASSERT_BUF_COMPARE(dnsEdit2Packet.getRawPacket()->getRawData(), buffer2, bufferLength2);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DnsEdit1.dat");

	pcpp::Packet dnsEdit1RefPacket(&rawPacket1);

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

	PTF_ASSERT_EQUAL(dnsEdit1Packet.getRawPacket()->getRawDataLen(), bufferLength1);

	PTF_ASSERT_BUF_COMPARE(dnsEdit1Packet.getRawPacket()->getRawData(), buffer1, bufferLength1);
}  // DnsLayerQueryCreationTest

PTF_TEST_CASE(DnsLayerResourceCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/DnsEdit4.dat");

	pcpp::Packet dnsEdit4RefPacket(&rawPacket4);

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
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(thirdAnswer->setData(nullptr));
	pcpp::Logger::getInstance().enableLogs();
	ipv4DnsData = pcpp::IPv4DnsResourceData(std::string("151.249.90.238"));
	PTF_ASSERT_TRUE(thirdAnswer->setData(&ipv4DnsData));

	PTF_ASSERT_EQUAL(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", true)->getData()->toString(),
	                 "151.249.90.217");
	PTF_ASSERT_EQUAL(
	    dns4Layer.getNextAnswer(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", false))->getData()->toString(),
	    "151.249.90.238");

	dnsEdit4Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit4Packet.getRawPacket()->getRawDataLen(), bufferLength4);

	PTF_ASSERT_BUF_COMPARE(dnsEdit4Packet.getRawPacket()->getRawData(), buffer4, bufferLength4);

	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/DnsEdit6.dat");

	pcpp::Packet dnsEdit6RefPacket(&rawPacket6);

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
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(authority->setData(nullptr));
	pcpp::Logger::getInstance().enableLogs();
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
	pcpp::Logger::getInstance().suppressLogs();
	genericData = pcpp::GenericDnsResourceData("a0123");
	PTF_ASSERT_FALSE(additional->setData(&genericData));
	genericData = pcpp::GenericDnsResourceData("a01j34");
	PTF_ASSERT_FALSE(additional->setData(&genericData));
	pcpp::Logger::getInstance().enableLogs();

	dnsEdit6Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(dnsEdit6Packet.getRawPacket()->getRawDataLen(), bufferLength6);

	PTF_ASSERT_BUF_COMPARE(dnsEdit6Packet.getRawPacket()->getRawData(), buffer6, bufferLength6);

	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/DnsEdit7.dat");

	pcpp::Packet dnsEdit7RefPacket(&rawPacket7);

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

	PTF_ASSERT_EQUAL(dnsEdit7Packet.getRawPacket()->getRawDataLen(), bufferLength7);

	PTF_ASSERT_BUF_COMPARE(dnsEdit7Packet.getRawPacket()->getRawData(), buffer7, bufferLength7);
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
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/DnsEdit3.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/DnsEdit5.dat");
	pcpp::RawPacket raw3PacketCopy(rawPacket3);

	pcpp::Packet dnsEdit3(&rawPacket3);
	pcpp::Packet dnsEdit5(&rawPacket5);

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
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/DnsEdit6.dat");

	pcpp::Packet dnsEdit6Packet(&rawPacket6);

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

	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/DnsEdit4.dat");

	pcpp::Packet dnsEdit4Packet(&rawPacket4);

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

PTF_TEST_CASE(DnsOverTcpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dns_over_tcp_query.dat");
	pcpp::Packet dnsPacket(&rawPacket1);

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

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/dns_over_tcp_response.dat");
	pcpp::Packet dnsPacket2(&rawPacket2);

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

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/dns_over_tcp_answer.dat");
	pcpp::Packet dnsPacket3(&rawPacket3);

	dnsLayer = dnsPacket3.getLayerOfType<pcpp::DnsLayer>();
	dnsOverTcpLayer = dnsPacket3.getLayerOfType<pcpp::DnsOverTcpLayer>();
	PTF_ASSERT_NOT_NULL(dnsLayer);
	PTF_ASSERT_EQUAL(dnsLayer->getQueryCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAnswerCount(), 1);
	PTF_ASSERT_EQUAL(dnsLayer->getAuthorityCount(), 0);
	PTF_ASSERT_EQUAL(dnsLayer->getAdditionalRecordCount(), 0);
	PTF_ASSERT_EQUAL(be16toh(dnsLayer->getDnsHeader()->transactionID), 0x38, hex);
	PTF_ASSERT_EQUAL(dnsOverTcpLayer->getTcpMessageLength(), 44);

	pcpp::DnsResource* answer = dnsLayer->getFirstAnswer();
	PTF_ASSERT_EQUAL(answer->getName(), "github.com");
	PTF_ASSERT_EQUAL(answer->getData().castAs<pcpp::IPv4DnsResourceData>()->getIpAddress().toString(),
	                 "192.30.255.113");
}  // DnsOverTcpParsingTest

PTF_TEST_CASE(DnsOverTcpCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dns_over_tcp_answer2.dat");

	pcpp::DnsOverTcpLayer newDnsLayer;
	newDnsLayer.getDnsHeader()->transactionID = htobe16(0x38);
	newDnsLayer.getDnsHeader()->queryOrResponse = 1;
	newDnsLayer.getDnsHeader()->recursionDesired = 1;
	newDnsLayer.getDnsHeader()->recursionAvailable = 1;
	newDnsLayer.addQuery("github.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	pcpp::IPv4DnsResourceData ipv4Answer("192.30.255.113");
	newDnsLayer.addAnswer("github.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 32, &ipv4Answer);

	pcpp::Packet dnsPacket(&rawPacket1);
	dnsPacket.removeLayer(pcpp::DNS);

	dnsPacket.addLayer(&newDnsLayer);
	dnsPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength1, dnsPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(dnsPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);
}  // DnsOverTcpCreationTest

PTF_TEST_CASE(DnsNXDomainTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DNS_NXDomain.dat");
	pcpp::Packet dnsPacket(&rawPacket1);

	pcpp::DnsLayer* dnsLayer = dnsPacket.getLayerOfType<pcpp::DnsLayer>();

	PTF_ASSERT_EQUAL(1, dnsLayer->getDnsHeader()->queryOrResponse);
}  // DnsNXDomainTest
