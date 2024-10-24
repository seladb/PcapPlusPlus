#include "../TestDefinition.h"
#include "../Common/PcapFileNamesDef.h"
#include <sstream>
#include <fstream>
#include "Packet.h"
#include "HttpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"

PTF_TEST_CASE(TestHttpRequestParsing)
{
	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_REQUEST);
	PTF_ASSERT_TRUE(readerDev.open());

	pcpp::RawPacket rawPacket;
	int packetCount = 0;

	int httpPackets = 0;
	int getReqs = 0;
	int postReqs = 0;
	int headReqs = 0;
	int optionsReqs = 0;
	int otherMethodReqs = 0;

	int swfReqs = 0;
	int homeReqs = 0;

	int winwinReqs = 0;
	int yad2Reqs = 0;
	int googleReqs = 0;

	int ieReqs = 0;
	int ffReqs = 0;
	int chromeReqs = 0;

	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::HTTPRequest))
			httpPackets++;
		else
			continue;

		pcpp::HttpRequestLayer* httpReqLayer = packet.getLayerOfType<pcpp::HttpRequestLayer>();
		PTF_ASSERT_NOT_NULL(httpReqLayer->getFirstLine());
		switch (httpReqLayer->getFirstLine()->getMethod())
		{
		case pcpp::HttpRequestLayer::HttpGET:
			getReqs++;
			break;
		case pcpp::HttpRequestLayer::HttpPOST:
			postReqs++;
			break;
		case pcpp::HttpRequestLayer::HttpOPTIONS:
			optionsReqs++;
			break;
		case pcpp::HttpRequestLayer::HttpHEAD:
			headReqs++;
			break;
		default:
			otherMethodReqs++;
		}

		if (httpReqLayer->getFirstLine()->isComplete())
		{
			PTF_ASSERT_EQUAL(httpReqLayer->getFirstLine()->getVersion(), pcpp::OneDotOne, enum);
		}

		if (httpReqLayer->getFirstLine()->getUri().find(".swf") != std::string::npos)
			swfReqs++;
		else if (httpReqLayer->getFirstLine()->getUri().find("home") != std::string::npos)
			homeReqs++;

		pcpp::HeaderField* hostField = httpReqLayer->getFieldByName("Host");
		if (hostField != nullptr)
		{
			std::string host = hostField->getFieldValue();
			if (host == "www.winwin.co.il")
				winwinReqs++;
			else if (host == "www.yad2.co.il")
				yad2Reqs++;
			else if (host == "www.google.com")
				googleReqs++;
		}

		pcpp::HeaderField* userAgentField = httpReqLayer->getFieldByName("User-Agent");
		if (userAgentField == nullptr)
			continue;

		std::string userAgent = userAgentField->getFieldValue();
		if (userAgent.find("Trident/7.0") != std::string::npos)
			ieReqs++;
		else if (userAgent.find("Firefox/33.0") != std::string::npos)
			ffReqs++;
		else if (userAgent.find("Chrome/38.0") != std::string::npos)
			chromeReqs++;
	}

	readerDev.close();

	PTF_ASSERT_EQUAL(packetCount, 385);

	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " ||
	// tcp contains "HEAD " || tcp contains "OPTIONS ")
	PTF_ASSERT_EQUAL(httpPackets, 385);

	PTF_ASSERT_EQUAL(otherMethodReqs, 0);

	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET ")
	PTF_ASSERT_EQUAL(getReqs, 217);
	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "POST ")
	PTF_ASSERT_EQUAL(postReqs, 156);
	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "OPTIONS ")
	PTF_ASSERT_EQUAL(optionsReqs, 7);
	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "HEAD ")
	PTF_ASSERT_EQUAL(headReqs, 5);

	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST ") &&
	// (tcp matches "home.*HTTP/1.1")
	PTF_ASSERT_EQUAL(homeReqs, 13);
	// Wireshark filter: http.request.full_uri contains .swf
	PTF_ASSERT_EQUAL(swfReqs, 4);

	// Wireshark filter: tcp contains "Host: www.google.com"
	PTF_ASSERT_EQUAL(googleReqs, 12);
	// Wireshark filter: tcp contains "Host: www.yad2.co.il"
	PTF_ASSERT_EQUAL(yad2Reqs, 15);
	// Wireshark filter: tcp contains "Host: www.winwin.co.il"
	PTF_ASSERT_EQUAL(winwinReqs, 20);

	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " ||
	// tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Firefox/33.0")
	PTF_ASSERT_EQUAL(ffReqs, 233);
	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " ||
	// tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Chrome/38.0")
	PTF_ASSERT_EQUAL(chromeReqs, 82);
	// Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " ||
	// tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Trident/7.0")
	PTF_ASSERT_EQUAL(ieReqs, 55);
}  // TestHttpRequestParsing

PTF_TEST_CASE(TestHttpResponseParsing)
{
	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_RESPONSE);
	PTF_ASSERT_TRUE(readerDev.open());

	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int httpResponsePackets = 0;

	int http200OKCounter = 0;
	int http302Counter = 0;
	int http304NotModifiedCounter = 0;

	int textHtmlCount = 0;
	int imageCount = 0;
	int gzipCount = 0;
	int chunkedCount = 0;

	int bigResponses = 0;

	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::HTTPResponse))
			httpResponsePackets++;
		else
			continue;

		pcpp::HttpResponseLayer* httpResLayer = packet.getLayerOfType<pcpp::HttpResponseLayer>();
		PTF_ASSERT_NOT_NULL(httpResLayer->getFirstLine());

		if (httpResLayer->getFirstLine()->getStatusCode() == pcpp::HttpResponseStatusCode::Http200OK)
		{
			http200OKCounter++;
		}
		else if (httpResLayer->getFirstLine()->getStatusCode() == pcpp::HttpResponseStatusCode::Http302)
		{
			http302Counter++;
		}
		else if (httpResLayer->getFirstLine()->getStatusCode() == pcpp::HttpResponseStatusCode::Http304NotModified)
		{
			http304NotModifiedCounter++;
		}

		pcpp::HeaderField* contentTypeField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		if (contentTypeField != nullptr)
		{
			std::string contentType = contentTypeField->getFieldValue();
			if (contentType.find("image/") != std::string::npos)
				imageCount++;
			else if (contentType == "text/html")
				textHtmlCount++;
		}

		pcpp::HeaderField* contentEncodingField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_ENCODING_FIELD);
		if (contentEncodingField != nullptr && contentEncodingField->getFieldValue() == "gzip")
			gzipCount++;

		pcpp::HeaderField* transferEncodingField = httpResLayer->getFieldByName(PCPP_HTTP_TRANSFER_ENCODING_FIELD);
		if (transferEncodingField != nullptr && transferEncodingField->getFieldValue() == "chunked")
			chunkedCount++;

		pcpp::HeaderField* contentLengthField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
		if (contentLengthField != nullptr)
		{
			std::string lengthAsString = contentLengthField->getFieldValue();
			int length = atoi(lengthAsString.c_str());
			if (length > 100000)
				bigResponses++;
		}
	}

	PTF_ASSERT_EQUAL(packetCount, 682);

	// *** wireshark has a bug there and displays 1 less packet as http response. Missing packet IP ID is 10419 ***
	// ************************************************************************************************************

	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080)
	PTF_ASSERT_EQUAL(httpResponsePackets, 682);
	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 200
	PTF_ASSERT_EQUAL(http200OKCounter, 592);
	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 302
	PTF_ASSERT_EQUAL(http302Counter, 15);
	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 304
	PTF_ASSERT_EQUAL(http304NotModifiedCounter, 26);

	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type == "text/html"
	PTF_ASSERT_EQUAL(textHtmlCount, 38);
	// wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type contains
	// "image/"
	PTF_ASSERT_EQUAL(imageCount, 369);

	// wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && (tcp contains
	// "Transfer-Encoding:  chunked" || tcp contains "Transfer-Encoding: chunked" || tcp contains "transfer-encoding:
	// chunked")
	PTF_ASSERT_EQUAL(chunkedCount, 45);
	// wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && tcp contains
	// "Content-Encoding: gzip"
	PTF_ASSERT_EQUAL(gzipCount, 148);

	// wireshark filter: http.content_length > 100000
	PTF_ASSERT_EQUAL(bigResponses, 14);

}  // TestHttpResponseParsing

PTF_TEST_CASE(TestPrintPacketAndLayers)
{
	pcpp::PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacket rawPacket;
	std::ostringstream outputStream;
	while (reader.getNextPacket(rawPacket))
	{
		pcpp::Packet packet(&rawPacket);
		outputStream << packet.toString(false) << "\n\n";
	}

	// std::ofstream outputFile("output.txt");
	// outputFile << outputStream.str();
	// outputFile.close();

	std::ifstream referenceFile("PcapExamples/example2_summary.txt");
	std::stringstream referenceBuffer;
	referenceBuffer << referenceFile.rdbuf();
	referenceFile.close();

	// example2_summary.txt was written with Windows so every '\n' is translated to '\r\n'
	// in Linux '\n' stays '\n' in writing to files. So these lines of code are meant to remove the '\r' so
	// files can be later compared
	std::string referenceBufferAsString = referenceBuffer.str();
	size_t index = 0;
	while (true)
	{
		index = referenceBufferAsString.find("\r\n", index);
		if (index == std::string::npos)
			break;
		referenceBufferAsString.replace(index, 2, "\n");
		index += 1;
	}

	PTF_ASSERT_EQUAL(referenceBufferAsString, outputStream.str());
}  // TestPrintPacketAndLayers

PTF_TEST_CASE(TestDnsParsing)
{
	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_DNS);
	PTF_ASSERT_TRUE(readerDev.open());

	pcpp::RawPacket rawPacket;
	int dnsPackets = 0;

	int packetsContainingDnsQuery = 0;
	int packetsContainingDnsAnswer = 0;
	int packetsContainingDnsAuthority = 0;
	int packetsContainingDnsAdditional = 0;

	int queriesWithNameGoogle = 0;
	int queriesWithNameMozillaOrg = 0;  // aus3.mozilla.org
	int queriesWithTypeA = 0;
	int queriesWithTypeNotA = 0;
	int queriesWithClassIN = 0;

	int answersWithTypeCNAME = 0;
	int answersWithTypePTR = 0;
	int answersWithNameGoogleAnalytics = 0;
	int answersWithTtlLessThan30 = 0;
	int answersWithDataCertainIPv6 = 0;

	int authoritiesWithNameYaelPhone = 0;
	int authoritiesWithData10_0_0_2 = 0;

	int additionalWithEmptyName = 0;
	int additionalWithLongUglyName = 0;
	int additionalWithTypeNSEC = 0;

	while (readerDev.getNextPacket(rawPacket))
	{
		dnsPackets++;
		pcpp::Packet packet(&rawPacket);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::DNS));

		pcpp::DnsLayer* dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
		if (dnsLayer->getQueryCount() > 0)
		{
			packetsContainingDnsQuery++;

			if (dnsLayer->getQuery("aus3.mozilla.org", true) != nullptr)
				queriesWithNameMozillaOrg++;
			if (dnsLayer->getQuery("www.google.com", true) != nullptr)
				queriesWithNameGoogle++;

			bool isTypeA = false;
			bool isClassIN = false;

			for (pcpp::DnsQuery* query = dnsLayer->getFirstQuery(); query != nullptr;
			     query = dnsLayer->getNextQuery(query))
			{
				if (query->getDnsType() == pcpp::DNS_TYPE_A)
					isTypeA = true;
				if (query->getDnsClass() == pcpp::DNS_CLASS_IN || query->getDnsClass() == pcpp::DNS_CLASS_IN_QU)
					isClassIN = true;
			}

			if (isTypeA)
				queriesWithTypeA++;
			else
				queriesWithTypeNotA++;
			if (isClassIN)
				queriesWithClassIN++;
		}

		if (dnsLayer->getAnswerCount() > 0)
		{
			packetsContainingDnsAnswer++;

			if (dnsLayer->getAnswer("www.google-analytics.com", true) != nullptr)
				answersWithNameGoogleAnalytics++;

			bool isTypeCNAME = false;
			bool isTypePTR = false;
			bool isTtlLessThan30 = false;

			for (pcpp::DnsResource* answer = dnsLayer->getFirstAnswer(); answer != nullptr;
			     answer = dnsLayer->getNextAnswer(answer))
			{
				if (answer->getTTL() < 30)
					isTtlLessThan30 = true;
				if (answer->getDnsType() == pcpp::DNS_TYPE_CNAME)
					isTypeCNAME = true;
				if (answer->getDnsType() == pcpp::DNS_TYPE_PTR)
					isTypePTR = true;
				if (answer->getData()->toString() == "fe80::5a1f:aaff:fe4f:3f9d")
					answersWithDataCertainIPv6++;
			}

			if (isTypeCNAME)
				answersWithTypeCNAME++;
			if (isTypePTR)
				answersWithTypePTR++;
			if (isTtlLessThan30)
				answersWithTtlLessThan30++;
		}

		if (dnsLayer->getAuthorityCount() > 0)
		{
			packetsContainingDnsAuthority++;

			if (dnsLayer->getAuthority("Yaels-iPhone.local", true) != nullptr)
				authoritiesWithNameYaelPhone++;

			for (pcpp::DnsResource* auth = dnsLayer->getFirstAuthority(); auth != nullptr;
			     auth = dnsLayer->getNextAuthority(auth))
			{
				if (auth->getData()->toString() == "10.0.0.2")
				{
					authoritiesWithData10_0_0_2++;
					break;
				}
			}
		}

		if (dnsLayer->getAdditionalRecordCount() > 0)
		{
			packetsContainingDnsAdditional++;

			if (dnsLayer->getAdditionalRecord("", true) != nullptr)
				additionalWithEmptyName++;

			if (dnsLayer->getAdditionalRecord(
			        "D.9.F.3.F.4.E.F.F.F.A.A.F.1.A.5.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa", true) != nullptr)
				additionalWithLongUglyName++;

			bool isTypeNSEC = false;

			for (pcpp::DnsResource* add = dnsLayer->getFirstAdditionalRecord(); add != nullptr;
			     add = dnsLayer->getNextAdditionalRecord(add))
			{
				if (add->getDnsType() == pcpp::DNS_TYPE_NSEC)
					isTypeNSEC = true;
			}

			if (isTypeNSEC)
				additionalWithTypeNSEC++;
		}
	}

	PTF_ASSERT_EQUAL(dnsPackets, 464);

	// wireshark filter: dns.count.queries > 0
	PTF_ASSERT_EQUAL(packetsContainingDnsQuery, 450);
	// wireshark filter: dns.count.answers > 0
	PTF_ASSERT_EQUAL(packetsContainingDnsAnswer, 224);
	// wireshark filter: dns.count.auth_rr > 0
	PTF_ASSERT_EQUAL(packetsContainingDnsAuthority, 11);
	// wireshark filter: dns.count.add_rr > 0
	PTF_ASSERT_EQUAL(packetsContainingDnsAdditional, 23);

	// wireshark filter: dns.qry.name == www.google.com
	PTF_ASSERT_EQUAL(queriesWithNameGoogle, 14);
	// wireshark filter: dns.qry.name == aus3.mozilla.org
	PTF_ASSERT_EQUAL(queriesWithNameMozillaOrg, 2);
	// wireshark filter: dns.qry.type == 1
	PTF_ASSERT_EQUAL(queriesWithTypeA, 436);
	// wireshark filter: dns.qry.type > 0 and not (dns.qry.type == 1)
	PTF_ASSERT_EQUAL(queriesWithTypeNotA, 14);
	// wireshark filter: dns.qry.class == 1
	PTF_ASSERT_EQUAL(queriesWithClassIN, 450);

	// wireshark filter: dns.count.answers > 0 and dns.resp.type == 12
	PTF_ASSERT_EQUAL(answersWithTypePTR, 14);
	// wireshark filter: dns.count.answers > 0 and dns.resp.type == 5
	PTF_ASSERT_EQUAL(answersWithTypeCNAME, 90);
	// wireshark filter: dns.count.answers > 0 and dns.resp.name == www.google-analytics.com
	PTF_ASSERT_EQUAL(answersWithNameGoogleAnalytics, 7);
	// wireshark filter: dns.count.answers > 0 and dns.aaaa == fe80::5a1f:aaff:fe4f:3f9d
	PTF_ASSERT_EQUAL(answersWithDataCertainIPv6, 12);
	// wireshark filter: dns.count.answers > 0 and dns.resp.ttl < 30
	PTF_ASSERT_EQUAL(answersWithTtlLessThan30, 17);

	// wireshark filter: dns.count.auth_rr > 0 and dns.resp.name == Yaels-iPhone.local
	PTF_ASSERT_EQUAL(authoritiesWithNameYaelPhone, 9);
	// wireshark filter: dns.count.auth_rr > 0 and dns.a == 10.0.0.2
	PTF_ASSERT_EQUAL(authoritiesWithData10_0_0_2, 9);

	// wireshark filter: dns.count.add_rr > 0 and dns.resp.name == "<Root>"
	PTF_ASSERT_EQUAL(additionalWithEmptyName, 23);
	// wireshark filter: dns.count.add_rr > 0 and dns.resp.name ==
	// D.9.F.3.F.4.E.F.F.F.A.A.F.1.A.5.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
	PTF_ASSERT_EQUAL(additionalWithLongUglyName, 12);
	// wireshark filter: dns.count.add_rr > 0 and dns.resp.type == 47
	PTF_ASSERT_EQUAL(additionalWithTypeNSEC, 14);
}  // TestDnsParsing
