#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "NtpLayer.h"
#include "SystemUtils.h"

#include <math.h>

#define EPSILON 1e-6
#define EPOCH_OFFSET 2208988800ULL

PTF_TEST_CASE(NtpMethodsTests)
{
	double val = 12345.125;
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertFromTimestampFormat(pcpp::NtpLayer::convertToTimestampFormat(val)), val);
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertFromShortFormat(pcpp::NtpLayer::convertToShortFormat(val)), val);

	// First check the epoch is correct
#if defined(_WIN32)
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(0.0), std::string("1970-01-01T00:00:00.0000Z"));
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(uint64_t(0)), std::string("1970-01-01T00:00:00.0000Z"));
#else
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(0.0), std::string("1970-01-01T00:00:00.0000Z"));
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(uint64_t(0)), std::string("1900-01-01T00:00:00.0000Z"));
#endif

	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(1642879410.0), "2022-01-22T19:23:30.0000Z");
	PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(pcpp::NtpLayer::convertToTimestampFormat(1642879410.0)),
	                 "2022-01-22T19:23:30.0000Z");

}  // NtpMethodsTests

PTF_TEST_CASE(NtpParsingV3Tests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv3.dat");

	pcpp::Packet ntpPacket(&rawPacket1);
	pcpp::NtpLayer* ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

	PTF_ASSERT_NOT_NULL(ntpLayer);
	PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 3);
	PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NtpLayer::NoWarning);
	PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NtpLayer::Server);
	PTF_ASSERT_EQUAL(ntpLayer->getModeString(), "Server");
	PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 4);
	PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), int8_t(-6));
	// NTPv3 pcap is a bit useless, too many zeros but these fields same with v4
	PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestamp(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), be64toh(0xd94f4f1100000000));
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), be64toh(0xd94f4f1100000000));
	PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v3, Mode: Server");

	// Since they are double it may or may not equal
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPollIntervalInSecs() - 16), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPrecisionInSecs() - 0.015625), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDelayInSecs() - 0), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDispersionInSecs() - 0), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReferenceTimestampInSecs() - -double(EPOCH_OFFSET)), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getOriginTimestampInSecs() - -double(EPOCH_OFFSET)), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReceiveTimestampInSecs() - 1436864657.0), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getTransmitTimestampInSecs() - 1436864657.0), EPSILON);

#if defined(_WIN32)
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestampAsString(), "1970-01-01T00:00:00.0000Z");
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "1970-01-01T00:00:00.0000Z");
#else
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestampAsString(), "1900-01-01T00:00:00.0000Z");
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "1900-01-01T00:00:00.0000Z");
#endif

	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestampAsString(), "2015-07-14T09:04:17.0000Z");
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestampAsString(), "2015-07-14T09:04:17.0000Z");

}  // NtpParsingV3Tests

PTF_TEST_CASE(NtpParsingV4Tests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv4.dat");

	// Test Ipv4
	pcpp::Packet ntpPacket(&rawPacket1);
	pcpp::NtpLayer* ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

	PTF_ASSERT_NOT_NULL(ntpLayer);
	PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
	PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NtpLayer::NoWarning);
	PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NtpLayer::Client);
	PTF_ASSERT_EQUAL(ntpLayer->getModeString(), "Client");
	PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 2);
	PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 7);
	PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), int8_t(0xeb));
	PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), be32toh(0x450));
	PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), be32toh(0x3ab));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), be32toh(0x83bc03df));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifierString(), "131.188.3.223");
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), be64toh(0xd94f51c33165b860));
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestamp(), be64toh(0xd944575530336fd0));
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), be64toh(0xd944575531b4e978));
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), be64toh(0xd94f51f42d26e2f4));
	PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v4, Mode: Client");

	// Since they are double it may or may not equal
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPollIntervalInSecs() - 128), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPrecisionInSecs() - 0.0000004), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDelayInSecs() - 0.0168457), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDispersionInSecs() - 0.014328), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReferenceTimestampInSecs() - 1436865347.192958377), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getOriginTimestampInSecs() - 1436145877.188284862), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReceiveTimestampInSecs() - 1436145877.194166747), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getTransmitTimestampInSecs() - 1436865396.176374611), EPSILON);

	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestampAsString(), "2015-07-14T09:15:47.1930Z");
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "2015-07-06T01:24:37.1883Z");
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestampAsString(), "2015-07-06T01:24:37.1942Z");
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestampAsString(), "2015-07-14T09:16:36.1764Z");

	// Test Ipv6
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ntpv4Ipv6_withAuth.dat");

	ntpPacket = pcpp::Packet(&rawPacket2);
	ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

	PTF_ASSERT_NOT_NULL(ntpLayer);
	PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
	PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NtpLayer::NoWarning);
	PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NtpLayer::Client);
	PTF_ASSERT_EQUAL(ntpLayer->getModeString(), "Client");
	PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 2);
	PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 6);
	PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), int8_t(0xe8));
	PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), be32toh(0x91));
	PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), be32toh(0x6b7));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), be32toh(0xb6a580db));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifierString(), "182.165.128.219");
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), be64toh(0xdcd2a7d77a05d46a));
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestamp(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), be64toh(0xdcd2aa817b9f9bdc));
	PTF_ASSERT_EQUAL(ntpLayer->getKeyID(), be32toh(1));
	PTF_ASSERT_EQUAL(ntpLayer->getDigest(), "ac017b69915ce5a7a9fb73ac8bd1603b");  // MD5
	PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v4, Mode: Client");

	// Since they are double it may or may not equal
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPollIntervalInSecs() - 64), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPrecisionInSecs() - 0.000000059), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDelayInSecs() - 0.002213), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDispersionInSecs() - 0.02623), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReferenceTimestampInSecs() - 1495804247.476651454), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getOriginTimestampInSecs() - -double(EPOCH_OFFSET)), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReceiveTimestampInSecs() - -double(EPOCH_OFFSET)), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getTransmitTimestampInSecs() - 1495804929.482904187), EPSILON);

	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestampAsString(), "2017-05-26T13:10:47.4767Z");
#if defined(_WIN32)
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "1970-01-01T00:00:00.0000Z");
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestampAsString(), "1970-01-01T00:00:00.0000Z");
#else
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "1900-01-01T00:00:00.0000Z");
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestampAsString(), "1900-01-01T00:00:00.0000Z");
#endif
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestampAsString(), "2017-05-26T13:22:09.4829Z");

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ntpv4Ipv6_withAuth2.dat");

	ntpPacket = pcpp::Packet(&rawPacket3);
	ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

	PTF_ASSERT_NOT_NULL(ntpLayer);
	PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
	PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NtpLayer::NoWarning);
	PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NtpLayer::Server);
	PTF_ASSERT_EQUAL(ntpLayer->getModeString(), "Server");
	PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 1);
	PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 10);
	PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), int8_t(0xee));
	PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), 0);
	PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), be32toh(0xfb));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), static_cast<uint32_t>(pcpp::NtpLayer::ClockSource::DCFa));
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifierString(), "Meinberg DCF77 with amplitude modulation");
	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), be64toh(0xdcd2aabfe3771e96));
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestamp(), be64toh(0xdcd2aae48e835d2a));
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), be64toh(0xdcd2aae48e9f4d3c));
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), be64toh(0xdcd2aae48ece4367));
	PTF_ASSERT_EQUAL(ntpLayer->getKeyID(), be32toh(0xb));
	PTF_ASSERT_EQUAL(ntpLayer->getDigest(), "ece2d5b07e9fc63279aa2322b76038e53cd0ecc6");  // SHA1
	PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v4, Mode: Server");

	// Since they are double it may or may not equal
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPollIntervalInSecs() - 1024), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getPrecisionInSecs() - 0.0000038), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDelayInSecs() - 0.0), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getRootDispersionInSecs() - 0.00383), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReferenceTimestampInSecs() - 1495804991.888536368), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getOriginTimestampInSecs() - 1495805028.556691954), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getReceiveTimestampInSecs() - 1495805028.55711825), EPSILON);
	PTF_ASSERT_LOWER_THAN(fabs(ntpLayer->getTransmitTimestampInSecs() - 1495805028.557834828), EPSILON);

	PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestampAsString(), "2017-05-26T13:23:11.8885Z");
	PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestampAsString(), "2017-05-26T13:23:48.5567Z");
	PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestampAsString(), "2017-05-26T13:23:48.5571Z");
	PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestampAsString(), "2017-05-26T13:23:48.5578Z");
}  // NtpParsingV4Tests

PTF_TEST_CASE(NtpCreationTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv4.dat");

	pcpp::Packet ntpPacket(&rawPacket1);

	pcpp::EthLayer ethLayer(*ntpPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer(*ntpPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer(*ntpPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::NtpLayer ntpLayer;

	// Set the values
	ntpLayer.setVersion(4);
	ntpLayer.setLeapIndicator(pcpp::NtpLayer::NoWarning);
	ntpLayer.setMode(pcpp::NtpLayer::Client);
	ntpLayer.setStratum(2);
	ntpLayer.setPollInterval(7);
	ntpLayer.setPrecision(int8_t(0xeb));
	ntpLayer.setRootDelay(be32toh(0x450));
	ntpLayer.setRootDispersion(be32toh(0x3ab));
	ntpLayer.setReferenceIdentifier(pcpp::IPv4Address("131.188.3.223"));
	ntpLayer.setReferenceTimestamp(be64toh(0xd94f51c33165b860));
	ntpLayer.setOriginTimestamp(be64toh(0xd944575530336fd0));
	ntpLayer.setReceiveTimestamp(be64toh(0xd944575531b4e978));
	ntpLayer.setTransmitTimestamp(be64toh(0xd94f51f42d26e2f4));

	pcpp::Packet craftedPacket;
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&ipv4Layer));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&udpLayer));
	craftedPacket.addLayer(&ntpLayer);

	PTF_ASSERT_EQUAL(bufferLength1, craftedPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer1, craftedPacket.getRawPacket()->getRawData(), bufferLength1);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ntpv3crafting.dat");

	pcpp::Packet ntpPacket2(&rawPacket2);

	pcpp::EthLayer ethLayer2(*ntpPacket2.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer2(*ntpPacket2.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer2(*ntpPacket2.getLayerOfType<pcpp::UdpLayer>());

	pcpp::NtpLayer ntpLayer2;

	// Set the values
	ntpLayer2.setVersion(3);
	ntpLayer2.setLeapIndicator(pcpp::NtpLayer::NoWarning);
	ntpLayer2.setMode(pcpp::NtpLayer::Server);
	ntpLayer2.setStratum(1);
	ntpLayer2.setPollInterval(10);
	ntpLayer2.setPrecision(int8_t(0xfa));
	ntpLayer2.setRootDelayInSecs(0.031250);
	ntpLayer2.setRootDispersionInSecs(0.125);
	ntpLayer2.setReferenceIdentifier(pcpp::NtpLayer::ClockSource::DCFa);
	ntpLayer2.setReferenceTimestampInSecs(1121509470.0);
	ntpLayer2.setOriginTimestampInSecs(1121509866.0);
	ntpLayer2.setReceiveTimestampInSecs(1121509865.0);
	ntpLayer2.setTransmitTimestampInSecs(1121509865.0);

	pcpp::Packet craftedPacket2;
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ipv4Layer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&udpLayer2));
	craftedPacket2.addLayer(&ntpLayer2);

	PTF_ASSERT_EQUAL(bufferLength2, craftedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer2, craftedPacket2.getRawPacket()->getRawData(), bufferLength2);
}  // NtpCraftingTests
