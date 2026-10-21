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
#include <sstream>

#define EPSILON 1e-6
#define EPOCH_OFFSET 2208988800ULL

using pcpp_tests::utils::createPacketAndBufferFromHexResource;
using pcpp_tests::utils::createPacketFromHexResource;

#if defined(_WIN32)
static constexpr const char* zeroTimestamp = "1970-01-01T00:00:00.0000Z";
#else
static constexpr const char* zeroTimestamp = "1900-01-01T00:00:00.0000Z";
#endif

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

	// Serialize signed exponent boundaries and maximum timestamps without trailing raw data.
	auto data = std::make_unique<uint8_t[]>(53);
	std::fill(data.get(), data.get() + 53, 0xff);
	data[0] = 0xe4;  // LI=3, version=4, server mode
	data[2] = 0x80;
	data[3] = 0x80;
	pcpp::NtpLayer layer(data.release(), 53, nullptr, nullptr);
	std::ostringstream output;
	pcpp::JsonSerializer serializer(output);
	layer.serialize(serializer);
	PTF_ASSERT_EQUAL(
	    output.str(),
	    R"({"protocolName":"NTP","protocolId":39,"length":53,"leapIndicator":"Unknown","version":4,"mode":4,"modeName":"Server","stratum":255,"pollInterval":-128,"precision":-128,"rootDelay":4294967295,"rootDispersion":4294967295,"referenceIdentifier":"0xffffffff","referenceTimestamp":"2036-02-07T06:28:16.0000Z","originTimestamp":"2036-02-07T06:28:16.0000Z","receiveTimestamp":"2036-02-07T06:28:16.0000Z","transmitTimestamp":"2036-02-07T06:28:16.0000Z"})");
	const char* leapNames[] = { "No warning", "Last minute has 61 seconds", "Last minute has 59 seconds", "Unknown" };
	for (uint8_t indicator = 0; indicator < 4; ++indicator)
	{
		layer.setLeapIndicator(static_cast<pcpp::NtpLayer::LeapIndicator>(indicator));
		std::ostringstream leapOutput;
		pcpp::JsonSerializer leapSerializer(leapOutput);
		layer.serialize(leapSerializer);
		PTF_ASSERT_CONTAINS(leapOutput.str(), std::string("\"leapIndicator\":\"") + leapNames[indicator] + "\"");
	}

	// NTPv3 authentication: preserve network byte order and the complete DES digest.
	auto authData = std::make_unique<uint8_t[]>(60);
	std::fill(authData.get(), authData.get() + 60, 0);
	authData[0] = 0x1c;
	authData[48] = 0x12;
	authData[49] = 0x34;
	authData[50] = 0x56;
	authData[51] = 0x78;
	std::fill(authData.get() + 52, authData.get() + 60, 0xab);
	pcpp::NtpLayer authLayer(authData.release(), 60, nullptr, nullptr);
	std::ostringstream authOutput;
	pcpp::JsonSerializer authSerializer(authOutput);
	authLayer.serialize(authSerializer);
	PTF_ASSERT_CONTAINS(authOutput.str(), "\"keyID\":305419896");
	PTF_ASSERT_CONTAINS(authOutput.str(), "\"digest\":\"abababababababab\"");

	// Incomplete or unsupported NTPv4 authentication must be omitted without logging errors.
	for (size_t length : { 48, 49, 59, 60, 67, 69, 71, 73 })
	{
		auto shortData = std::make_unique<uint8_t[]>(length);
		std::fill(shortData.get(), shortData.get() + length, 0);
		shortData[0] = 0x24;
		pcpp::NtpLayer shortLayer(shortData.release(), length, nullptr, nullptr);
		std::ostringstream shortOutput;
		pcpp::JsonSerializer shortSerializer(shortOutput);
		shortLayer.serialize(shortSerializer);
		PTF_ASSERT_TRUE(shortOutput.str().find("\"keyID\"") == std::string::npos);
		PTF_ASSERT_TRUE(shortOutput.str().find("\"digest\"") == std::string::npos);
	}

}  // NtpMethodsTests

PTF_TEST_CASE(NtpParsingV3Tests)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/ntpv3.dat");

	pcpp::Packet ntpPacket(rawPacket1.get());
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

	{
		std::ostringstream output;
		pcpp::JsonSerializer serializer(output);
		ntpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    output.str(),
		    R"({"protocolName":"NTP","protocolId":39,"length":48,"leapIndicator":"No warning","version":3,"mode":4,"modeName":"Server","stratum":0,"pollInterval":4,"precision":-6,"rootDelay":0,"rootDispersion":0,"referenceIdentifier":"0x0","referenceTimestamp":")" +
		        std::string(zeroTimestamp) + R"(","originTimestamp":")" + std::string(zeroTimestamp) +
		        R"(","receiveTimestamp":"2015-07-14T09:04:17.0000Z","transmitTimestamp":"2015-07-14T09:04:17.0000Z"})");
	}
}  // NtpParsingV3Tests

PTF_TEST_CASE(NtpParsingV4Tests)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/ntpv4.dat");

	// Test Ipv4
	pcpp::Packet ntpPacket(rawPacket1.get());
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

	{
		std::ostringstream output;
		pcpp::JsonSerializer serializer(output);
		ntpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    output.str(),
		    R"({"protocolName":"NTP","protocolId":39,"length":48,"leapIndicator":"No warning","version":4,"mode":3,"modeName":"Client","stratum":2,"pollInterval":7,"precision":-21,"rootDelay":1104,"rootDispersion":939,"referenceIdentifier":"0x83bc03df","referenceTimestamp":"2015-07-14T09:15:47.1930Z","originTimestamp":"2015-07-06T01:24:37.1883Z","receiveTimestamp":"2015-07-06T01:24:37.1942Z","transmitTimestamp":"2015-07-14T09:16:36.1764Z"})");
	}

	// Test Ipv6
	auto rawPacket2 = createPacketFromHexResource("PacketExamples/ntpv4Ipv6_withAuth.dat");

	ntpPacket = pcpp::Packet(rawPacket2.get());
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

	{
		std::ostringstream output;
		pcpp::JsonSerializer serializer(output);
		ntpLayer->serialize(serializer);
		PTF_ASSERT_EQUAL(
		    output.str(),
		    R"({"protocolName":"NTP","protocolId":39,"length":68,"leapIndicator":"No warning","version":4,"mode":3,"modeName":"Client","stratum":2,"pollInterval":6,"precision":-24,"rootDelay":145,"rootDispersion":1719,"referenceIdentifier":"0xb6a580db","referenceTimestamp":"2017-05-26T13:10:47.4767Z","originTimestamp":")" +
		        std::string(zeroTimestamp) + R"(","receiveTimestamp":")" + std::string(zeroTimestamp) +
		        R"(","transmitTimestamp":"2017-05-26T13:22:09.4829Z","keyID":1,"digest":"ac017b69915ce5a7a9fb73ac8bd1603b"})");
	}

	auto rawPacket3 = createPacketFromHexResource("PacketExamples/ntpv4Ipv6_withAuth2.dat");

	ntpPacket = pcpp::Packet(rawPacket3.get());
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

	{
		std::ostringstream output;
		pcpp::JsonSerializer serializer(output);
		ntpLayer->serialize(serializer);
		PTF_ASSERT_CONTAINS(output.str(), "\"referenceIdentifier\":\"0x44434661\"");
		PTF_ASSERT_CONTAINS(output.str(), "\"keyID\":11");
		PTF_ASSERT_CONTAINS(output.str(), "\"digest\":\"ece2d5b07e9fc63279aa2322b76038e53cd0ecc6\"");
		const auto fields = pcpp::NtpLayer::SerializedFields::all();
		PTF_ASSERT_EQUAL(fields.size(), 19);
		for (const auto& field : fields)
		{
			const std::string key = "\"" + field.name + "\":";
			const auto pos = output.str().find(key);
			PTF_ASSERT_TRUE(pos != std::string::npos);
			PTF_ASSERT_TRUE(output.str().find(key, pos + key.size()) == std::string::npos);
		}
	}
}  // NtpParsingV4Tests

PTF_TEST_CASE(NtpCreationTests)
{
	auto rawPacketAndBuf1 = createPacketAndBufferFromHexResource("PacketExamples/ntpv4.dat");
	auto& resource1 = rawPacketAndBuf1.resourceBuffer;
	auto& rawPacket1 = rawPacketAndBuf1.packet;

	pcpp::Packet ntpPacket(rawPacket1.get());

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

	PTF_ASSERT_EQUAL(resource1.length, craftedPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(resource1.data.get(), craftedPacket.getRawPacket()->getRawData(), resource1.length);

	auto rawPacketAndBuf2 = createPacketAndBufferFromHexResource("PacketExamples/ntpv3crafting.dat");
	auto& resource2 = rawPacketAndBuf2.resourceBuffer;
	auto& rawPacket2 = rawPacketAndBuf2.packet;

	pcpp::Packet ntpPacket2(rawPacket2.get());

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

	PTF_ASSERT_EQUAL(resource2.length, craftedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(resource2.data.get(), craftedPacket2.getRawPacket()->getRawData(), resource2.length);
}  // NtpCraftingTests
