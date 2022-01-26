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

PTF_TEST_CASE(NtpMethodsTests)
{

    double val = 12345.125;
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertFromTimestampFormat(pcpp::NtpLayer::convertToTimestampFormat(val)), val);
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertFromShortFormat(pcpp::NtpLayer::convertToShortFormat(val)), val);

    // First check the epoch is correct
#if defined(_WIN32)
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(0.0), std::string("1970-01-01T00:00:00.000000000Z"));
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(uint64_t(0)), std::string("1970-01-01T00:00:00.000000000Z"));
#else
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(0.0), std::string("1970-01-01T00:00:00.000000000Z"));
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(uint64_t(0)), std::string("1900-01-01T00:00:00.000000000Z"));
#endif

    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(1642879410.0), "2022-01-22T19:23:30.000000000Z");
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(pcpp::NtpLayer::convertToTimestampFormat(1642879410.0)), "2022-01-22T19:23:30.000000000Z");

} // NtpMethodsTests

PTF_TEST_CASE(NtpParsingV3Tests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv3.dat");

    pcpp::Packet ntpPacket(&rawPacket1);
    pcpp::NtpLayer *ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

    PTF_ASSERT_NOT_NULL(ntpLayer);
    PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 3);
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::Server);
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

} // NtpParsingV3Tests

PTF_TEST_CASE(NtpParsingV4Tests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv4.dat");

    // Test Ipv4
    pcpp::Packet ntpPacket(&rawPacket1);
    pcpp::NtpLayer *ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

    PTF_ASSERT_NOT_NULL(ntpLayer);
    PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::Client);
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

    // Test Ipv6
    READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ntpv4Ipv6_withAuth.dat");

    ntpPacket = pcpp::Packet(&rawPacket2);
    ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

    PTF_ASSERT_NOT_NULL(ntpLayer);
    PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::Client);
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
    PTF_ASSERT_EQUAL(ntpLayer->getDigest(), "ac017b69915ce5a7a9fb73ac8bd1603b"); // MD5
    PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v4, Mode: Client");

    READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ntpv4Ipv6_withAuth2.dat");

    ntpPacket = pcpp::Packet(&rawPacket3);
    ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

    PTF_ASSERT_NOT_NULL(ntpLayer);
    PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::Server);
    PTF_ASSERT_EQUAL(ntpLayer->getModeString(), "Server");
    PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 1);
    PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 10);
    PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), int8_t(0xee));
    PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), be32toh(0xfb));
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), be32toh(0x44434661));
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifierString(), "Meinberg DCF77 with amplitud modulation");
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), be64toh(0xdcd2aabfe3771e96));
    PTF_ASSERT_EQUAL(ntpLayer->getOriginTimestamp(), be64toh(0xdcd2aae48e835d2a));
    PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), be64toh(0xdcd2aae48e9f4d3c));
    PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), be64toh(0xdcd2aae48ece4367));
    PTF_ASSERT_EQUAL(ntpLayer->getKeyID(), be32toh(0xb));
    PTF_ASSERT_EQUAL(ntpLayer->getDigest(), "ece2d5b07e9fc63279aa2322b76038e53cd0ecc6"); // SHA1
    PTF_ASSERT_EQUAL(ntpLayer->toString(), "NTP Layer v4, Mode: Server");

} // NtpParsingV4Tests

PTF_TEST_CASE(NtpCraftingTests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv4.dat");

    pcpp::Packet ntpPacket(&rawPacket1);
    pcpp::Packet craftedPacket;

    pcpp::EthLayer ethLayer(*ntpPacket.getLayerOfType<pcpp::EthLayer>());
    PTF_ASSERT_TRUE(craftedPacket.addLayer(&ethLayer));

    pcpp::IPv4Layer ipv4Layer(*ntpPacket.getLayerOfType<pcpp::IPv4Layer>());
    PTF_ASSERT_TRUE(craftedPacket.addLayer(&ipv4Layer));

    pcpp::UdpLayer udpLayer(*ntpPacket.getLayerOfType<pcpp::UdpLayer>());
    PTF_ASSERT_TRUE(craftedPacket.addLayer(&udpLayer));

    pcpp::NtpLayer ntpLayer;

    // Set the values
    ntpLayer.setVersion(4);
    ntpLayer.setLeapIndicator(pcpp::NoWarning);
    ntpLayer.setMode(pcpp::Client);
    ntpLayer.setStratum(2);
    ntpLayer.setPollInterval(7);
    ntpLayer.setPrecision(int8_t(0xeb));
    ntpLayer.setRootDelay(be32toh(0x450));
    ntpLayer.setRootDispersion(be32toh(0x3ab));
    ntpLayer.setReferenceIdentifier(be32toh(0x83bc03df));
    ntpLayer.setReferenceTimestamp(be64toh(0xd94f51c33165b860));
    ntpLayer.setOriginTimestamp(be64toh(0xd944575530336fd0));
    ntpLayer.setReceiveTimestamp(be64toh(0xd944575531b4e978));
    ntpLayer.setTransmitTimestamp(be64toh(0xd94f51f42d26e2f4));

    craftedPacket.addLayer(&ntpLayer);

    PTF_ASSERT_EQUAL(bufferLength1, craftedPacket.getRawPacket()->getRawDataLen());
    PTF_ASSERT_BUF_COMPARE(buffer1, craftedPacket.getRawPacket()->getRawData(), bufferLength1);

} // NtpCraftingTests