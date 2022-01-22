#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "NtpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(NtpMethodsTests)
{
    // First check the epoch is correct
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(0.0), "1970-01-01T00:00:00.000000000Z");
    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(uint64_t(0)), "1900-01-01T00:00:00.000000000Z");

    PTF_ASSERT_EQUAL(pcpp::NtpLayer::convertToIsoFormat(1642879410.0), "2022-01-22T07:23:30.000000000Z");

    /*
    pcpp::NtpLayer::convertFromShortFormat();
    pcpp::NtpLayer::convertFromTimestampFormat;
    pcpp::NtpLayer::convertToShortFormat;
    pcpp::NtpLayer::convertToTimestampFormat;
    */

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
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NTPLeapIndicator::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NTPMode::Server);
    PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 4);
    PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), -6);
    // NTPv3 pcap is a bit useless, too many zeros
    PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getOriginateTimestamp(), 0);
    PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), uint64_t(-2787922709886009344));
    PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), uint64_t(-2787922709886009344));

} // NtpParsingV3Tests

PTF_TEST_CASE(NtpParsingV4Tests)
{
    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ntpv4.dat");

    pcpp::Packet ntpPacket(&rawPacket1);
    pcpp::NtpLayer *ntpLayer = ntpPacket.getLayerOfType<pcpp::NtpLayer>();

    std::cout << ntpPacket << std::endl;

    PTF_ASSERT_NOT_NULL(ntpLayer);
    PTF_ASSERT_EQUAL(ntpLayer->getVersion(), 4);
    PTF_ASSERT_EQUAL(ntpLayer->getLeapIndicator(), pcpp::NTPLeapIndicator::NoWarning);
    PTF_ASSERT_EQUAL(ntpLayer->getMode(), pcpp::NTPMode::Client);
    PTF_ASSERT_EQUAL(ntpLayer->getStratum(), 2);
    PTF_ASSERT_EQUAL(ntpLayer->getPollInterval(), 7);
    PTF_ASSERT_EQUAL(ntpLayer->getPrecision(), -100);
    // PTF_ASSERT_EQUAL(ntpLayer->getRootDelay(), uint32_t(1104));
    // PTF_ASSERT_EQUAL(ntpLayer->getRootDispersion(), uint32_t(939));
    // PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifier(), uint32_t(2210137055));
    // PTF_ASSERT_EQUAL(ntpLayer->getReferenceIdentifierString(), "131.188.3.223");
    PTF_ASSERT_EQUAL(ntpLayer->getReferenceTimestamp(), uint64_t(-2787919745529825184));
    PTF_ASSERT_EQUAL(ntpLayer->getOriginateTimestamp(), uint64_t(-2791009845670350896));
    PTF_ASSERT_EQUAL(ntpLayer->getReceiveTimestamp(), uint64_t(-2791009845645088392));
    PTF_ASSERT_EQUAL(ntpLayer->getTransmitTimestamp(), uint64_t(-2787919535147654412));

} // NtpParsingV4Tests