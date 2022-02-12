#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "TelnetLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"

#include <string.h>

PTF_TEST_CASE(TelnetCommandParsingTests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetCommand.dat");

    pcpp::Packet telnetPacket(&rawPacket1);
    pcpp::TelnetLayer *telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

    PTF_ASSERT_NOT_NULL(telnetLayer);

    PTF_ASSERT_EQUAL(telnetLayer->getDataAsString(), "");
    PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(), 8);

    PTF_ASSERT_EQUAL(telnetLayer->getCommand(0), pcpp::TelnetLayer::WillPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(1), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(2), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(3), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(4), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(5), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(6), pcpp::TelnetLayer::Subnegotiation);
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(7), pcpp::TelnetLayer::SubnegotiationEnd);

    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(0), "Will Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(1), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(2), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(3), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(4), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(5), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(6), "Subnegotiation");
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(7), "Subnegotiation End");

    // This index not exist should return error
    pcpp::Logger::getInstance().suppressLogs();
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(8), pcpp::TelnetLayer::TelnetCommandInternalError);
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(8), "Internal Error");
    pcpp::Logger::getInstance().enableLogs();

    PTF_ASSERT_EQUAL(telnetLayer->getOption(0), pcpp::TelnetLayer::SuppressGoAhead);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(1), pcpp::TelnetLayer::TerminalType);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(2), pcpp::TelnetLayer::NegotiateAboutWindowSize);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(3), pcpp::TelnetLayer::TerminalSpeed);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(4), pcpp::TelnetLayer::RemoteFlowControl);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(5), pcpp::TelnetLayer::Linemode);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(6), pcpp::TelnetLayer::Linemode);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(7), pcpp::TelnetLayer::TelnetOptionNoOption);

    // This index not exist should return error
    pcpp::Logger::getInstance().suppressLogs();
    PTF_ASSERT_EQUAL(telnetLayer->getOption(8), pcpp::TelnetLayer::TelnetOptionInternalError);
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetOptionAsString(8), "Internal Error");
    pcpp::Logger::getInstance().enableLogs();

    PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Control");

    // Telnet TN3270 sample (not supported but should not raise an error)
    READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/telnetTN3270.dat");

    pcpp::Packet telnetPacket2(&rawPacket2);
    pcpp::TelnetLayer *telnetLayer2 = telnetPacket2.getLayerOfType<pcpp::TelnetLayer>();

    PTF_ASSERT_NOT_NULL(telnetLayer2);

    PTF_ASSERT_EQUAL(telnetLayer2->getDataAsString(), "");
    PTF_ASSERT_EQUAL(telnetLayer2->getNumberOfCommands(), 3);

    PTF_ASSERT_EQUAL(telnetLayer2->getCommand(0), pcpp::TelnetLayer::DoPerform);
    PTF_ASSERT_EQUAL(telnetLayer2->getCommand(1), pcpp::TelnetLayer::WillPerform);
    PTF_ASSERT_EQUAL(telnetLayer2->getCommand(2), pcpp::TelnetLayer::EndOfRecordCommand);

    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetCommandAsString(0), "Do Perform");
    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetCommandAsString(1), "Will Perform");
    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetCommandAsString(2), "End of Record");

    PTF_ASSERT_EQUAL(telnetLayer2->getOption(0), pcpp::TelnetLayer::TransmitBinary);
    PTF_ASSERT_EQUAL(telnetLayer2->getOption(1), pcpp::TelnetLayer::TransmitBinary);
    PTF_ASSERT_EQUAL(telnetLayer2->getOption(2), pcpp::TelnetLayer::TelnetOptionNoOption);

    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetOptionAsString(0), "Binary Transmission");
    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetOptionAsString(1), "Binary Transmission");
    PTF_ASSERT_EQUAL(telnetLayer2->getTelnetOptionAsString(2), "No option for this command");

    uint8_t valPtr[] = {0x11, 0x00, 0x06, 0x40, 0x00, 0xf1, 0xc2, 0x00, 0x05, 0x01, 0xff, 0xff, 0x02};

    size_t len = 0;
    const uint8_t *ptr1 = telnetLayer2->getOptionData(1, len);
    PTF_ASSERT_NOT_NULL(ptr1);
    PTF_ASSERT_EQUAL(len, 13);
    PTF_ASSERT_BUF_COMPARE(ptr1, valPtr, 13);

    const uint8_t *ptr2 = telnetLayer2->getOptionData(0, len);
    PTF_ASSERT_NULL(ptr2);
    PTF_ASSERT_EQUAL(len, 13); // It should be not changed during the function call so equal 13

    PTF_ASSERT_EQUAL(telnetLayer2->toString(), "Telnet Control");
}

PTF_TEST_CASE(TelnetDataParsingTests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetData.dat");

    pcpp::Packet telnetPacket(&rawPacket1);
    pcpp::TelnetLayer *telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

    PTF_ASSERT_NOT_NULL(telnetLayer);

    PTF_ASSERT_EQUAL(telnetLayer->getDataAsString(), "OpenBSD/i386 (oof) (ttyp2)");
    PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(), 0);

    pcpp::Logger::getInstance().suppressLogs();
    // This index not exist should return error
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(0), pcpp::TelnetLayer::TelnetCommandInternalError);
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(0), "Internal Error");
    // This index not exist should return error
    PTF_ASSERT_EQUAL(telnetLayer->getOption(0), pcpp::TelnetLayer::TelnetOptionInternalError);
    PTF_ASSERT_EQUAL(telnetLayer->getTelnetOptionAsString(0), "Internal Error");
    pcpp::Logger::getInstance().enableLogs();

    PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Data");
}