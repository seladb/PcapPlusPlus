#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "TelnetLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(TelnetControlParsingTests)
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
    
    // This index not exist should return error
	pcpp::Logger::getInstance().suppressLogs();
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(8), pcpp::TelnetLayer::TelnetCommandInternalError);
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
	pcpp::Logger::getInstance().enableLogs();
   
    PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Control");
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

    // This index not exist should return error
	pcpp::Logger::getInstance().suppressLogs();
    PTF_ASSERT_EQUAL(telnetLayer->getCommand(0), pcpp::TelnetLayer::TelnetCommandInternalError);
    // This index not exist should return error
    PTF_ASSERT_EQUAL(telnetLayer->getOption(0), pcpp::TelnetLayer::TelnetOptionInternalError);
	pcpp::Logger::getInstance().enableLogs();

    PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Data");
}