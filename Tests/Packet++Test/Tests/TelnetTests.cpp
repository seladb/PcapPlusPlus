#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "TelnetLayer.h"

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
	PTF_ASSERT_EQUAL(telnetLayer->getTotalNumberOfCommands(), 8);

	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::WillPerform), 1);
	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::DoPerform), 5);
	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::SubnegotiationEnd), 1);

	PTF_ASSERT_EQUAL(telnetLayer->getFirstCommand(), pcpp::TelnetLayer::WillPerform);

    PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::WillPerform), pcpp::TelnetLayer::SuppressGoAhead);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::DoPerform), pcpp::TelnetLayer::TerminalType);
    PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::AreYouThere), pcpp::TelnetLayer::TelnetOptionNoOption);

    // Check iteration
	std::vector<pcpp::TelnetLayer::TelnetCommands> vCommand = {
		pcpp::TelnetLayer::WillPerform,	   pcpp::TelnetLayer::DoPerform,		pcpp::TelnetLayer::DoPerform,
		pcpp::TelnetLayer::DoPerform,	   pcpp::TelnetLayer::DoPerform,		pcpp::TelnetLayer::DoPerform,
		pcpp::TelnetLayer::Subnegotiation, pcpp::TelnetLayer::SubnegotiationEnd};
	std::vector<pcpp::TelnetLayer::TelnetOptions> vOptions = {pcpp::TelnetLayer::SuppressGoAhead,
															  pcpp::TelnetLayer::TerminalType,
															  pcpp::TelnetLayer::NegotiateAboutWindowSize,
															  pcpp::TelnetLayer::TerminalSpeed,
															  pcpp::TelnetLayer::RemoteFlowControl,
															  pcpp::TelnetLayer::Linemode,
															  pcpp::TelnetLayer::Linemode,
															  pcpp::TelnetLayer::TelnetOptionNoOption};
	std::vector<std::string> vCommandString = {"Will Perform", "Do Perform", "Do Perform",	   "Do Perform",
											   "Do Perform",   "Do Perform", "Subnegotiation", "Subnegotiation End"};
	std::vector<std::string> vOptionString = {
		"Suppress Go Ahead", "Terminal Type", "Negotiate About Window Size", "Terminal Speed", "Remote Flow Control",
		"Line mode",			 "Line mode",	  "No option for this command"};

	size_t ctr = 0;
	size_t length = 0;
	pcpp::TelnetLayer::TelnetCommands commandVal = telnetLayer->getNextCommand();
	while (commandVal != pcpp::TelnetLayer::TelnetCommands::TelnetCommandEndOfPacket)
	{
		// Check command
		PTF_ASSERT_EQUAL(commandVal, vCommand[ctr]);
		PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(commandVal), vCommandString[ctr]);

		// Check option
		pcpp::TelnetLayer::TelnetOptions option = telnetLayer->getOption();
		PTF_ASSERT_EQUAL(option, vOptions[ctr]);
		PTF_ASSERT_EQUAL(telnetLayer->getTelnetOptionAsString(option), vOptionString[ctr]);

		// Check option data
		if (ctr != 6)
		{
			PTF_ASSERT_NULL(telnetLayer->getOptionData(length));
			PTF_ASSERT_EQUAL(length, 0);
		}
		else
		{
			PTF_ASSERT_NOT_NULL(telnetLayer->getOptionData(length));
			PTF_ASSERT_EQUAL(length, 2);
		}

        commandVal = telnetLayer->getNextCommand();
		++ctr;
	}
	PTF_ASSERT_EQUAL(ctr, 8);
	PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Control");

	// Telnet TN3270 sample (not supported but should not raise an error)
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/telnetTN3270.dat");

	pcpp::Packet telnetPacket2(&rawPacket2);
	pcpp::TelnetLayer *telnetLayer2 = telnetPacket2.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer2);

	PTF_ASSERT_EQUAL(telnetLayer2->getDataAsString(), ""); // <--------- It should return TN3270 field!
	PTF_ASSERT_EQUAL(telnetLayer2->getTotalNumberOfCommands(), 3);

    std::vector<pcpp::TelnetLayer::TelnetCommands> vCommand2 = {
		pcpp::TelnetLayer::DoPerform,       pcpp::TelnetLayer::WillPerform,
		pcpp::TelnetLayer::EndOfRecordCommand};
	std::vector<pcpp::TelnetLayer::TelnetOptions> vOptions2 = {pcpp::TelnetLayer::TransmitBinary,
															  pcpp::TelnetLayer::TransmitBinary,
															  pcpp::TelnetLayer::TelnetOptionNoOption};

    size_t ctr2 = 0;
	size_t length2 = 0;
	pcpp::TelnetLayer::TelnetCommands commandVal2 = telnetLayer2->getNextCommand();
	while (commandVal2 != pcpp::TelnetLayer::TelnetCommands::TelnetCommandEndOfPacket)
	{
		PTF_ASSERT_EQUAL(commandVal2, vCommand2[ctr2]);
		PTF_ASSERT_EQUAL(telnetLayer2->getOption(), vOptions2[ctr2]);

		// Check option data
        PTF_ASSERT_NULL(telnetLayer2->getOptionData(length2));
        PTF_ASSERT_EQUAL(length2, 0);

        commandVal2 = telnetLayer2->getNextCommand();
		++ctr2;
    }
    PTF_ASSERT_EQUAL(ctr2, 3);
	PTF_ASSERT_EQUAL(telnetLayer2->toString(), "Telnet Control");

	// Test Command with data Case
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/telnetCommandWithData.dat");

	pcpp::Packet telnetPacket3(&rawPacket3);
	pcpp::TelnetLayer *telnetLayer3 = telnetPacket3.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer3);

	PTF_ASSERT_EQUAL(telnetLayer3->getDataAsString(), ""); // <--------- It should return data field!
	PTF_ASSERT_EQUAL(telnetLayer3->getTotalNumberOfCommands(), 2);

    /*
	PTF_ASSERT_EQUAL(telnetLayer3->getCommand(0), pcpp::TelnetLayer::Subnegotiation);
	PTF_ASSERT_EQUAL(telnetLayer3->getCommand(1), pcpp::TelnetLayer::SubnegotiationEnd);
	PTF_ASSERT_EQUAL(telnetLayer3->getTelnetCommandAsString(0), "Subnegotiation");
	PTF_ASSERT_EQUAL(telnetLayer3->getTelnetCommandAsString(1), "Subnegotiation End");

	PTF_ASSERT_EQUAL(telnetLayer3->getOption(0), pcpp::TelnetLayer::AuthenticationOption);
	PTF_ASSERT_EQUAL(telnetLayer3->getOption(1), pcpp::TelnetLayer::TelnetOptionNoOption);
	PTF_ASSERT_EQUAL(telnetLayer3->getTelnetOptionAsString(0), "Authentication Option");
	PTF_ASSERT_EQUAL(telnetLayer3->getTelnetOptionAsString(1), "No option for this command");

	const uint8_t valPtr2[] = {
		0x0d, 0x0a, 0x54, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x63,
		0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6c, 0x6f, 0x67, 0x20, 0x79, 0x6f, 0x75, 0x20,
		0x69, 0x6e, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4e, 0x54, 0x4c, 0x4d, 0x20, 0x61, 0x75, 0x74,
		0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x0d, 0x0a, 0x59, 0x6f, 0x75,
		0x72, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x68, 0x61,
		0x76, 0x65, 0x20, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x2e, 0x0d, 0x0a, 0x4c, 0x6f, 0x67, 0x69,
		0x6e, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x20,
		0x61, 0x6e, 0x64, 0x20, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x0d, 0x0a, 0x0d, 0x0a, 0x57,
		0x65, 0x6c, 0x63, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f,
		0x66, 0x74, 0x20, 0x54, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
		0x20, 0x0d, 0x0a, 0x0a, 0x0d, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x3a, 0x20};
	const uint8_t *ptr3 = telnetLayer3->getOptionData(1, len);
	PTF_ASSERT_NOT_NULL(ptr3);
	PTF_ASSERT_EQUAL(len, 182);

	PTF_ASSERT_BUF_COMPARE(ptr3, valPtr2, len);

	PTF_ASSERT_EQUAL(telnetLayer3->toString(), "Telnet Control");
    */
}

PTF_TEST_CASE(TelnetDataParsingTests)
{
    /*
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
    */
}
