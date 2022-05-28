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
	pcpp::TelnetLayer::TelnetCommand vCommand[] = {
		pcpp::TelnetLayer::WillPerform,	   pcpp::TelnetLayer::DoPerform,		pcpp::TelnetLayer::DoPerform,
		pcpp::TelnetLayer::DoPerform,	   pcpp::TelnetLayer::DoPerform,		pcpp::TelnetLayer::DoPerform,
		pcpp::TelnetLayer::Subnegotiation, pcpp::TelnetLayer::SubnegotiationEnd};
	pcpp::TelnetLayer::TelnetOption vOptions[] = {pcpp::TelnetLayer::SuppressGoAhead,
												   pcpp::TelnetLayer::TerminalType,
												   pcpp::TelnetLayer::NegotiateAboutWindowSize,
												   pcpp::TelnetLayer::TerminalSpeed,
												   pcpp::TelnetLayer::RemoteFlowControl,
												   pcpp::TelnetLayer::Linemode,
												   pcpp::TelnetLayer::Linemode,
												   pcpp::TelnetLayer::TelnetOptionNoOption};
	std::string vCommandString[] = {"Will Perform", "Do Perform", "Do Perform",		"Do Perform",
									"Do Perform",	"Do Perform", "Subnegotiation", "Subnegotiation End"};
	std::string vOptionString[] = {
		"Suppress Go Ahead", "Terminal Type", "Negotiate About Window Size", "Terminal Speed", "Remote Flow Control",
		"Line mode",		 "Line mode",	  "No option for this command"};

	size_t ctr = 0;
	size_t length = 0;
	pcpp::TelnetLayer::TelnetCommand commandVal = telnetLayer->getNextCommand();
	while (commandVal != pcpp::TelnetLayer::TelnetCommandEndOfPacket)
	{
		// Check command
		PTF_ASSERT_EQUAL(commandVal, vCommand[ctr]);
		PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(commandVal), vCommandString[ctr]);

		// Check option
		pcpp::TelnetLayer::TelnetOption option = telnetLayer->getOption();
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

	// It should return TN3270 field
	PTF_ASSERT_EQUAL(telnetLayer2->getDataAsString(), "@");
	PTF_ASSERT_EQUAL(telnetLayer2->getTotalNumberOfCommands(), 3);

	pcpp::TelnetLayer::TelnetCommand vCommand2[] = {pcpp::TelnetLayer::DoPerform, pcpp::TelnetLayer::WillPerform,
													 pcpp::TelnetLayer::EndOfRecordCommand};
	pcpp::TelnetLayer::TelnetOption vOptions2[] = {
		pcpp::TelnetLayer::TransmitBinary, pcpp::TelnetLayer::TransmitBinary, pcpp::TelnetLayer::TelnetOptionNoOption};

	size_t ctr2 = 0;
	size_t length2 = 0;
	pcpp::TelnetLayer::TelnetCommand commandVal2 = telnetLayer2->getNextCommand();
	while (commandVal2 != pcpp::TelnetLayer::TelnetCommandEndOfPacket)
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

	PTF_ASSERT_EQUAL(telnetLayer3->getDataAsString(),
					 "Telnet server could not log you in using NTLM authentication.Your password may have "
					 "expired.Login using username and passwordWelcome to Microsoft Telnet Service login: ");
	PTF_ASSERT_EQUAL(telnetLayer3->getTotalNumberOfCommands(), 2);

	PTF_ASSERT_EQUAL(telnetLayer3->getNumberOfCommands(pcpp::TelnetLayer::Subnegotiation), 1);
	PTF_ASSERT_EQUAL(telnetLayer3->getNumberOfCommands(pcpp::TelnetLayer::SubnegotiationEnd), 1);

	PTF_ASSERT_EQUAL(telnetLayer3->getOption(pcpp::TelnetLayer::Subnegotiation),
					 pcpp::TelnetLayer::AuthenticationOption);
	PTF_ASSERT_EQUAL(telnetLayer3->getOption(pcpp::TelnetLayer::SubnegotiationEnd),
					 pcpp::TelnetLayer::TelnetOptionNoOption);
	PTF_ASSERT_EQUAL(telnetLayer3->toString(), "Telnet Control");
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
	PTF_ASSERT_EQUAL(telnetLayer->getTotalNumberOfCommands(), 0);
	PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Data");
}
