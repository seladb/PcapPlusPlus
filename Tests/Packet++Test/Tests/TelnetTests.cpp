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
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetCommand.dat");

	pcpp::Packet telnetPacket(&rawPacket1);
	pcpp::TelnetLayer* telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer);

	PTF_ASSERT_EQUAL(telnetLayer->getDataAsString(), "");
	PTF_ASSERT_EQUAL(telnetLayer->getTotalNumberOfCommands(), 8);

	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::TelnetCommand::WillPerform), 1);
	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::TelnetCommand::DoPerform), 5);
	PTF_ASSERT_EQUAL(telnetLayer->getNumberOfCommands(pcpp::TelnetLayer::TelnetCommand::SubnegotiationEnd), 1);

	PTF_ASSERT_EQUAL(telnetLayer->getFirstCommand(), pcpp::TelnetLayer::TelnetCommand::WillPerform, enumclass);

	PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::TelnetCommand::WillPerform),
	                 pcpp::TelnetLayer::TelnetOption::SuppressGoAhead, enumclass);
	PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::TelnetCommand::DoPerform),
	                 pcpp::TelnetLayer::TelnetOption::TerminalType, enumclass);
	PTF_ASSERT_EQUAL(telnetLayer->getOption(pcpp::TelnetLayer::TelnetCommand::AreYouThere),
	                 pcpp::TelnetLayer::TelnetOption::TelnetOptionNoOption, enumclass);

	// Check iteration
	std::vector<pcpp::TelnetLayer::TelnetCommand> vCommand = {
		pcpp::TelnetLayer::TelnetCommand::WillPerform,    pcpp::TelnetLayer::TelnetCommand::DoPerform,
		pcpp::TelnetLayer::TelnetCommand::DoPerform,      pcpp::TelnetLayer::TelnetCommand::DoPerform,
		pcpp::TelnetLayer::TelnetCommand::DoPerform,      pcpp::TelnetLayer::TelnetCommand::DoPerform,
		pcpp::TelnetLayer::TelnetCommand::Subnegotiation, pcpp::TelnetLayer::TelnetCommand::SubnegotiationEnd
	};

	std::vector<pcpp::TelnetLayer::TelnetOption> vOptions = { pcpp::TelnetLayer::TelnetOption::SuppressGoAhead,
		                                                      pcpp::TelnetLayer::TelnetOption::TerminalType,
		                                                      pcpp::TelnetLayer::TelnetOption::NegotiateAboutWindowSize,
		                                                      pcpp::TelnetLayer::TelnetOption::TerminalSpeed,
		                                                      pcpp::TelnetLayer::TelnetOption::RemoteFlowControl,
		                                                      pcpp::TelnetLayer::TelnetOption::Linemode,
		                                                      pcpp::TelnetLayer::TelnetOption::Linemode,
		                                                      pcpp::TelnetLayer::TelnetOption::TelnetOptionNoOption };

	std::vector<std::string> vCommandString = { "Will Perform", "Do Perform", "Do Perform",     "Do Perform",
		                                        "Do Perform",   "Do Perform", "Subnegotiation", "Subnegotiation End" };
	std::vector<std::string> vOptionString = {
		"Suppress Go Ahead", "Terminal Type", "Negotiate About Window Size", "Terminal Speed", "Remote Flow Control",
		"Line mode",         "Line mode",     "No option for this command"
	};

	size_t ctr = 0;
	size_t length = 0;
	pcpp::TelnetLayer::TelnetCommand commandVal = telnetLayer->getNextCommand();
	while (commandVal != pcpp::TelnetLayer::TelnetCommand::TelnetCommandEndOfPacket)
	{
		// Check command
		PTF_ASSERT_EQUAL(commandVal, vCommand[ctr], enumclass);
		PTF_ASSERT_EQUAL(telnetLayer->getTelnetCommandAsString(commandVal), vCommandString[ctr]);

		// Check option
		pcpp::TelnetLayer::TelnetOption option = telnetLayer->getOption();
		PTF_ASSERT_EQUAL(option, vOptions[ctr], enumclass);
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
	pcpp::TelnetLayer* telnetLayer2 = telnetPacket2.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer2);

	// It should return TN3270 field
	PTF_ASSERT_EQUAL(telnetLayer2->getDataAsString(), "@");
	PTF_ASSERT_EQUAL(telnetLayer2->getTotalNumberOfCommands(), 3);

	std::vector<pcpp::TelnetLayer::TelnetCommand> vCommand2 = { pcpp::TelnetLayer::TelnetCommand::DoPerform,
		                                                        pcpp::TelnetLayer::TelnetCommand::WillPerform,
		                                                        pcpp::TelnetLayer::TelnetCommand::EndOfRecordCommand };

	std::vector<pcpp::TelnetLayer::TelnetOption> vOptions2 = { pcpp::TelnetLayer::TelnetOption::TransmitBinary,
		                                                       pcpp::TelnetLayer::TelnetOption::TransmitBinary,
		                                                       pcpp::TelnetLayer::TelnetOption::TelnetOptionNoOption };

	size_t ctr2 = 0;
	size_t length2 = 0;
	pcpp::TelnetLayer::TelnetCommand commandVal2 = telnetLayer2->getNextCommand();
	while (commandVal2 != pcpp::TelnetLayer::TelnetCommand::TelnetCommandEndOfPacket)
	{
		PTF_ASSERT_EQUAL(commandVal2, vCommand2[ctr2], enumclass);
		PTF_ASSERT_EQUAL(telnetLayer2->getOption(), vOptions2[ctr2], enumclass);

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
	pcpp::TelnetLayer* telnetLayer3 = telnetPacket3.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer3);

	PTF_ASSERT_EQUAL(telnetLayer3->getDataAsString(),
	                 "Telnet server could not log you in using NTLM authentication.Your password may have "
	                 "expired.Login using username and passwordWelcome to Microsoft Telnet Service login: ");
	PTF_ASSERT_EQUAL(telnetLayer3->getTotalNumberOfCommands(), 2);

	PTF_ASSERT_EQUAL(telnetLayer3->getNumberOfCommands(pcpp::TelnetLayer::TelnetCommand::Subnegotiation), 1);
	PTF_ASSERT_EQUAL(telnetLayer3->getNumberOfCommands(pcpp::TelnetLayer::TelnetCommand::SubnegotiationEnd), 1);

	PTF_ASSERT_EQUAL(telnetLayer3->getOption(pcpp::TelnetLayer::TelnetCommand::Subnegotiation),
	                 pcpp::TelnetLayer::TelnetOption::AuthenticationOption, enumclass);
	PTF_ASSERT_EQUAL(telnetLayer3->getOption(pcpp::TelnetLayer::TelnetCommand::SubnegotiationEnd),
	                 pcpp::TelnetLayer::TelnetOption::TelnetOptionNoOption, enumclass);
	PTF_ASSERT_EQUAL(telnetLayer3->toString(), "Telnet Control");

	// Commands
	std::vector<std::pair<pcpp::TelnetLayer::TelnetCommand, std::string>> possibleCommands = {
		{ static_cast<pcpp::TelnetLayer::TelnetCommand>(0),           "Unknown Command"                     },
		{ pcpp::TelnetLayer::TelnetCommand::TelnetCommandEndOfPacket, "Reached end of packet while parsing" },
		{ pcpp::TelnetLayer::TelnetCommand::EndOfFile,                "End of File"                         },
		{ pcpp::TelnetLayer::TelnetCommand::Suspend,                  "Suspend current process"             },
		{ pcpp::TelnetLayer::TelnetCommand::Abort,                    "Abort Process"                       },
		{ pcpp::TelnetLayer::TelnetCommand::EndOfRecordCommand,       "End of Record"                       },
		{ pcpp::TelnetLayer::TelnetCommand::SubnegotiationEnd,        "Subnegotiation End"                  },
		{ pcpp::TelnetLayer::TelnetCommand::NoOperation,              "No Operation"                        },
		{ pcpp::TelnetLayer::TelnetCommand::DataMark,                 "Data Mark"                           },
		{ pcpp::TelnetLayer::TelnetCommand::Break,                    "Break"                               },
		{ pcpp::TelnetLayer::TelnetCommand::InterruptProcess,         "Interrupt Process"                   },
		{ pcpp::TelnetLayer::TelnetCommand::AbortOutput,              "Abort Output"                        },
		{ pcpp::TelnetLayer::TelnetCommand::AreYouThere,              "Are You There"                       },
		{ pcpp::TelnetLayer::TelnetCommand::EraseCharacter,           "Erase Character"                     },
		{ pcpp::TelnetLayer::TelnetCommand::EraseLine,                "Erase Line"                          },
		{ pcpp::TelnetLayer::TelnetCommand::GoAhead,                  "Go Ahead"                            },
		{ pcpp::TelnetLayer::TelnetCommand::Subnegotiation,           "Subnegotiation"                      },
		{ pcpp::TelnetLayer::TelnetCommand::WillPerform,              "Will Perform"                        },
		{ pcpp::TelnetLayer::TelnetCommand::WontPerform,              "Wont Perform"                        },
		{ pcpp::TelnetLayer::TelnetCommand::DoPerform,                "Do Perform"                          },
		{ pcpp::TelnetLayer::TelnetCommand::DontPerform,              "Dont Perform"                        },
		{ pcpp::TelnetLayer::TelnetCommand::InterpretAsCommand,       "Interpret As Command"                }
	};

	for (const auto& entry : possibleCommands)
	{
		PTF_ASSERT_EQUAL(pcpp::TelnetLayer::getTelnetCommandAsString(entry.first), entry.second);
	}

	// Options
	std::vector<std::pair<pcpp::TelnetLayer::TelnetOption, std::string>> possibleOptions = {
		{ static_cast<pcpp::TelnetLayer::TelnetOption>(-10),                "Unknown Option"                              },
		{ pcpp::TelnetLayer::TelnetOption::TelnetOptionNoOption,            "No option for this command"                  },
		{ pcpp::TelnetLayer::TelnetOption::TransmitBinary,                  "Binary Transmission"                         },
		{ pcpp::TelnetLayer::TelnetOption::Echo,                            "Echo"                                        },
		{ pcpp::TelnetLayer::TelnetOption::Reconnection,                    "Reconnection"                                },
		{ pcpp::TelnetLayer::TelnetOption::SuppressGoAhead,                 "Suppress Go Ahead"                           },
		{ pcpp::TelnetLayer::TelnetOption::ApproxMsgSizeNegotiation,        "Negotiate approximate message size"          },
		{ pcpp::TelnetLayer::TelnetOption::Status,                          "Status"                                      },
		{ pcpp::TelnetLayer::TelnetOption::TimingMark,                      "Timing Mark"                                 },
		{ pcpp::TelnetLayer::TelnetOption::RemoteControlledTransAndEcho,    "Remote Controlled Transmission and Echo"     },
		{ pcpp::TelnetLayer::TelnetOption::OutputLineWidth,                 "Output Line Width"                           },
		{ pcpp::TelnetLayer::TelnetOption::OutputPageSize,                  "Output Page Size"                            },
		{ pcpp::TelnetLayer::TelnetOption::OutputCarriageReturnDisposition,
         "Negotiate About Output Carriage-Return Disposition"                                                             },
		{ pcpp::TelnetLayer::TelnetOption::OutputHorizontalTabStops,        "Negotiate About Output Horizontal Tabstops"  },
		{ pcpp::TelnetLayer::TelnetOption::OutputHorizontalTabDisposition,
         "Negotiate About Output Horizontal Tab Disposition"		                                                      },
		{ pcpp::TelnetLayer::TelnetOption::OutputFormfeedDisposition,       "Negotiate About Output Formfeed Disposition" },
		{ pcpp::TelnetLayer::TelnetOption::OutputVerticalTabStops,          "Negotiate About Vertical Tabstops"           },
		{ pcpp::TelnetLayer::TelnetOption::OutputVerticalTabDisposition,
         "Negotiate About Output Vertcial Tab Disposition"		                                                        },
		{ pcpp::TelnetLayer::TelnetOption::OutputLinefeedDisposition,       "Negotiate About Output Linefeed Disposition" },
		{ pcpp::TelnetLayer::TelnetOption::ExtendedASCII,                   "Extended ASCII"                              },
		{ pcpp::TelnetLayer::TelnetOption::Logout,                          "Logout"                                      },
		{ pcpp::TelnetLayer::TelnetOption::ByteMacro,                       "Byte Macro"                                  },
		{ pcpp::TelnetLayer::TelnetOption::DataEntryTerminal,               "Data Entry Terminal"                         },
		{ pcpp::TelnetLayer::TelnetOption::SUPDUP,                          "SUPDUP"                                      },
		{ pcpp::TelnetLayer::TelnetOption::SUPDUPOutput,                    "SUPDUP Output"                               },
		{ pcpp::TelnetLayer::TelnetOption::SendLocation,                    "Send Location"                               },
		{ pcpp::TelnetLayer::TelnetOption::TerminalType,                    "Terminal Type"                               },
		{ pcpp::TelnetLayer::TelnetOption::EndOfRecordOption,               "End Of Record"                               },
		{ pcpp::TelnetLayer::TelnetOption::TACACSUserIdentification,        "TACACS User Identification"                  },
		{ pcpp::TelnetLayer::TelnetOption::OutputMarking,                   "Output Marking"                              },
		{ pcpp::TelnetLayer::TelnetOption::TerminalLocationNumber,          "Terminal Location Number"                    },
		{ pcpp::TelnetLayer::TelnetOption::Telnet3270Regime,                "Telnet 3270 Regime"                          },
		{ pcpp::TelnetLayer::TelnetOption::X3Pad,                           "X3 Pad"                                      },
		{ pcpp::TelnetLayer::TelnetOption::NegotiateAboutWindowSize,        "Negotiate About Window Size"                 },
		{ pcpp::TelnetLayer::TelnetOption::TerminalSpeed,                   "Terminal Speed"                              },
		{ pcpp::TelnetLayer::TelnetOption::RemoteFlowControl,               "Remote Flow Control"                         },
		{ pcpp::TelnetLayer::TelnetOption::Linemode,                        "Line mode"                                   },
		{ pcpp::TelnetLayer::TelnetOption::XDisplayLocation,                "X Display Location"                          },
		{ pcpp::TelnetLayer::TelnetOption::EnvironmentOption,               "Environment Option"                          },
		{ pcpp::TelnetLayer::TelnetOption::AuthenticationOption,            "Authentication Option"                       },
		{ pcpp::TelnetLayer::TelnetOption::EncryptionOption,                "Encryption Option"                           },
		{ pcpp::TelnetLayer::TelnetOption::NewEnvironmentOption,            "New Environment Option"                      },
		{ pcpp::TelnetLayer::TelnetOption::TN3270E,                         "TN3270E"                                     },
		{ pcpp::TelnetLayer::TelnetOption::XAuth,                           "X Server Authentication"                     },
		{ pcpp::TelnetLayer::TelnetOption::Charset,                         "Charset"                                     },
		{ pcpp::TelnetLayer::TelnetOption::TelnetRemoteSerialPort,          "Telnet Remote Serial Port"                   },
		{ pcpp::TelnetLayer::TelnetOption::ComPortControlOption,            "Com Port Control Option"                     },
		{ pcpp::TelnetLayer::TelnetOption::TelnetSuppressLocalEcho,         "Telnet Suppress Local Echo"                  },
		{ pcpp::TelnetLayer::TelnetOption::TelnetStartTLS,                  "Telnet Start TLS"                            },
		{ pcpp::TelnetLayer::TelnetOption::Kermit,                          "Kermit"                                      },
		{ pcpp::TelnetLayer::TelnetOption::SendURL,                         "Send URL"                                    },
		{ pcpp::TelnetLayer::TelnetOption::ForwardX,                        "Forward X Server"                            },
		{ pcpp::TelnetLayer::TelnetOption::TelOptPragmaLogon,               "Telnet Option Pragma Logon"                  },
		{ pcpp::TelnetLayer::TelnetOption::TelOptSSPILogon,                 "Telnet Option SSPI Logon"                    },
		{ pcpp::TelnetLayer::TelnetOption::TelOptPragmaHeartbeat,           "Telnet Option Pragma Heartbeat"              },
		{ pcpp::TelnetLayer::TelnetOption::ExtendedOptions,                 "Extended option list"                        }
	};

	for (const auto& entry : possibleOptions)
	{
		PTF_ASSERT_EQUAL(pcpp::TelnetLayer::getTelnetOptionAsString(entry.first), entry.second);
	}
}

PTF_TEST_CASE(TelnetDataParsingTests)
{

	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetData.dat");

	pcpp::Packet telnetPacket(&rawPacket1);
	pcpp::TelnetLayer* telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

	PTF_ASSERT_NOT_NULL(telnetLayer);

	PTF_ASSERT_EQUAL(telnetLayer->getDataAsString(), "OpenBSD/i386 (oof) (ttyp2)");
	PTF_ASSERT_EQUAL(telnetLayer->getTotalNumberOfCommands(), 0);
	PTF_ASSERT_EQUAL(telnetLayer->toString(), "Telnet Data");
}
