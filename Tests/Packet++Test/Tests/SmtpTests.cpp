#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Packet.h"
#include "SmtpLayer.h"
#include "SystemUtils.h"
#include "TcpLayer.h"

PTF_TEST_CASE(SmtpParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Command
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/smtpCommand.dat");
	pcpp::Packet smtpPacket1(&rawPacket1);
	auto* smtpLayer1 = smtpPacket1.getLayerOfType<pcpp::SmtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer1);
	PTF_ASSERT_EQUAL(smtpLayer1->getHeaderLen(), 12);
	PTF_ASSERT_EQUAL(smtpLayer1->getCommand(), pcpp::SmtpRequestLayer::SmtpCommand::AUTH, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer1->getCommandString(), "AUTH");
	PTF_ASSERT_EQUAL(smtpLayer1->getCommandOption(), "LOGIN");
	PTF_ASSERT_EQUAL(smtpLayer1->getCommandOption(false), "LOGIN");
	PTF_ASSERT_EQUAL(smtpLayer1->toString(), "SMTP request layer, command: Authenticate client and server");
	PTF_ASSERT_FALSE(smtpLayer1->isMultiLine());

	// Response packet
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/smtpResponse.dat");
	pcpp::Packet smtpPacket2(&rawPacket2);
	auto* smtpLayer2 = smtpPacket2.getLayerOfType<pcpp::SmtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer2);
	PTF_ASSERT_EQUAL(smtpLayer2->getHeaderLen(), 18);
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusCode(), pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_INPUT, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusCodeString(), "334");
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusOption(), "VXNlcm5hbWU6");
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusOption(false), "VXNlcm5hbWU6");
	PTF_ASSERT_EQUAL(smtpLayer2->toString(), "SMTP response layer, status code: AUTH input");
	PTF_ASSERT_FALSE(smtpLayer2->isMultiLine());

	// Multiline
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/smtpMultiLine.dat");
	pcpp::Packet smtpPacket3(&rawPacket3);
	auto* smtpLayer3 = smtpPacket3.getLayerOfType<pcpp::SmtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer3);
	PTF_ASSERT_EQUAL(smtpLayer3->getHeaderLen(), 181);
	PTF_ASSERT_EQUAL(smtpLayer3->getStatusCode(), pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer3->getStatusCodeString(), "220");
	PTF_ASSERT_EQUAL(smtpLayer3->getStatusOption(),
	                 "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 We do not authorize "
	                 "the use of this system to transport unsolicited, and/or bulk e-mail.");
	PTF_ASSERT_EQUAL(smtpLayer3->getStatusOption(false),
	                 "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 \r\n"
	                 "We do not authorize the use of this system to transport unsolicited, \r\nand/or bulk e-mail.")
	PTF_ASSERT_EQUAL(smtpLayer3->toString(), "SMTP response layer, status code: Service ready");
	PTF_ASSERT_TRUE(smtpLayer3->isMultiLine());

	// IPv6
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/smtpIpv6.dat");
	pcpp::Packet smtpPacket4(&rawPacket4);
	auto* smtpLayer4 = smtpPacket4.getLayerOfType<pcpp::SmtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer4);
	PTF_ASSERT_EQUAL(smtpLayer4->getHeaderLen(), 51);
	PTF_ASSERT_EQUAL(smtpLayer4->getStatusCode(), pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer4->getStatusCodeString(), "220");
	PTF_ASSERT_EQUAL(smtpLayer4->getStatusOption(), "mx.google.com ESMTP m17si1051593vck.2 - gsmtp");
	PTF_ASSERT_EQUAL(smtpLayer4->getStatusOption(false), "mx.google.com ESMTP m17si1051593vck.2 - gsmtp");
	PTF_ASSERT_EQUAL(smtpLayer4->toString(), "SMTP response layer, status code: Service ready");
	PTF_ASSERT_FALSE(smtpLayer4->isMultiLine());

	// Username and Password packets. They should return Unknown since there is no command in packets
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/smtpUser.dat");
	pcpp::Packet smtpPacket5(&rawPacket5);
	auto* smtpLayer5 = smtpPacket5.getLayerOfType<pcpp::SmtpRequestLayer>();

	PTF_ASSERT_EQUAL(smtpLayer5->getHeaderLen(), 30);
	PTF_ASSERT_EQUAL(smtpLayer5->getCommand(), pcpp::SmtpRequestLayer::SmtpCommand::UNK, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer5->getCommandString(), "");
	PTF_ASSERT_EQUAL(smtpLayer5->getCommandOption(), "Z3VycGFydGFwQHBhdHJpb3RzLmlu");
	PTF_ASSERT_EQUAL(smtpLayer5->getCommandOption(false), "Z3VycGFydGFwQHBhdHJpb3RzLmlu");
	PTF_ASSERT_EQUAL(smtpLayer5->toString(), "SMTP request layer, command: Unknown command");
	PTF_ASSERT_FALSE(smtpLayer5->isMultiLine());

	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/smtpPassword.dat");
	pcpp::Packet smtpPacket6(&rawPacket6);
	auto* smtpLayer6 = smtpPacket6.getLayerOfType<pcpp::SmtpRequestLayer>();

	PTF_ASSERT_EQUAL(smtpLayer6->getHeaderLen(), 18);
	PTF_ASSERT_EQUAL(smtpLayer6->getCommand(), pcpp::SmtpRequestLayer::SmtpCommand::UNK, enumclass);
	PTF_ASSERT_EQUAL(smtpLayer6->getCommandString(), "");
	PTF_ASSERT_EQUAL(smtpLayer6->getCommandOption(), "cHVuamFiQDEyMw==");
	PTF_ASSERT_EQUAL(smtpLayer6->getCommandOption(false), "cHVuamFiQDEyMw==");
	PTF_ASSERT_EQUAL(smtpLayer6->toString(), "SMTP request layer, command: Unknown command");
	PTF_ASSERT_FALSE(smtpLayer6->isMultiLine());

	// Command descriptions
	std::vector<std::pair<pcpp::SmtpRequestLayer::SmtpCommand, std::string>> possibleCommandCodes = {
		{ static_cast<pcpp::SmtpRequestLayer::SmtpCommand>(0), "Unknown command"                                            },
		{ pcpp::SmtpRequestLayer::SmtpCommand::DATA,           "Starting mail body"                                         },
		{ pcpp::SmtpRequestLayer::SmtpCommand::EHLO,           "Initiate conversation"                                      },
		{ pcpp::SmtpRequestLayer::SmtpCommand::EXPN,           "Expand the mailing list"                                    },
		{ pcpp::SmtpRequestLayer::SmtpCommand::HELO,           "Initiate conversation"                                      },
		{ pcpp::SmtpRequestLayer::SmtpCommand::HELP,           "Ask information"                                            },
		{ pcpp::SmtpRequestLayer::SmtpCommand::MAIL,           "Sender indication"                                          },
		{ pcpp::SmtpRequestLayer::SmtpCommand::NOOP,           "No operation"                                               },
		{ pcpp::SmtpRequestLayer::SmtpCommand::QUIT,           "Close conversation"                                         },
		{ pcpp::SmtpRequestLayer::SmtpCommand::RCPT,           "Receiver indication"                                        },
		{ pcpp::SmtpRequestLayer::SmtpCommand::RSET,           "Abort transaction"                                          },
		{ pcpp::SmtpRequestLayer::SmtpCommand::VRFY,           "Identify user"                                              },
		{ pcpp::SmtpRequestLayer::SmtpCommand::STARTTLS,       "Start TLS handshake"                                        },
		{ pcpp::SmtpRequestLayer::SmtpCommand::TURN,           "Reverse the role of sender and receiver"                    },
		{ pcpp::SmtpRequestLayer::SmtpCommand::SEND,           "Send mail to terminal"                                      },
		{ pcpp::SmtpRequestLayer::SmtpCommand::SOML,           "Send mail to terminal or to mailbox"                        },
		{ pcpp::SmtpRequestLayer::SmtpCommand::SAML,           "Send mail to terminal and mailbox"                          },
		{ pcpp::SmtpRequestLayer::SmtpCommand::AUTH,           "Authenticate client and server"                             },
		{ pcpp::SmtpRequestLayer::SmtpCommand::ATRN,           "Reverse the role of sender and receiver"                    },
		{ pcpp::SmtpRequestLayer::SmtpCommand::BDAT,           "Submit mail contents"                                       },
		{ pcpp::SmtpRequestLayer::SmtpCommand::ETRN,           "Request to start SMTP queue processing"                     },
		{ pcpp::SmtpRequestLayer::SmtpCommand::XADR,           "Release status of the channel"                              },
		{ pcpp::SmtpRequestLayer::SmtpCommand::XCIR,           "Release status of the circuit checking facility"            },
		{ pcpp::SmtpRequestLayer::SmtpCommand::XSTA,           "Release status of the number of messages in channel queues" },
		{ pcpp::SmtpRequestLayer::SmtpCommand::XGEN,
         "Release status of whether a compiled configuration and character set are in use"                                  }
	};

	for (const auto& entry : possibleCommandCodes)
	{
		PTF_ASSERT_EQUAL(pcpp::SmtpRequestLayer::getCommandInfo(entry.first), entry.second);
	}

	// Status descriptions
	std::vector<std::pair<pcpp::SmtpResponseLayer::SmtpStatusCode, std::string>> possibleStatusCodes = {
		{ static_cast<pcpp::SmtpResponseLayer::SmtpStatusCode>(0),           "Unknown status code"                            },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::SYSTEM_STATUS,            "System status, or system help reply"            },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::HELP_MESSAGE,             "Help message"                                   },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY,            "Service ready"                                  },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_CLOSE,            "Service closing transmission channel"           },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_SUCCESS,             "Authentication successful"                      },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::COMPLETED,                "Requested mail action okay, completed"          },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::WILL_FORWARD,             "User not local; will forward to <forward-path>" },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::CANNOT_VERIFY,
         "Cannot VRFY user, but will accept message and attempt delivery"                                                     },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_INPUT,               "AUTH input"                                     },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::MAIL_INPUT,               "Start mail input; end with <CRLF>.<CRLF>"       },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_UNAVAILABLE,
         "Service not available, closing transmission channel"		                                                        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::PASS_NEEDED,              "A password transition is needed"                },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::MAILBOX_UNAVAILABLE_TEMP,
         "Requested mail action not taken: mailbox unavailable (mail busy or temporarily blocked)"                            },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::ABORT_LOCAL_ERROR,
         "Requested action aborted: local error in processing"		                                                        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::INSUFFICIENT_STORAGE,
         "Requested action not taken: insufficient system storage"                                                            },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::TEMP_AUTH_FAILED,         "Temporary authentication failed"                },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::PARAM_NOT_ACCOMMODATED,   "Server unable to accommodate parameters"        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::CMD_NOT_RECOGNIZED,       "Syntax error, command unrecognized"             },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::SYNTAX_ERROR_PARAM,       "Syntax error in parameters or arguments"        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::CMD_NOT_IMPLEMENTED,      "Command not implemented"                        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::CMD_BAD_SEQUENCE,         "Bad sequence of commands"                       },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::PARAM_NOT_IMPLEMENTED,    "Command parameter not implemented"              },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::MAIL_NOT_ACCEPTED,        "Server does not accept mail"                    },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::ENCRYPT_NEED,             "Encryption needed"                              },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_REQUIRED,            "Authentication required"                        },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_TOO_WEAK,            "Authentication mechanism is too weak"           },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::AUTH_CRED_INVALID,        "Authentication credentials invalid"             },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::ENCRYPT_REQUIRED,
         "Encryption required for requested authentication mechanism"                                                         },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::MAILBOX_UNAVAILABLE,
         "Requested action not taken: mailbox unavailable"		                                                            },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::USER_NOT_LOCAL,           "User not local; please try <forward-path>"      },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::EXCEED_STORAGE,
         "Requested mail action aborted: exceeded storage allocation"                                                         },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::NAME_NOT_ALLOWED,
         "Requested action not taken: mailbox name not allowed"                                                               },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::TRANSACTION_FAIL,         "Transaction failed"                             },
		{ pcpp::SmtpResponseLayer::SmtpStatusCode::DOMAIN_NOT_ACCEPT,        "Domain does not accept mail"                    }
	};

	for (const auto& entry : possibleStatusCodes)
	{
		PTF_ASSERT_EQUAL(pcpp::SmtpResponseLayer::getStatusCodeAsString(entry.first), entry.second);
	}
}

PTF_TEST_CASE(SmtpCreationTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Request
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/smtpCommand.dat");
	pcpp::Packet smtpPacket1(&rawPacket1);

	pcpp::EthLayer ethLayer1(*smtpPacket1.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer1(*smtpPacket1.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer1(*smtpPacket1.getLayerOfType<pcpp::TcpLayer>());

	pcpp::SmtpRequestLayer smtpReqLayer1(pcpp::SmtpRequestLayer::SmtpCommand::AUTH, "LOGIN");

	pcpp::Packet craftedPacket1;
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ethLayer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ipv4Layer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&tcpLayer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&smtpReqLayer1));

	PTF_ASSERT_EQUAL(bufferLength1, craftedPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer1, craftedPacket1.getRawPacket()->getRawData(), bufferLength1);

	// Response multiline
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/smtpMultiLine.dat");
	pcpp::Packet smtpPacket2(&rawPacket2);

	pcpp::EthLayer ethLayer2(*smtpPacket2.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer2(*smtpPacket2.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer2(*smtpPacket2.getLayerOfType<pcpp::TcpLayer>());

	pcpp::SmtpResponseLayer smtpRespLayer1(
	    pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY,
	    "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 \r\n220-We do not authorize the "
	    "use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.");

	pcpp::Packet craftedPacket2;
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ipv4Layer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&tcpLayer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&smtpRespLayer1));

	PTF_ASSERT_EQUAL(bufferLength2, craftedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer2, craftedPacket2.getRawPacket()->getRawData(), bufferLength2);
}

PTF_TEST_CASE(SmtpEditTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Request
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/smtpCommand.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/smtpCommandEdited.dat");

	pcpp::Packet smtpPacket1(&rawPacket1);
	auto* smtpLayer1 = smtpPacket1.getLayerOfType<pcpp::SmtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer1);
	smtpLayer1->setCommand(pcpp::SmtpRequestLayer::SmtpCommand::EHLO);
	smtpLayer1->setCommandOption("Test Option");
	smtpPacket1.computeCalculateFields();

	pcpp::Packet smtpEditedPacket1(&rawPacket2);
	PTF_ASSERT_EQUAL(smtpPacket1.getRawPacket()->getRawDataLen(), smtpEditedPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(smtpPacket1.getRawPacket()->getRawData(), smtpEditedPacket1.getRawPacket()->getRawData(),
	                       smtpPacket1.getRawPacket()->getRawDataLen());

	// Response multiline
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/smtpMultiLine.dat");
	pcpp::Packet smtpPacket2(&rawPacket3);

	auto* smtpLayer2 = smtpPacket2.getLayerOfType<pcpp::SmtpResponseLayer>();
	PTF_ASSERT_NOT_NULL(smtpLayer2);
	smtpLayer2->setStatusCode(pcpp::SmtpResponseLayer::SmtpStatusCode::ABORT_LOCAL_ERROR);
	smtpLayer2->setStatusOption("Test Option Line 1\r\n451 Test Option Line 2");
	smtpPacket2.computeCalculateFields();

	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/smtpMultiLineEdited.dat");
	pcpp::Packet smtpEditedPacket2(&rawPacket4);

	PTF_ASSERT_EQUAL(smtpPacket2.getRawPacket()->getRawDataLen(), smtpEditedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(smtpPacket2.getRawPacket()->getRawData(), smtpEditedPacket2.getRawPacket()->getRawData(),
	                       smtpPacket2.getRawPacket()->getRawDataLen());
}
