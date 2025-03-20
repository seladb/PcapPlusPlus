#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "FtpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "TcpLayer.h"

PTF_TEST_CASE(FtpParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Test IPv4 packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");

	pcpp::Packet ftpPacket1(&rawPacket1);
	pcpp::FtpRequestLayer* ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer1);
	PTF_ASSERT_EQUAL(int(ftpLayer1->getCommand()), int(pcpp::FtpRequestLayer::FtpCommand::USER));
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandString(), "USER");
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "csanders");
	PTF_ASSERT_EQUAL(ftpLayer1->toString(), "FTP Request: USER");
	PTF_ASSERT_FALSE(ftpLayer1->isMultiLine());

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4Resp.dat");

	pcpp::Packet ftpPacket2(&rawPacket2);
	pcpp::FtpResponseLayer* ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer2);
	PTF_ASSERT_EQUAL(int(ftpLayer2->getStatusCode()), int(pcpp::FtpResponseLayer::FtpStatusCode::REQ_FILE_OK_COMPLETE));
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusCodeString(), "250");
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "CWD command successful. \"/\" is current directory.");
	PTF_ASSERT_EQUAL(ftpLayer2->toString(), "FTP Response: 250");
	PTF_ASSERT_FALSE(ftpLayer2->isMultiLine());

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ftpIpv4RespHyphen.dat");

	pcpp::Packet ftpPacket3(&rawPacket3);
	pcpp::FtpResponseLayer* ftpLayer3 = ftpPacket3.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer3);
	PTF_ASSERT_EQUAL(int(ftpLayer3->getStatusCode()), int(pcpp::FtpResponseLayer::FtpStatusCode::SYSTEM_STATUS));
	PTF_ASSERT_EQUAL(ftpLayer3->getStatusCodeString(), "211");
	PTF_ASSERT_EQUAL(ftpLayer3->getStatusOption(), "Extensions supported: CLNT MDTM PASV REST STREAM SIZEEnd.");
	PTF_ASSERT_EQUAL(ftpLayer3->toString(), "FTP Response: 211");
	PTF_ASSERT_TRUE(ftpLayer3->isMultiLine());

	// Test IPv6 packets
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/ftpIpv6Req.dat");

	pcpp::Packet ftpPacket4(&rawPacket4);
	pcpp::FtpRequestLayer* ftpLayer4 = ftpPacket4.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer4);
	PTF_ASSERT_EQUAL(int(ftpLayer4->getCommand()), int(pcpp::FtpRequestLayer::FtpCommand::PASS));
	PTF_ASSERT_EQUAL(ftpLayer4->getCommandString(), "PASS");
	PTF_ASSERT_EQUAL(ftpLayer4->getCommandOption(), "IEUser@");
	PTF_ASSERT_EQUAL(ftpLayer4->toString(), "FTP Request: PASS");
	PTF_ASSERT_FALSE(ftpLayer4->isMultiLine());

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/ftpIpv6Resp.dat");

	pcpp::Packet ftpPacket5(&rawPacket5);
	pcpp::FtpResponseLayer* ftpLayer5 = ftpPacket5.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer5);
	PTF_ASSERT_EQUAL(int(ftpLayer5->getStatusCode()),
	                 int(pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED));
	PTF_ASSERT_EQUAL(ftpLayer5->getStatusCodeString(), "502");
	PTF_ASSERT_EQUAL(ftpLayer5->getStatusOption(), "Unknown command 'utf8'.");
	PTF_ASSERT_EQUAL(ftpLayer5->toString(), "FTP Response: 502");
	PTF_ASSERT_FALSE(ftpLayer5->isMultiLine());

	// Test FTP Data
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/ftp-data.dat");

	pcpp::Packet ftpDataPacket(&rawPacket6);
	pcpp::FtpDataLayer* ftpDataLayer = ftpDataPacket.getLayerOfType<pcpp::FtpDataLayer>();

	PTF_ASSERT_NOT_NULL(ftpDataLayer);

	PTF_ASSERT_EQUAL(ftpDataLayer->getDataLen(), 1452);
	PTF_ASSERT_EQUAL(ftpDataLayer->toString(), "FTP Data");

	// Test IPv4 Command Only Request Packet
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/ftpIpv4CmdOnlyReq.dat");

	pcpp::Packet ftpPacket7(&rawPacket7);
	pcpp::FtpRequestLayer* ftpLayer7 = ftpPacket7.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer7);
	PTF_ASSERT_EQUAL(int(ftpLayer7->getCommand()), int(pcpp::FtpRequestLayer::FtpCommand::SYST));
	PTF_ASSERT_EQUAL(ftpLayer7->getCommandString(), "SYST");
	PTF_ASSERT_EQUAL(ftpLayer7->getCommandOption(), "");
	PTF_ASSERT_EQUAL(ftpLayer7->toString(), "FTP Request: SYST");
	PTF_ASSERT_FALSE(ftpLayer7->isMultiLine());

	// Command codes
	// clang-format off
	std::vector<std::pair<pcpp::FtpRequestLayer::FtpCommand, std::string>> possibleCommandCodes = {
		{ static_cast<pcpp::FtpRequestLayer::FtpCommand>(0), "Unknown command"},
		{ pcpp::FtpRequestLayer::FtpCommand::ABOR,           "Abort an active file transfer"},
		{ pcpp::FtpRequestLayer::FtpCommand::ACCT,           "Account information"},
		{ pcpp::FtpRequestLayer::FtpCommand::ADAT,           "Authentication/Security Data"},
		{ pcpp::FtpRequestLayer::FtpCommand::ALLO,           "Allocate sufficient disk space to receive a file"},
		{ pcpp::FtpRequestLayer::FtpCommand::APPE,           "Append (with create)"},
		{ pcpp::FtpRequestLayer::FtpCommand::AUTH,           "Authentication/Security Mechanism"},
		{ pcpp::FtpRequestLayer::FtpCommand::AVBL,           "Get the available space"},
		{ pcpp::FtpRequestLayer::FtpCommand::CCC,            "Clear Command Channel"},
		{ pcpp::FtpRequestLayer::FtpCommand::CDUP,           "Change to Parent Directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::CONF,           "Confidentiality Protection Command"},
		{ pcpp::FtpRequestLayer::FtpCommand::CSID,           "Client / Server Identification"},
		{ pcpp::FtpRequestLayer::FtpCommand::CWD,            "Change working directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::DELE,           "Delete file"},
		{ pcpp::FtpRequestLayer::FtpCommand::DSIZ,           "Get the directory size"},
		{ pcpp::FtpRequestLayer::FtpCommand::ENC,            "Privacy Protected Channel"},
		{ pcpp::FtpRequestLayer::FtpCommand::EPRT,           "Specifies an extended address and port to which the server should connect"},
		{ pcpp::FtpRequestLayer::FtpCommand::EPSV,           "Enter extended passive mode"},
		{ pcpp::FtpRequestLayer::FtpCommand::FEAT,           "Get the feature list implemented by the server"},
		{ pcpp::FtpRequestLayer::FtpCommand::HELP,           "Returns usage documentation on a command if specified, else a general help document is returned"},
		{ pcpp::FtpRequestLayer::FtpCommand::HOST,           "Identify desired virtual host on server, by name"},
		{ pcpp::FtpRequestLayer::FtpCommand::LANG,           "Language Negotiation"},
		{ pcpp::FtpRequestLayer::FtpCommand::LIST,           "Returns information of a file or directory if specified, else information of the current working directory is returned"},
		{ pcpp::FtpRequestLayer::FtpCommand::LPRT,           "Specifies a long address and port to which the server should connect"},
		{ pcpp::FtpRequestLayer::FtpCommand::LPSV,           "Enter long passive mode"},
		{ pcpp::FtpRequestLayer::FtpCommand::MDTM,           "Return the last-modified time of a specified file"},
		{ pcpp::FtpRequestLayer::FtpCommand::MFCT,           "Modify the creation time of a file"},
		{ pcpp::FtpRequestLayer::FtpCommand::MFF,            "Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file)"},
		{ pcpp::FtpRequestLayer::FtpCommand::MFMT,           "Modify the last modification time of a file"},
		{ pcpp::FtpRequestLayer::FtpCommand::MIC,            "Integrity Protected Command"},
		{ pcpp::FtpRequestLayer::FtpCommand::MKD,            "Make directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::MLSD,           "Lists the contents of a directory in a standardized machine-readable format"},
		{ pcpp::FtpRequestLayer::FtpCommand::MLST,           "Provides data about exactly the object named on its command line in a standardized machine-readable format"},
		{ pcpp::FtpRequestLayer::FtpCommand::MODE,           "Sets the transfer mode (Stream, Block, or Compressed)"},
		{ pcpp::FtpRequestLayer::FtpCommand::NLST,           "Returns a list of file names in a specified directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::NOOP,           "No operation (dummy packet; used mostly on keepalives)"},
		{ pcpp::FtpRequestLayer::FtpCommand::OPTS,           "Select options for a feature (for example OPTS UTF8 ON)"},
		{ pcpp::FtpRequestLayer::FtpCommand::PASS,           "Authentication password"},
		{ pcpp::FtpRequestLayer::FtpCommand::PASV,           "Enter passive mode"},
		{ pcpp::FtpRequestLayer::FtpCommand::PBSZ,           "Protection Buffer Size"},
		{ pcpp::FtpRequestLayer::FtpCommand::PORT,           "Specifies an address and port to which the server should connect"},
		{ pcpp::FtpRequestLayer::FtpCommand::PROT,           "Data Channel Protection Level"},
		{ pcpp::FtpRequestLayer::FtpCommand::PWD,            "Print working directory. Returns the current directory of the host"},
		{ pcpp::FtpRequestLayer::FtpCommand::QUIT,           "Disconnect"},
		{ pcpp::FtpRequestLayer::FtpCommand::REIN,           "Re initializes the connection"},
		{ pcpp::FtpRequestLayer::FtpCommand::REST,           "Restart transfer from the specified point"},
		{ pcpp::FtpRequestLayer::FtpCommand::RETR,           "Retrieve a copy of the file"},
		{ pcpp::FtpRequestLayer::FtpCommand::RMD,            "Remove a directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::RMDA,           "Remove a directory tree"},
		{ pcpp::FtpRequestLayer::FtpCommand::RNFR,           "Rename from"},
		{ pcpp::FtpRequestLayer::FtpCommand::RNTO,           "Rename to"},
		{ pcpp::FtpRequestLayer::FtpCommand::SITE,           "Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands"},
		{ pcpp::FtpRequestLayer::FtpCommand::SIZE,           "Return the size of a file"},
		{ pcpp::FtpRequestLayer::FtpCommand::SMNT,           "Mount file structure"},
		{ pcpp::FtpRequestLayer::FtpCommand::SPSV,           "Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)"},
		{ pcpp::FtpRequestLayer::FtpCommand::STAT,           "Returns information on the server status, including the status of the current connection"},
		{ pcpp::FtpRequestLayer::FtpCommand::STOR,           "Accept the data and to store the data as a file at the server site"},
		{ pcpp::FtpRequestLayer::FtpCommand::STOU,           "Store file uniquely"},
		{ pcpp::FtpRequestLayer::FtpCommand::STRU,           "Set file transfer structure"},
		{ pcpp::FtpRequestLayer::FtpCommand::SYST,           "Return system type"},
		{ pcpp::FtpRequestLayer::FtpCommand::THMB,           "Get a thumbnail of a remote image file"},
		{ pcpp::FtpRequestLayer::FtpCommand::TYPE,           "Sets the transfer mode (ASCII/Binary)"},
		{ pcpp::FtpRequestLayer::FtpCommand::USER,           "Authentication username"},
		{ pcpp::FtpRequestLayer::FtpCommand::XCUP,           "Change to the parent of the current working directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::XMKD,           "Make a directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::XPWD,           "Print the current working directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::XRCP,           ""},
		{ pcpp::FtpRequestLayer::FtpCommand::XRMD,           "Remove the directory"},
		{ pcpp::FtpRequestLayer::FtpCommand::XRSQ,           ""},
		{ pcpp::FtpRequestLayer::FtpCommand::XSEM,           "Send, mail if cannot"},
		{ pcpp::FtpRequestLayer::FtpCommand::XSEN,           "Send to terminal"},
	};
	// clang-format on

	for (const auto& entry : possibleCommandCodes)
	{
		PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandInfo(entry.first), entry.second);
	}

	// clang-format off
	// Status codes
	std::vector<std::pair<pcpp::FtpResponseLayer::FtpStatusCode, std::string>> possibleStatusCodes = {
		{ static_cast<pcpp::FtpResponseLayer::FtpStatusCode>(0),                          "Unknown Status Code"                             },
		{ pcpp::FtpResponseLayer::FtpStatusCode::RESTART_MARKER,                          "Restart marker reply"                            },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SERVICE_READY_IN_MIN,                    "Service ready in nnn minutes"                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::DATA_ALREADY_OPEN_START_TRANSFER,        "Data connection already open; transfer starting"                                                                                  },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FILE_OK,                                 "File status okay; about to open data connection" },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_OK,                              "Command okay"                                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS,     "Command not implemented, superfluous at this site"                                                                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SYSTEM_STATUS,                           "System status, or system help reply"             },
		{ pcpp::FtpResponseLayer::FtpStatusCode::DIR_STATUS,                              "Directory status"                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FILE_STATUS,                             "File status"                                     },
		{ pcpp::FtpResponseLayer::FtpStatusCode::HELP_MESSAGE,                            "Help message"                                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NAME_SYSTEM_TYPE,                        "NAME system type"                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SERVICE_READY_FOR_USER,                  "Service ready for new user"                      },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SERVICE_CLOSING_CONTROL,                 "Service closing control connection"              },
		{ pcpp::FtpResponseLayer::FtpStatusCode::DATA_OPEN_NO_TRANSFER,                   "Data connection open; no transfer in progress"                                                                                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::CLOSING_DATA,                            "Closing data connection"                         },
		{ pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_PASSIVE,                        "Entering Passive Mode"                           },
		{ pcpp::FtpResponseLayer::FtpStatusCode::ENTERING_EXTENDED_PASSIVE,               "Entering Extended Passive Mode"                  },
		{ pcpp::FtpResponseLayer::FtpStatusCode::USER_LOG_IN_PROCEED,                     "User logged in, proceed"                         },
		{ pcpp::FtpResponseLayer::FtpStatusCode::USER_LOG_IN_AUTHORIZED,                  "User logged in, authorized by security data exchange"                                                                             },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE,              "Security data exchange complete"                 },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SEC_DATA_EXCHANGE_COMPLETE_SUCCESS,      "Security data exchange completed successfully"                                                                                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_FILE_OK_COMPLETE,                    "Requested file action okay, completed"           },
		{ pcpp::FtpResponseLayer::FtpStatusCode::PATHNAME_CREATED,                        "PATHNAME created"                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::USER_OK_NEED_PASSWORD,                   "User name okay, need password"                   },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NEED_ACCOUNT,                            "Need account for login"                          },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_SEC_MECHANISM_OK,                    "Requested security mechanism is ok"              },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SEC_IS_ACCEPTABLE,                       "Security data is acceptable, more is required"   },
		{ pcpp::FtpResponseLayer::FtpStatusCode::USER_OK_NEED_PASS_CHALLENGE,             "Username okay, need password. Challenge is ..."                                                                                   },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FILE_PENDING_ACTION,                     "Requested file action pending further information"                                                                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SERVICE_NOT_AVAILABLE,                   "Service not available, closing control connection"                                                                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::CANT_OPEN_DATA_CONNECTION,               "Can't open data connection"                      },
		{ pcpp::FtpResponseLayer::FtpStatusCode::CONNECTION_CLOSED,                       "Connection closed; transfer aborted"             },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NEED_UNAVAILABLE_RESOURCE_TO_SEC,        "Need some unavailable resource to process security"                                                                               },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_FILE_ACTION_NOT_TAKEN,               "Requested file action not taken"                 },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_ACTION_ABORTED,                      "Requested action aborted: local error in processing"                                                                              },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_ACTION_NOT_TAKEN,                    "Requested action not taken. Insufficient storage space in system"                                                                 },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SYNTAX_ERROR_COMMAND_UNRECOGNIZED,       "Syntax error, command unrecognized"                                                                                               },
		{ pcpp::FtpResponseLayer::FtpStatusCode::SYNTAX_ERROR_PARAMETER_OR_ARGUMENT,      "Syntax error in parameters or arguments"                                                                                          },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED,                 "Command not implemented"                         },
		{ pcpp::FtpResponseLayer::FtpStatusCode::BAD_SEQUENCE_COMMANDS,                   "Bad sequence of commands"                        },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER,   "Command not implemented for that parameter"                                                                                       },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NETWORK_PROTOCOL_NOT_SUPPORTED,          "Network protocol not supported"                  },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NOT_LOGGED_IN,                           "Not logged in"                                   },
		{ pcpp::FtpResponseLayer::FtpStatusCode::NEED_ACCOUNT_FOR_STORE_FILE,             "Need account for storing files"                  },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_PROTECTION_DENIED,               "Command protection level denied for policy reasons"                                                                               },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQUEST_DENIED,                          "Request denied for policy reasons"               },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FAILED_SEC_CHECK,                        "Failed security check (hash, sequence, etc)"     },
		{ pcpp::FtpResponseLayer::FtpStatusCode::REQ_PROT_LEVEL_NOT_SUPPORTED,            "Requested PROT level not supported by mechanism"                                                                                  },
		{ pcpp::FtpResponseLayer::FtpStatusCode::COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED,  "Command protection level not supported by security mechanism"                                                                     },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FILE_UNAVAILABLE,                        "Requested action not taken: File unavailable"    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::PAGE_TYPE_UNKNOWN,                       "Requested action aborted: page type unknown"     },
		{ pcpp::FtpResponseLayer::FtpStatusCode::EXCEED_STORAGE_ALLOCATION,               "Requested file action aborted: Exceeded storage allocation"                                                                       },
		{ pcpp::FtpResponseLayer::FtpStatusCode::FILENAME_NOT_ALLOWED,                    "Requested action not taken: File name not allowed"                                                                                },
		{ pcpp::FtpResponseLayer::FtpStatusCode::INTEGRITY_PROTECTED,                     "Integrity protected reply"                       },
		{ pcpp::FtpResponseLayer::FtpStatusCode::CONFIDENTIALITY_AND_INTEGRITY_PROTECTED, "Confidentiality and integrity protected reply"                                                                                    },
		{ pcpp::FtpResponseLayer::FtpStatusCode::CONFIDENTIALITY_PROTECTED,               "Confidentiality protected reply"                 }
	};
	// clang-format off


	for (const auto& entry : possibleStatusCodes)
	{
		PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(entry.first), entry.second);
	}
}

PTF_TEST_CASE(FtpCreationTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Craft packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");

	pcpp::Packet ftpPacket1(&rawPacket1);

	pcpp::EthLayer ethLayer1(*ftpPacket1.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer1(*ftpPacket1.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer1(*ftpPacket1.getLayerOfType<pcpp::TcpLayer>());

	pcpp::FtpRequestLayer ftpReqLayer1(pcpp::FtpRequestLayer::FtpCommand::USER, "csanders");

	pcpp::Packet craftedPacket1;
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ethLayer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ipv4Layer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&tcpLayer1));
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ftpReqLayer1));

	PTF_ASSERT_EQUAL(bufferLength1, craftedPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer1, craftedPacket1.getRawPacket()->getRawData(), bufferLength1);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4RespHyphen.dat");

	pcpp::Packet ftpPacket2(&rawPacket2);

	pcpp::EthLayer ethLayer2(*ftpPacket2.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ipv4Layer2(*ftpPacket2.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer2(*ftpPacket2.getLayerOfType<pcpp::TcpLayer>());

	pcpp::FtpResponseLayer ftpRespLayer1(
	    pcpp::FtpResponseLayer::FtpStatusCode::SYSTEM_STATUS,
	    "Extensions supported:\r\n CLNT\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n211 End.");

	pcpp::Packet craftedPacket2;
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ipv4Layer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&tcpLayer2));
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ftpRespLayer1));

	PTF_ASSERT_EQUAL(bufferLength2, craftedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer2, craftedPacket2.getRawPacket()->getRawData(), bufferLength2);
}

PTF_TEST_CASE(FtpEditTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Modify existing request packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");
	pcpp::Packet ftpPacket1(&rawPacket1);
	pcpp::FtpRequestLayer* ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();
	PTF_ASSERT_NOT_NULL(ftpLayer1);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpReqEdited1.dat");
	pcpp::Packet ftpReqEdited1(&rawPacket2);
	pcpp::FtpRequestLayer* ftpReqEditedLayer1 = ftpReqEdited1.getLayerOfType<pcpp::FtpRequestLayer>();
	PTF_ASSERT_NOT_NULL(ftpReqEditedLayer1);

	ftpLayer1->setCommand(pcpp::FtpRequestLayer::FtpCommand::FEAT);
	PTF_ASSERT_EQUAL(ftpLayer1->getDataLen(), ftpReqEditedLayer1->getDataLen());
	PTF_ASSERT_BUF_COMPARE(ftpLayer1->getData(), ftpReqEditedLayer1->getData(), ftpLayer1->getDataLen());

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ftpReqEdited2.dat");
	pcpp::Packet ftpReqEdited2(&rawPacket3);
	pcpp::FtpRequestLayer* ftpReqEditedLayer2 = ftpReqEdited2.getLayerOfType<pcpp::FtpRequestLayer>();
	PTF_ASSERT_NOT_NULL(ftpReqEditedLayer2);

	ftpLayer1->setCommandOption("Test option");
	PTF_ASSERT_EQUAL(ftpLayer1->getDataLen(), ftpReqEditedLayer2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(ftpLayer1->getData(), ftpReqEditedLayer2->getData(), ftpLayer1->getDataLen());

	// Modify existing response packets
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/ftpIpv4Resp.dat");
	pcpp::Packet ftpPacket2(&rawPacket4);
	pcpp::FtpResponseLayer* ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();
	PTF_ASSERT_NOT_NULL(ftpLayer2);

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/ftpRespEdited1.dat");
	pcpp::Packet ftpRespEdited1(&rawPacket5);
	pcpp::FtpResponseLayer* ftpRespEditedLayer1 = ftpRespEdited1.getLayerOfType<pcpp::FtpResponseLayer>();
	PTF_ASSERT_NOT_NULL(ftpRespEditedLayer1);

	ftpLayer2->setStatusCode(pcpp::FtpResponseLayer::FtpStatusCode::CLOSING_DATA);
	PTF_ASSERT_EQUAL(ftpLayer2->getDataLen(), ftpRespEditedLayer1->getDataLen());
	PTF_ASSERT_BUF_COMPARE(ftpLayer2->getData(), ftpRespEditedLayer1->getData(), ftpLayer2->getDataLen());

	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/ftpRespEdited2.dat");
	pcpp::Packet ftpRespEdited2(&rawPacket6);
	pcpp::FtpResponseLayer* ftpRespEditedLayer2 = ftpRespEdited2.getLayerOfType<pcpp::FtpResponseLayer>();
	PTF_ASSERT_NOT_NULL(ftpRespEditedLayer2);

	ftpLayer2->setStatusOption("Test option");
	PTF_ASSERT_EQUAL(ftpLayer2->getDataLen(), ftpRespEditedLayer2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(ftpLayer2->getData(), ftpRespEditedLayer2->getData(), ftpLayer2->getDataLen());
}
