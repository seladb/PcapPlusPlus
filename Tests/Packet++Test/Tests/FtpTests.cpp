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
	gettimeofday(&time, NULL);

	// Test IPv4 packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");

	pcpp::Packet ftpPacket1(&rawPacket1);
	pcpp::FtpRequestLayer *ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer1);
	PTF_ASSERT_EQUAL(ftpLayer1->getCommand(), pcpp::FtpRequestLayer::USER);
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandString(), "USER");
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "csanders");
	PTF_ASSERT_EQUAL(ftpLayer1->toString(), "FTP Request: USER");
	PTF_ASSERT_FALSE(ftpLayer1->isMultiLine());

	PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandInfo(pcpp::FtpRequestLayer::USER),
					 "Authentication username.");
	PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandAsString(pcpp::FtpRequestLayer::USER), "USER");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4Resp.dat");

	pcpp::Packet ftpPacket2(&rawPacket2);
	pcpp::FtpResponseLayer *ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer2);
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusCode(), pcpp::FtpResponseLayer::REQ_FILE_OK_COMPLETE);
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusCodeString(), "250");
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "CWD command successful. \"/\" is current directory.");
	PTF_ASSERT_EQUAL(ftpLayer2->toString(), "FTP Response: 250");
	PTF_ASSERT_FALSE(ftpLayer2->isMultiLine());

	PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(pcpp::FtpResponseLayer::REQ_FILE_OK_COMPLETE),
					 "Requested file action okay, completed");

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ftpIpv4RespHyphen.dat");

	pcpp::Packet ftpPacket3(&rawPacket3);
	pcpp::FtpResponseLayer *ftpLayer3 = ftpPacket3.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer3);
	PTF_ASSERT_EQUAL(ftpLayer3->getStatusCode(), pcpp::FtpResponseLayer::SYSTEM_STATUS);
	PTF_ASSERT_EQUAL(ftpLayer3->getStatusCodeString(), "211");
	PTF_ASSERT_EQUAL(ftpLayer3->getStatusOption(), "Extensions supported: CLNT MDTM PASV REST STREAM SIZE211 End.");
	PTF_ASSERT_EQUAL(ftpLayer3->toString(), "FTP Response: 211");
	PTF_ASSERT_TRUE(ftpLayer3->isMultiLine());

	PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(pcpp::FtpResponseLayer::SYSTEM_STATUS),
					 "System status, or system help reply");

	// Test IPv6 packets
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/ftpIpv6Req.dat");

	pcpp::Packet ftpPacket4(&rawPacket4);
	pcpp::FtpRequestLayer *ftpLayer4 = ftpPacket4.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer4);
	PTF_ASSERT_EQUAL(ftpLayer4->getCommand(), pcpp::FtpRequestLayer::PASS);
	PTF_ASSERT_EQUAL(ftpLayer4->getCommandString(), "PASS");
	PTF_ASSERT_EQUAL(ftpLayer4->getCommandOption(), "IEUser@");
	PTF_ASSERT_EQUAL(ftpLayer4->toString(), "FTP Request: PASS");
	PTF_ASSERT_FALSE(ftpLayer4->isMultiLine());

	PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandInfo(pcpp::FtpRequestLayer::PASS),
					 "Authentication password.");
	PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandAsString(pcpp::FtpRequestLayer::PASS), "PASS");

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/ftpIpv6Resp.dat");

	pcpp::Packet ftpPacket5(&rawPacket5);
	pcpp::FtpResponseLayer *ftpLayer5 = ftpPacket5.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer5);
	PTF_ASSERT_EQUAL(ftpLayer5->getStatusCode(), pcpp::FtpResponseLayer::COMMAND_NOT_IMPLEMENTED);
	PTF_ASSERT_EQUAL(ftpLayer5->getStatusCodeString(), "502");
	PTF_ASSERT_EQUAL(ftpLayer5->getStatusOption(), "Unknown command 'utf8'.");
	PTF_ASSERT_EQUAL(ftpLayer5->toString(), "FTP Response: 502");
	PTF_ASSERT_FALSE(ftpLayer5->isMultiLine());

	PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(pcpp::FtpResponseLayer::COMMAND_NOT_IMPLEMENTED),
					 "Command not implemented");
}

PTF_TEST_CASE(FtpCreationTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	// Craft packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");

	pcpp::Packet ftpPacket1(&rawPacket1);
	pcpp::Packet craftedPacket1;

	pcpp::EthLayer ethLayer1(*ftpPacket1.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ethLayer1));

	pcpp::IPv4Layer ipv4Layer1(*ftpPacket1.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ipv4Layer1));

	pcpp::TcpLayer tcpLayer1(*ftpPacket1.getLayerOfType<pcpp::TcpLayer>());
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&tcpLayer1));

	pcpp::FtpRequestLayer ftpReqLayer1(pcpp::FtpRequestLayer::USER, "csanders");
	PTF_ASSERT_TRUE(craftedPacket1.addLayer(&ftpReqLayer1));

	PTF_ASSERT_EQUAL(bufferLength1, craftedPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer1, craftedPacket1.getRawPacket()->getRawData(), bufferLength1);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4RespHyphen.dat");

	pcpp::Packet ftpPacket2(&rawPacket2);
	pcpp::Packet craftedPacket2;

	pcpp::EthLayer ethLayer2(*ftpPacket2.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ethLayer2));

	pcpp::IPv4Layer ipv4Layer2(*ftpPacket2.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ipv4Layer2));

	pcpp::TcpLayer tcpLayer2(*ftpPacket2.getLayerOfType<pcpp::TcpLayer>());
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&tcpLayer2));

	pcpp::FtpResponseLayer ftpRespLayer1(pcpp::FtpResponseLayer::SYSTEM_STATUS, "Extensions supported:\r\n CLNT\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n211 End.");
	PTF_ASSERT_TRUE(craftedPacket2.addLayer(&ftpRespLayer1));

	PTF_ASSERT_EQUAL(bufferLength2, craftedPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer2, craftedPacket2.getRawPacket()->getRawData(), bufferLength2);
}

PTF_TEST_CASE(FtpEditTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	// Modify existing packets
	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");
	pcpp::Packet ftpPacket1(&rawPacket1);
	pcpp::FtpRequestLayer *ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer1);
	ftpLayer1->setCommand(pcpp::FtpRequestLayer::FEAT);
	PTF_ASSERT_EQUAL(ftpLayer1->getCommand(), pcpp::FtpRequestLayer::FEAT);
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "csanders");

	ftpLayer1->setCommandOption("Test option");
	PTF_ASSERT_EQUAL(ftpLayer1->getCommand(), pcpp::FtpRequestLayer::FEAT);
	PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "Test option");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4Resp.dat");

	pcpp::Packet ftpPacket2(&rawPacket2);
	pcpp::FtpResponseLayer *ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(ftpLayer2);
	ftpLayer2->setStatusCode(pcpp::FtpResponseLayer::CLOSING_DATA);
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusCode(), pcpp::FtpResponseLayer::CLOSING_DATA);
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "CWD command successful. \"/\" is current directory.");
	PTF_ASSERT_FALSE(ftpLayer2->isMultiLine());

	ftpLayer2->setStatusOption("Test option");
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusCode(), pcpp::FtpResponseLayer::CLOSING_DATA);
	PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "Test option");
	PTF_ASSERT_FALSE(ftpLayer2->isMultiLine());
}
