#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "FtpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(FtpParsingIpv4Tests)
{
    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv4Req.dat");

    pcpp::Packet ftpPacket1(&rawPacket1);
    pcpp::FtpRequestLayer *ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();

    PTF_ASSERT_NOT_NULL(ftpLayer1);
    PTF_ASSERT_EQUAL(ftpLayer1->getCommand(), pcpp::FtpRequestLayer::USER);
    PTF_ASSERT_EQUAL(ftpLayer1->getCommandString(), "USER");
    PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "csanders");
    PTF_ASSERT_EQUAL(ftpLayer1->toString(), "FTP Request: USER");

    PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandInfoAsString(pcpp::FtpRequestLayer::USER), "Authentication username.");
    PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandAsString(pcpp::FtpRequestLayer::USER), "USER");


    READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv4Resp.dat");

    pcpp::Packet ftpPacket2(&rawPacket2);
    pcpp::FtpResponseLayer *ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();

    PTF_ASSERT_NOT_NULL(ftpLayer2);
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusCode(), pcpp::FtpResponseLayer::REQ_FILE_OK_COMPLETE);
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusCodeString(), "250");
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "CWD command successful. \"/\" is current directory.");
    PTF_ASSERT_EQUAL(ftpLayer2->toString(), "FTP Response: 250");

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

    PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(pcpp::FtpResponseLayer::SYSTEM_STATUS), 
                    "System status, or system help reply");
}

PTF_TEST_CASE(FtpParsingIpv6Tests)
{
    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ftpIpv6Req.dat");

    pcpp::Packet ftpPacket1(&rawPacket1);
    pcpp::FtpRequestLayer *ftpLayer1 = ftpPacket1.getLayerOfType<pcpp::FtpRequestLayer>();

    PTF_ASSERT_NOT_NULL(ftpLayer1);
    PTF_ASSERT_EQUAL(ftpLayer1->getCommand(), pcpp::FtpRequestLayer::PASS);
    PTF_ASSERT_EQUAL(ftpLayer1->getCommandString(), "PASS");
    PTF_ASSERT_EQUAL(ftpLayer1->getCommandOption(), "IEUser@");
    PTF_ASSERT_EQUAL(ftpLayer1->toString(), "FTP Request: PASS");

    PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandInfoAsString(pcpp::FtpRequestLayer::PASS), "Authentication password.");
    PTF_ASSERT_EQUAL(pcpp::FtpRequestLayer::getCommandAsString(pcpp::FtpRequestLayer::PASS), "PASS");


    READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ftpIpv6Resp.dat");

    pcpp::Packet ftpPacket2(&rawPacket2);
    pcpp::FtpResponseLayer *ftpLayer2 = ftpPacket2.getLayerOfType<pcpp::FtpResponseLayer>();

    PTF_ASSERT_NOT_NULL(ftpLayer2);
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusCode(), pcpp::FtpResponseLayer::COMMAND_NOT_IMPLEMENTED);
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusCodeString(), "502");
    PTF_ASSERT_EQUAL(ftpLayer2->getStatusOption(), "Unknown command 'utf8'.");
    PTF_ASSERT_EQUAL(ftpLayer2->toString(), "FTP Response: 502");

    PTF_ASSERT_EQUAL(pcpp::FtpResponseLayer::getStatusCodeAsString(pcpp::FtpResponseLayer::COMMAND_NOT_IMPLEMENTED), 
                    "Command not implemented");
}
