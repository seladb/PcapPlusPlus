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
	pcpp::SmtpRequestLayer *smtpLayer1 = smtpPacket1.getLayerOfType<pcpp::SmtpRequestLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer1);
	PTF_ASSERT_EQUAL(int(smtpLayer1->getCommand()), int(pcpp::SmtpRequestLayer::SmtpCommand::AUTH));
	PTF_ASSERT_EQUAL(smtpLayer1->getCommandString(), "AUTH");
	PTF_ASSERT_EQUAL(smtpLayer1->getCommandOption(), "LOGIN");
	PTF_ASSERT_EQUAL(smtpLayer1->toString(), "SMTP Request: AUTH");
	PTF_ASSERT_FALSE(smtpLayer1->isMultiLine());

	// PTF_ASSERT_EQUAL(pcpp::SmtpRequestLayer::getCommandInfo(pcpp::SmtpRequestLayer::SmtpCommand::AUTH),
	// 				 "Authenticate client and server");
	PTF_ASSERT_EQUAL(pcpp::SmtpRequestLayer::getCommandAsString(pcpp::SmtpRequestLayer::SmtpCommand::AUTH), "AUTH");

	// Response packet
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/smtpResponse.dat");

	pcpp::Packet smtpPacket2(&rawPacket2);
	pcpp::SmtpResponseLayer *smtpLayer2 = smtpPacket2.getLayerOfType<pcpp::SmtpResponseLayer>();

	PTF_ASSERT_NOT_NULL(smtpLayer2);
	PTF_ASSERT_EQUAL(int(smtpLayer2->getStatusCode()), int(pcpp::SmtpResponseLayer::SmtpStatusCode::SERVER_CHALLENGE));
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusCodeString(), "334");
	PTF_ASSERT_EQUAL(smtpLayer2->getStatusOption(), "VXNlcm5hbWU6");
	PTF_ASSERT_EQUAL(smtpLayer2->toString(), "SMTP Response: 334");
	PTF_ASSERT_FALSE(smtpLayer2->isMultiLine());

	PTF_ASSERT_EQUAL(
		pcpp::SmtpResponseLayer::getStatusCodeAsString(pcpp::SmtpResponseLayer::SmtpStatusCode::SERVER_CHALLENGE),
		"Server challenge");

	// Multiline

	// IPv6
}

PTF_TEST_CASE(SmtpCreationTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Request

	// Response packet

	// Multiline

	// IPv6
}

PTF_TEST_CASE(SmtpEditTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Request

	// Response packet

	// Multiline

	// IPv6
}
