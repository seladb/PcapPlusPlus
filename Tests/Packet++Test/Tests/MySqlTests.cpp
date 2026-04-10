#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "MySqlLayer.h"
#include "NullLoopbackLayer.h"
#include "TcpLayer.h"

#include <algorithm>
#include <memory>
#include <vector>

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(MySqlLayerParsingTest)
{
	// Server message
	{
		pcpp_tests::utils::PacketFactory nullFactory(pcpp::LINKTYPE_NULL);

		auto rawPacket = createPacketFromHexResource("PacketExamples/mysql_server.dat", nullFactory);
		pcpp::Packet packet(rawPacket.get());

		auto tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_NOT_NULL(tcpLayer);

		auto mySqlLayer = std::unique_ptr<pcpp::MySqlLayer>(pcpp::MySqlLayer::parseMySqlServerMessage(
		    tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize(), tcpLayer, &packet));
		PTF_ASSERT_NOT_NULL(mySqlLayer);

		PTF_ASSERT_EQUAL(mySqlLayer->getMySqlOrigin(), pcpp::MySqlMessageOrigin::Server, enumclass);
		PTF_ASSERT_EQUAL(mySqlLayer->getOsiModelLayer(), pcpp::OsiModelApplicationLayer, enum);

		auto& messages = mySqlLayer->getMySqlMessages();
		PTF_ASSERT_EQUAL(messages.size(), 10);

		std::vector<pcpp::MySqlMessageType::Value> expectedTypes = {
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_Other,
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_Other,
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_Other,
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_Other,
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_AuthContinue
		};

		for (size_t i = 0; i < messages.size(); i++)
		{
			PTF_ASSERT_EQUAL(messages.at(i)->getMessageType(), expectedTypes[i], enum);
		}
	}

	// Client message
	{
		pcpp_tests::utils::PacketFactory nullFactory(pcpp::LINKTYPE_NULL);

		auto rawPacket = createPacketFromHexResource("PacketExamples/mysql_client.dat", nullFactory);
		pcpp::Packet packet(rawPacket.get());

		auto tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_NOT_NULL(tcpLayer);

		auto mySqlLayer = std::unique_ptr<pcpp::MySqlLayer>(pcpp::MySqlLayer::parseMySqlClientMessage(
		    tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize(), tcpLayer, &packet));
		PTF_ASSERT_NOT_NULL(mySqlLayer);

		PTF_ASSERT_EQUAL(mySqlLayer->getMySqlOrigin(), pcpp::MySqlMessageOrigin::Client, enumclass);
		PTF_ASSERT_EQUAL(mySqlLayer->getOsiModelLayer(), pcpp::OsiModelApplicationLayer, enum);

		auto& messages = mySqlLayer->getMySqlMessages();
		PTF_ASSERT_EQUAL(messages.size(), 1);

		PTF_ASSERT_EQUAL(messages.at(0)->getMessageType(), pcpp::MySqlMessageType::Client_HandshakeResponse, enum);
	}
}

PTF_TEST_CASE(MySqlMessageParsingTest)
{
#define ASSERT_MYSQL_MESSAGE(message, expectedMessageType, expectedOrigin, expectedMessageString)                      \
	PTF_ASSERT_NOT_NULL(message.get());                                                                                \
	PTF_ASSERT_EQUAL(message->getMessageType(), expectedMessageType, enum);                                            \
	PTF_ASSERT_EQUAL(message->getMessageOrigin(), expectedOrigin, enumclass);                                          \
	PTF_ASSERT_EQUAL(message->getMessageType().toString(), expectedMessageString);

	// Server - Ok
	{
		std::vector<uint8_t> okData = {
			0x07, 0x00, 0x00,        // Packet length (7)
			0x02,                    // Packet number (2)
			0x00,                    // Server OK type
			0x00, 0x00, 0x00, 0x20,  // Affected rows + flags
			0x00, 0x00,              // Warnings
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(okData.data(), okData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Ok, pcpp::MySqlMessageOrigin::Server, "OK");
		PTF_ASSERT_EQUAL(message->getPacketNumber(), 2);
		PTF_ASSERT_EQUAL(message->getMessageLength(), 6);
		PTF_ASSERT_EQUAL(message->getTotalMessageLength(), 11);
		std::vector<uint8_t> expectedPayload = { 0x00, 0x00, 0x00, 0x20, 0x00, 0x00 };
		PTF_ASSERT_VECTORS_EQUAL(message->getRawPayload(), expectedPayload);
	}

	// Server - Error packet (0xFF)
	{
		std::vector<uint8_t> errorData = { 0xFF, 0x00, 0x00, 0x02, 0x00 };  // packet length + error marker
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(errorData.data(), errorData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Error, pcpp::MySqlMessageOrigin::Server,
		                     "Server_Error");
	}

	// Server - AuthSwitchRequest packet (0xFE)
	{
		std::vector<uint8_t> authSwitchData = { 0xFE, 0x00, 0x00, 0x02, 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(authSwitchData.data(), authSwitchData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_AuthSwitchRequest,
		                     pcpp::MySqlMessageOrigin::Server, "Server_AuthSwitchRequest");
	}

	// Server - AuthContinue packet (0x01)
	{
		std::vector<uint8_t> authContinueData = { 0x01, 0x00, 0x00, 0x02, 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(authContinueData.data(), authContinueData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_AuthContinue, pcpp::MySqlMessageOrigin::Server,
		                     "Server_AuthContinue");
	}

	// Server - Handshake (initial handshake from server starts with protocol version)
	{
		std::vector<uint8_t> handshakeData = { 0x0A };  // protocol version 10
		auto message = pcpp::MySqlMessage::parseMySqlMessage(handshakeData.data(), handshakeData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Handshake, pcpp::MySqlMessageOrigin::Server,
		                     "Server_Handshake");
	}

	// Server - Unknown/Other (EOF marker 0xFE in some contexts but not auth switch)
	{
		std::vector<uint8_t> otherData = { 0x00, 0x00, 0x00, 0x00 };
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(otherData.data(), otherData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageOrigin::Server,
		                     "Server_Other");
	}
}

PTF_TEST_CASE(MySqlInvalidDataTest)
{}
