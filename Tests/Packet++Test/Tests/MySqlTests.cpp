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
			pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageType::Server_EOF
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

	// Server - Ok (0x00)
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
		std::vector<uint8_t> errorData = {
			0x03, 0x00, 0x00,  // Packet length (3)
			0x01,              // Packet number (1)
			0xFF,              // Error type
			0x01, 0x04         // Error code
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(errorData.data(), errorData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Error, pcpp::MySqlMessageOrigin::Server,
		                     "Error");
	}

	// Server - AuthSwitchRequest packet (0xFE)
	{
		std::vector<uint8_t> authSwitchData = {
			0x0B, 0x00, 0x00,  // Packet length (11)
			0x05,              // Packet number (5)
			0xFE,              // Message type (0xFE)
			0x00,              // Plugin name terminator
			'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0  // Plugin name + terminator
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(authSwitchData.data(), authSwitchData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_AuthSwitchRequest,
		                     pcpp::MySqlMessageOrigin::Server, "AuthSwitchRequest");
		PTF_ASSERT_EQUAL(message->getMessageLength(), 10);
	}

	// Server - EOF packet
	{
		std::vector<uint8_t> eofData = {
			0x07, 0x00, 0x00,  // Packet length (7)
			0x0A,              // Packet number (10)
			0xFE,              // Message type (0xFE)
			0x00, 0x00, 0x02, 0x00, 0x00, 0x00  // EOF data
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(eofData.data(), eofData.size(),
													 pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_EOF,
							 pcpp::MySqlMessageOrigin::Server, "EOF");
	}

	// Server - Handshake (protocol version)
	{
		std::vector<uint8_t> handshakeData = {
			0x49, 0x00, 0x00,  // Packet length (73)
			0x00,              // Packet number (0)
			0x0A,              // Protocol version
			0x39, 0x2E, 0x36, 0x2E, 0x30, 0x00,  // Server version string "9.6.0"
			0x49, 0x00, 0x00, 0x00,  // Thread ID
			0x04, 0x23, 0x75, 0x36, 0x63, 0x3E, 0x51, 0x16,  // Auth-plugin-data-part-1
			0x00,              // Filler
			0xFF, 0xFF,        // Capability flags (lower 2 bytes)
			0xFF,              // Character set
			0x02, 0x00,        // Status flags
			0xFF, 0xDF,        // Capability flags (upper 2 bytes)
			0x15,              // Auth plugin data length
			0x00, 0x00, 0x00, 0x00, 0x00,  // Reserved (10 bytes)
			0x00, 0x00, 0x00, 0x00, 0x00,
			0x36, 0x2D, 0x4D, 0x44, 0x76, 0x2B, 0x5A, 0x55,  // Auth-plugin-data-part-2
			0x20, 0x7B, 0x30, 0x6D, 0x00,
			0x63, 0x61, 0x63, 0x68, 0x69, 0x6E, 0x67, 0x5F,  // Auth plugin name "caching_sha2_password"
			0x73, 0x68, 0x61, 0x32, 0x5F, 0x70, 0x61, 0x73,
			0x73, 0x77, 0x6F, 0x72, 0x64, 0x00
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(handshakeData.data(), handshakeData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Handshake, pcpp::MySqlMessageOrigin::Server,
		                     "Handshake");
		PTF_ASSERT_EQUAL(message->getPacketNumber(), 0);
		PTF_ASSERT_EQUAL(message->getMessageLength(), 73);
		PTF_ASSERT_EQUAL(message->getTotalMessageLength(), 77);
		PTF_ASSERT_EQUAL(message->getRawPayload().size(), 73);
	}

	// Server - Other (unknown first byte)
	{
		std::vector<uint8_t> otherData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x01,              // Packet number (1)
			0x01               // Data
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(otherData.data(), otherData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Other, pcpp::MySqlMessageOrigin::Server,
		                     "Other");
		PTF_ASSERT_EQUAL(message->getPacketNumber(), 1);
		PTF_ASSERT_EQUAL(message->getMessageLength(), 1);
	}
}

PTF_TEST_CASE(MySqlInvalidDataTest)
{}
