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
			pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageType::Server_Data,
			pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageType::Server_Data,
			pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageType::Server_Data,
			pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageType::Server_Data,
			pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageType::Server_EOF
		};

		for (size_t i = 0; i < messages.size(); i++)
		{
			PTF_ASSERT_EQUAL(messages.at(i)->getMessageType(), expectedTypes[i], enum);
		}

		PTF_ASSERT_EQUAL(mySqlLayer->toString(), "MySQL Server Layer, 10 message(s)");
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

		PTF_ASSERT_EQUAL(mySqlLayer->toString(), "MySQL Client Layer, 1 message(s)");
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
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Error, pcpp::MySqlMessageOrigin::Server, "Error");
	}

	// Server - AuthSwitchRequest packet (0xFE)
	{
		std::vector<uint8_t> authSwitchData = {
			0x0B, 0x00, 0x00,                             // Packet length (11)
			0x05,                                         // Packet number (5)
			0xFE,                                         // Message type (0xFE)
			0x00,                                         // Plugin name terminator
			'p',  'a',  's',  's', 'w', 'o', 'r', 'd', 0  // Plugin name + terminator
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
			0x07, 0x00, 0x00,                   // Packet length (7)
			0x0A,                               // Packet number (10)
			0xFE,                               // Message type (0xFE)
			0x00, 0x00, 0x02, 0x00, 0x00, 0x00  // EOF data
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(eofData.data(), eofData.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_EOF, pcpp::MySqlMessageOrigin::Server, "EOF");
	}

	// Server - Handshake (protocol version)
	{
		std::vector<uint8_t> handshakeData = {
			0x49, 0x00, 0x00,                                // Packet length (73)
			0x00,                                            // Packet number (0)
			0x0A,                                            // Protocol version
			0x39, 0x2E, 0x36, 0x2E, 0x30, 0x00,              // Server version string "9.6.0"
			0x49, 0x00, 0x00, 0x00,                          // Thread ID
			0x04, 0x23, 0x75, 0x36, 0x63, 0x3E, 0x51, 0x16,  // Auth-plugin-data-part-1
			0x00,                                            // Filler
			0xFF, 0xFF,                                      // Capability flags (lower 2 bytes)
			0xFF,                                            // Character set
			0x02, 0x00,                                      // Status flags
			0xFF, 0xDF,                                      // Capability flags (upper 2 bytes)
			0x15,                                            // Auth plugin data length
			0x00, 0x00, 0x00, 0x00, 0x00,                    // Reserved (10 bytes)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x2D, 0x4D, 0x44, 0x76, 0x2B, 0x5A, 0x55,  // Auth-plugin-data-part-2
			0x20, 0x7B, 0x30, 0x6D, 0x00, 0x63, 0x61, 0x63, 0x68, 0x69, 0x6E, 0x67, 0x5F,  // Auth plugin name
			                                                                               // "caching_sha2_password"
			0x73, 0x68, 0x61, 0x32, 0x5F, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x00
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

	// Server - data (unknown first byte)
	{
		std::vector<uint8_t> data = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x01,              // Packet number (1)
			0x01               // Data
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(data.data(), data.size(), pcpp::MySqlMessageOrigin::Server);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Server_Data, pcpp::MySqlMessageOrigin::Server, "Data");
		PTF_ASSERT_EQUAL(message->getPacketNumber(), 1);
		PTF_ASSERT_EQUAL(message->getMessageLength(), 1);
	}

	// Client - COM_QUIT (0x01)
	{
		std::vector<uint8_t> quitData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x01               // COM_QUIT type
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(quitData.data(), quitData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Quit, pcpp::MySqlMessageOrigin::Client,
		                     "COM_QUIT");
		PTF_ASSERT_EQUAL(message->getMessageLength(), 0);
		PTF_ASSERT_EQUAL(message->getTotalMessageLength(), 5);
		PTF_ASSERT_EQUAL(message->getRawPayload().size(), 0);
	}

	// Client - COM_QUERY (0x03)
	{
		std::vector<uint8_t> queryData = {
			0x1B, 0x00, 0x00,                                // Packet length (10)
			0x00,                                            // Packet number (0)
			0x03,                                            // COM_QUERY type
			0x00, 0x01,                                      // Num of params
			0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a,  // Query statement
			0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x74, 0x6f, 0x75, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x6e, 0x74,
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(queryData.data(), queryData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Query, pcpp::MySqlMessageOrigin::Client,
		                     "COM_QUERY");
		PTF_ASSERT_EQUAL(message->getMessageLength(), 26);
		PTF_ASSERT_EQUAL(message->getTotalMessageLength(), 31);
		std::vector<uint8_t> expectedPayload = { 0x00, 0x01, 's', 'e', 'l', 'e', 'c', 't', ' ', '*', ' ', 'f', 'r',
			                                     'o',  'm',  ' ', 't', 'o', 'u', 'r', 'n', 'a', 'm', 'e', 'n', 't' };
		PTF_ASSERT_VECTORS_EQUAL(message->getRawPayload(), expectedPayload);
		auto queryMessage = dynamic_cast<pcpp::MySqlQueryMessage*>(message.get());
		PTF_ASSERT_EQUAL(queryMessage->getQuery(), "select * from tournament");
	}

	// Client - COM_PING (0x0E)
	{
		std::vector<uint8_t> pingData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0E               // COM_PING type
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(pingData.data(), pingData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Ping, pcpp::MySqlMessageOrigin::Client,
		                     "COM_PING");
	}

	// Client - COM_INIT_DB (0x02)
	{
		std::vector<uint8_t> initDbData = { 0x05, 0x00, 0x00,  // Packet length (5)
			                                0x00,              // Packet number (0)
			                                0x02,              // COM_INIT_DB type
			                                't',  'e',  's',  't', 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(initDbData.data(), initDbData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_InitDb, pcpp::MySqlMessageOrigin::Client,
		                     "COM_INIT_DB");
	}

	// Client - COM_FIELD_LIST (0x04)
	{
		std::vector<uint8_t> fieldListData = { 0x05, 0x00, 0x00,  // Packet length (5)
			                                   0x00,              // Packet number (0)
			                                   0x04,              // COM_FIELD_LIST type
			                                   't',  'a',  'b',  'l', 'e', 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(fieldListData.data(), fieldListData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_FieldList, pcpp::MySqlMessageOrigin::Client,
		                     "COM_FIELD_LIST");
	}

	// Client - COM_CREATE_DB (0x05)
	{
		std::vector<uint8_t> createDbData = { 0x05, 0x00, 0x00,  // Packet length (5)
			                                  0x00,              // Packet number (0)
			                                  0x05,              // COM_CREATE_DB type
			                                  't',  'e',  's',  't', 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(createDbData.data(), createDbData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_CreateDb, pcpp::MySqlMessageOrigin::Client,
		                     "COM_CREATE_DB");
	}

	// Client - COM_DROP_DB (0x06)
	{
		std::vector<uint8_t> dropDbData = { 0x05, 0x00, 0x00,  // Packet length (5)
			                                0x00,              // Packet number (0)
			                                0x06,              // COM_DROP_DB type
			                                't',  'e',  's',  't', 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(dropDbData.data(), dropDbData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_DropDb, pcpp::MySqlMessageOrigin::Client,
		                     "COM_DROP_DB");
	}

	// Client - COM_REFRESH (0x07)
	{
		std::vector<uint8_t> refreshData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x07               // COM_REFRESH type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(refreshData.data(), refreshData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Refresh, pcpp::MySqlMessageOrigin::Client,
		                     "COM_REFRESH");
	}

	// Client - COM_SHUTDOWN (0x08)
	{
		std::vector<uint8_t> shutdownData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x08               // COM_SHUTDOWN type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(shutdownData.data(), shutdownData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Shutdown, pcpp::MySqlMessageOrigin::Client,
		                     "COM_SHUTDOWN");
	}

	// Client - COM_STATISTICS (0x09)
	{
		std::vector<uint8_t> statisticsData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x09               // COM_STATISTICS type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(statisticsData.data(), statisticsData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Statistics, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STATISTICS");
	}

	// Client - COM_PROCESS_INFO (0x0A)
	{
		std::vector<uint8_t> processInfoData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0A               // COM_PROCESS_INFO type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(processInfoData.data(), processInfoData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_ProcessInfo, pcpp::MySqlMessageOrigin::Client,
		                     "COM_PROCESS_INFO");
	}

	// Client - COM_DEBUG (0x0D)
	{
		std::vector<uint8_t> debugData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0D               // COM_DEBUG type
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(debugData.data(), debugData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Debug, pcpp::MySqlMessageOrigin::Client,
		                     "COM_DEBUG");
	}

	// Client - COM_TIME (0x0F)
	{
		std::vector<uint8_t> timeData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0F               // COM_TIME type
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(timeData.data(), timeData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Time, pcpp::MySqlMessageOrigin::Client,
		                     "COM_TIME");
	}

	// Client - COM_CHANGE_USER (0x11)
	{
		std::vector<uint8_t> changeUserData = { 0x05, 0x00, 0x00,  // Packet length (5)
			                                    0x00,              // Packet number (0)
			                                    0x11,              // COM_CHANGE_USER type
			                                    't',  'e',  's',  't', 0x00 };
		auto message = pcpp::MySqlMessage::parseMySqlMessage(changeUserData.data(), changeUserData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_ChangeUser, pcpp::MySqlMessageOrigin::Client,
		                     "COM_CHANGE_USER");
	}

	// Client - COM_SLEEP (0x00)
	{
		std::vector<uint8_t> sleepData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x00               // COM_SLEEP type
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(sleepData.data(), sleepData.size(), pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Sleep, pcpp::MySqlMessageOrigin::Client,
		                     "COM_SLEEP");
	}

	// Client - COM_CONNECT (0x0B)
	{
		std::vector<uint8_t> connectData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0B               // COM_CONNECT type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(connectData.data(), connectData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Connect, pcpp::MySqlMessageOrigin::Client,
		                     "COM_CONNECT");
	}

	// Client - COM_PROCESS_KILL (0x0C)
	{
		std::vector<uint8_t> processKillData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x0C               // COM_PROCESS_KILL type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(processKillData.data(), processKillData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_ProcessKill, pcpp::MySqlMessageOrigin::Client,
		                     "COM_PROCESS_KILL");
	}

	// Client - COM_DELAYED_INSERT (0x10)
	{
		std::vector<uint8_t> delayedInsertData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x10               // COM_DELAYED_INSERT type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(delayedInsertData.data(), delayedInsertData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_DelayedInsert, pcpp::MySqlMessageOrigin::Client,
		                     "COM_DELAYED_INSERT");
	}

	// Client - COM_BINLOG_DUMP (0x12)
	{
		std::vector<uint8_t> binlogDumpData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x12               // COM_BINLOG_DUMP type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(binlogDumpData.data(), binlogDumpData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_BinlogDump, pcpp::MySqlMessageOrigin::Client,
		                     "COM_BINLOG_DUMP");
	}

	// Client - COM_TABLE_DUMP (0x13)
	{
		std::vector<uint8_t> tableDumpData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x13               // COM_TABLE_DUMP type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(tableDumpData.data(), tableDumpData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_TableDump, pcpp::MySqlMessageOrigin::Client,
		                     "COM_TABLE_DUMP");
	}

	// Client - COM_CONNECT_OUT (0x14)
	{
		std::vector<uint8_t> connectOutData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x14               // COM_CONNECT_OUT type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(connectOutData.data(), connectOutData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_ConnectOut, pcpp::MySqlMessageOrigin::Client,
		                     "COM_CONNECT_OUT");
	}

	// Client - COM_REGISTER_SLAVE (0x15)
	{
		std::vector<uint8_t> registerSlaveData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x15               // COM_REGISTER_SLAVE type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(registerSlaveData.data(), registerSlaveData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_RegisterSlave, pcpp::MySqlMessageOrigin::Client,
		                     "COM_REGISTER_SLAVE");
	}

	// Client - COM_STMT_PREPARE (0x16)
	{
		std::vector<uint8_t> stmtExecuteData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x16               // COM_STMT_PREPARE type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(stmtExecuteData.data(), stmtExecuteData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_StmtPrepare, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STMT_PREPARE");
	}

	// Client - COM_STMT_EXECUTE (0x17)
	{
		std::vector<uint8_t> stmtFetchData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x17               // COM_STMT_EXECUTE type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(stmtFetchData.data(), stmtFetchData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_StmtExecute, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STMT_EXECUTE");
	}

	// Client - COM_STMT_SEND_LONG_DATA (0x18)
	{
		std::vector<uint8_t> stmtCloseData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x18               // COM_STMT_SEND_LONG_DATA type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(stmtCloseData.data(), stmtCloseData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_StmtSendLongData, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STMT_SEND_LONG_DATA");
	}

	// Client - COM_STMT_CLOSE (0x19)
	{
		std::vector<uint8_t> stmtCloseData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x19               // COM_STMT_CLOSE type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(stmtCloseData.data(), stmtCloseData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_StmtClose, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STMT_CLOSE");
	}

	// Client - COM_STMT_RESET (0x1A)
	{
		std::vector<uint8_t> stmtResetData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x1A               // COM_STMT_RESET type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(stmtResetData.data(), stmtResetData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_StmtReset, pcpp::MySqlMessageOrigin::Client,
		                     "COM_STMT_RESET");
	}

	// Client - COM_SET_OPTION (0x1B)
	{
		std::vector<uint8_t> setOptionData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x1B               // COM_SET_OPTION type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(setOptionData.data(), setOptionData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_SetOption, pcpp::MySqlMessageOrigin::Client,
		                     "COM_SET_OPTION");
	}

	// Client - COM_DAEMON (0x1D)
	{
		std::vector<uint8_t> daemonData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x1D               // COM_DAEMON type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(daemonData.data(), daemonData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Daemon, pcpp::MySqlMessageOrigin::Client,
		                     "COM_DAEMON");
	}

	// Client - COM_BINLOG_DUMP_GTID (0x1E)
	{
		std::vector<uint8_t> binlogDumpGtidData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x1E               // COM_BINLOG_DUMP_GTID type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(binlogDumpGtidData.data(), binlogDumpGtidData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_BinlogDumpGtid, pcpp::MySqlMessageOrigin::Client,
		                     "COM_BINLOG_DUMP_GTID");
	}

	// Client - COM_RESET_CONNECTION (0x1F)
	{
		std::vector<uint8_t> resetConnectionData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x1F               // COM_RESET_CONNECTION type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(resetConnectionData.data(), resetConnectionData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_ResetConnection, pcpp::MySqlMessageOrigin::Client,
		                     "COM_RESET_CONNECTION");
	}

	// Client - COM_CLONE (0x20)
	{
		std::vector<uint8_t> resetConnectionData = {
			0x01, 0x00, 0x00,  // Packet length (1)
			0x00,              // Packet number (0)
			0x20               // COM_CLONE type
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(resetConnectionData.data(), resetConnectionData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		ASSERT_MYSQL_MESSAGE(message, pcpp::MySqlMessageType::Client_Clone, pcpp::MySqlMessageOrigin::Client,
		                     "COM_CLONE");
	}
}

PTF_TEST_CASE(MySqlInvalidDataTest)
{
	// Null data should return nullptr
	{
		auto message = pcpp::MySqlMessage::parseMySqlMessage(nullptr, 10, pcpp::MySqlMessageOrigin::Server);
		PTF_ASSERT_NULL(message);
	}

	// Data too short (less than 4 bytes header)
	{
		std::vector<uint8_t> shortData = { 0x01, 0x02, 0x03 };
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(shortData.data(), shortData.size(), pcpp::MySqlMessageOrigin::Server);
		PTF_ASSERT_NULL(message);
	}

	// Message length mismatch - declared length > actual data
	{
		std::vector<uint8_t> mismatchData = {
			0xFF, 0x00, 0x00,  // Declared length: 255
			0x01,              // Packet number
			0x00               // Only 1 byte of actual data
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(mismatchData.data(), mismatchData.size(),
		                                                     pcpp::MySqlMessageOrigin::Server);
		PTF_ASSERT_NULL(message);
	}

	// Empty server payload with declared length 0
	{
		std::vector<uint8_t> emptyData = {
			0x00, 0x00, 0x00,  // Length = 0
			0x01,              // Packet number
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(emptyData.data(), emptyData.size(), pcpp::MySqlMessageOrigin::Server);
		PTF_ASSERT_NOT_NULL(message);
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::MySqlMessageType::Unknown, enum);
	}

	// Empty client payload with declared length 0
	{
		std::vector<uint8_t> emptyData = {
			0x00, 0x00, 0x00,  // Length = 0
			0x05,              // Packet number
		};
		auto message =
		    pcpp::MySqlMessage::parseMySqlMessage(emptyData.data(), emptyData.size(), pcpp::MySqlMessageOrigin::Client);
		PTF_ASSERT_NOT_NULL(message);
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::MySqlMessageType::Unknown, enum);
	}

	// Client with unknown command byte
	{
		std::vector<uint8_t> unknownCmd = {
			0x01, 0x00, 0x00,  // Length = 1
			0x00,              // Packet number
			0xFF               // Unknown command
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(unknownCmd.data(), unknownCmd.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		PTF_ASSERT_NOT_NULL(message);
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::MySqlMessageType::Unknown, enum);
	}

	// Query with not enough data
	{
		std::vector<uint8_t> invalidQueryData = {
			0x02, 0x00, 0x00,  // Packet length (10)
			0x00,              // Packet number (0)
			0x03,              // COM_QUERY type
			0x00,              // Num of params
		};
		auto message = pcpp::MySqlMessage::parseMySqlMessage(invalidQueryData.data(), invalidQueryData.size(),
		                                                     pcpp::MySqlMessageOrigin::Client);
		PTF_ASSERT_NOT_NULL(message);
		auto queryMessage = dynamic_cast<pcpp::MySqlQueryMessage*>(message.get());
		PTF_ASSERT_EQUAL(queryMessage->getQuery(), "");
	}
}
