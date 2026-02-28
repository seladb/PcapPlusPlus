#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "PostgresLayer.h"

#include <algorithm>
#include <map>
#include <memory>

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(PostgresLayerParsingTest)
{
	// Postgres Backend messages
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/postgres_backend_messages.dat");
		pcpp::Packet postgresPacket(rawPacket.get());

		auto postgresLayer = postgresPacket.getLayerOfType<pcpp::PostgresLayer>();
		PTF_ASSERT_NOT_NULL(postgresLayer);

		PTF_ASSERT_EQUAL(postgresLayer->getPostgresOrigin(), pcpp::PostgresMessageOrigin::Backend, enumclass);
		PTF_ASSERT_EQUAL(postgresLayer->getOsiModelLayer(), pcpp::OsiModelApplicationLayer, enum);

		PTF_ASSERT_EQUAL(postgresLayer->toString(), "PostgreSQL Backend Layer, 14 message(s)");

		auto& messages = postgresLayer->getPostgresMessages();
		PTF_ASSERT_EQUAL(messages.size(), 14);

		pcpp::PostgresMessageType expectedTypes[] = {
			pcpp::PostgresMessageType::Backend_AuthenticationOk, pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_ParameterStatus,  pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_ParameterStatus,  pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_ParameterStatus,  pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_ParameterStatus,  pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_ParameterStatus,  pcpp::PostgresMessageType::Backend_ParameterStatus,
			pcpp::PostgresMessageType::Backend_BackendKeyData,   pcpp::PostgresMessageType::Backend_ReadyForQuery,
		};

		for (size_t i = 0; i < messages.size(); i++)
		{
			PTF_ASSERT_EQUAL(messages.at(i)->getMessageType(), expectedTypes[i], enum);
		}

		PTF_ASSERT_NOT_NULL(postgresLayer->getPostgresMessage(pcpp::PostgresMessageType::Backend_ParameterStatus));
		PTF_ASSERT_NULL(postgresLayer->getPostgresMessage(pcpp::PostgresMessageType::Backend_AuthenticationGSS));
		PTF_ASSERT_NULL(postgresLayer->getPostgresMessage(pcpp::PostgresMessageType::Frontend_Bind));
	}

	// Postgres frontend messages
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/postgres_frontend_messages.dat");
		pcpp::Packet postgresPacket(rawPacket.get());

		auto postgresLayer = postgresPacket.getLayerOfType<pcpp::PostgresLayer>();
		PTF_ASSERT_NOT_NULL(postgresLayer);

		PTF_ASSERT_EQUAL(postgresLayer->getPostgresOrigin(), pcpp::PostgresMessageOrigin::Frontend, enumclass);

		PTF_ASSERT_EQUAL(postgresLayer->toString(), "PostgreSQL Frontend Layer, 1 message(s)");

		auto& messages = postgresLayer->getPostgresMessages();
		PTF_ASSERT_EQUAL(messages.size(), 1);

		PTF_ASSERT_EQUAL(messages.at(0)->getMessageType(), pcpp::PostgresMessageType::Frontend_StartupMessage, enum);

		PTF_ASSERT_NOT_NULL(postgresLayer->getPostgresMessage(pcpp::PostgresMessageType::Frontend_StartupMessage));
	}
}

PTF_TEST_CASE(PostgresMessageParsingTest)
{
#define ASSERT_MESSAGE(message, expectedMessageType, expectedOrigin, expectedLength, expectedTotalLength,              \
                       expectedMessageString)                                                                          \
	PTF_ASSERT_NOT_NULL(message.get());                                                                                \
	PTF_ASSERT_EQUAL(message->getMessageType(), expectedMessageType, enum);                                            \
	PTF_ASSERT_EQUAL(message->getMessageOrigin(), expectedOrigin, enumclass);                                          \
	PTF_ASSERT_EQUAL(message->getMessageLength(), expectedLength);                                                     \
	PTF_ASSERT_EQUAL(message->getTotalMessageLength(), expectedTotalLength);                                           \
	PTF_ASSERT_EQUAL(message->getMessageType().toString(), expectedMessageString);

	// Backend - AuthenticationOk message
	{
		std::vector<uint8_t> authOkData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x00         // auth type 0
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authOkData.data(), authOkData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationOk,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationOk");
	}

	// Backend - AuthenticationCleartextPassword message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x03         // auth type 3
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationCleartextPassword,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationCleartextPassword");
		std::vector<uint8_t> expectedPayload = { 0x00, 0x00, 0x00, 0x03 };
		PTF_ASSERT_VECTORS_EQUAL(message->getRawPayload(), expectedPayload);
	}

	// Backend - AuthenticationMD5Password message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x0C,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x05,        // auth type 5
			0xAB, 0xCD, 0xEF, 0x12         // salt value
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationMD5Password,
		               pcpp::PostgresMessageOrigin::Backend, 12, 13, "Backend_AuthenticationMD5Password");
	}

	// Backend - AuthenticationKerberosV4 message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x01         // auth type 1
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationKerberosV4,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationKerberosV4");
	}

	// Backend - AuthenticationKerberosV5 message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x02         // auth type 2
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationKerberosV5,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationKerberosV5");
	}

	// Backend - AuthenticationGSS message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x07         // auth type 7
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationGSS,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationGSS");
	}

	// Backend - AuthenticationGSSContinue message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x0C,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x08,        // auth type 8
			0x01, 0x02, 0x03, 0x04         // GSS data
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationGSSContinue,
		               pcpp::PostgresMessageOrigin::Backend, 12, 13, "Backend_AuthenticationGSSContinue");
	}

	// Backend - AuthenticationSSPI message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x09         // auth type 9
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationSSPI,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_AuthenticationSSPI");
	}

	// Backend - AuthenticationSASL message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x10,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x0A,        // auth type 10
			0x53, 0x43, 0x52, 0x41,        // "SCRAM"
			0x2D, 0x53, 0x48, 0x41,        // "-SHA256"
			0x00                           // null terminator
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationSASL,
		               pcpp::PostgresMessageOrigin::Backend, 16, 17, "Backend_AuthenticationSASL");
	}

	// Backend - AuthenticationSASLContinue message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x0C,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x0B,        // auth type 11
			0x01, 0x02, 0x03, 0x04         // SASL data
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationSASLContinue,
		               pcpp::PostgresMessageOrigin::Backend, 12, 13, "Backend_AuthenticationSASLContinue");
	}

	// Backend - AuthenticationSASLFinal message
	{
		std::vector<uint8_t> authData = {
			0x52, 0x00, 0x00, 0x00, 0x0C,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x0C,        // auth type 12
			0x01, 0x02, 0x03, 0x04         // SASL final data
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(authData.data(), authData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_AuthenticationSASLFinal,
		               pcpp::PostgresMessageOrigin::Backend, 12, 13, "Backend_AuthenticationSASLFinal");
	}

	// Backend - BackendKeyData message
	{
		std::vector<uint8_t> keyData = {
			0x4B, 0x00, 0x00, 0x00, 0x0C,  // message type 'K' + length
			0x00, 0x00, 0x00, 0x01,        // process ID
			0x00, 0x00, 0x00, 0x02         // secret key
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(keyData.data(), keyData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_BackendKeyData, pcpp::PostgresMessageOrigin::Backend,
		               12, 13, "Backend_BackendKeyData");
	}

	// Backend - BindComplete message
	{
		std::vector<uint8_t> bindCompleteData = {
			0x32, 0x00, 0x00, 0x00, 0x04  // message type '2' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(bindCompleteData.data(), bindCompleteData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_BindComplete, pcpp::PostgresMessageOrigin::Backend,
		               4, 5, "Backend_BindComplete");
	}

	// Backend - CloseComplete message
	{
		std::vector<uint8_t> closeCompleteData = {
			0x33, 0x00, 0x00, 0x00, 0x04  // message type '3' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(closeCompleteData.data(), closeCompleteData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CloseComplete, pcpp::PostgresMessageOrigin::Backend,
		               4, 5, "Backend_CloseComplete");
	}

	// Backend - CommandComplete message
	{
		std::vector<uint8_t> cmdCompleteData = {
			0x43, 0x00, 0x00, 0x00, 0x0D,  // message type 'C' + length
			0x53, 0x45, 0x4C, 0x45, 0x43,  // "SELECT"
			0x54, 0x20, 0x31, 0x00         // "T 1" + null
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(cmdCompleteData.data(), cmdCompleteData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CommandComplete,
		               pcpp::PostgresMessageOrigin::Backend, 13, 14, "Backend_CommandComplete");
	}

	// Backend - CopyData message
	{
		std::vector<uint8_t> copyData = {
			0x64, 0x00, 0x00, 0x00, 0x08,  // message type 'd' + length
			0x01, 0x02, 0x03, 0x04         // copy data
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(copyData.data(), copyData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CopyData, pcpp::PostgresMessageOrigin::Backend, 8, 9,
		               "Backend_CopyData");
	}

	// Backend - CopyDone message
	{
		std::vector<uint8_t> copyDoneData = {
			0x63, 0x00, 0x00, 0x00, 0x04  // message type 'c' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(copyDoneData.data(), copyDoneData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CopyDone, pcpp::PostgresMessageOrigin::Backend, 4, 5,
		               "Backend_CopyDone");
	}

	// Backend - CopyInResponse message
	{
		std::vector<uint8_t> copyInData = {
			0x47, 0x00, 0x00, 0x00, 0x08,  // message type 'G' + length
			0x66,                          // copy format (text)
			0x00, 0x01,                    // num columns (1)
			0x00                           // column format (text)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(copyInData.data(), copyInData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CopyInResponse, pcpp::PostgresMessageOrigin::Backend,
		               8, 9, "Backend_CopyInResponse");
	}

	// Backend - CopyOutResponse message
	{
		std::vector<uint8_t> copyOutData = {
			0x48, 0x00, 0x00, 0x00, 0x08,  // message type 'H' + length
			0x66,                          // copy format (text)
			0x00, 0x01,                    // num columns (1)
			0x00                           // column format (text)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(copyOutData.data(), copyOutData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CopyOutResponse,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_CopyOutResponse");
	}

	// Backend - CopyBothResponse message
	{
		std::vector<uint8_t> copyBothData = {
			0x57, 0x00, 0x00, 0x00, 0x08,  // message type 'W' + length
			0x66,                          // copy format (text)
			0x00, 0x01,                    // num columns (1)
			0x00                           // column format (text)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(copyBothData.data(), copyBothData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_CopyBothResponse,
		               pcpp::PostgresMessageOrigin::Backend, 8, 9, "Backend_CopyBothResponse");
	}

	// Backend - DataRow message
	{
		std::vector<uint8_t> data = {
			0x44, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00,
			0x00, 0x00, 0x04, 0x4d, 0x61, 0x72, 0x79, 0x00, 0x00, 0x00, 0x05, 0x53, 0x6d, 0x69, 0x74, 0x68, 0x00, 0x00,
			0x00, 0x1d, 0x6d, 0x61, 0x72, 0x79, 0x2e, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x40, 0x73, 0x61, 0x6b, 0x69, 0x6c,
			0x61, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x65, 0x72, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x00, 0x01, 0x35,
			0x00, 0x00, 0x00, 0x01, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x32, 0x30, 0x30, 0x36, 0x2d, 0x30, 0x32, 0x2d, 0x31,
			0x34, 0x00, 0x00, 0x00, 0x17, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x35, 0x2d, 0x32, 0x36, 0x20, 0x31, 0x34,
			0x3a, 0x34, 0x39, 0x3a, 0x34, 0x35, 0x2e, 0x37, 0x33, 0x38, 0x00, 0x00, 0x00, 0x01, 0x31
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(data.data(), data.size()));
		auto* dataRowMsg = dynamic_cast<pcpp::PostgresDataRowMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(dataRowMsg);
		PTF_ASSERT_EQUAL(dataRowMsg->getMessageType(), pcpp::PostgresMessageType::Backend_DataRow, enum);
		PTF_ASSERT_EQUAL(dataRowMsg->getMessageOrigin(), pcpp::PostgresMessageOrigin::Backend, enumclass);
		PTF_ASSERT_EQUAL(dataRowMsg->getMessageLength(), 122);
		PTF_ASSERT_EQUAL(dataRowMsg->getTotalMessageLength(), 123);

		auto dataRow = dataRowMsg->getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 10);

		std::vector<std::string> dataRowAsString(dataRow.size());
		std::transform(dataRow.begin(), dataRow.end(), dataRowAsString.begin(),
		               [](const pcpp::PostgresDataRowMessage::ColumnData& obj) { return obj.toString(); });
		std::vector<std::string> expectedStrings = { "1",
			                                         "1",
			                                         "Mary",
			                                         "Smith",
			                                         "mary.smith@sakilacustomer.org",
			                                         "5",
			                                         "t",
			                                         "2006-02-14",
			                                         "2013-05-26 14:49:45.738",
			                                         "1" };
		PTF_ASSERT_VECTORS_EQUAL(dataRowAsString, expectedStrings);

		std::vector<std::string> dataRowAsHexString(dataRow.size());
		std::transform(dataRow.begin(), dataRow.end(), dataRowAsHexString.begin(),
		               [](const pcpp::PostgresDataRowMessage::ColumnData& obj) { return obj.toHexString(); });
		std::vector<std::string> expectedHexStrings = { "31",
			                                            "31",
			                                            "4d617279",
			                                            "536d697468",
			                                            "6d6172792e736d6974684073616b696c61637573746f6d65722e6f7267",
			                                            "35",
			                                            "74",
			                                            "323030362d30322d3134",
			                                            "323031332d30352d32362031343a34393a34352e373338",
			                                            "31" };
		PTF_ASSERT_VECTORS_EQUAL(dataRowAsHexString, expectedHexStrings);
	}

	// Backend - DataRow with NULL values
	{
		std::vector<uint8_t> mixedValues = {
			0x44,                          // message type 'D'
			0x00, 0x00, 0x00, 0x17,        // length (23)
			0x00, 0x03,                    // column count (3)
			0xFF, 0xFF, 0xFF, 0xFF,        // column 1: NULL
			0x00, 0x00, 0x00, 0x05,        // column 2 length (5)
			0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello"
			0xFF, 0xFF, 0xFF, 0xFF         // column 3: NULL
		};
		pcpp::PostgresDataRowMessage dataRowMsg(mixedValues.data(), mixedValues.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 3);
		PTF_ASSERT_TRUE(dataRow[0].isNull());
		PTF_ASSERT_EQUAL(dataRow[0].toString(), "");
		PTF_ASSERT_EQUAL(dataRow[1].toString(), "Hello");
		PTF_ASSERT_TRUE(dataRow[2].isNull());
	}

	// Backend - EmptyQueryResponse message
	{
		std::vector<uint8_t> emptyQueryData = {
			0x49, 0x00, 0x00, 0x00, 0x04  // message type 'I' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(emptyQueryData.data(), emptyQueryData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_EmptyQueryResponse,
		               pcpp::PostgresMessageOrigin::Backend, 4, 5, "Backend_EmptyQueryResponse");
	}

	// Backend - ErrorResponse message
	{
		std::vector<uint8_t> errorData = {
			0x45, 0x00, 0x00, 0x00, 0xfe, 0x53, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x00, 0x56, 0x45, 0x52, 0x52, 0x4f,
			0x52, 0x00, 0x43, 0x32, 0x33, 0x35, 0x30, 0x32, 0x00, 0x4d, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x76, 0x61,
			0x6c, 0x75, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x20, 0x22, 0x66, 0x69,
			0x72, 0x73, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x20, 0x6f, 0x66, 0x20, 0x72, 0x65, 0x6c, 0x61,
			0x74, 0x69, 0x6f, 0x6e, 0x20, 0x22, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x22, 0x20, 0x76, 0x69, 0x6f, 0x6c,
			0x61, 0x74, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x2d, 0x6e, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e,
			0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x00, 0x44, 0x46, 0x61, 0x69, 0x6c, 0x69, 0x6e, 0x67, 0x20,
			0x72, 0x6f, 0x77, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x28, 0x32, 0x30, 0x31,
			0x2c, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x2c, 0x20, 0x53, 0x6d, 0x69, 0x74, 0x68, 0x2c, 0x20, 0x32, 0x30,
			0x32, 0x36, 0x2d, 0x30, 0x32, 0x2d, 0x32, 0x35, 0x20, 0x32, 0x31, 0x3a, 0x31, 0x32, 0x3a, 0x34, 0x35,
			0x2e, 0x39, 0x37, 0x33, 0x37, 0x38, 0x31, 0x29, 0x2e, 0x00, 0x73, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
			0x00, 0x74, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x00, 0x63, 0x66, 0x69, 0x72, 0x73, 0x74, 0x5f, 0x6e, 0x61,
			0x6d, 0x65, 0x00, 0x46, 0x65, 0x78, 0x65, 0x63, 0x4d, 0x61, 0x69, 0x6e, 0x2e, 0x63, 0x00, 0x4c, 0x32,
			0x32, 0x31, 0x39, 0x00, 0x52, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x4e, 0x6f, 0x74, 0x4e, 0x75, 0x6c,
			0x6c, 0x56, 0x69, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x00, 0x00
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(errorData.data(), errorData.size()));
		auto* errorMsg = dynamic_cast<pcpp::PostgresErrorResponseMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(errorMsg);
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_ErrorResponse, pcpp::PostgresMessageOrigin::Backend,
		               254, 255, "Backend_ErrorResponse");

		std::map<pcpp::PostgresErrorResponseMessage::ErrorField, std::string> expectedFields = {
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Severity,             "ERROR"                       },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::SeverityNonLocalized, "ERROR"                       },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::SQLState,             "23502"                       },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Message,
             "null value in column \"first_name\" of relation \"actor\" violates not-null constraint"             },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Detail,
             "Failing row contains (201, null, Smith, 2026-02-25 21:12:45.973781)."                               },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Schema,               "public"                      },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Table,                "actor"                       },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Column,               "first_name"                  },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::File,                 "execMain.c"                  },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Line,                 "2219"                        },
			{ pcpp::PostgresErrorResponseMessage::ErrorField::Routine,              "ReportNotNullViolationError" }
		};
		auto& fields = errorMsg->getFields();
		PTF_ASSERT_EQUAL(fields.size(), expectedFields.size());
		for (const auto& expected : expectedFields)
		{
			PTF_ASSERT_EQUAL(fields.at(expected.first), expected.second);
		}
	}

	// Backend - FunctionCallResponse message
	{
		std::vector<uint8_t> funcCallData = {
			0x56, 0x00, 0x00, 0x00, 0x06,  // message type 'V' + length
			0x00, 0x00, 0x00, 0x02         // result length (2)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(funcCallData.data(), funcCallData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_FunctionCallResponse,
		               pcpp::PostgresMessageOrigin::Backend, 6, 7, "Backend_FunctionCallResponse");
	}

	// Backend - NegotiateProtocolVersion message
	{
		std::vector<uint8_t> negotiateData = {
			0x76, 0x00, 0x00, 0x00, 0x0C,  // message type 'v' + length
			0x00, 0x00, 0x00, 0x03,        // protocol version major
			0x00, 0x00, 0x00, 0x00,        // protocol version minor
			0x00                           // no additional info
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(negotiateData.data(), negotiateData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_NegotiateProtocolVersion,
		               pcpp::PostgresMessageOrigin::Backend, 12, 13, "Backend_NegotiateProtocolVersion");
	}

	// Backend - NoData message
	{
		std::vector<uint8_t> noDataData = {
			0x6E, 0x00, 0x00, 0x00, 0x04  // message type 'n' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(noDataData.data(), noDataData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_NoData, pcpp::PostgresMessageOrigin::Backend, 4, 5,
		               "Backend_NoData");
	}

	// Backend - NoticeResponse message
	{
		std::vector<uint8_t> noticeData = {
			0x4E, 0x00, 0x00, 0x00, 0x0C,  // message type 'N' + length
			0x53, 0x00, 0x4E, 0x00,        // severity + null
			0x57, 0x41, 0x52, 0x00         // "WARN" + null
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(noticeData.data(), noticeData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_NoticeResponse, pcpp::PostgresMessageOrigin::Backend,
		               12, 13, "Backend_NoticeResponse");
	}

	// Backend - NotificationResponse message
	{
		std::vector<uint8_t> notificationData = {
			0x41, 0x00, 0x00, 0x00, 0x14,  // message type 'A' + length
			0x00, 0x00, 0x00, 0x01,        // process ID
			0x63, 0x68, 0x61, 0x6E, 0x6E,  // "channel"
			0x65, 0x6C, 0x00,              // null
			0x70, 0x61, 0x79, 0x6C, 0x6F,  // "payload"
			0x61, 0x64, 0x00               // "ad" + null
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(notificationData.data(), notificationData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_NotificationResponse,
		               pcpp::PostgresMessageOrigin::Backend, 20, 21, "Backend_NotificationResponse");
	}

	// Backend - ParameterStatus message
	{
		std::vector<uint8_t> paramStatusData = {
			0x53,                                            // message type 'S'
			0x00, 0x00, 0x00, 0x19,                          // length (25 = 0x19) - includes length field itself
			0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x5F, 0x65,  // "client_encoding"
			0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67,
			0x00,                    // null terminator for name
			0x55, 0x54, 0x46, 0x38,  // "UTF8"
			0x00                     // null terminator for value
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(paramStatusData.data(), paramStatusData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_ParameterStatus,
		               pcpp::PostgresMessageOrigin::Backend, 25, 26, "Backend_ParameterStatus");

		auto* paramMsg = dynamic_cast<pcpp::PostgresParameterStatus*>(message.get());
		PTF_ASSERT_NOT_NULL(paramMsg);
		PTF_ASSERT_EQUAL(paramMsg->getParameterName(), "client_encoding");
		PTF_ASSERT_EQUAL(paramMsg->getParameterValue(), "UTF8");
	}

	// Backend - ParseComplete message
	{
		std::vector<uint8_t> parseCompleteData = {
			0x31, 0x00, 0x00, 0x00, 0x04  // message type '1' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(parseCompleteData.data(), parseCompleteData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_ParseComplete, pcpp::PostgresMessageOrigin::Backend,
		               4, 5, "Backend_ParseComplete");
	}

	// Backend - ReadyForQuery message
	{
		std::vector<uint8_t> readyData = {
			0x5A, 0x00, 0x00, 0x00, 0x05,  // message type 'Z' + length
			0x49                           // transaction status: Idle (I)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(readyData.data(), readyData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_ReadyForQuery, pcpp::PostgresMessageOrigin::Backend,
		               5, 6, "Backend_ReadyForQuery");
	}

	// Backend - RowDescription message with multiple columns
	{
		std::vector<uint8_t> rowDescData = {
			0x54, 0x00, 0x00, 0x00, 0xA2, 0x00, 0x06, 0x69, 0x64, 0x00, 0x03, 0x2E, 0x96, 0xAE, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x14, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x74, 0x69, 0x74, 0x6C, 0x65, 0x00,
			0x03, 0x2E, 0x96, 0xAE, 0x00, 0x02, 0x00, 0x00, 0x04, 0x13, 0xFF, 0xFF, 0x00, 0x00, 0x03, 0xEC, 0x00,
			0x00, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x00, 0x03, 0x2E, 0x96, 0xAE, 0x00, 0x03, 0x00, 0x00,
			0x00, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
			0x00, 0x03, 0x2E, 0x96, 0xAE, 0x00, 0x04, 0x00, 0x00, 0x04, 0x3A, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
			0x00, 0x00, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x64, 0x00, 0x03, 0x2E, 0x96, 0xAE, 0x00, 0x05,
			0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x72, 0x65, 0x6C, 0x65, 0x61,
			0x73, 0x65, 0x5F, 0x69, 0x6D, 0x61, 0x67, 0x65, 0x00, 0x03, 0x2E, 0x96, 0xAE, 0x00, 0x06, 0x00, 0x00,
			0x04, 0x13, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00
		};

		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(rowDescData.data(), rowDescData.size()));
		auto* rowDescMsg = dynamic_cast<pcpp::PostgresRowDescriptionMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(rowDescMsg);
		auto columnInfos = rowDescMsg->getColumnInfos();
		PTF_ASSERT_EQUAL(columnInfos.size(), 6);

		std::vector<std::tuple<std::string, uint32_t, uint16_t, uint32_t, int32_t, int32_t,
		                       pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat>>
		    expected = {
			    { "id",            53384878, 1, 20,   8,  -1,   pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text },
			    { "title",         53384878, 2, 1043, -1, 1004,
                 pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text                                                },
			    { "content",       53384878, 3, 25,   -1, -1,   pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text },
			    { "created",       53384878, 4, 1082, 4,  -1,
                 pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text                                                },
			    { "featured",      53384878, 5, 16,   1,  -1,   pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text },
			    { "release_image", 53384878, 6, 1043, -1, 259,
                 pcpp::PostgresRowDescriptionMessage::PostgresColumnFormat::Text                                                }
        };

		for (size_t i = 0; i < expected.size(); ++i)
		{
			PTF_ASSERT_EQUAL(columnInfos[i].name, std::get<0>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].tableOID, std::get<1>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].columnIndex, std::get<2>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].typeOID, std::get<3>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].typeSize, std::get<4>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].typeModifier, std::get<5>(expected[i]));
			PTF_ASSERT_EQUAL(columnInfos[i].format, std::get<6>(expected[i]), enumclass);
		}
	}

	// Backend - RowDescription message with zero columns
	{
		std::vector<uint8_t> rowDescData = {
			0x54,                    // message type 'T'
			0x00, 0x00, 0x00, 0x06,  // length (6)
			0x00, 0x00               // number of fields (0)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(rowDescData.data(), rowDescData.size()));
		auto* rowDescMsg = dynamic_cast<pcpp::PostgresRowDescriptionMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(rowDescMsg);
		auto columnInfos = rowDescMsg->getColumnInfos();
		PTF_ASSERT_EQUAL(columnInfos.size(), 0);
	}

	// Backend - PortalSuspended message
	{
		std::vector<uint8_t> portalSuspendedData = { 0x73, 0x00, 0x00, 0x00, 0x04 };
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(portalSuspendedData.data(), portalSuspendedData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_PortalSuspended,
		               pcpp::PostgresMessageOrigin::Backend, 4, 5, "Backend_PortalSuspended");
	}

	// Backend - ParameterDescription message
	{
		std::vector<uint8_t> paramDescData = {
			0x74, 0x00, 0x00, 0x00, 0x0E,  // message type 't' + length
			0x00, 0x02,                    // number of parameters (2)
			0x00, 0x00, 0x00, 0x17,        // OID 23 (INTEGER)
			0x00, 0x00, 0x04, 0x13         // OID 1043 (VARCHAR)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(paramDescData.data(), paramDescData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Backend_ParameterDescription,
		               pcpp::PostgresMessageOrigin::Backend, 14, 15, "Backend_ParameterDescription");
	}

	// Frontend - StartupMessage message
	{
		std::vector<uint8_t> startupData = {
			0x00, 0x00, 0x00, 0x55,                          // length (85)
			0x00, 0x03, 0x00, 0x00,                          // protocol version 3.0 (196608)
			0x75, 0x73, 0x65, 0x72,                          // param name: "user"
			0x00,                                            // null terminator
			0x72, 0x65, 0x61, 0x64, 0x65, 0x72,              // param value: "reader"
			0x00,                                            // null terminator
			0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,  // param name: "database"
			0x00,                                            // null terminator
			0x70, 0x66, 0x6d, 0x65, 0x67, 0x72, 0x6e, 0x61,  // param value: "pfmegrnargs"
			0x72, 0x67, 0x73,
			0x00,                                            // null terminator
			0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,  // param name: "application_name"
			0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
			0x00,                                            // null terminator
			0x70, 0x73, 0x71, 0x6c,                          // param value: "psql"
			0x00,                                            // null terminator
			0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,  // param name: "client_encoding"
			0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,
			0x00,                    // null terminator
			0x55, 0x54, 0x46, 0x38,  // param value: "UTF8"
			0x00,                    // null terminator
			0x00                     // null terminator (end of message)
		};

		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(startupData.data(), startupData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_StartupMessage,
		               pcpp::PostgresMessageOrigin::Frontend, 85, 85, "Frontend_StartupMessage");

		auto* startupMsg = dynamic_cast<pcpp::PostgresStartupMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(startupMsg);
		PTF_ASSERT_EQUAL(startupMsg->getProtocolVersion(), 0x300);
		PTF_ASSERT_EQUAL(startupMsg->getProtocolMajorVersion(), 3);
		PTF_ASSERT_EQUAL(startupMsg->getProtocolMinorVersion(), 0);

		auto parameters = startupMsg->getParameters();
		PTF_ASSERT_EQUAL(parameters.size(), 4);
		pcpp::PostgresStartupMessage::ParameterMap expectedParameters = {
			{ "user",             "reader"      },
			{ "database",         "pfmegrnargs" },
			{ "application_name", "psql"        },
			{ "client_encoding",  "UTF8"        }
		};
		for (const auto& paramNameAndValue : expectedParameters)
		{
			PTF_ASSERT_EQUAL(parameters[paramNameAndValue.first], paramNameAndValue.second);
		}

		PTF_ASSERT_EQUAL(startupMsg->getParameter("user"), "reader");
		PTF_ASSERT_EQUAL(startupMsg->getParameter("non-existing"), "");
	}

	// Frontend - SSLRequest message
	{
		std::vector<uint8_t> sslData = {
			0x00, 0x00, 0x00, 0x08,  // length (8)
			0x04, 0xD2, 0x16, 0x2F   // SSL request code (80877103)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(sslData.data(), sslData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_SSLRequest, pcpp::PostgresMessageOrigin::Frontend,
		               8, 8, "Frontend_SSLRequest");
	}

	// Frontend - CancelRequest message
	{
		std::vector<uint8_t> cancelData = {
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0x04, 0xD2, 0x16, 0x2E,  // cancel request code (80877102)
			0x00, 0x00, 0x00, 0x01,  // process ID
			0x00, 0x00, 0x00, 0x02   // secret key
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(cancelData.data(), cancelData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_CancelRequest,
		               pcpp::PostgresMessageOrigin::Frontend, 16, 16, "Frontend_CancelRequest");
	}

	// Frontend - GSSENCRequest message
	{
		std::vector<uint8_t> gssData = {
			0x00, 0x00, 0x00, 0x08,  // length (8)
			0x04, 0xD2, 0x16, 0x30   // GSS request code (80877104)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(gssData.data(), gssData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_GSSENCRequest,
		               pcpp::PostgresMessageOrigin::Frontend, 8, 8, "Frontend_GSSENCRequest");
	}

	// Frontend - Query message
	{
		std::vector<uint8_t> queryData = {
			0x51,                                            // message type 'Q'
			0x00, 0x00, 0x00, 0x18,                          // length (24)
			0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a,  // "select * from blog;"
			0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x62, 0x6c, 0x6f, 0x67, 0x3b,
			0x00  // null terminator

		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(queryData.data(), queryData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Query, pcpp::PostgresMessageOrigin::Frontend, 24,
		               25, "Frontend_Query");
		auto* queryMsg = dynamic_cast<pcpp::PostgresQueryMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(queryMsg);
		PTF_ASSERT_EQUAL(queryMsg->getQuery(), "select * from blog;");
	}

	// Frontend - Parse message
	{
		std::vector<uint8_t> parseData = {
			0x50,                          // message type 'P'
			0x00, 0x00, 0x00, 0x1A,        // length (26)
			0x73, 0x74, 0x6D, 0x74, 0x31,  // "stmt1"
			0x00,                          // null terminator
			0x53, 0x45, 0x4C, 0x45, 0x43,  // "SELECT"
			0x54, 0x20, 0x31, 0x00,        // "T 1" + null
			0x00, 0x01,                    // num parameter types (1)
			0x00, 0x00, 0x00, 0x17,        // parameter type OID (23 = INTEGER)
			0x00                           // padding
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(parseData.data(), parseData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Parse, pcpp::PostgresMessageOrigin::Frontend, 26,
		               27, "Frontend_Parse");
	}

	// Frontend - Bind message
	{
		std::vector<uint8_t> bindData = {
			0x42,                                // message type 'B'
			0x00, 0x00, 0x00, 0x14,              // length (20)
			0x00,                                // portal name (empty)
			0x73, 0x74, 0x6D, 0x74, 0x31, 0x00,  // "stmt1" + null
			0x00, 0x01,                          // num parameter format codes (1)
			0x00, 0x00,                          // format code (0 = text)
			0x00, 0x01,                          // num parameters (1)
			0x00, 0x00, 0x00, 0x05,              // parameter length (5)
			0x68, 0x65, 0x6C, 0x6C, 0x6F,        // "hello"
			0x00, 0x01,                          // num result format codes (1)
			0x00, 0x00                           // format code (0 = text)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(bindData.data(), bindData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Bind, pcpp::PostgresMessageOrigin::Frontend, 20, 21,
		               "Frontend_Bind");
	}

	// Frontend - Execute message
	{
		std::vector<uint8_t> executeData = {
			0x45,                    // message type 'E'
			0x00, 0x00, 0x00, 0x0C,  // length (12)
			0x00,                    // portal name (empty)
			0x00, 0x00, 0x00, 0x00,  // max rows (0 = all)
			0x00, 0x00, 0x00         // padding
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(executeData.data(), executeData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Execute, pcpp::PostgresMessageOrigin::Frontend, 12,
		               13, "Frontend_Execute");
	}

	// Frontend - Close message
	{
		std::vector<uint8_t> closeData = {
			0x43,                               // message type 'C'
			0x00, 0x00, 0x00, 0x09,             // length (9)
			0x53,                               // 'S' (statement)
			0x73, 0x74, 0x6D, 0x74, 0x31, 0x00  // "stmt1" + null
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(closeData.data(), closeData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Close, pcpp::PostgresMessageOrigin::Frontend, 9, 10,
		               "Frontend_Close");
	}

	// Frontend - Describe message
	{
		std::vector<uint8_t> describeData = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x08,  // length (8)
			0x53,                    // 'S' (statement)
			0x00, 0x00, 0x00         // name (empty) + null + padding
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(describeData.data(), describeData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Describe, pcpp::PostgresMessageOrigin::Frontend, 8,
		               9, "Frontend_Describe");
	}

	// Frontend - FunctionCall message
	{
		std::vector<uint8_t> funcCallData = {
			0x46,                          // message type 'F'
			0x00, 0x00, 0x00, 0x10,        // length (16)
			0x00, 0x00, 0x00, 0x1E,        // function OID (30)
			0x00, 0x01,                    // num argument format codes (1)
			0x00, 0x00,                    // format code (0 = text)
			0x00, 0x01,                    // num arguments (1)
			0x00, 0x00, 0x00, 0x05,        // argument length (5)
			0x68, 0x65, 0x6C, 0x6C, 0x6F,  // "hello"
			0x00, 0x00                     // result format code (0 = text)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(funcCallData.data(), funcCallData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_FunctionCall, pcpp::PostgresMessageOrigin::Frontend,
		               16, 17, "Frontend_FunctionCall");
	}

	// Frontend - Flush message
	{
		std::vector<uint8_t> flushData = {
			0x48, 0x00, 0x00, 0x00, 0x04  // message type 'H' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(flushData.data(), flushData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Flush, pcpp::PostgresMessageOrigin::Frontend, 4, 5,
		               "Frontend_Flush");
	}

	// Frontend - Sync message
	{
		std::vector<uint8_t> syncData = {
			0x53, 0x00, 0x00, 0x00, 0x04  // message type 'S' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(syncData.data(), syncData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Sync, pcpp::PostgresMessageOrigin::Frontend, 4, 5,
		               "Frontend_Sync");
	}

	// Frontend - CopyData message
	{
		std::vector<uint8_t> copyData = {
			0x64, 0x00, 0x00, 0x00, 0x08,  // message type 'd' + length
			0x01, 0x02, 0x03, 0x04         // copy data
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(copyData.data(), copyData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_CopyData, pcpp::PostgresMessageOrigin::Frontend, 8,
		               9, "Frontend_CopyData");
	}

	// Frontend - CopyDone message
	{
		std::vector<uint8_t> copyDoneData = {
			0x63, 0x00, 0x00, 0x00, 0x04  // message type 'c' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(copyDoneData.data(), copyDoneData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_CopyDone, pcpp::PostgresMessageOrigin::Frontend, 4,
		               5, "Frontend_CopyDone");
	}

	// Frontend - CopyFail message
	{
		std::vector<uint8_t> copyFailData = {
			0x66, 0x00, 0x00, 0x00, 0x0C,       // message type 'f' + length
			0x63, 0x6F, 0x70, 0x79, 0x20,       // "copy "
			0x66, 0x61, 0x69, 0x6C, 0x65, 0x64  // "failed"
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(copyFailData.data(), copyFailData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_CopyFail, pcpp::PostgresMessageOrigin::Frontend, 12,
		               13, "Frontend_CopyFail");
	}

	// Frontend - Terminate message
	{
		std::vector<uint8_t> terminateData = {
			0x58, 0x00, 0x00, 0x00, 0x04  // message type 'X' + length
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(terminateData.data(), terminateData.size()));
		ASSERT_MESSAGE(message, pcpp::PostgresMessageType::Frontend_Terminate, pcpp::PostgresMessageOrigin::Frontend, 4,
		               5, "Frontend_Terminate");
	}

#undef ASSERT_MESSAGE
}

PTF_TEST_CASE(PostgresInvalidDataTest)
{
	// nullptr data
	{
		PTF_ASSERT_NULL(
		    std::unique_ptr<pcpp::PostgresMessage>(pcpp::PostgresMessage::parsePostgresBackendMessage(nullptr, 10)));
		PTF_ASSERT_NULL(
		    std::unique_ptr<pcpp::PostgresMessage>(pcpp::PostgresMessage::parsePostgresFrontendMessage(nullptr, 10)));
	}

	// Zero length data
	{
		std::vector<uint8_t> emptyData = {};
		PTF_ASSERT_NULL(std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(emptyData.data(), emptyData.size())));
		PTF_ASSERT_NULL(std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(emptyData.data(), emptyData.size())));
	}

	// Truncated message (less than 5 bytes)
	{
		std::vector<uint8_t> truncatedData = { 0x52, 0x00, 0x00 };
		auto backendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(truncatedData.data(), truncatedData.size()));
		PTF_ASSERT_EQUAL(backendMessage->getMessageType(), pcpp::PostgresMessageType::Backend_Unknown, enum);
		auto frontendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(truncatedData.data(), truncatedData.size()));
		PTF_ASSERT_EQUAL(frontendMessage->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Invalid length field (claims more data than available)
	{
		std::vector<uint8_t> invalidLenData = {
			0x64, 0x00, 0x00, 0x00, 0xFF  // message type 'd' + length claims 255 bytes
		};
		auto backendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(invalidLenData.data(), invalidLenData.size()));
		PTF_ASSERT_EQUAL(backendMessage->getMessageType(), pcpp::PostgresMessageType::Backend_Unknown, enum);
		auto frontendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(invalidLenData.data(), invalidLenData.size()));
		PTF_ASSERT_EQUAL(frontendMessage->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Unknown message type
	{
		std::vector<uint8_t> unknownData = {
			0x3F, 0x00, 0x00, 0x00, 0x05,  // message type '?' (unknown) + length
			0x49                           // transaction status
		};
		auto backendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(unknownData.data(), unknownData.size()));
		PTF_ASSERT_EQUAL(backendMessage->getMessageType(), pcpp::PostgresMessageType::Backend_Unknown, enum);
		auto frontendMessage = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(unknownData.data(), unknownData.size()));
		PTF_ASSERT_EQUAL(frontendMessage->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Backend - Authentication with invalid auth type (not in switch)
	{
		std::vector<uint8_t> invalidAuthData = {
			0x52, 0x00, 0x00, 0x00, 0x08,  // message type 'R' + length
			0x00, 0x00, 0x00, 0x04         // auth type 4 (not a valid auth type)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(invalidAuthData.data(), invalidAuthData.size()));
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::PostgresMessageType::Backend_Unknown, enum);
	}

	// Backend - ParameterStatus with truncated data (no null terminator for name)
	{
		std::vector<uint8_t> truncatedParamData = {
			0x53,                                                        // message type 'S'
			0x00, 0x00, 0x00, 0x10,                                      // length (16)
			0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x5F, 0x65, 0x6E, 0x63,  // "client_encod"
			0x00, 0x55                                                   // null + partial value
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(truncatedParamData.data(), truncatedParamData.size()));
		auto* paramMsg = dynamic_cast<pcpp::PostgresParameterStatus*>(message.get());
		PTF_ASSERT_EQUAL(paramMsg->getParameterName(), "client_enc");
		PTF_ASSERT_EQUAL(paramMsg->getParameterValue(), "U");
	}

	// Frontend - truncated startup message (less than 8 bytes)
	{
		std::vector<uint8_t> truncatedStartup = { 0x00, 0x00, 0x00, 0x08 };
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(truncatedStartup.data(), truncatedStartup.size()));
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Frontend - startup message with invalid length
	{
		std::vector<uint8_t> invalidStartup = {
			0x00, 0x00, 0x00, 0xFF  // length claims 255 bytes
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(invalidStartup.data(), invalidStartup.size()));
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Frontend - startup message with unknown tag
	{
		std::vector<uint8_t> unknownTagStartup = {
			0x00, 0x00, 0x00, 0x08,  // length (8)
			0x00, 0x00, 0x00, 0x00   // unknown tag (0)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(unknownTagStartup.data(), unknownTagStartup.size()));
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Frontend - StartupMessage with truncated protocol version
	{
		std::vector<uint8_t> truncatedProtocol = {
			0x00, 0x00, 0x00, 0x06,  // length (6) - less than minimum 8 for startup
			0x00, 0x03               // partial protocol version
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(truncatedProtocol.data(), truncatedProtocol.size()));
		PTF_ASSERT_EQUAL(message->getMessageType(), pcpp::PostgresMessageType::Frontend_Unknown, enum);
	}

	// Frontend - StartupMessage with missing null terminator for parameter
	{
		std::vector<uint8_t> missingNullParam = {
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0x00, 0x03, 0x00, 0x00,  // protocol version 3.0
			0x75, 0x73, 0x65, 0x72,  // "user"
			0x00,                    // null terminator for name
			0x70, 0x6F, 0x73, 0x74   // "post" - missing null terminator (value incomplete)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(missingNullParam.data(), missingNullParam.size()));
		auto* startupMsg = dynamic_cast<pcpp::PostgresStartupMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(startupMsg);
		PTF_ASSERT_EQUAL(startupMsg->getParameter("user"), "pos");
	}

	// getMessageLength with short data
	{
		std::vector<uint8_t> shortData = { 0x52, 0x00 };
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresBackendMessage(shortData.data(), shortData.size()));
		PTF_ASSERT_NOT_NULL(message);
		PTF_ASSERT_EQUAL(message->getMessageLength(), 0);
		PTF_ASSERT_EQUAL(message->getRawPayload().size(), 0);
	}

	// Frontend - Query message without null terminator
	{
		std::vector<uint8_t> noNullTerminator = {
			0x51,                                // message type 'Q'
			0x00, 0x00, 0x00, 0x0C,              // length (12)
			0x53, 0x45, 0x4C, 0x45, 0x43, 0x54,  // "SELECT"
			0x20, 0x31                           // " 1" (no null terminator)
		};
		auto message = std::unique_ptr<pcpp::PostgresMessage>(
		    pcpp::PostgresMessage::parsePostgresFrontendMessage(noNullTerminator.data(), noNullTerminator.size()));
		auto* queryMsg = dynamic_cast<pcpp::PostgresQueryMessage*>(message.get());
		PTF_ASSERT_NOT_NULL(queryMsg);
		PTF_ASSERT_EQUAL(queryMsg->getQuery(), "SELECT 1");
	}

	// Frontend - Query message with data shorter than header (direct construction)
	{
		std::vector<uint8_t> shortData = {
			0x51, 0x00, 0x00, 0x00, 0x05  // only 5 bytes (less than header)
		};
		pcpp::PostgresQueryMessage queryMsg(shortData.data(), shortData.size());
		PTF_ASSERT_EQUAL(queryMsg.getQuery(), "");
	}

	// Frontend - Query message with length claiming 32 bytes but only 9 bytes available (direct construction)
	{
		std::vector<uint8_t> mismatchedLength = {
			0x51,                         // message type 'Q'
			0x00, 0x00, 0x00, 0x20,       // length claims 32, but only 9 bytes available
			0x53, 0x45, 0x4C, 0x45, 0x43  // partial query "SELEC"
		};
		pcpp::PostgresQueryMessage queryMsg(mismatchedLength.data(), mismatchedLength.size());
		PTF_ASSERT_EQUAL(queryMsg.getQuery(), "SELEC");
	}

	// Backend - RowDescription with truncated header (less than 7 bytes)
	{
		std::vector<uint8_t> truncatedHeader = {
			0x54,                    // message type 'T'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			                         // missing: numFields
		};
		pcpp::PostgresRowDescriptionMessage rowDescMsg(truncatedHeader.data(), truncatedHeader.size());
		auto columnInfos = rowDescMsg.getColumnInfos();
		PTF_ASSERT_EQUAL(columnInfos.size(), 0);
	}

	// Backend - RowDescription with invalid field count (claims more than message length)
	{
		std::vector<uint8_t> invalidFieldCount = {
			0x54,                    // message type 'T'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0xFF, 0xFF               // field count (65535 - invalid)
		};
		pcpp::PostgresRowDescriptionMessage rowDescMsg(invalidFieldCount.data(), invalidFieldCount.size());
		auto columnInfos = rowDescMsg.getColumnInfos();
		PTF_ASSERT_EQUAL(columnInfos.size(), 0);
	}

	// Backend - RowDescription with truncated field metadata
	{
		std::vector<uint8_t> truncatedMeta = {
			0x54,                    // message type 'T'
			0x00, 0x00, 0x00, 0x19,  // length (25)
			0x00, 0x01,              // number of fields (1)
			0x69, 0x64, 0x00,        // "id" + null
			0x00, 0x00, 0x00, 0x17,  // table OID (23)
			0x00, 0x01,              // column index (1)
			                         // type OID, type size, type modifier, format code - all missing
		};
		pcpp::PostgresRowDescriptionMessage rowDescMsg(truncatedMeta.data(), truncatedMeta.size());
		auto columnInfos = rowDescMsg.getColumnInfos();
		PTF_ASSERT_EQUAL(columnInfos.size(), 1);
		PTF_ASSERT_EQUAL(columnInfos[0].name, std::string("id"));
	}

	// Backend - DataRow with truncated header (less than 7 bytes)
	{
		std::vector<uint8_t> truncatedHeader = {
			0x44,                   // message type 'D'
			0x00, 0x00, 0x00, 0x0a  // length (10)
			                        // missing: column count
		};
		pcpp::PostgresDataRowMessage dataRowMsg(truncatedHeader.data(), truncatedHeader.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - DataRow with invalid column count (too high)
	{
		std::vector<uint8_t> invalidColumnCount = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0xFF, 0xFF               // column count (65535 - invalid)
		};
		pcpp::PostgresDataRowMessage dataRowMsg(invalidColumnCount.data(), invalidColumnCount.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - DataRow with truncated column count (only 1 byte)
	{
		std::vector<uint8_t> truncatedColumnCount = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0x01                     // partial column count
		};
		pcpp::PostgresDataRowMessage dataRowMsg(truncatedColumnCount.data(), truncatedColumnCount.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - DataRow with zero columns (empty row)
	{
		std::vector<uint8_t> zeroColumns = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x07,  // length (7 - header only)
			0x00, 0x00               // column count = 0
		};
		pcpp::PostgresDataRowMessage dataRowMsg(zeroColumns.data(), zeroColumns.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - DataRow with truncated column length field (only 2 bytes provided instead of 4)
	{
		std::vector<uint8_t> truncatedColLength = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0x00, 0x01,              // column count (1)
			0x00, 0x00               // partial column length (only 2 bytes, reads as 0)
		};
		pcpp::PostgresDataRowMessage dataRowMsg(truncatedColLength.data(), truncatedColLength.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 1);
		PTF_ASSERT_TRUE(dataRow[0].isNull());
	}

	// Backend - DataRow with column claiming more data than available
	{
		std::vector<uint8_t> invalidColLength = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x10,  // length (16)
			0x00, 0x01,              // column count (1)
			0x00, 0x00, 0x00, 0xFF   // column length claims 255 bytes, but no data follows
		};
		pcpp::PostgresDataRowMessage dataRowMsg(invalidColLength.data(), invalidColLength.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - DataRow with column count claiming more columns than message length allows
	{
		std::vector<uint8_t> excessColumns = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0x0D,  // length (13) - enough for header + 1 col length + 2 bytes data
			0x00, 0x10,              // column count (16) - more than data can hold
			0x00, 0x00, 0x00, 0x02,  // first column: length=2
			0x41, 0x42               // "AB" - 2 bytes of data
		};
		pcpp::PostgresDataRowMessage dataRowMsg(excessColumns.data(), excessColumns.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 1);
		PTF_ASSERT_EQUAL(dataRow[0].toString(), std::string("AB"));
	}

	// Backend - DataRow message with length claiming more data than available (direct construction)
	{
		std::vector<uint8_t> mismatchedLength = {
			0x44,                    // message type 'D'
			0x00, 0x00, 0x00, 0xFF,  // length claims 255 bytes
			0x00, 0x01               // column count (1) - but no actual data
		};
		pcpp::PostgresDataRowMessage dataRowMsg(mismatchedLength.data(), mismatchedLength.size());
		auto dataRow = dataRowMsg.getDataRow();
		PTF_ASSERT_EQUAL(dataRow.size(), 0);
	}

	// Backend - PostgresErrorResponseMessage with empty fields (only header)
	{
		std::vector<uint8_t> emptyErrorData = {
			0x45,                    // message type 'E'
			0x00, 0x00, 0x00, 0x01,  // length (1 = only null terminator)
			0x00                     // null terminator
		};
		pcpp::PostgresErrorResponseMessage errorMsg(emptyErrorData.data(), emptyErrorData.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 0);
	}

	// Backend - PostgresErrorResponseMessage with only severity field
	{
		std::vector<uint8_t> minimalErrorData = {
			0x45,                          // message type 'E'
			0x00, 0x00, 0x00, 0x09,        // length (9 = 1 field type + 5 value + 2 null terminators)
			0x53,                          // field type 'S' (Severity)
			0x45, 0x52, 0x52, 0x4F, 0x52,  // "ERROR"
			0x00,                          // null terminator for value
			0x00                           // null terminator for fields list
		};
		pcpp::PostgresErrorResponseMessage errorMsg(minimalErrorData.data(), minimalErrorData.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 1);
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Severity), "ERROR");
	}

	// Backend - PostgresErrorResponseMessage with truncated header (less than 5 bytes)
	{
		std::vector<uint8_t> truncatedHeader = {
			0x45, 0x00, 0x00  // message type 'E' + partial length
		};
		pcpp::PostgresErrorResponseMessage errorMsg(truncatedHeader.data(), truncatedHeader.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 0);
	}

	// Backend - PostgresErrorResponseMessage with field type at end (no value)
	{
		std::vector<uint8_t> fieldTypeNoValue = {
			0x45,                    // message type 'E'
			0x00, 0x00, 0x00, 0x07,  // length (7)
			0x53,                    // field type 'S' (Severity)
			                         // no value bytes after field type
			0x00                     // terminator (but comes right after field type)
		};
		pcpp::PostgresErrorResponseMessage errorMsg(fieldTypeNoValue.data(), fieldTypeNoValue.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 1);
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Severity), "");
	}

	// Backend - PostgresErrorResponseMessage with unknown field type (should be skipped)
	{
		std::vector<uint8_t> unknownFieldType = {
			0x45,                    // message type 'E'
			0x00, 0x00, 0x00, 0x0C,  // length (12)
			0x5A,                    // field type 'Z' (unknown/invalid)
			0x73, 0x6F, 0x6D, 0x65,  // "some"
			0x00,                    // null terminator for value
			0x53,                    // valid field type 'S' (Severity)
			0x57, 0x41, 0x52, 0x4E,  // "WARN"
			0x00                     // null terminator
		};
		pcpp::PostgresErrorResponseMessage errorMsg(unknownFieldType.data(), unknownFieldType.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 1);
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Severity), "WARN");
	}

	// Backend - PostgresErrorResponseMessage with empty field value
	{
		std::vector<uint8_t> emptyValueField = {
			0x45,                    // message type 'E'
			0x00, 0x00, 0x00, 0x09,  // length (9)
			0x53,                    // field type 'S' (Severity)
			0x00,                    // empty value (immediate null)
			0x4D,                    // field type 'M' (Message)
			0x00                     // null terminator
		};
		pcpp::PostgresErrorResponseMessage errorMsg(emptyValueField.data(), emptyValueField.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 2);
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Severity), "");
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Message), "");
	}

	// Backend - PostgresErrorResponseMessage with duplicate fields (last one wins)
	{
		std::vector<uint8_t> duplicateFields = {
			0x45,                          // message type 'E'
			0x00, 0x00, 0x00, 0x10,        // length (16)
			0x53,                          // field type 'S' (Severity)
			0x45, 0x52, 0x52, 0x4F, 0x52,  // "ERROR"
			0x00,
			0x53,                          // field type 'S' again (Severity)
			0x46, 0x41, 0x54, 0x41, 0x4C,  // "FATAL"
			0x00,
			0x00  // terminator
		};
		pcpp::PostgresErrorResponseMessage errorMsg(duplicateFields.data(), duplicateFields.size());
		auto& fields = errorMsg.getFields();
		PTF_ASSERT_EQUAL(fields.size(), 1);
		PTF_ASSERT_EQUAL(fields.at(pcpp::PostgresErrorResponseMessage::ErrorField::Severity), "FATAL");
	}
}
