#include "MySqlLayer.h"
#include "EndianPortable.h"
#include <algorithm>

namespace pcpp
{

	char MySqlMessageType::toChar() const
	{
		switch (m_Value)
		{
		case Client_Sleep:
			return 0x00;
		case Client_Quit:
			return 0x01;
		case Client_InitDb:
			return 0x02;
		case Client_Query:
			return 0x03;
		case Client_FieldList:
			return 0x04;
		case Client_CreateDb:
			return 0x05;
		case Client_DropDb:
			return 0x06;
		case Client_Refresh:
			return 0x07;
		case Client_Shutdown:
			return 0x08;
		case Client_Statistics:
			return 0x09;
		case Client_ProcessInfo:
			return 0x0a;
		case Client_Connect:
			return 0x0b;
		case Client_ProcessKill:
			return 0x0c;
		case Client_Debug:
			return 0x0d;
		case Client_Ping:
			return 0x0e;
		case Client_Time:
			return 0x0f;
		case Client_DelayedInsert:
			return 0x10;
		case Client_ChangeUser:
			return 0x11;
		case Client_BinlogDump:
			return 0x12;
		case Client_TableDump:
			return 0x13;
		case Client_ConnectOut:
			return 0x14;
		case Client_RegisterSlave:
			return 0x15;
		case Client_StmtPrepare:
			return 0x16;
		case Client_StmtExecute:
			return 0x17;
		case Client_StmtSendLongData:
			return 0x18;
		case Client_StmtClose:
			return 0x19;
		case Client_StmtReset:
			return 0x1a;
		case Client_SetOption:
			return 0x1b;
		case Client_StmtFetch:
			return 0x1c;
		case Client_Daemon:
			return 0x1d;
		case Client_BinlogDumpGtid:
			return 0x1e;
		case Client_ResetConnection:
			return 0x1f;
		case Client_Clone:
			return 0x20;
		default:
			return '\0';
		}
	}

	std::string MySqlMessageType::toString() const
	{
		switch (m_Value)
		{
		case Client_HandshakeResponse:
			return "HandshakeResponse";
		case Client_Sleep:
			return "COM_SLEEP";
		case Client_Quit:
			return "COM_QUIT";
		case Client_InitDb:
			return "COM_INIT_DB";
		case Client_Query:
			return "COM_QUERY";
		case Client_FieldList:
			return "COM_FIELD_LIST";
		case Client_CreateDb:
			return "COM_CREATE_DB";
		case Client_DropDb:
			return "COM_DROP_DB";
		case Client_Refresh:
			return "COM_REFRESH";
		case Client_Shutdown:
			return "COM_SHUTDOWN";
		case Client_Statistics:
			return "COM_STATISTICS";
		case Client_ProcessInfo:
			return "COM_PROCESS_INFO";
		case Client_Connect:
			return "COM_CONNECT";
		case Client_ProcessKill:
			return "COM_PROCESS_KILL";
		case Client_Debug:
			return "COM_DEBUG";
		case Client_Ping:
			return "COM_PING";
		case Client_Time:
			return "COM_TIME";
		case Client_DelayedInsert:
			return "COM_DELAYED_INSERT";
		case Client_ChangeUser:
			return "COM_CHANGE_USER";
		case Client_BinlogDump:
			return "COM_BINLOG_DUMP";
		case Client_TableDump:
			return "COM_TABLE_DUMP";
		case Client_ConnectOut:
			return "COM_CONNECT_OUT";
		case Client_RegisterSlave:
			return "COM_REGISTER_SLAVE";
		case Client_StmtPrepare:
			return "COM_STMT_PREPARE";
		case Client_StmtExecute:
			return "COM_STMT_EXECUTE";
		case Client_StmtFetch:
			return "COM_STMT_FETCH";
		case Client_StmtClose:
			return "COM_STMT_CLOSE";
		case Client_StmtReset:
			return "COM_STMT_RESET";
		case Client_SetOption:
			return "COM_SET_OPTION";
		case Client_StmtSendLongData:
			return "COM_STMT_SEND_LONG_DATA";
		case Client_Daemon:
			return "COM_DAEMON";
		case Client_BinlogDumpGtid:
			return "COM_BINLOG_DUMP_GTID";
		case Client_ResetConnection:
			return "COM_RESET_CONNECTION";
		case Client_Clone:
			return "COM_CLONE";
		case Server_Handshake:
			return "Handshake";
		case Server_Ok:
			return "OK";
		case Server_AuthSwitchRequest:
			return "AuthSwitchRequest";
		case Server_Error:
			return "Error";
		case Server_EOF:
			return "EOF";
		case Server_Other:
			return "Other";
		default:
			return "Unknown";
		}
	}

	MySqlMessageOrigin MySqlMessageType::getOrigin() const
	{
		switch (m_Value)
		{
		case Client_HandshakeResponse:
		case Client_Sleep:
		case Client_Quit:
		case Client_InitDb:
		case Client_Query:
		case Client_FieldList:
		case Client_CreateDb:
		case Client_DropDb:
		case Client_Refresh:
		case Client_Shutdown:
		case Client_Statistics:
		case Client_ProcessInfo:
		case Client_Connect:
		case Client_ProcessKill:
		case Client_Debug:
		case Client_Ping:
		case Client_Time:
		case Client_DelayedInsert:
		case Client_ChangeUser:
		case Client_BinlogDump:
		case Client_TableDump:
		case Client_ConnectOut:
		case Client_RegisterSlave:
		case Client_StmtPrepare:
		case Client_StmtExecute:
		case Client_StmtFetch:
		case Client_StmtClose:
		case Client_StmtReset:
		case Client_SetOption:
		case Client_StmtSendLongData:
		case Client_Daemon:
		case Client_BinlogDumpGtid:
		case Client_ResetConnection:
		case Client_Clone:
			return MySqlMessageOrigin::Client;
		default:
			return MySqlMessageOrigin::Server;
		}
	}

	uint32_t MySqlMessage::getMessageLength() const
	{
		if (m_Data == nullptr || m_DataLen < basicMessageLength)
		{
			return 0;
		}
		return static_cast<uint32_t>(m_Data[0]) | (static_cast<uint32_t>(m_Data[1]) << 8) |
		       (static_cast<uint32_t>(m_Data[2]) << 16);
	}

	uint8_t MySqlMessage::getPacketNumber() const
	{
		if (m_Data == nullptr || m_DataLen < basicMessageLength)
		{
			return 0;
		}
		return m_Data[packetNumberIndex];
	}

	std::unique_ptr<MySqlMessage> MySqlMessage::parseMySqlMessage(const uint8_t* data, size_t dataLen,
	                                                              MySqlMessageOrigin origin)
	{
		if (data == nullptr || dataLen < basicMessageLength)
		{
			return nullptr;
		}

		auto messageLength = static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
		                     (static_cast<uint32_t>(data[2]) << 16);
		if (dataLen < messageLength + basicMessageLength)
		{
			return nullptr;
		}

		MySqlMessageType messageType = MySqlMessageType::Unknown;

		if (origin == MySqlMessageOrigin::Client)
		{
			if (data[packetNumberIndex] == 1)
			{
				return std::unique_ptr<MySqlMessage>(new MySqlMessage(data, messageLength + 4, MySqlMessageType::Client_HandshakeResponse, origin));
			}

			auto command = data[commandIndex];
			switch (command)
			{
			case 0x00:
				messageType = MySqlMessageType::Client_Sleep;
				break;
			case 0x01:
				messageType = MySqlMessageType::Client_Quit;
				break;
			case 0x02:
				messageType = MySqlMessageType::Client_InitDb;
				break;
			case 0x03:
				messageType = MySqlMessageType::Client_Query;
				break;
			case 0x04:
				messageType = MySqlMessageType::Client_FieldList;
				break;
			case 0x05:
				messageType = MySqlMessageType::Client_CreateDb;
				break;
			case 0x06:
				messageType = MySqlMessageType::Client_DropDb;
				break;
			case 0x07:
				messageType = MySqlMessageType::Client_Refresh;
				break;
			case 0x08:
				messageType = MySqlMessageType::Client_Shutdown;
				break;
			case 0x09:
				messageType = MySqlMessageType::Client_Statistics;
				break;
			case 0x0a:
				messageType = MySqlMessageType::Client_ProcessInfo;
				break;
			case 0x0b:
				messageType = MySqlMessageType::Client_Connect;
				break;
			case 0x0c:
				messageType = MySqlMessageType::Client_ProcessKill;
				break;
			case 0x0d:
				messageType = MySqlMessageType::Client_Debug;
				break;
			case 0x0e:
				messageType = MySqlMessageType::Client_Ping;
				break;
			case 0x0f:
				messageType = MySqlMessageType::Client_Time;
				break;
			case 0x10:
				messageType = MySqlMessageType::Client_DelayedInsert;
				break;
			case 0x11:
				messageType = MySqlMessageType::Client_ChangeUser;
				break;
			case 0x12:
				messageType = MySqlMessageType::Client_BinlogDump;
				break;
			case 0x13:
				messageType = MySqlMessageType::Client_TableDump;
				break;
			case 0x14:
				messageType = MySqlMessageType::Client_ConnectOut;
				break;
			case 0x15:
				messageType = MySqlMessageType::Client_RegisterSlave;
				break;
			case 0x16:
				messageType = MySqlMessageType::Client_StmtPrepare;
				break;
			case 0x17:
				messageType = MySqlMessageType::Client_StmtExecute;
				break;
			case 0x18:
				messageType = MySqlMessageType::Client_StmtSendLongData;
				break;
			case 0x19:
				messageType = MySqlMessageType::Client_StmtClose;
				break;
			case 0x1a:
				messageType = MySqlMessageType::Client_StmtReset;
				break;
			case 0x1b:
				messageType = MySqlMessageType::Client_SetOption;
				break;
			case 0x1c:
				messageType = MySqlMessageType::Client_StmtFetch;
				break;
			case 0x1d:
				messageType = MySqlMessageType::Client_Daemon;
				break;
			case 0x1e:
				messageType = MySqlMessageType::Client_BinlogDumpGtid;
				break;
			case 0x1f:
				messageType = MySqlMessageType::Client_ResetConnection;
				break;
			case 0x20:
				messageType = MySqlMessageType::Client_Clone;
				break;
			default:
				break;
			}
		}
		else  // Server message
		{
			if (data[packetNumberIndex] == 0)
			{
				return std::unique_ptr<MySqlMessage>(new MySqlMessage(data, messageLength + 4, MySqlMessageType::Server_Handshake, origin));
			}
			auto firstByte = data[commandIndex];
			switch (firstByte)
			{
			case 0x00:
				messageType = MySqlMessageType::Server_Ok;
				break;
			case 0xff:
				messageType = MySqlMessageType::Server_Error;
				break;
			case 0xfe:
			{
				messageLength = dataLen - basicMessageLength;
				if (messageLength < 9)
				{
					messageType = MySqlMessageType::Server_EOF;
				}
				else
				{
					messageType = MySqlMessageType::Server_AuthSwitchRequest;
				}
				break;
			}
			default:
				return std::unique_ptr<MySqlMessage>(new MySqlMessage(data, messageLength + basicMessageLength, MySqlMessageType::Server_Other, origin));
			}
		}

		if (messageType == MySqlMessageType::Unknown)
		{
			return nullptr;
		}

		return std::unique_ptr<MySqlCommandMessage>(new MySqlCommandMessage(data, messageLength + basicMessageLength, messageType, origin));
	}

	std::vector<uint8_t> MySqlMessage::getRawPayload() const
	{
		if (m_DataLen < basicMessageLength)
		{
			return {};
		}
		return { m_Data + basicMessageLength, m_Data + m_DataLen };
	}

	uint32_t MySqlCommandMessage::getMessageLength() const
	{
		auto length = MySqlMessage::getMessageLength();
		if (length > 0)
		{
			length--;
		}

		return length;
	}

	std::vector<uint8_t> MySqlCommandMessage::getRawPayload() const
	{
		if (m_DataLen < basicMessageLength)
		{
			return {};
		}
		return { m_Data + basicMessageLength + commandLength, m_Data + m_DataLen };
	}

	MySqlLayer* MySqlLayer::parseMySqlClientMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		return new MySqlLayer(data, dataLen, prevLayer, packet, MySqlMessageOrigin::Client);
	}

	MySqlLayer* MySqlLayer::parseMySqlServerMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		return new MySqlLayer(data, dataLen, prevLayer, packet, MySqlMessageOrigin::Server);
	}

	const PointerVector<MySqlMessage>& MySqlLayer::getMySqlMessages() const
	{
		if (!m_MessagesInitialized)
		{
			auto data = m_Data;
			auto dataLen = m_DataLen;

			while (dataLen > 0)
			{
				auto curMessage = MySqlMessage::parseMySqlMessage(data, dataLen, m_MessageOrigin);
				if (curMessage == nullptr)
				{
					break;
				}

				dataLen -= curMessage->getTotalMessageLength();
				data += curMessage->getTotalMessageLength();
				m_Messages.pushBack(std::move(curMessage));
			}

			m_MessagesInitialized = true;
		}

		return m_Messages;
	}

	const MySqlMessage* MySqlLayer::getMySqlMessage(const MySqlMessageType& messageType) const
	{
		const auto& messages = getMySqlMessages();
		auto it = std::find_if(messages.begin(), messages.end(), [&messageType](const MySqlMessage* message) {
			return message->getMessageType() == messageType;
		});

		return it != messages.end() ? *it : nullptr;
	}

	std::string MySqlLayer::toString() const
	{
		const auto& messages = getMySqlMessages();
		return std::string("MySQL ") + (m_MessageOrigin == MySqlMessageOrigin::Client ? "Client" : "Server") +
		       " Layer, " + std::to_string(messages.size()) + " message(s)";
	}
}  // namespace pcpp
