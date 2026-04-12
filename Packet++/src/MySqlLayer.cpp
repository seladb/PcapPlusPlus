#include "MySqlLayer.h"
#include "EndianPortable.h"
#include <algorithm>

namespace pcpp
{
	constexpr uint8_t ClientSleepCommand = 0x00;
	constexpr uint8_t ClientQuitCommand = 0x01;
	constexpr uint8_t ClientInitDbCommand = 0x02;
	constexpr uint8_t ClientQueryCommand = 0x03;
	constexpr uint8_t ClientFieldListCommand = 0x04;
	constexpr uint8_t ClientCreateDbCommand = 0x05;
	constexpr uint8_t ClientDropDbCommand = 0x06;
	constexpr uint8_t ClientRefreshCommand = 0x07;
	constexpr uint8_t ClientShutdownCommand = 0x08;
	constexpr uint8_t ClientStatisticsCommand = 0x09;
	constexpr uint8_t ClientProcessInfoCommand = 0x0a;
	constexpr uint8_t ClientConnectCommand = 0x0b;
	constexpr uint8_t ClientProcessKillCommand = 0x0c;
	constexpr uint8_t ClientDebugCommand = 0x0d;
	constexpr uint8_t ClientPingCommand = 0x0e;
	constexpr uint8_t ClientTimeCommand = 0x0f;
	constexpr uint8_t ClientDelayedInsertCommand = 0x10;
	constexpr uint8_t ClientChangeUserCommand = 0x11;
	constexpr uint8_t ClientBinlogDumpCommand = 0x12;
	constexpr uint8_t ClientTableDumpCommand = 0x13;
	constexpr uint8_t ClientConnectOutCommand = 0x14;
	constexpr uint8_t ClientRegisterSlaveCommand = 0x15;
	constexpr uint8_t ClientStmtPrepareCommand = 0x16;
	constexpr uint8_t ClientStmtExecuteCommand = 0x17;
	constexpr uint8_t ClientStmtSendLongDataCommand = 0x18;
	constexpr uint8_t ClientStmtCloseCommand = 0x19;
	constexpr uint8_t ClientStmtResetCommand = 0x1a;
	constexpr uint8_t ClientSetOptionCommand = 0x1b;
	constexpr uint8_t ClientStmtFetchCommand = 0x1c;
	constexpr uint8_t ClientDaemonCommand = 0x1d;
	constexpr uint8_t ClientBinlogDumpGtidCommand = 0x1e;
	constexpr uint8_t ClientResetConnectionCommand = 0x1f;
	constexpr uint8_t ClientCloneCommand = 0x20;

	constexpr uint8_t ServerOk = 0x00;
	constexpr uint8_t ServerError = 0xff;
	constexpr uint8_t ServerEof_AuthSwitchRequest = 0xfe;

	char MySqlMessageType::toChar() const
	{
		switch (m_Value)
		{
		case Client_Sleep:
			return ClientSleepCommand;
		case Client_Quit:
			return ClientQuitCommand;
		case Client_InitDb:
			return ClientInitDbCommand;
		case Client_Query:
			return ClientQueryCommand;
		case Client_FieldList:
			return ClientFieldListCommand;
		case Client_CreateDb:
			return ClientCreateDbCommand;
		case Client_DropDb:
			return ClientDropDbCommand;
		case Client_Refresh:
			return ClientRefreshCommand;
		case Client_Shutdown:
			return ClientShutdownCommand;
		case Client_Statistics:
			return ClientStatisticsCommand;
		case Client_ProcessInfo:
			return ClientProcessInfoCommand;
		case Client_Connect:
			return ClientConnectCommand;
		case Client_ProcessKill:
			return ClientProcessKillCommand;
		case Client_Debug:
			return ClientDebugCommand;
		case Client_Ping:
			return ClientPingCommand;
		case Client_Time:
			return ClientTimeCommand;
		case Client_DelayedInsert:
			return ClientDelayedInsertCommand;
		case Client_ChangeUser:
			return ClientChangeUserCommand;
		case Client_BinlogDump:
			return ClientBinlogDumpCommand;
		case Client_TableDump:
			return ClientTableDumpCommand;
		case Client_ConnectOut:
			return ClientConnectOutCommand;
		case Client_RegisterSlave:
			return ClientRegisterSlaveCommand;
		case Client_StmtPrepare:
			return ClientStmtPrepareCommand;
		case Client_StmtExecute:
			return ClientStmtExecuteCommand;
		case Client_StmtSendLongData:
			return ClientStmtSendLongDataCommand;
		case Client_StmtClose:
			return ClientStmtCloseCommand;
		case Client_StmtReset:
			return ClientStmtResetCommand;
		case Client_SetOption:
			return ClientSetOptionCommand;
		case Client_StmtFetch:
			return ClientStmtFetchCommand;
		case Client_Daemon:
			return ClientDaemonCommand;
		case Client_BinlogDumpGtid:
			return ClientBinlogDumpGtidCommand;
		case Client_ResetConnection:
			return ClientResetConnectionCommand;
		case Client_Clone:
			return ClientCloneCommand;
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
		case Server_Data:
			return "Data";
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
				return std::unique_ptr<MySqlMessage>(
				    new MySqlMessage(data, messageLength + 4, MySqlMessageType::Client_HandshakeResponse, origin));
			}

			if (dataLen < commandIndex + 1 || messageLength == 0)
			{
				return std::unique_ptr<MySqlMessage>(
				    new MySqlMessage(data, messageLength + 4, MySqlMessageType::Unknown, origin));
			}

			auto command = data[commandIndex];
			switch (command)
			{
			case ClientSleepCommand:
				messageType = MySqlMessageType::Client_Sleep;
				break;
			case ClientQuitCommand:
				messageType = MySqlMessageType::Client_Quit;
				break;
			case ClientInitDbCommand:
				messageType = MySqlMessageType::Client_InitDb;
				break;
			case ClientQueryCommand:
				return std::unique_ptr<MySqlMessage>(new MySqlQueryMessage(data, messageLength + 4));
			case ClientFieldListCommand:
				messageType = MySqlMessageType::Client_FieldList;
				break;
			case ClientCreateDbCommand:
				messageType = MySqlMessageType::Client_CreateDb;
				break;
			case ClientDropDbCommand:
				messageType = MySqlMessageType::Client_DropDb;
				break;
			case ClientRefreshCommand:
				messageType = MySqlMessageType::Client_Refresh;
				break;
			case ClientShutdownCommand:
				messageType = MySqlMessageType::Client_Shutdown;
				break;
			case ClientStatisticsCommand:
				messageType = MySqlMessageType::Client_Statistics;
				break;
			case ClientProcessInfoCommand:
				messageType = MySqlMessageType::Client_ProcessInfo;
				break;
			case ClientConnectCommand:
				messageType = MySqlMessageType::Client_Connect;
				break;
			case ClientProcessKillCommand:
				messageType = MySqlMessageType::Client_ProcessKill;
				break;
			case ClientDebugCommand:
				messageType = MySqlMessageType::Client_Debug;
				break;
			case ClientPingCommand:
				messageType = MySqlMessageType::Client_Ping;
				break;
			case ClientTimeCommand:
				messageType = MySqlMessageType::Client_Time;
				break;
			case ClientDelayedInsertCommand:
				messageType = MySqlMessageType::Client_DelayedInsert;
				break;
			case ClientChangeUserCommand:
				messageType = MySqlMessageType::Client_ChangeUser;
				break;
			case ClientBinlogDumpCommand:
				messageType = MySqlMessageType::Client_BinlogDump;
				break;
			case ClientTableDumpCommand:
				messageType = MySqlMessageType::Client_TableDump;
				break;
			case ClientConnectOutCommand:
				messageType = MySqlMessageType::Client_ConnectOut;
				break;
			case ClientRegisterSlaveCommand:
				messageType = MySqlMessageType::Client_RegisterSlave;
				break;
			case ClientStmtPrepareCommand:
				messageType = MySqlMessageType::Client_StmtPrepare;
				break;
			case ClientStmtExecuteCommand:
				messageType = MySqlMessageType::Client_StmtExecute;
				break;
			case ClientStmtSendLongDataCommand:
				messageType = MySqlMessageType::Client_StmtSendLongData;
				break;
			case ClientStmtCloseCommand:
				messageType = MySqlMessageType::Client_StmtClose;
				break;
			case ClientStmtResetCommand:
				messageType = MySqlMessageType::Client_StmtReset;
				break;
			case ClientSetOptionCommand:
				messageType = MySqlMessageType::Client_SetOption;
				break;
			case ClientStmtFetchCommand:
				messageType = MySqlMessageType::Client_StmtFetch;
				break;
			case ClientDaemonCommand:
				messageType = MySqlMessageType::Client_Daemon;
				break;
			case ClientBinlogDumpGtidCommand:
				messageType = MySqlMessageType::Client_BinlogDumpGtid;
				break;
			case ClientResetConnectionCommand:
				messageType = MySqlMessageType::Client_ResetConnection;
				break;
			case ClientCloneCommand:
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
				return std::unique_ptr<MySqlMessage>(
				    new MySqlMessage(data, messageLength + 4, MySqlMessageType::Server_Handshake, origin));
			}

			if (dataLen < commandIndex + 1 || messageLength == 0)
			{
				return std::unique_ptr<MySqlMessage>(
				    new MySqlMessage(data, messageLength + 4, MySqlMessageType::Unknown, origin));
			}

			auto firstByte = data[commandIndex];
			switch (firstByte)
			{
			case ServerOk:
				messageType = MySqlMessageType::Server_Ok;
				break;
			case ServerError:
				return std::unique_ptr<MySqlMessage>(new MySqlErrorMessage(data, messageLength + 4));
			case ServerEof_AuthSwitchRequest:
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
				return std::unique_ptr<MySqlMessage>(
				    new MySqlMessage(data, messageLength + basicMessageLength, MySqlMessageType::Server_Data, origin));
			}
		}

		return std::unique_ptr<MySqlCommandMessage>(
		    new MySqlCommandMessage(data, messageLength + basicMessageLength, messageType, origin));
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

	std::string MySqlQueryMessage::getQuery() const
	{
		if (!m_Data || m_DataLen < statementIndex + 1)
		{
			return {};
		}

		return { reinterpret_cast<const char*>(m_Data + statementIndex), m_DataLen - statementIndex };
	}

	uint16_t MySqlErrorMessage::getErrorCode() const
	{
		if (!m_Data || m_DataLen < errorCodeIndex + sizeof(uint16_t))
		{
			return 0;
		}

		return *reinterpret_cast<const uint16_t*>(m_Data + errorCodeIndex);
	}

	std::string MySqlErrorMessage::getSqlState() const
	{
		if (!m_Data || m_DataLen < sqlStateIndex + sqlStateSize)
		{
			return {};
		}

		return { reinterpret_cast<const char*>(m_Data + sqlStateIndex), sqlStateSize };
	}

	std::string MySqlErrorMessage::getErrorMessage() const
	{
		if (!m_Data || m_DataLen < errorMessageIndex + 1)
		{
			return {};
		}

		return { reinterpret_cast<const char*>(m_Data + errorMessageIndex), m_DataLen - errorMessageIndex };
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
