#pragma once

#include "Layer.h"
#include "PointerVector.h"
#include <memory>
#include <ostream>
#include <unordered_map>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @enum MySqlMessageOrigin
	/// Indicates whether the message is from the client or server
	enum class MySqlMessageOrigin
	{
		Client,
		Server
	};

	/// @class MySqlMessageType
	/// Represents MySQL message types
	class MySqlMessageType
	{
	public:
		/// Define enum types for MySQL message types
		enum Value : uint8_t
		{
			/// Handshake response
			Client_HandshakeResponse,
			/// COM_SLEEP command
			Client_Sleep,
			/// COM_QUIT command - close connection
			Client_Quit,
			/// COM_INIT_DB command - change default database
			Client_InitDb,
			/// COM_QUERY command - execute SQL query
			Client_Query,
			/// COM_FIELD_LIST command - get field information for a table
			Client_FieldList,
			/// COM_CREATE_DB command
			Client_CreateDb,
			/// COM_DROP_DB command
			Client_DropDb,
			/// COM_REFRESH command - flush tables, caches, or logs
			Client_Refresh,
			/// COM_SHUTDOWN command - shutdown the server
			Client_Shutdown,
			/// COM_STATISTICS command - get server status information
			Client_Statistics,
			/// COM_PROCESS_INFO command - get list of active threads
			Client_ProcessInfo,
			/// COM_CONNECT command - connect to server (internal use)
			Client_Connect,
			/// COM_PROCESS_KILL command - kill a server thread
			Client_ProcessKill,
			/// COM_DEBUG command - send debug info to server
			Client_Debug,
			/// COM_PING command - check server availability
			Client_Ping,
			/// COM_TIME command
			Client_Time,
			/// COM_DELAYED_INSERT command
			Client_DelayedInsert,
			/// COM_CHANGE_USER command - change user and database
			Client_ChangeUser,
			/// COM_BINLOG_DUMP command - start binary log dump (slave replication)
			Client_BinlogDump,
			/// COM_TABLE_DUMP command - dump table data (slave replication)
			Client_TableDump,
			/// COM_CONNECT_OUT command - slave connecting to master (internal use)
			Client_ConnectOut,
			/// COM_REGISTER_SLAVE command - register slave with master
			Client_RegisterSlave,
			/// COM_STMT_PREPARE command - prepare statement
			Client_StmtPrepare,
			/// COM_STMT_EXECUTE command - execute prepared statement
			Client_StmtExecute,
			/// COM_STMT_FETCH command - fetch rows from prepared statement
			Client_StmtFetch,
			/// COM_STMT_CLOSE command - close prepared statement
			Client_StmtClose,
			/// COM_STMT_RESET command - reset prepared statement data
			Client_StmtReset,
			/// COM_SET_OPTION command - set option (e.g., multi-statements)
			Client_SetOption,
			/// COM_STMT_SEND_LONG_DATA command - send long data for prepared statement
			Client_StmtSendLongData,
			/// COM_DAEMON command
			Client_Daemon,
			/// COM_BINLOG_DUMP_GTID command - start GTID-based binary log dump
			Client_BinlogDumpGtid,
			/// COM_RESET_CONNECTION command - reset connection without re-authentication
			Client_ResetConnection,
			/// COM_CLONE command
			Client_Clone,

			/// Initial handshake
			Server_Handshake,
			/// OK packet - successful response from server
			Server_Ok,
			/// AuthSwitchRequest packet - server requests authentication method switch
			Server_AuthSwitchRequest,
			/// EOF message
			Server_EOF,
			/// Error packet - error response from server
			Server_Error,
			/// Other server message
			Server_Other,

			/// Unknown message
			Unknown
		};

		constexpr MySqlMessageType() : m_Value(Unknown)
		{}

		// cppcheck-suppress noExplicitConstructor
		/// @brief Constructs a MySqlMessageType object from a Value enum
		/// @param[in] value The Value enum value
		constexpr MySqlMessageType(Value value) : m_Value(value)
		{}

		/// @brief Converts the message type to its character representation
		/// @return The message type character
		char toChar() const;

		/// @brief Returns a string representation of the message type
		/// @return A string representation of the message type
		std::string toString() const;

		/// @brief Stream operator for MySqlMessageType
		/// @param[in] os The output stream
		/// @param[in] messageType The message type to print
		/// @return The output stream
		friend std::ostream& operator<<(std::ostream& os, const MySqlMessageType& messageType)
		{
			os << messageType.toString();
			return os;
		}

		/// @brief Converts the message type to a string
		/// @return The message type as a string
		explicit operator std::string() const
		{
			return toString();
		}

		/// @brief Returns the origin of the message (client or server)
		/// @return The message origin
		MySqlMessageOrigin getOrigin() const;

		// Allow switch and comparisons
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(MySqlMessageType)
		explicit operator bool() const = delete;

	private:
		Value m_Value;
	};

	/// @class MySqlMessage
	/// Represents a MySQL message (base class)
	class MySqlMessage
	{
	public:
		virtual ~MySqlMessage() = default;

		/// @brief Parse a MySQL message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] origin The message origin (client or server)
		/// @return A unique pointer to the parsed MySqlMessage, or nullptr if parsing fails
		static std::unique_ptr<MySqlMessage> parseMySqlMessage(const uint8_t* data, size_t dataLen,
		                                                       MySqlMessageOrigin origin);

		/// @return The message type
		MySqlMessageType getMessageType() const
		{
			return m_MessageType;
		}

		/// @return The message origin (client or server)
		MySqlMessageOrigin getMessageOrigin() const
		{
			return m_MessageOrigin;
		}

		/// @brief Returns the length of the message payload
		/// @return The message length
		virtual uint32_t getMessageLength() const;

		/// @brief Returns the packet number
		/// @return The packet number
		uint8_t getPacketNumber() const;

		/// @brief Returns the total length of the message including the length field
		/// @return The total message length in bytes
		size_t getTotalMessageLength() const
		{
			return m_DataLen;
		}

		/// @brief Returns the raw payload bytes of the message
		/// @return The raw payload bytes of the message
		virtual std::vector<uint8_t> getRawPayload() const;

	protected:
		MySqlMessage(const uint8_t* data, size_t dataLen, const MySqlMessageType& messageType,
		             MySqlMessageOrigin origin)
		    : m_Data(data), m_DataLen(dataLen), m_MessageType(messageType), m_MessageOrigin(origin)
		{}

		static constexpr int basicMessageLength = 4;
		static constexpr int commandLength = 1;
		static constexpr int packetNumberIndex = 3;
		static constexpr int commandIndex = 4;

		const uint8_t* m_Data;
		size_t m_DataLen;
		MySqlMessageType m_MessageType;
		MySqlMessageOrigin m_MessageOrigin;
	};

	class MySqlCommandMessage : public MySqlMessage
	{
		friend class MySqlMessage;

	public:
		uint32_t getMessageLength() const override;
		std::vector<uint8_t> getRawPayload() const override;

	protected:
		MySqlCommandMessage(const uint8_t* data, size_t dataLen, const MySqlMessageType& messageType,
		                    MySqlMessageOrigin origin)
		    : MySqlMessage(data, dataLen, messageType, origin)
		{}
	};

	/// @class MySqlLayer
	/// Represents a MySQL protocol layer
	class MySqlLayer : public Layer
	{
	public:
		/// A d'tor for this layer
		~MySqlLayer() override = default;

		/// A static method that checks whether the port is considered as MySQL
		/// @param[in] port The port number to be checked
		static bool isMySqlPort(uint16_t port)
		{
			return port == 3306;
		}

		static MySqlLayer* parseMySqlClientMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static MySqlLayer* parseMySqlServerMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @return The message origin (client or server)
		MySqlMessageOrigin getMySqlOrigin() const
		{
			return m_MessageOrigin;
		}

		/// @return A vector of all MySQL messages in this layer
		const PointerVector<MySqlMessage>& getMySqlMessages() const;

		/// @brief Get a MySQL message by its type
		/// @param[in] messageType The type of message to retrieve
		/// @return A pointer to the message, or nullptr if not found
		const MySqlMessage* getMySqlMessage(const MySqlMessageType& messageType) const;

		/// @brief Get a MySQL message by its type (template version)
		/// @tparam TMessage The message type to retrieve (must derive from MySqlMessage)
		/// @return A pointer to the message of the specified type, or nullptr if not found
		template <class TMessage, std::enable_if_t<std::is_base_of<MySqlMessage, TMessage>::value, bool> = nullptr>
		const TMessage* getMySqlMessage() const
		{
			const auto& messages = getMySqlMessages();
			for (const auto& msg : messages)
			{
				auto result = dynamic_cast<const TMessage*>(msg);
				if (result != nullptr)
				{
					return result;
				}
			}
			return nullptr;
		}

		// Overridden methods

		/// @return The size of the MySQL layer header
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer, MySQL is always last
		void parseNextLayer() override
		{}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return The OSI layer level of MySQL (Application Layer).
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

		/// @return Returns the protocol info as readable string
		std::string toString() const override;

	private:
		MySqlMessageOrigin m_MessageOrigin;
		mutable PointerVector<MySqlMessage> m_Messages;
		mutable bool m_MessagesInitialized = false;

		MySqlLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, MySqlMessageOrigin origin)
		    : Layer(data, dataLen, prevLayer, packet, MySQL), m_MessageOrigin(origin)
		{}
	};

}  // namespace pcpp
