#pragma once

#include "Layer.h"
#include "PointerVector.h"
#include <ostream>
#include <unordered_map>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @enum PostgresMessageOrigin
	/// Indicates whether the message is from the frontend (client) or backend (server)
	enum class PostgresMessageOrigin
	{
		Frontend,
		Backend
	};

	/// @class PostgresMessageType
	/// Represents PostgreSQL message types (both frontend and backend)
	class PostgresMessageType
	{
	public:
		/// Define enum types for all PostgreSQL message types
		enum Value : uint8_t
		{
			// Frontend (client) message types

			/// Startup message (first message in connection)
			Frontend_StartupMessage,
			/// SSL request code (sent by client to request SSL)
			Frontend_SSLRequest,
			/// Cancel request (sent by client to cancel a running query)
			Frontend_CancelRequest,
			/// GSSAPI encryption request
			Frontend_GSSENCRequest,
			/// Simple query message
			Frontend_Query,
			/// Parse message (prepared statement)
			Frontend_Parse,
			/// Bind message (portal binding)
			Frontend_Bind,
			/// Execute message (portal execution)
			Frontend_Execute,
			/// Close message (close a prepared statement or portal)
			Frontend_Close,
			/// Describe message (describe a prepared statement or portal)
			Frontend_Describe,
			/// Function call message
			Frontend_FunctionCall,
			/// Flush message
			Frontend_Flush,
			/// Sync message (sync after batch)
			Frontend_Sync,
			/// Copy data message (during COPY)
			Frontend_CopyData,
			/// Copy done message (during COPY)
			Frontend_CopyDone,
			/// Copy fail message (during COPY)
			Frontend_CopyFail,
			/// Terminate message (disconnect)
			Frontend_Terminate,
			/// Unknown frontend message type
			Frontend_Unknown,

			// Backend (server) message types

			/// Authentication successful
			Backend_AuthenticationOk,
			/// Authentication using Kerberos V4
			Backend_AuthenticationKerberosV4,
			/// Authentication using Kerberos V5
			Backend_AuthenticationKerberosV5,
			/// Authentication using cleartext password
			Backend_AuthenticationCleartextPassword,
			/// Authentication using MD5 password
			Backend_AuthenticationMD5Password,
			/// Authentication using GSSAPI
			Backend_AuthenticationGSS,
			/// GSSAPI authentication continues
			Backend_AuthenticationGSSContinue,
			/// Authentication using SSPI
			Backend_AuthenticationSSPI,
			/// SASL authentication mechanism list
			Backend_AuthenticationSASL,
			/// SASL authentication continues
			Backend_AuthenticationSASLContinue,
			/// SASL authentication final message
			Backend_AuthenticationSASLFinal,
			/// Backend key data (secret key for cancel)
			Backend_BackendKeyData,
			/// Bind complete
			Backend_BindComplete,
			/// Close complete
			Backend_CloseComplete,
			/// Command complete (after query execution)
			Backend_CommandComplete,
			/// Copy data (during COPY)
			Backend_CopyData,
			/// Copy done (during COPY)
			Backend_CopyDone,
			/// Copy in response (during COPY from client)
			Backend_CopyInResponse,
			/// Copy out response (during COPY to client)
			Backend_CopyOutResponse,
			/// Copy both response (during COPY bidirectional)
			Backend_CopyBothResponse,
			/// Data row (result set)
			Backend_DataRow,
			/// Empty query response
			Backend_EmptyQueryResponse,
			/// Error response
			Backend_ErrorResponse,
			/// Function call response
			Backend_FunctionCallResponse,
			/// Negotiate protocol version
			Backend_NegotiateProtocolVersion,
			/// No data (for queries that don't return rows)
			Backend_NoData,
			/// Notice response (warning)
			Backend_NoticeResponse,
			/// Notification response (LISTEN/NOTIFY)
			Backend_NotificationResponse,
			/// Parameter description (for prepared statements)
			Backend_ParameterDescription,
			/// Parameter status (runtime parameter setting)
			Backend_ParameterStatus,
			/// Parse complete
			Backend_ParseComplete,
			/// Portal suspended (during cursor fetch)
			Backend_PortalSuspended,
			/// Ready for query (idle state)
			Backend_ReadyForQuery,
			/// Row description (column definitions)
			Backend_RowDescription,
			/// Unknown backend message type
			Backend_Unknown,
		};

		constexpr PostgresMessageType() : m_Value(Frontend_Unknown)
		{}

		// cppcheck-suppress noExplicitConstructor
		/// @brief Constructs a PostgresMessageType object from a Value enum
		/// @param[in] value The Value enum value
		constexpr PostgresMessageType(Value value) : m_Value(value)
		{}

		/// @brief Converts the message type to its character representation
		/// @return The message type character
		char toChar() const;

		/// @brief Returns a string representation of the message type
		/// @return A string representation of the message type
		std::string toString() const;

		/// @brief Stream operator for PostgresMessageType
		/// @param[in] os The output stream
		/// @param[in] messageType The message type to print
		/// @return The output stream
		friend std::ostream& operator<<(std::ostream& os, const PostgresMessageType& messageType)
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

		/// @brief Returns the origin of the message (frontend or backend)
		/// @return The message origin
		PostgresMessageOrigin getOrigin() const;

		// Allow switch and comparisons
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(PostgresMessageType)
		explicit operator bool() const = delete;

	private:
		Value m_Value;
	};

	/// @class PostgresMessage
	/// Represents a PostgreSQL message (base class)
	class PostgresMessage
	{
	public:
		virtual ~PostgresMessage() = default;

		/// @brief Parse a PostgreSQL backend message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @return A pointer to the parsed PostgresMessage, or nullptr if parsing fails
		static PostgresMessage* parsePostgresBackendMessage(const uint8_t* data, size_t dataLen);

		/// @brief Parse a PostgreSQL frontend message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @return A pointer to the parsed PostgresMessage, or nullptr if parsing fails
		static PostgresMessage* parsePostgresFrontendMessage(const uint8_t* data, size_t dataLen);

		/// @return The message type
		PostgresMessageType getMessageType() const
		{
			return m_MessageType;
		}

		/// @return The message origin (frontend or backend)
		PostgresMessageOrigin getMessageOrigin() const
		{
			return m_MessageType.getOrigin();
		}

		/// @brief Returns the length of the message payload
		/// @return The message length. If the first byte the message starts is 0, with length (no message type)
		uint32_t getMessageLength() const;

		/// @brief Returns the total length of the message including the length field
		/// @return The total message length in bytes
		size_t getTotalMessageLength() const
		{
			return m_DataLen;
		}

		/// @brief Returns the raw payload bytes of the message
		/// @return The raw payload bytes of the message
		std::vector<uint8_t> getRawPayload() const;

	protected:
		PostgresMessage(const uint8_t* data, size_t dataLen, const PostgresMessageType& messageType)
		    : m_Data(data), m_DataLen(dataLen), m_MessageType(messageType)
		{}

		const uint8_t* m_Data;
		size_t m_DataLen;
		PostgresMessageType m_MessageType;
	};

	/// @class PostgresStartupMessage
	/// Represents a PostgreSQL StartupMessage
	class PostgresStartupMessage : public PostgresMessage
	{
	public:
		/// A map of parameter name to value
		using ParameterMap = std::unordered_map<std::string, std::string>;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresStartupMessage(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Frontend_StartupMessage)
		{}

		/// @return The protocol version (major version in high 16 bits, minor version in low 16 bits)
		uint32_t getProtocolVersion() const;

		/// @return The major protocol version number
		uint16_t getProtocolMajorVersion() const;

		/// @return The minor protocol version number
		uint16_t getProtocolMinorVersion() const;

		/// @return The parameter name/value pairs as a map
		const ParameterMap& getParameters() const;

		/// @return The value of a specific parameter, or empty string if not found
		std::string getParameter(const std::string& name) const;

	private:
		static constexpr size_t ProtocolVersionOffset = 4;
		static constexpr size_t MinStartupMessageLength = 8;

		mutable ParameterMap m_Parameters;
		mutable bool m_ParametersParsed = false;

		std::string readString(size_t offset) const;
	};

	/// @class PostgresParameterStatus
	/// Represents a PostgreSQL ParameterStatus message
	class PostgresParameterStatus : public PostgresMessage
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresParameterStatus(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Backend_ParameterStatus)
		{}

		/// @return The parameter name
		std::string getParameterName() const;

		/// @return The parameter value
		std::string getParameterValue() const;
	};

	/// @class PostgresQueryMessage
	/// Represents a PostgreSQL Query message (Frontend)
	class PostgresQueryMessage : public PostgresMessage
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresQueryMessage(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Frontend_Query)
		{}

		/// @return The SQL query string
		std::string getQuery() const;
	};

	/// @class PostgresRowDescriptionMessage
	/// Represents a PostgreSQL RowDescription message (backend)
	class PostgresRowDescriptionMessage : public PostgresMessage
	{
	public:
		/// @enum PostgresColumnFormat
		/// Represents the format of a column in a PostgreSQL RowDescription message.
		/// PostgreSQL supports two formats: text (0) and binary (1).
		enum class PostgresColumnFormat
		{
			/// Text format (format code 0)
			Text = 0,
			/// Binary format (format code 1)
			Binary = 1,
			/// Unknown format (format code >= 2)
			Unknown = 2
		};

		/// @struct PostgresColumnInfo
		/// Represents metadata for a single column in a RowDescription message
		struct PostgresColumnInfo
		{
			/// Column name
			std::string name;
			/// Table OID (0 if not from a table column)
			uint32_t tableOID;
			/// Column index within the table
			uint16_t columnIndex;
			/// Data type OID
			uint32_t typeOID;
			/// Type size (-1 for variable length)
			int16_t typeSize;
			/// Type modifier (-1 if none)
			int32_t typeModifier;
			/// Format
			PostgresColumnFormat format;
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresRowDescriptionMessage(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Backend_RowDescription)
		{}

		/// @return Vector of column metadata
		std::vector<PostgresColumnInfo> getColumnInfos() const;
	};

	/// @class PostgresDataRowMessage
	/// Represents a PostgreSQL DataRow message (backend)
	class PostgresDataRowMessage : public PostgresMessage
	{
	public:
		/// @class ColumnData
		/// Represents raw column data in a PostgreSQL DataRow message
		class ColumnData
		{
		public:
			/// A constructor that creates ColumnData from raw bytes
			/// @param[in] data A pointer to the raw column data
			/// @param[in] dataLen Size of the data in bytes
			ColumnData(const uint8_t* data, size_t dataLen) : m_Data(data), m_DataLen(dataLen)
			{}

			/// @return The raw column data as a vector of bytes
			std::vector<uint8_t> getData() const
			{
				return { m_Data, m_Data + m_DataLen };
			}

			/// @return The column data as a hex string
			std::string toHexString() const;

			/// @return The column data as a UTF-8 string (empty if conversion fails)
			std::string toString() const;

			/// @return True if the column value is NULL
			bool isNull() const
			{
				return m_Data == nullptr;
			}

		private:
			const uint8_t* m_Data;
			size_t m_DataLen;
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresDataRowMessage(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Backend_DataRow)
		{}

		/// @return Vector of column data values
		std::vector<ColumnData> getDataRow() const;
	};

	/// @class PostgresErrorResponseMessage
	/// Represents a PostgreSQL ErrorResponse or NoticeResponse message (backend)
	class PostgresErrorResponseMessage : public PostgresMessage
	{
	public:
		/// @enum ErrorField
		/// Represents the field types in a PostgreSQL ErrorResponse or NoticeResponse message
		enum class ErrorField : uint8_t
		{
			/// Severity: the field contents are ERROR, FATAL, or PANIC (localized)
			Severity = 'S',
			/// Severity: the field contents are ERROR, FATAL, PANIC or DEBUG, LOG, INFO, NOTICE, WARNING, or DEBUG
			/// (non-localized)
			SeverityNonLocalized = 'V',
			/// SQLSTATE code
			SQLState = 'C',
			/// Primary human-readable error message
			Message = 'M',
			/// Optional secondary error message
			Detail = 'D',
			/// Optional hint
			Hint = 'H',
			/// Decimal integer indicating an error cursor position
			Position = 'P',
			/// Internal cursor position (where error occurred)
			InternalPosition = 'p',
			/// Text of internal query
			InternalQuery = 'q',
			/// Indicating context of error
			Where = 'W',
			/// Schema name
			Schema = 's',
			/// Table name
			Table = 't',
			/// Column name
			Column = 'c',
			/// Data type name
			DataType = 'd',
			/// Constraint name
			Constraint = 'n',
			/// File name of error
			File = 'F',
			/// Line number of error
			Line = 'L',
			/// Routine name
			Routine = 'R',
			/// Terminator (always '\0')
			Terminator = '\0'
		};

		/// A map of error field type to value
		using FieldMap = std::unordered_map<ErrorField, std::string>;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		PostgresErrorResponseMessage(const uint8_t* data, size_t dataLen)
		    : PostgresMessage(data, dataLen, PostgresMessageType::Backend_ErrorResponse)
		{}

		/// @return The error fields as a map
		const FieldMap& getFields() const;

	private:
		mutable FieldMap m_Fields;
		mutable bool m_FieldsParsed = false;
	};

	/// @class PostgresLayer
	/// Represents a PostgreSQL protocol layer
	class PostgresLayer : public Layer
	{
	public:
		/// A d'tor for this layer
		~PostgresLayer() override = default;

		/// A static method that checks whether the port is considered as PostgreSQL
		/// @param[in] port The port number to be checked
		static bool isPostgresPort(uint16_t port)
		{
			return port == 5432;
		}

		/// Parse a PostgreSQL backend message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return A pointer to the parsed PostgresLayer, or nullptr if parsing fails
		static PostgresLayer* parsePostgresBackendMessages(uint8_t* data, size_t dataLen, Layer* prevLayer,
		                                                   Packet* packet);

		/// Parse a PostgreSQL frontend message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return A pointer to the parsed PostgresLayer, or nullptr if parsing fails
		static PostgresLayer* parsePostgresFrontendMessages(uint8_t* data, size_t dataLen, Layer* prevLayer,
		                                                    Packet* packet);

		/// @return The message origin (frontend or backend)
		PostgresMessageOrigin getPostgresOrigin() const
		{
			return m_MessageOrigin;
		}

		/// @return A vector of all PostgreSQL messages in this layer
		const PointerVector<PostgresMessage>& getPostgresMessages() const;

		/// @brief Get a PostgreSQL message by its type
		/// @param[in] messageType The type of message to retrieve
		/// @return A pointer to the message, or nullptr if not found
		const PostgresMessage* getPostgresMessage(const PostgresMessageType& messageType) const;

		/// @brief Get a PostgreSQL message by its type (template version)
		/// @tparam TMessage The message type to retrieve (must derive from PostgresMessage)
		/// @return A pointer to the message of the specified type, or nullptr if not found
		template <class TMessage,
		          typename std::enable_if<std::is_base_of<PostgresMessage, TMessage>::value>::type* = nullptr>
		const TMessage* getPostgresMessage() const
		{
			const auto& messages = getPostgresMessages();
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

		/// @return The size of the Postgres layer header
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer, Postgres is always last
		void parseNextLayer() override
		{}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return The OSI layer level of Postgres (Application Layer).
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

		/// @return Returns the protocol info as readable string
		std::string toString() const override;

	private:
		PostgresMessageOrigin m_MessageOrigin;
		mutable PointerVector<PostgresMessage> m_Messages;
		mutable bool m_MessagesInitialized = false;

		PostgresLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet,
		              PostgresMessageOrigin messageOrigin)
		    : Layer(data, dataLen, prevLayer, packet, Postgres), m_MessageOrigin(messageOrigin)
		{}
	};
}  // namespace pcpp
