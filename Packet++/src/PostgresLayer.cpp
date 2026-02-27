#include "PostgresLayer.h"
#include "EndianPortable.h"
#include "GeneralUtils.h"
#include <algorithm>
#include <cstring>
#include <unordered_set>

#pragma pack(push, 1)
namespace internal
{
	struct PostgresColumnFixedData
	{
		uint32_t tableOID;
		uint16_t columnIndex;
		uint32_t typeOID;
		int16_t typeSize;
		int32_t typeModifier;
		uint16_t formatCode;
	};
}  // namespace internal
#pragma pack(pop)

static_assert(sizeof(::internal::PostgresColumnFixedData) == 18, "PostgresColumnFixedData must be 18 bytes");

namespace pcpp
{
	constexpr char PostgresMessage_0 = '\0';
	constexpr char PostgresBackendMessage_R = 'R';
	constexpr char PostgresBackendMessage_K = 'K';
	constexpr char PostgresBackendMessage_2 = '2';
	constexpr char PostgresBackendMessage_3 = '3';
	constexpr char PostgresBackendMessage_S = 'S';
	constexpr char PostgresBackendMessage_Z = 'Z';
	constexpr char PostgresBackendMessage_C = 'C';
	constexpr char PostgresBackendMessage_d = 'd';
	constexpr char PostgresBackendMessage_c = 'c';
	constexpr char PostgresBackendMessage_G = 'G';
	constexpr char PostgresBackendMessage_H = 'H';
	constexpr char PostgresBackendMessage_W = 'W';
	constexpr char PostgresBackendMessage_D = 'D';
	constexpr char PostgresBackendMessage_I = 'I';
	constexpr char PostgresBackendMessage_E = 'E';
	constexpr char PostgresBackendMessage_V = 'V';
	constexpr char PostgresBackendMessage_v = 'v';
	constexpr char PostgresBackendMessage_n = 'n';
	constexpr char PostgresBackendMessage_N = 'N';
	constexpr char PostgresBackendMessage_A = 'A';
	constexpr char PostgresBackendMessage_t = 't';
	constexpr char PostgresBackendMessage_1 = '1';
	constexpr char PostgresBackendMessage_s = 's';
	constexpr char PostgresBackendMessage_T = 'T';
	constexpr char PostgresFrontendMessage_Q = 'Q';
	constexpr char PostgresFrontendMessage_P = 'P';
	constexpr char PostgresFrontendMessage_B = 'B';
	constexpr char PostgresFrontendMessage_E = 'E';
	constexpr char PostgresFrontendMessage_C = 'C';
	constexpr char PostgresFrontendMessage_D = 'D';
	constexpr char PostgresFrontendMessage_F = 'F';
	constexpr char PostgresFrontendMessage_H = 'H';
	constexpr char PostgresFrontendMessage_S = 'S';
	constexpr char PostgresFrontendMessage_d = 'd';
	constexpr char PostgresFrontendMessage_c = 'c';
	constexpr char PostgresFrontendMessage_f = 'f';
	constexpr char PostgresFrontendMessage_X = 'X';

	const std::unordered_set<uint8_t> validErrorFieldTypes = { 'S', 'V', 'C', 'M', 'D', 'H', 'P', 'p', 'q',
		                                                       'W', 's', 't', 'c', 'd', 'n', 'F', 'L', 'R' };

	constexpr uint32_t PostgresFrontendTag_SSLRequest = 80877103;
	constexpr uint32_t PostgresFrontendTag_GSSENCRequest = 80877104;
	constexpr uint32_t PostgresFrontendTag_CancelRequest = 80877102;
	constexpr uint32_t PostgresFrontendTag_StartupMessage = 196608;

	char PostgresMessageType::toChar() const
	{
		switch (m_Value)
		{
		// Frontend message types
		case Frontend_Query:
			return PostgresFrontendMessage_Q;
		case Frontend_Parse:
			return PostgresFrontendMessage_P;
		case Frontend_Bind:
			return PostgresFrontendMessage_B;
		case Frontend_Execute:
			return PostgresFrontendMessage_E;
		case Frontend_Close:
			return PostgresFrontendMessage_C;
		case Frontend_Describe:
			return PostgresFrontendMessage_D;
		case Frontend_FunctionCall:
			return PostgresFrontendMessage_F;
		case Frontend_Flush:
			return PostgresFrontendMessage_H;
		case Frontend_Sync:
			return PostgresFrontendMessage_S;
		case Frontend_CopyData:
			return PostgresFrontendMessage_d;
		case Frontend_CopyDone:
			return PostgresFrontendMessage_c;
		case Frontend_CopyFail:
			return PostgresFrontendMessage_f;
		case Frontend_Terminate:
			return PostgresFrontendMessage_X;
		// Backend message types
		case Backend_AuthenticationOk:
		case Backend_AuthenticationMD5Password:
		case Backend_AuthenticationSASL:
		case Backend_AuthenticationSASLContinue:
		case Backend_AuthenticationSASLFinal:
			return PostgresBackendMessage_R;
		case Backend_BackendKeyData:
			return PostgresBackendMessage_K;
		case Backend_BindComplete:
			return PostgresBackendMessage_2;
		case Backend_CloseComplete:
			return PostgresBackendMessage_3;
		case Backend_CommandComplete:
			return PostgresBackendMessage_C;
		case Backend_CopyData:
			return PostgresBackendMessage_d;
		case Backend_CopyDone:
			return PostgresBackendMessage_c;
		case Backend_CopyInResponse:
			return PostgresBackendMessage_G;
		case Backend_CopyOutResponse:
			return PostgresBackendMessage_H;
		case Backend_CopyBothResponse:
			return PostgresBackendMessage_W;
		case Backend_DataRow:
			return PostgresBackendMessage_D;
		case Backend_EmptyQueryResponse:
			return PostgresBackendMessage_I;
		case Backend_ErrorResponse:
			return PostgresBackendMessage_E;
		case Backend_FunctionCallResponse:
			return PostgresBackendMessage_V;
		case Backend_NegotiateProtocolVersion:
			return PostgresBackendMessage_v;
		case Backend_NoData:
			return PostgresBackendMessage_n;
		case Backend_NoticeResponse:
			return PostgresBackendMessage_N;
		case Backend_NotificationResponse:
			return PostgresBackendMessage_A;
		case Backend_ParameterDescription:
			return PostgresBackendMessage_t;
		case Backend_ParameterStatus:
			return PostgresBackendMessage_S;
		case Backend_ParseComplete:
			return PostgresBackendMessage_1;
		case Backend_PortalSuspended:
			return PostgresBackendMessage_s;
		case Backend_ReadyForQuery:
			return PostgresBackendMessage_Z;
		case Backend_RowDescription:
			return PostgresBackendMessage_T;
		default:
			return '\0';
		}
	}

	std::string PostgresMessageType::toString() const
	{
		switch (m_Value)
		{
		// Frontend message types
		case Frontend_StartupMessage:
			return "Frontend_StartupMessage";
		case Frontend_SSLRequest:
			return "Frontend_SSLRequest";
		case Frontend_CancelRequest:
			return "Frontend_CancelRequest";
		case Frontend_GSSENCRequest:
			return "Frontend_GSSENCRequest";
		case Frontend_Query:
			return "Frontend_Query";
		case Frontend_Parse:
			return "Frontend_Parse";
		case Frontend_Bind:
			return "Frontend_Bind";
		case Frontend_Execute:
			return "Frontend_Execute";
		case Frontend_Close:
			return "Frontend_Close";
		case Frontend_Describe:
			return "Frontend_Describe";
		case Frontend_FunctionCall:
			return "Frontend_FunctionCall";
		case Frontend_Flush:
			return "Frontend_Flush";
		case Frontend_Sync:
			return "Frontend_Sync";
		case Frontend_CopyData:
			return "Frontend_CopyData";
		case Frontend_CopyDone:
			return "Frontend_CopyDone";
		case Frontend_CopyFail:
			return "Frontend_CopyFail";
		case Frontend_Terminate:
			return "Frontend_Terminate";
		case Frontend_Unknown:
			return "Frontend_Unknown";
		// Backend message types
		case Backend_AuthenticationOk:
			return "Backend_AuthenticationOk";
		case Backend_AuthenticationKerberosV4:
			return "Backend_AuthenticationKerberosV4";
		case Backend_AuthenticationKerberosV5:
			return "Backend_AuthenticationKerberosV5";
		case Backend_AuthenticationCleartextPassword:
			return "Backend_AuthenticationCleartextPassword";
		case Backend_AuthenticationMD5Password:
			return "Backend_AuthenticationMD5Password";
		case Backend_AuthenticationGSS:
			return "Backend_AuthenticationGSS";
		case Backend_AuthenticationGSSContinue:
			return "Backend_AuthenticationGSSContinue";
		case Backend_AuthenticationSSPI:
			return "Backend_AuthenticationSSPI";
		case Backend_AuthenticationSASL:
			return "Backend_AuthenticationSASL";
		case Backend_AuthenticationSASLContinue:
			return "Backend_AuthenticationSASLContinue";
		case Backend_AuthenticationSASLFinal:
			return "Backend_AuthenticationSASLFinal";
		case Backend_BackendKeyData:
			return "Backend_BackendKeyData";
		case Backend_BindComplete:
			return "Backend_BindComplete";
		case Backend_CloseComplete:
			return "Backend_CloseComplete";
		case Backend_CommandComplete:
			return "Backend_CommandComplete";
		case Backend_CopyData:
			return "Backend_CopyData";
		case Backend_CopyDone:
			return "Backend_CopyDone";
		case Backend_CopyInResponse:
			return "Backend_CopyInResponse";
		case Backend_CopyOutResponse:
			return "Backend_CopyOutResponse";
		case Backend_CopyBothResponse:
			return "Backend_CopyBothResponse";
		case Backend_DataRow:
			return "Backend_DataRow";
		case Backend_EmptyQueryResponse:
			return "Backend_EmptyQueryResponse";
		case Backend_ErrorResponse:
			return "Backend_ErrorResponse";
		case Backend_FunctionCallResponse:
			return "Backend_FunctionCallResponse";
		case Backend_NegotiateProtocolVersion:
			return "Backend_NegotiateProtocolVersion";
		case Backend_NoData:
			return "Backend_NoData";
		case Backend_NoticeResponse:
			return "Backend_NoticeResponse";
		case Backend_NotificationResponse:
			return "Backend_NotificationResponse";
		case Backend_ParameterDescription:
			return "Backend_ParameterDescription";
		case Backend_ParameterStatus:
			return "Backend_ParameterStatus";
		case Backend_ParseComplete:
			return "Backend_ParseComplete";
		case Backend_PortalSuspended:
			return "Backend_PortalSuspended";
		case Backend_ReadyForQuery:
			return "Backend_ReadyForQuery";
		case Backend_RowDescription:
			return "Backend_RowDescription";
		case Backend_Unknown:
			return "Backend_Unknown";
		default:
			return "Unknown";
		}
	}

	PostgresMessageOrigin PostgresMessageType::getOrigin() const
	{
		switch (m_Value)
		{
		case Frontend_StartupMessage:
		case Frontend_SSLRequest:
		case Frontend_CancelRequest:
		case Frontend_GSSENCRequest:
		case Frontend_Query:
		case Frontend_Parse:
		case Frontend_Bind:
		case Frontend_Execute:
		case Frontend_Close:
		case Frontend_Describe:
		case Frontend_FunctionCall:
		case Frontend_Flush:
		case Frontend_Sync:
		case Frontend_CopyData:
		case Frontend_CopyDone:
		case Frontend_CopyFail:
		case Frontend_Terminate:
		case Frontend_Unknown:
			return PostgresMessageOrigin::Frontend;
		default:
			return PostgresMessageOrigin::Backend;
		}
	}

	PostgresMessage* PostgresMessage::parsePostgresBackendMessage(const uint8_t* data, size_t dataLen)
	{
		if (data == nullptr || dataLen < 1)
		{
			return nullptr;
		}

		if (dataLen < 5)
		{
			return new PostgresMessage(data, dataLen, PostgresMessageType::Backend_Unknown);
		}

		auto messageLength = be32toh(*reinterpret_cast<const uint32_t*>(data + 1));
		if (dataLen < messageLength + 1)
		{
			return new PostgresMessage(data, dataLen, PostgresMessageType::Backend_Unknown);
		}

		auto messageTypeValue = data[0];
		auto messageType = PostgresMessageType::Backend_Unknown;

		switch (messageTypeValue)
		{
		case PostgresBackendMessage_R:
		{
			uint32_t authType = be32toh(*reinterpret_cast<const uint32_t*>(data + 5));
			switch (authType)
			{
			case 0:
			{
				messageType = PostgresMessageType::Backend_AuthenticationOk;
				break;
			}
			case 1:
			{
				messageType = PostgresMessageType::Backend_AuthenticationKerberosV4;
				break;
			}
			case 2:
			{
				messageType = PostgresMessageType::Backend_AuthenticationKerberosV5;
				break;
			}
			case 3:
			{
				messageType = PostgresMessageType::Backend_AuthenticationCleartextPassword;
				break;
			}
			case 5:
			{
				messageType = PostgresMessageType::Backend_AuthenticationMD5Password;
				break;
			}
			case 7:
			{
				messageType = PostgresMessageType::Backend_AuthenticationGSS;
				break;
			}
			case 8:
			{
				messageType = PostgresMessageType::Backend_AuthenticationGSSContinue;
				break;
			}
			case 9:
			{
				messageType = PostgresMessageType::Backend_AuthenticationSSPI;
				break;
			}
			case 10:
			{
				messageType = PostgresMessageType::Backend_AuthenticationSASL;
				break;
			}
			case 11:
			{
				messageType = PostgresMessageType::Backend_AuthenticationSASLContinue;
				break;
			}
			case 12:
			{
				messageType = PostgresMessageType::Backend_AuthenticationSASLFinal;
				break;
			}
			default:
			{
				break;
			}
			}
			break;
		}
		case PostgresBackendMessage_K:
		{
			messageType = PostgresMessageType::Backend_BackendKeyData;
			break;
		}
		case PostgresBackendMessage_2:
		{
			messageType = PostgresMessageType::Backend_BindComplete;
			break;
		}
		case PostgresBackendMessage_3:
		{
			messageType = PostgresMessageType::Backend_CloseComplete;
			break;
		}
		case PostgresBackendMessage_S:
		{
			return new PostgresParameterStatus(data, messageLength + 1);
		}
		case PostgresBackendMessage_Z:
		{
			messageType = PostgresMessageType::Backend_ReadyForQuery;
			break;
		}
		case PostgresBackendMessage_C:
		{
			messageType = PostgresMessageType::Backend_CommandComplete;
			break;
		}
		case PostgresBackendMessage_d:
		{
			messageType = PostgresMessageType::Backend_CopyData;
			break;
		}
		case PostgresBackendMessage_c:
		{
			messageType = PostgresMessageType::Backend_CopyDone;
			break;
		}
		case PostgresBackendMessage_G:
		{
			messageType = PostgresMessageType::Backend_CopyInResponse;
			break;
		}
		case PostgresBackendMessage_H:
		{
			messageType = PostgresMessageType::Backend_CopyOutResponse;
			break;
		}
		case PostgresBackendMessage_W:
		{
			messageType = PostgresMessageType::Backend_CopyBothResponse;
			break;
		}
		case PostgresBackendMessage_D:
		{
			return new PostgresDataRowMessage(data, messageLength + 1);
		}
		case PostgresBackendMessage_I:
		{
			messageType = PostgresMessageType::Backend_EmptyQueryResponse;
			break;
		}
		case PostgresBackendMessage_E:
		{
			return new PostgresErrorResponseMessage(data, messageLength + 1);
		}
		case PostgresBackendMessage_V:
		{
			messageType = PostgresMessageType::Backend_FunctionCallResponse;
			break;
		}
		case PostgresBackendMessage_v:
		{
			messageType = PostgresMessageType::Backend_NegotiateProtocolVersion;
			break;
		}
		case PostgresBackendMessage_n:
		{
			messageType = PostgresMessageType::Backend_NoData;
			break;
		}
		case PostgresBackendMessage_N:
		{
			messageType = PostgresMessageType::Backend_NoticeResponse;
			break;
		}
		case PostgresBackendMessage_A:
		{
			messageType = PostgresMessageType::Backend_NotificationResponse;
			break;
		}
		case PostgresBackendMessage_t:
		{
			messageType = PostgresMessageType::Backend_ParameterDescription;
			break;
		}
		case PostgresBackendMessage_1:
		{
			messageType = PostgresMessageType::Backend_ParseComplete;
			break;
		}
		case PostgresBackendMessage_s:
		{
			messageType = PostgresMessageType::Backend_PortalSuspended;
			break;
		}
		case PostgresBackendMessage_T:
		{
			return new PostgresRowDescriptionMessage(data, messageLength + 1);
		}
		default:
		{
			break;
		}
		}

		return new PostgresMessage(data, messageLength + 1, messageType);
	}

	PostgresMessage* PostgresMessage::parsePostgresFrontendMessage(const uint8_t* data, size_t dataLen)
	{
		if (data == nullptr || dataLen < 1)
		{
			return nullptr;
		}

		uint8_t messageTypeValue = data[0];
		if (messageTypeValue == PostgresMessage_0)
		{
			if (dataLen < 8)
			{
				return new PostgresMessage(data, dataLen, PostgresMessageType::Frontend_Unknown);
			}

			auto messageLength = be32toh(*reinterpret_cast<const uint32_t*>(data));
			if (messageLength > dataLen)
			{
				return new PostgresMessage(data, dataLen, PostgresMessageType::Frontend_Unknown);
			}

			auto messageTag = be32toh(*reinterpret_cast<const uint32_t*>(data + 4));
			auto messageType = PostgresMessageType::Frontend_Unknown;

			switch (messageTag)
			{
			case PostgresFrontendTag_StartupMessage:
			{
				return new PostgresStartupMessage(data, messageLength);
			}
			case PostgresFrontendTag_SSLRequest:
			{
				messageType = PostgresMessageType::Frontend_SSLRequest;
				break;
			}
			case PostgresFrontendTag_CancelRequest:
			{
				messageType = PostgresMessageType::Frontend_CancelRequest;
				break;
			}
			case PostgresFrontendTag_GSSENCRequest:
			{
				messageType = PostgresMessageType::Frontend_GSSENCRequest;
				break;
			}
			default:
			{
				break;
			}
			}

			return new PostgresMessage(data, messageLength, messageType);
		}

		if (dataLen < 5)
		{
			return new PostgresMessage(data, dataLen, PostgresMessageType::Frontend_Unknown);
		}

		auto messageLength = be32toh(*reinterpret_cast<const uint32_t*>(data + 1));
		if (dataLen < messageLength + 1)
		{
			return new PostgresMessage(data, dataLen, PostgresMessageType::Frontend_Unknown);
		}

		auto messageType = PostgresMessageType::Frontend_Unknown;
		switch (messageTypeValue)
		{
		case PostgresFrontendMessage_Q:
		{
			return new PostgresQueryMessage(data, std::min(static_cast<size_t>(messageLength) + 1, dataLen));
		}
		case PostgresFrontendMessage_P:
		{
			messageType = PostgresMessageType::Frontend_Parse;
			break;
		}
		case PostgresFrontendMessage_B:
		{
			messageType = PostgresMessageType::Frontend_Bind;
			break;
		}
		case PostgresFrontendMessage_E:
		{
			messageType = PostgresMessageType::Frontend_Execute;
			break;
		}
		case PostgresFrontendMessage_C:
		{
			messageType = PostgresMessageType::Frontend_Close;
			break;
		}
		case PostgresFrontendMessage_D:
		{
			messageType = PostgresMessageType::Frontend_Describe;
			break;
		}
		case PostgresFrontendMessage_F:
		{
			messageType = PostgresMessageType::Frontend_FunctionCall;
			break;
		}
		case PostgresFrontendMessage_H:
		{
			messageType = PostgresMessageType::Frontend_Flush;
			break;
		}
		case PostgresFrontendMessage_S:
		{
			messageType = PostgresMessageType::Frontend_Sync;
			break;
		}
		case PostgresFrontendMessage_d:
		{
			messageType = PostgresMessageType::Frontend_CopyData;
			break;
		}
		case PostgresFrontendMessage_c:
		{
			messageType = PostgresMessageType::Frontend_CopyDone;
			break;
		}
		case PostgresFrontendMessage_f:
		{
			messageType = PostgresMessageType::Frontend_CopyFail;
			break;
		}
		case PostgresFrontendMessage_X:
		{
			messageType = PostgresMessageType::Frontend_Terminate;
			break;
		}
		default:
		{
			break;
		}
		}

		return new PostgresMessage(data, messageLength + 1, messageType);
	}

	uint32_t PostgresMessage::getMessageLength() const
	{
		if (m_Data == nullptr || m_DataLen < 4)
		{
			return 0;
		}

		const auto offset = (m_Data[0] == 0) ? 0 : 1;
		return be32toh(*reinterpret_cast<const uint32_t*>(m_Data + offset));
	}

	std::vector<uint8_t> PostgresMessage::getRawPayload() const
	{
		const size_t offset = (m_Data[0] == 0) ? 0 : 1;
		if (m_DataLen < offset + 4)
		{
			return {};
		}
		return { m_Data + offset + 4, m_Data + m_DataLen };
	}

	std::string PostgresParameterStatus::getParameterName() const
	{
		if (m_DataLen < 6)
		{
			return {};
		}

		const auto* start = reinterpret_cast<const char*>(m_Data + 5);
		const auto maxLen = m_DataLen - 5;
		const auto* end = static_cast<const char*>(memchr(start, '\0', maxLen));

		return std::string(start, end != nullptr ? end : start + maxLen);
	}

	std::string PostgresParameterStatus::getParameterValue() const
	{
		constexpr size_t headerLen = 5;

		if (m_DataLen < headerLen + 1)
		{
			return "";
		}

		const char* base = reinterpret_cast<const char*>(m_Data) + headerLen;
		const size_t remaining = m_DataLen - headerLen;

		const char* nameEnd = static_cast<const char*>(memchr(base, '\0', remaining));
		if (nameEnd == nullptr)
		{
			return "";
		}

		const size_t nameLen = static_cast<size_t>(nameEnd - base);
		const char* valueStart = nameEnd + 1;
		const size_t valueMaxLen = remaining - nameLen - 1;

		const char* valueEnd = static_cast<const char*>(memchr(valueStart, '\0', valueMaxLen));
		return std::string(valueStart, valueEnd != nullptr ? valueEnd : valueStart + valueMaxLen);
	}

	std::string PostgresQueryMessage::getQuery() const
	{
		constexpr size_t headerLen = 5;

		if (m_DataLen < headerLen + 1)
		{
			return "";
		}

		const char* queryStart = reinterpret_cast<const char*>(m_Data) + headerLen;
		const size_t maxQueryLen = m_DataLen - headerLen;

		const char* nullPos = static_cast<const char*>(memchr(queryStart, '\0', maxQueryLen));
		return std::string(queryStart, nullPos != nullptr ? nullPos : queryStart + maxQueryLen);
	}

	std::vector<PostgresRowDescriptionMessage::PostgresColumnInfo> PostgresRowDescriptionMessage::getColumnInfos() const
	{
		std::vector<PostgresColumnInfo> columns;

		constexpr size_t headerLen = 7;
		if (m_DataLen < headerLen)
			return columns;

		uint16_t numFields = be16toh(*reinterpret_cast<const uint16_t*>(m_Data + 5));
		if (numFields > 10000)
			return columns;

		size_t offset = headerLen;

		for (uint16_t i = 0; i < numFields; ++i)
		{
			if (offset >= m_DataLen)
				break;

			PostgresColumnInfo column;

			const char* nameStart = reinterpret_cast<const char*>(m_Data) + offset;
			size_t remaining = m_DataLen - offset;
			const char* nullPos = static_cast<const char*>(memchr(nameStart, '\0', remaining));

			if (nullPos != nullptr)
			{
				column.name.assign(nameStart, nullPos - nameStart);
				offset = static_cast<size_t>(nullPos - reinterpret_cast<const char*>(m_Data)) + 1;
			}
			else
			{
				column.name.assign(nameStart, remaining);
				break;
			}

			if (offset + sizeof(::internal::PostgresColumnFixedData) > m_DataLen)
			{
				columns.push_back(column);
				break;
			}

			const auto* fixedData = reinterpret_cast<const ::internal::PostgresColumnFixedData*>(m_Data + offset);
			column.tableOID = be32toh(fixedData->tableOID);
			column.columnIndex = be16toh(fixedData->columnIndex);
			column.typeOID = be32toh(fixedData->typeOID);
			column.typeSize = be16toh(fixedData->typeSize);
			column.typeModifier = be32toh(fixedData->typeModifier);
			auto formatCode = be16toh(fixedData->formatCode);
			column.format =
			    formatCode < 2 ? static_cast<PostgresColumnFormat>(formatCode) : PostgresColumnFormat::Unknown;

			offset += sizeof(::internal::PostgresColumnFixedData);
			columns.push_back(column);
		}

		return columns;
	}

	std::vector<PostgresDataRowMessage::ColumnData> PostgresDataRowMessage::getDataRow() const
	{
		constexpr size_t headerLen = 7;
		if (m_DataLen < headerLen)
		{
			return {};
		}

		uint16_t numColumns = be16toh(*reinterpret_cast<const uint16_t*>(m_Data + 5));
		if (numColumns > 10000)
		{
			return {};
		}

		std::vector<ColumnData> rowData;

		size_t offset = headerLen;

		for (uint16_t i = 0; i < numColumns; ++i)
		{
			if (offset >= m_DataLen)
			{
				break;
			}

			const auto colLength = be32toh(*reinterpret_cast<const uint32_t*>(m_Data + offset));
			offset += 4;

			if (colLength == 0 || colLength == 0xffffffff)
			{
				rowData.emplace_back(nullptr, 0);
				continue;
			}

			if (offset + colLength > m_DataLen)
			{
				break;
			}

			rowData.emplace_back(m_Data + offset, colLength);
			offset += colLength;
		}

		return rowData;
	}

	std::string PostgresDataRowMessage::ColumnData::toHexString() const
	{
		return byteArrayToHexString(m_Data, m_DataLen);
	}

	std::string PostgresDataRowMessage::ColumnData::toString() const
	{
		if (m_Data == nullptr || m_DataLen == 0)
		{
			return "";
		}

		return { m_Data, m_Data + m_DataLen };
	}

	const PostgresErrorResponseMessage::FieldMap& PostgresErrorResponseMessage::getFields() const
	{
		if (m_FieldsParsed)
		{
			return m_Fields;
		}

		constexpr auto headerLen = static_cast<size_t>(5);
		if (m_DataLen < headerLen)
		{
			m_FieldsParsed = true;
			return m_Fields;
		}

		auto offset = headerLen;
		while (offset < m_DataLen)
		{
			auto fieldTypeValue = m_Data[offset];
			if (fieldTypeValue == 0)
			{
				break;
			}

			const bool isKnownField = validErrorFieldTypes.find(fieldTypeValue) != validErrorFieldTypes.end();

			offset++;
			if (offset >= m_DataLen)
			{
				break;
			}

			auto* valueStart = reinterpret_cast<const char*>(m_Data) + offset;
			auto remaining = m_DataLen - offset;
			auto* nullPos = static_cast<const char*>(memchr(valueStart, '\0', remaining));

			std::string fieldValue;
			if (nullPos != nullptr)
			{
				fieldValue.assign(valueStart, nullPos - valueStart);
				offset = static_cast<size_t>(nullPos - reinterpret_cast<const char*>(m_Data)) + 1;
			}
			else
			{
				fieldValue.assign(valueStart, remaining);
				break;
			}

			if (isKnownField)
			{
				const auto fieldType = static_cast<ErrorField>(fieldTypeValue);
				m_Fields[fieldType] = std::move(fieldValue);
			}
		}

		m_FieldsParsed = true;
		return m_Fields;
	}

	uint32_t PostgresStartupMessage::getProtocolVersion() const
	{
		if (m_DataLen < MinStartupMessageLength)
		{
			return 0;
		}
		return *reinterpret_cast<const uint32_t*>(m_Data + ProtocolVersionOffset);
	}

	uint16_t PostgresStartupMessage::getProtocolMajorVersion() const
	{
		return be16toh(*reinterpret_cast<const uint16_t*>(m_Data + ProtocolVersionOffset));
	}

	uint16_t PostgresStartupMessage::getProtocolMinorVersion() const
	{
		return be16toh(*reinterpret_cast<const uint16_t*>(m_Data + ProtocolVersionOffset + 2));
	}

	std::string PostgresStartupMessage::readString(size_t offset) const
	{
		if (offset >= m_DataLen)
		{
			return "";
		}

		const auto* strStart = m_Data + offset;
		const auto* dataEnd = m_Data + m_DataLen;

		const uint8_t* nullPos = std::find(strStart, dataEnd, uint8_t{ 0 });

		if (nullPos == strStart)
		{
			return "";
		}

		return { strStart, nullPos };
	}

	const PostgresStartupMessage::ParameterMap& PostgresStartupMessage::getParameters() const
	{
		if (m_ParametersParsed)
		{
			return m_Parameters;
		}

		if (m_DataLen < MinStartupMessageLength)
		{
			m_ParametersParsed = true;
			return m_Parameters;
		}

		size_t offset = MinStartupMessageLength;
		while (offset < m_DataLen)
		{
			auto name = readString(offset);
			if (name.empty())
			{
				break;
			}
			offset += name.length() + 1;

			if (offset >= m_DataLen)
			{
				break;
			}
			auto value = readString(offset);
			offset += value.length() + 1;

			m_Parameters.emplace(std::move(name), std::move(value));
		}

		m_ParametersParsed = true;
		return m_Parameters;
	}

	std::string PostgresStartupMessage::getParameter(const std::string& name) const
	{
		auto parameters = getParameters();
		auto it = parameters.find(name);
		if (it != parameters.end())
		{
			return it->second;
		}
		return "";
	}

	PostgresLayer* PostgresLayer::parsePostgresBackendMessages(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                           Packet* packet)
	{
		return new PostgresLayer(data, dataLen, prevLayer, packet, PostgresMessageOrigin::Backend);
	}

	PostgresLayer* PostgresLayer::parsePostgresFrontendMessages(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                            Packet* packet)
	{
		return new PostgresLayer(data, dataLen, prevLayer, packet, PostgresMessageOrigin::Frontend);
	}

	const PointerVector<PostgresMessage>& PostgresLayer::getPostgresMessages() const
	{
		if (!m_MessagesInitialized)
		{
			auto parseFunc = (m_MessageOrigin == PostgresMessageOrigin::Backend)
			                     ? &PostgresMessage::parsePostgresBackendMessage
			                     : &PostgresMessage::parsePostgresFrontendMessage;

			auto data = m_Data;
			auto dataLen = m_DataLen;

			while (dataLen > 0)
			{
				auto curMessage = std::unique_ptr<PostgresMessage>(parseFunc(data, dataLen));
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

	const PostgresMessage* PostgresLayer::getPostgresMessage(const PostgresMessageType& messageType) const
	{
		const auto& messages = getPostgresMessages();
		auto it = std::find_if(messages.begin(), messages.end(), [&messageType](const PostgresMessage* message) {
			return message->getMessageType() == messageType;
		});

		return it != messages.end() ? *it : nullptr;
	}

	std::string PostgresLayer::toString() const
	{
		const auto& messages = getPostgresMessages();
		return std::string("PostgreSQL ") +
		       (m_MessageOrigin == PostgresMessageOrigin::Frontend ? "Frontend" : "Backend") + " Layer, " +
		       std::to_string(messages.size()) + " message(s)";
	}
}  // namespace pcpp
