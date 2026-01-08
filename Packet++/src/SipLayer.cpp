#define LOG_MODULE PacketLogModuleSipLayer

#include "SipLayer.h"
#include "SdpLayer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <array>
#include <string>
#include <algorithm>
#include <exception>
#include <utility>
#include <unordered_map>

namespace pcpp
{
	namespace
	{
		constexpr uint32_t pack4(const char* data, size_t len)
		{
			return ((len > 0 ? static_cast<uint32_t>(data[0]) << 24 : 0) |
			        (len > 1 ? static_cast<uint32_t>(data[1]) << 16 : 0) |
			        (len > 2 ? static_cast<uint32_t>(data[2]) << 8 : 0) |
			        (len > 3 ? static_cast<uint32_t>(data[3]) : 0));
		}

		constexpr uint32_t operator""_packed4(const char* str, size_t len)
		{
			return pack4(str, len);
		}

		const std::array<std::string, 14> SipMethodEnumToString = {  //
			"INVITE",    "ACK",    "BYE",     "CANCEL", "REGISTER", "PRACK",   "OPTIONS",
			"SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO",   "REFER",    "MESSAGE", "UPDATE"
		};

		const std::unordered_map<std::string, SipRequestLayer::SipMethod> SipMethodStringToEnum{
			{ "INVITE",    SipRequestLayer::SipMethod::SipINVITE    },
			{ "ACK",       SipRequestLayer::SipMethod::SipACK       },
			{ "BYE",       SipRequestLayer::SipMethod::SipBYE       },
			{ "CANCEL",    SipRequestLayer::SipMethod::SipCANCEL    },
			{ "REGISTER",  SipRequestLayer::SipMethod::SipREGISTER  },
			{ "PRACK",     SipRequestLayer::SipMethod::SipPRACK     },
			{ "OPTIONS",   SipRequestLayer::SipMethod::SipOPTIONS   },
			{ "SUBSCRIBE", SipRequestLayer::SipMethod::SipSUBSCRIBE },
			{ "NOTIFY",    SipRequestLayer::SipMethod::SipNOTIFY    },
			{ "PUBLISH",   SipRequestLayer::SipMethod::SipPUBLISH   },
			{ "INFO",      SipRequestLayer::SipMethod::SipINFO      },
			{ "REFER",     SipRequestLayer::SipMethod::SipREFER     },
			{ "MESSAGE",   SipRequestLayer::SipMethod::SipMESSAGE   },
			{ "UPDATE",    SipRequestLayer::SipMethod::SipUPDATE    },
		};
	}  // namespace

	// -------- Class SipLayer -----------------

	int SipLayer::getContentLength() const
	{
		std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		std::transform(contentLengthFieldName.begin(), contentLengthFieldName.end(), contentLengthFieldName.begin(),
		               ::tolower);
		HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
		if (contentLengthField != nullptr)
			return atoi(contentLengthField->getFieldValue().c_str());
		return 0;
	}

	HeaderField* SipLayer::setContentLength(int contentLength, const std::string& prevFieldName)
	{
		std::ostringstream contentLengthAsString;
		contentLengthAsString << contentLength;
		std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
		if (contentLengthField == nullptr)
		{
			HeaderField* prevField = getFieldByName(prevFieldName);
			contentLengthField = insertField(prevField, PCPP_SIP_CONTENT_LENGTH_FIELD, contentLengthAsString.str());
		}
		else
			contentLengthField->setFieldValue(contentLengthAsString.str());

		return contentLengthField;
	}

	void SipLayer::parseNextLayer()
	{
		if (getLayerPayloadSize() == 0)
			return;

		size_t headerLen = getHeaderLen();
		std::string contentType;
		if (getContentLength() > 0)
		{
			HeaderField* contentTypeField = getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD);
			if (contentTypeField != nullptr)
				contentType = contentTypeField->getFieldValue();
		}

		if (contentType.find("application/sdp") != std::string::npos)
		{
			m_NextLayer = new SdpLayer(m_Data + headerLen, m_DataLen - headerLen, this, getAttachedPacket());
		}
		else
		{
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, getAttachedPacket());
		}
	}

	void SipLayer::computeCalculateFields()
	{
		HeaderField* contentLengthField = getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		if (contentLengthField == nullptr)
			return;

		size_t headerLen = getHeaderLen();
		if (m_DataLen > headerLen)
		{
			int currentContentLength = getContentLength();
			if (currentContentLength != static_cast<int>(m_DataLen - headerLen))
				setContentLength(m_DataLen - headerLen);
		}
	}

	SipLayer::SipParseResult SipLayer::detectSipMessageType(const uint8_t* data, size_t dataLen)
	{
		if (!data || dataLen < 3)
		{
			return SipLayer::SipParseResult::Unknown;
		}

		uint32_t key = pack4(reinterpret_cast<const char*>(data), dataLen);

		switch (key)
		{
		case "INVI"_packed4:  // INVITE
		case "ACK "_packed4:  // ACK
		case "BYE "_packed4:  // BYE
		case "CANC"_packed4:  // CANCEL
		case "REGI"_packed4:  // REGISTER
		case "PRAC"_packed4:  // PRACK
		case "OPTI"_packed4:  // OPTIONS
		case "SUBS"_packed4:  // SUBSCRIBE
		case "NOTI"_packed4:  // NOTIFY
		case "PUBL"_packed4:  // PUBLISH
		case "INFO"_packed4:  // INFO
		case "REFE"_packed4:  // REFER
		case "MESS"_packed4:  // MESSAGE
		case "UPDA"_packed4:  // UPDATE
			return SipLayer::SipParseResult::Request;

		case "SIP/"_packed4:
			return SipLayer::SipParseResult::Response;

		default:
			return SipLayer::SipParseResult::Unknown;
		}
	}

	SipLayer* SipLayer::parseSipLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, uint16_t srcPort,
	                                  uint16_t dstPort)
	{
		if (!(SipLayer::isSipPort(srcPort) || SipLayer::isSipPort(dstPort)))
		{
			return nullptr;
		}

		if (SipRequestFirstLine::parseMethod(reinterpret_cast<char*>(data), dataLen) !=
		    SipRequestLayer::SipMethodUnknown)
		{
			return new SipRequestLayer(data, dataLen, prevLayer, packet);
		}

		if (SipResponseFirstLine::parseStatusCode(reinterpret_cast<char*>(data), dataLen) !=
		        SipResponseLayer::SipStatusCodeUnknown &&
		    !SipResponseFirstLine::parseVersion(reinterpret_cast<char*>(data), dataLen).empty())
		{
			return new SipResponseLayer(data, dataLen, prevLayer, packet);
		}

		return nullptr;
	}

	SipLayer* SipLayer::parseSipLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		SipLayer::SipParseResult sipParseResult = detectSipMessageType(data, dataLen);

		if (sipParseResult == SipLayer::SipParseResult::Unknown)
		{
			return nullptr;
		}

		if (sipParseResult == SipLayer::SipParseResult::Request)
		{
			if (SipRequestFirstLine::parseFirstLine(reinterpret_cast<char*>(data), dataLen).first)
			{
				return new SipRequestLayer(data, dataLen, prevLayer, packet);
			}
			return nullptr;
		}

		if (SipResponseFirstLine::parseFirstLine(reinterpret_cast<char*>(data), dataLen).first)
		{
			return new SipResponseLayer(data, dataLen, prevLayer, packet);
		}
		return nullptr;
	}

	// -------- Class SipRequestFirstLine -----------------

	SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest) : m_SipRequest(sipRequest)
	{
		m_Method = parseMethod(reinterpret_cast<char*>(m_SipRequest->m_Data), m_SipRequest->getDataLen());
		if (m_Method == SipRequestLayer::SipMethodUnknown)
		{
			m_UriOffset = -1;
			PCPP_LOG_DEBUG("Couldn't resolve SIP request method");
		}
		else
			m_UriOffset = SipMethodEnumToString[m_Method].length() + 1;

		parseVersion();

		char* endOfFirstLine;
		if ((endOfFirstLine =
		         static_cast<char*>(memchr(reinterpret_cast<char*>(m_SipRequest->m_Data + m_VersionOffset), '\n',
		                                   m_SipRequest->m_DataLen - static_cast<size_t>(m_VersionOffset)))) != nullptr)
		{
			m_FirstLineEndOffset = endOfFirstLine - reinterpret_cast<char*>(m_SipRequest->m_Data) + 1;
			m_IsComplete = true;
		}
		else
		{
			m_FirstLineEndOffset = m_SipRequest->getDataLen();
			m_IsComplete = false;
		}

		if (Logger::getInstance().isDebugEnabled(PacketLogModuleSipLayer))
		{
			std::string method =
			    (m_Method == SipRequestLayer::SipMethodUnknown ? "Unknown" : SipMethodEnumToString[m_Method]);
			PCPP_LOG_DEBUG("Method='" << method << "'; SIP version='" << m_Version << "'; URI='" << getUri() << "'");
		}
	}

	SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest, SipRequestLayer::SipMethod method,
	                                         const std::string& version, const std::string& uri)
	try  // throw(SipRequestFirstLineException)
	{
		if (method == SipRequestLayer::SipMethodUnknown)
		{
			m_Exception.setMessage("Method supplied was SipMethodUnknown");
			throw m_Exception;
		}

		if (version == "")
		{
			m_Exception.setMessage("Version supplied was empty string");
			throw m_Exception;
		}

		m_SipRequest = sipRequest;

		m_Method = method;
		m_Version = version;

		std::string firstLine = SipMethodEnumToString[m_Method] + " " + uri + " " + version + "\r\n";

		m_UriOffset = SipMethodEnumToString[m_Method].length() + 1;
		m_FirstLineEndOffset = firstLine.length();
		m_VersionOffset = m_UriOffset + uri.length() + 6;

		m_SipRequest->m_DataLen = firstLine.length();
		m_SipRequest->m_Data = new uint8_t[m_SipRequest->m_DataLen];
		memcpy(m_SipRequest->m_Data, firstLine.c_str(), m_SipRequest->m_DataLen);

		m_IsComplete = true;
	}
	catch (const SipRequestFirstLineException&)
	{
		throw;
	}
	catch (...)
	{
		std::terminate();
	}

	SipRequestLayer::SipMethod SipRequestFirstLine::parseMethod(const char* data, size_t dataLen)
	{
		if (!data || dataLen < 4)
		{
			return SipRequestLayer::SipMethodUnknown;
		}

		size_t spaceIndex = 0;
		while (spaceIndex < dataLen && data[spaceIndex] != ' ')
		{
			spaceIndex++;
		}

		if (spaceIndex == 0 || spaceIndex == dataLen)
		{
			return SipRequestLayer::SipMethodUnknown;
		}

		auto methodAdEnum = SipMethodStringToEnum.find(std::string(data, data + spaceIndex));
		if (methodAdEnum == SipMethodStringToEnum.end())
		{
			return SipRequestLayer::SipMethodUnknown;
		}
		return methodAdEnum->second;
	}

	std::pair<bool, SipRequestFirstLine::SipFirstLineData> SipRequestFirstLine::parseFirstLine(const char* data,
	                                                                                           size_t dataLen)
	{
		SipFirstLineData result = { "", "", "" };

		if (data == nullptr || dataLen == 0)
		{
			PCPP_LOG_DEBUG("Empty data in SIP request line");
			return { false, result };
		}

		// Find first space (end of METHOD)
		size_t firstSpaceIndex = 0;
		while (firstSpaceIndex < dataLen && data[firstSpaceIndex] != ' ')
		{
			firstSpaceIndex++;
		}

		if (firstSpaceIndex == 0 || firstSpaceIndex == dataLen)
		{
			PCPP_LOG_DEBUG("Invalid METHOD in SIP request line");
			return { false, result };
		}

		// Validate method exists in SipMethodStringToEnum
		std::string methodStr{ data, firstSpaceIndex };
		if (SipMethodStringToEnum.find(methodStr) == SipMethodStringToEnum.end())
		{
			PCPP_LOG_DEBUG("Unknown SIP method");
			return { false, result };
		}

		// Find second space (end of URI)
		size_t secondSpaceIndex = firstSpaceIndex + 1;
		while (secondSpaceIndex < dataLen && data[secondSpaceIndex] != ' ')
			secondSpaceIndex++;

		if (secondSpaceIndex == dataLen)
		{
			PCPP_LOG_DEBUG("No space before version");
			return { false, result };
		}

		size_t uriLen = secondSpaceIndex - firstSpaceIndex - 1;
		if (uriLen == 0)
		{
			PCPP_LOG_DEBUG("Empty URI");
			return { false, result };
		}

		// Find end of line
		size_t lineEnd = secondSpaceIndex + 1;
		while (lineEnd < dataLen && data[lineEnd] != '\r' && data[lineEnd] != '\n')
			lineEnd++;

		// Minimum length for "SIP/x.y"
		size_t versionLen = lineEnd - secondSpaceIndex - 1;
		if (versionLen < 7)
		{
			PCPP_LOG_DEBUG("Version too short");
			return { false, result };
		}

		const char* versionStart = data + secondSpaceIndex + 1;
		if (versionStart[0] != 'S' || versionStart[1] != 'I' || versionStart[2] != 'P' || versionStart[3] != '/')
		{
			PCPP_LOG_DEBUG("Invalid SIP version format");
			return { false, result };
		}

		// All validations passed
		result.method = std::move(methodStr);
		result.uri = std::string{ data + firstSpaceIndex + 1, uriLen };
		result.version = std::string{ versionStart, versionLen };

		return { true, result };
	}

	void SipRequestFirstLine::parseVersion()
	{
		if (m_SipRequest->getDataLen() < static_cast<size_t>(m_UriOffset))
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		char* data = reinterpret_cast<char*>(m_SipRequest->m_Data + m_UriOffset);
		char* verPos = cross_platform_memmem(data, m_SipRequest->getDataLen() - m_UriOffset, " SIP/", 5);
		if (verPos == nullptr)
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		// verify packet doesn't end before the version, meaning still left place for " SIP/x.y" (7 chars)
		if (static_cast<uint16_t>(verPos + 7 - reinterpret_cast<char*>(m_SipRequest->m_Data)) >
		    m_SipRequest->getDataLen())
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		// skip the space char
		verPos++;

		int endOfVerPos = 0;
		while (((verPos + endOfVerPos) < reinterpret_cast<char*>(m_SipRequest->m_Data + m_SipRequest->m_DataLen)) &&
		       ((verPos + endOfVerPos)[0] != '\r') && ((verPos + endOfVerPos)[0] != '\n'))
			endOfVerPos++;

		m_Version = std::string(verPos, endOfVerPos);

		m_VersionOffset = verPos - reinterpret_cast<char*>(m_SipRequest->m_Data);
	}

	bool SipRequestFirstLine::setMethod(SipRequestLayer::SipMethod newMethod)
	{
		if (newMethod == SipRequestLayer::SipMethodUnknown)
		{
			PCPP_LOG_ERROR("Requested method is SipMethodUnknown");
			return false;
		}

		// extend or shorten layer
		int lengthDifference = SipMethodEnumToString[newMethod].length() - SipMethodEnumToString[m_Method].length();
		if (lengthDifference > 0)
		{
			if (!m_SipRequest->extendLayer(0, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipRequest->shortenLayer(0, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipRequest->shiftFieldsOffset(m_SipRequest->getFirstField(), lengthDifference);
			m_SipRequest->m_FieldsOffset += lengthDifference;
		}

		memcpy(m_SipRequest->m_Data, SipMethodEnumToString[newMethod].c_str(),
		       SipMethodEnumToString[newMethod].length());

		m_UriOffset += lengthDifference;
		m_VersionOffset += lengthDifference;
		m_FirstLineEndOffset += lengthDifference;

		m_Method = newMethod;

		return true;
	}

	std::string SipRequestFirstLine::getUri() const
	{
		std::string result;
		if (m_UriOffset != -1 && m_VersionOffset != -1)
			result.assign(reinterpret_cast<char*>(m_SipRequest->m_Data + m_UriOffset),
			              m_VersionOffset - 1 - m_UriOffset);

		// else first line is illegal, return empty string

		return result;
	}

	bool SipRequestFirstLine::setUri(const std::string& newUri)
	{
		if (newUri == "")
		{
			PCPP_LOG_ERROR("URI cannot be empty");
			return false;
		}

		// extend or shorten layer
		std::string currentUri = getUri();
		int lengthDifference = newUri.length() - currentUri.length();
		if (lengthDifference > 0)
		{
			if (!m_SipRequest->extendLayer(m_UriOffset, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipRequest->shortenLayer(m_UriOffset, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipRequest->shiftFieldsOffset(m_SipRequest->getFirstField(), lengthDifference);
			m_SipRequest->m_FieldsOffset += lengthDifference;
		}

		memcpy(m_SipRequest->m_Data + m_UriOffset, newUri.c_str(), newUri.length());

		m_VersionOffset += lengthDifference;
		m_FirstLineEndOffset += lengthDifference;

		return true;
	}

	// -------- Class SipRequestLayer -----------------

	SipRequestLayer::SipRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : SipLayer(data, dataLen, prevLayer, packet, SIPRequest)
	{
		m_FirstLine = new SipRequestFirstLine(this);
		m_FieldsOffset = m_FirstLine->getSize();
		parseFields();
	}

	SipRequestLayer::SipRequestLayer(SipMethod method, const std::string& requestUri, const std::string& version)
	{
		m_Protocol = SIPRequest;
		m_FirstLine = new SipRequestFirstLine(this, method, version, requestUri);
		m_FieldsOffset = m_FirstLine->getSize();
	}

	SipRequestLayer::SipRequestLayer(const SipRequestLayer& other) : SipLayer(other)
	{
		m_FirstLine = new SipRequestFirstLine(this);
	}

	SipRequestLayer& SipRequestLayer::operator=(const SipRequestLayer& other)
	{
		SipLayer::operator=(other);

		if (m_FirstLine != nullptr)
			delete m_FirstLine;

		m_FirstLine = new SipRequestFirstLine(this);

		return *this;
	}

	SipRequestLayer::~SipRequestLayer()
	{
		delete m_FirstLine;
	}

	std::string SipRequestLayer::toString() const
	{
		static const int maxLengthToPrint = 120;
		std::string result = "SIP request, ";
		int size = m_FirstLine->getSize() - 2;  // the -2 is to remove \r\n at the end of the first line
		if (size <= 0)
		{
			result += std::string("CORRUPT DATA");
			return result;
		}
		if (size <= maxLengthToPrint)
		{
			char* firstLine = new char[size + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), size);
			firstLine[size] = 0;
			result += std::string(firstLine);
			delete[] firstLine;
		}
		else
		{
			char firstLine[maxLengthToPrint + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), maxLengthToPrint - 3);
			firstLine[maxLengthToPrint - 3] = '.';
			firstLine[maxLengthToPrint - 2] = '.';
			firstLine[maxLengthToPrint - 1] = '.';
			firstLine[maxLengthToPrint] = 0;
			result += std::string(firstLine);
		}

		return result;
	}

	// -------- Class SipResponseLayer -----------------

	namespace
	{
		const std::array<std::string, 77> StatusCodeEnumToString = {  // format override comment
			"Trying",
			"Ringing",
			"Call is Being Forwarded",
			"Queued",
			"Session in Progress",
			"Early Dialog Terminated",
			"OK",
			"Accepted",
			"No Notification",
			"Multiple Choices",
			"Moved Permanently",
			"Moved Temporarily",
			"Use Proxy",
			"Alternative Service",
			"Bad Request",
			"Unauthorized",
			"Payment Required",
			"Forbidden",
			"Not Found",
			"Method Not Allowed",
			"Not Acceptable",
			"Proxy Authentication Required",
			"Request Timeout",
			"Conflict",
			"Gone",
			"Length Required",
			"Conditional Request Failed",
			"Request Entity Too Large",
			"Request-URI Too Long",
			"Unsupported Media Type",
			"Unsupported URI Scheme",
			"Unknown Resource-Priority",
			"Bad Extension",
			"Extension Required",
			"Session Interval Too Small",
			"Interval Too Brief",
			"Bad Location Information",
			"Bad Alert Message",
			"Use Identity Header",
			"Provide Referrer Identity",
			"Flow Failed",
			"Anonymity Disallowed",
			"Bad Identity-Info",
			"Unsupported Certificate",
			"Invalid Identity Header",
			"First Hop Lacks Outbound Support",
			"Max-Breadth Exceeded",
			"Bad Info Package",
			"Consent Needed",
			"Temporarily Unavailable",
			"Call_Transaction Does Not Exist",
			"Loop Detected",
			"Too Many Hops",
			"Address Incomplete",
			"Ambiguous",
			"Busy Here",
			"Request Terminated",
			"Not Acceptable Here",
			"Bad Event",
			"Request Pending",
			"Undecipherable",
			"Security Agreement Required",
			"Server Internal Error",
			"Not Implemented",
			"Bad Gateway",
			"Service Unavailable",
			"Server Timeout",
			"Version Not Supported",
			"Message Too Large",
			"Push Notification Service Not Supported",
			"Precondition Failure",
			"Busy Everywhere",
			"Decline",
			"Does Not Exist Anywhere",
			"Not Acceptable",
			"Unwanted",
			"Rejected"
		};

		const std::array<int, 77> StatusCodeEnumToInt = {
			100, 180, 181, 182, 183, 199, 200, 202, 204, 300, 301, 302, 305, 380, 400, 401, 402, 403, 404, 405,
			406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 420, 421, 422, 425, 423, 424, 428, 429,
			430, 433, 436, 437, 438, 439, 440, 469, 470, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 491,
			493, 494, 500, 501, 502, 503, 504, 505, 513, 555, 580, 600, 603, 604, 606, 607, 608
		};

		// Parses the SIP status code from raw data. The data must point to the beginning of the status code.
		SipResponseLayer::SipResponseStatusCode parseStatusCodePure(const char* data, size_t dataLen)
		{
			if (data == nullptr || dataLen < 3)
			{
				return SipResponseLayer::SipStatusCodeUnknown;
			}

			uint16_t code = 0;
			code += (static_cast<uint16_t>(data[0]) - '0') * 100;
			code += (static_cast<uint16_t>(data[1]) - '0') * 10;
			code += (static_cast<uint16_t>(data[2]) - '0');

			switch (code)
			{
			// 1xx: Informational
			case 100:
				return SipResponseLayer::SipResponseStatusCode::Sip100Trying;
			case 180:
				return SipResponseLayer::SipResponseStatusCode::Sip180Ringing;
			case 181:
				return SipResponseLayer::SipResponseStatusCode::Sip181CallisBeingForwarded;
			case 182:
				return SipResponseLayer::SipResponseStatusCode::Sip182Queued;
			case 183:
				return SipResponseLayer::SipResponseStatusCode::Sip183SessioninProgress;
			case 199:
				return SipResponseLayer::SipResponseStatusCode::Sip199EarlyDialogTerminated;
			// 2xx: Success
			case 200:
				return SipResponseLayer::SipResponseStatusCode::Sip200OK;
			case 202:
				return SipResponseLayer::SipResponseStatusCode::Sip202Accepted;
			case 204:
				return SipResponseLayer::SipResponseStatusCode::Sip204NoNotification;
			// 3xx: Redirection
			case 300:
				return SipResponseLayer::SipResponseStatusCode::Sip300MultipleChoices;
			case 301:
				return SipResponseLayer::SipResponseStatusCode::Sip301MovedPermanently;
			case 302:
				return SipResponseLayer::SipResponseStatusCode::Sip302MovedTemporarily;
			case 305:
				return SipResponseLayer::SipResponseStatusCode::Sip305UseProxy;
			case 380:
				return SipResponseLayer::SipResponseStatusCode::Sip380AlternativeService;
			// 4xx: Client Failure
			case 400:
				return SipResponseLayer::SipResponseStatusCode::Sip400BadRequest;
			case 401:
				return SipResponseLayer::SipResponseStatusCode::Sip401Unauthorized;
			case 402:
				return SipResponseLayer::SipResponseStatusCode::Sip402PaymentRequired;
			case 403:
				return SipResponseLayer::SipResponseStatusCode::Sip403Forbidden;
			case 404:
				return SipResponseLayer::SipResponseStatusCode::Sip404NotFound;
			case 405:
				return SipResponseLayer::SipResponseStatusCode::Sip405MethodNotAllowed;
			case 406:
				return SipResponseLayer::SipResponseStatusCode::Sip406NotAcceptable;
			case 407:
				return SipResponseLayer::SipResponseStatusCode::Sip407ProxyAuthenticationRequired;
			case 408:
				return SipResponseLayer::SipResponseStatusCode::Sip408RequestTimeout;
			case 409:
				return SipResponseLayer::SipResponseStatusCode::Sip409Conflict;
			case 410:
				return SipResponseLayer::SipResponseStatusCode::Sip410Gone;
			case 411:
				return SipResponseLayer::SipResponseStatusCode::Sip411LengthRequired;
			case 412:
				return SipResponseLayer::SipResponseStatusCode::Sip412ConditionalRequestFailed;
			case 413:
				return SipResponseLayer::SipResponseStatusCode::Sip413RequestEntityTooLarge;
			case 414:
				return SipResponseLayer::SipResponseStatusCode::Sip414RequestURITooLong;
			case 415:
				return SipResponseLayer::SipResponseStatusCode::Sip415UnsupportedMediaType;
			case 416:
				return SipResponseLayer::SipResponseStatusCode::Sip416UnsupportedURIScheme;
			case 417:
				return SipResponseLayer::SipResponseStatusCode::Sip417UnknownResourcePriority;
			case 420:
				return SipResponseLayer::SipResponseStatusCode::Sip420BadExtension;
			case 421:
				return SipResponseLayer::SipResponseStatusCode::Sip421ExtensionRequired;
			case 422:
				return SipResponseLayer::SipResponseStatusCode::Sip422SessionIntervalTooSmall;
			case 423:
				return SipResponseLayer::SipResponseStatusCode::Sip423IntervalTooBrief;
			case 424:
				return SipResponseLayer::SipResponseStatusCode::Sip424BadLocationInformation;
			case 425:
				return SipResponseLayer::SipResponseStatusCode::Sip425BadAlertMessage;
			case 428:
				return SipResponseLayer::SipResponseStatusCode::Sip428UseIdentityHeader;
			case 429:
				return SipResponseLayer::SipResponseStatusCode::Sip429ProvideReferrerIdentity;
			case 430:
				return SipResponseLayer::SipResponseStatusCode::Sip430FlowFailed;
			case 433:
				return SipResponseLayer::SipResponseStatusCode::Sip433AnonymityDisallowed;
			case 436:
				return SipResponseLayer::SipResponseStatusCode::Sip436BadIdentityInfo;
			case 437:
				return SipResponseLayer::SipResponseStatusCode::Sip437UnsupportedCertificate;
			case 438:
				return SipResponseLayer::SipResponseStatusCode::Sip438InvalidIdentityHeader;
			case 439:
				return SipResponseLayer::SipResponseStatusCode::Sip439FirstHopLacksOutboundSupport;
			case 440:
				return SipResponseLayer::SipResponseStatusCode::Sip440MaxBreadthExceeded;
			case 469:
				return SipResponseLayer::SipResponseStatusCode::Sip469BadInfoPackage;
			case 470:
				return SipResponseLayer::SipResponseStatusCode::Sip470ConsentNeeded;
			case 480:
				return SipResponseLayer::SipResponseStatusCode::Sip480TemporarilyUnavailable;
			case 481:
				return SipResponseLayer::SipResponseStatusCode::Sip481Call_TransactionDoesNotExist;
			case 482:
				return SipResponseLayer::SipResponseStatusCode::Sip482LoopDetected;
			case 483:
				return SipResponseLayer::SipResponseStatusCode::Sip483TooManyHops;
			case 484:
				return SipResponseLayer::SipResponseStatusCode::Sip484AddressIncomplete;
			case 485:
				return SipResponseLayer::SipResponseStatusCode::Sip485Ambiguous;
			case 486:
				return SipResponseLayer::SipResponseStatusCode::Sip486BusyHere;
			case 487:
				return SipResponseLayer::SipResponseStatusCode::Sip487RequestTerminated;
			case 488:
				return SipResponseLayer::SipResponseStatusCode::Sip488NotAcceptableHere;
			case 489:
				return SipResponseLayer::SipResponseStatusCode::Sip489BadEvent;
			case 491:
				return SipResponseLayer::SipResponseStatusCode::Sip491RequestPending;
			case 493:
				return SipResponseLayer::SipResponseStatusCode::Sip493Undecipherable;
			case 494:
				return SipResponseLayer::SipResponseStatusCode::Sip494SecurityAgreementRequired;
			// 5xx: Server Failure
			case 500:
				return SipResponseLayer::SipResponseStatusCode::Sip500ServerInternalError;
			case 501:
				return SipResponseLayer::SipResponseStatusCode::Sip501NotImplemented;
			case 502:
				return SipResponseLayer::SipResponseStatusCode::Sip502BadGateway;
			case 503:
				return SipResponseLayer::SipResponseStatusCode::Sip503ServiceUnavailable;
			case 504:
				return SipResponseLayer::SipResponseStatusCode::Sip504ServerTimeout;
			case 505:
				return SipResponseLayer::SipResponseStatusCode::Sip505VersionNotSupported;
			case 513:
				return SipResponseLayer::SipResponseStatusCode::Sip513MessageTooLarge;
			case 555:
				return SipResponseLayer::SipResponseStatusCode::Sip555PushNotificationServiceNotSupported;
			case 580:
				return SipResponseLayer::SipResponseStatusCode::Sip580PreconditionFailure;
			// 6xx: Global Failure
			case 600:
				return SipResponseLayer::SipResponseStatusCode::Sip600BusyEverywhere;
			case 603:
				return SipResponseLayer::SipResponseStatusCode::Sip603Decline;
			case 604:
				return SipResponseLayer::SipResponseStatusCode::Sip604DoesNotExistAnywhere;
			case 606:
				return SipResponseLayer::SipResponseStatusCode::Sip606NotAcceptable;
			case 607:
				return SipResponseLayer::SipResponseStatusCode::Sip607Unwanted;
			case 608:
				return SipResponseLayer::SipResponseStatusCode::Sip608Rejected;
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			}
		}
	}  // namespace

	SipResponseLayer::SipResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : SipLayer(data, dataLen, prevLayer, packet, SIPResponse)
	{
		m_FirstLine = new SipResponseFirstLine(this);
		m_FieldsOffset = m_FirstLine->getSize();
		parseFields();
	}

	SipResponseLayer::SipResponseLayer(SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString,
	                                   const std::string& sipVersion)
	{
		m_Protocol = SIPResponse;
		m_FirstLine = new SipResponseFirstLine(this, sipVersion, statusCode, std::move(statusCodeString));
		m_FieldsOffset = m_FirstLine->getSize();
	}

	SipResponseLayer::~SipResponseLayer()
	{
		delete m_FirstLine;
	}

	SipResponseLayer::SipResponseLayer(const SipResponseLayer& other) : SipLayer(other)
	{
		m_FirstLine = new SipResponseFirstLine(this);
	}

	SipResponseLayer& SipResponseLayer::operator=(const SipResponseLayer& other)
	{
		SipLayer::operator=(other);

		if (m_FirstLine != nullptr)
			delete m_FirstLine;

		m_FirstLine = new SipResponseFirstLine(this);

		return *this;
	}

	std::string SipResponseLayer::toString() const
	{
		static const int maxLengthToPrint = 120;
		std::string result = "SIP response, ";
		int size = m_FirstLine->getSize() - 2;  // the -2 is to remove \r\n at the end of the first line
		if (size <= 0)
		{
			result += std::string("CORRUPT DATA");
			return result;
		}
		if (size <= maxLengthToPrint)
		{
			char* firstLine = new char[size + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), size);
			firstLine[size] = 0;
			result += std::string(firstLine);
			delete[] firstLine;
		}
		else
		{
			char firstLine[maxLengthToPrint + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), maxLengthToPrint - 3);
			firstLine[maxLengthToPrint - 3] = '.';
			firstLine[maxLengthToPrint - 2] = '.';
			firstLine[maxLengthToPrint - 1] = '.';
			firstLine[maxLengthToPrint] = 0;
			result += std::string(firstLine);
		}

		return result;
	}

	// -------- Class SipResponseFirstLine -----------------

	int SipResponseFirstLine::getStatusCodeAsInt() const
	{
		return StatusCodeEnumToInt[m_StatusCode];
	}

	std::string SipResponseFirstLine::getStatusCodeString() const
	{
		std::string result;
		const int statusStringOffset = 12;
		if (m_StatusCode != SipResponseLayer::SipStatusCodeUnknown)
		{
			int statusStringEndOffset = m_FirstLineEndOffset - 2;
			if ((*(m_SipResponse->m_Data + statusStringEndOffset)) != '\r')
				statusStringEndOffset++;
			result.assign(reinterpret_cast<char*>(m_SipResponse->m_Data + statusStringOffset),
			              statusStringEndOffset - statusStringOffset);
		}

		// else first line is illegal, return empty string

		return result;
	}

	bool SipResponseFirstLine::setStatusCode(SipResponseLayer::SipResponseStatusCode newStatusCode,
	                                         std::string statusCodeString)
	{
		if (newStatusCode == SipResponseLayer::SipStatusCodeUnknown)
		{
			PCPP_LOG_ERROR("Requested status code is SipStatusCodeUnknown");
			return false;
		}

		// extend or shorten layer

		size_t statusStringOffset = 12;
		if (statusCodeString == "")
			statusCodeString = StatusCodeEnumToString[newStatusCode];
		int lengthDifference = statusCodeString.length() - getStatusCodeString().length();

		if (lengthDifference > 0)
		{
			if (!m_SipResponse->extendLayer(statusStringOffset, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipResponse->shortenLayer(statusStringOffset, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipResponse->shiftFieldsOffset(m_SipResponse->getFirstField(), lengthDifference);
			m_SipResponse->m_FieldsOffset += lengthDifference;
		}

		// copy status string
		memcpy(m_SipResponse->m_Data + statusStringOffset, statusCodeString.c_str(), statusCodeString.length());

		// change status code
		std::ostringstream statusCodeAsString;
		statusCodeAsString << StatusCodeEnumToInt[newStatusCode];
		memcpy(m_SipResponse->m_Data + 8, statusCodeAsString.str().c_str(), 3);

		m_StatusCode = newStatusCode;
		m_FirstLineEndOffset += lengthDifference;

		return true;
	}

	void SipResponseFirstLine::setVersion(const std::string& newVersion)
	{
		if (newVersion == "")
			return;

		if (newVersion.length() != m_Version.length())
		{
			PCPP_LOG_ERROR("Expected version length is " << m_Version.length()
			                                             << " characters in the format of SIP/x.y");
			return;
		}

		char* verPos = reinterpret_cast<char*>(m_SipResponse->m_Data);
		memcpy(verPos, newVersion.c_str(), newVersion.length());
		m_Version = newVersion;
	}

	SipResponseLayer::SipResponseStatusCode SipResponseFirstLine::parseStatusCode(const char* data, size_t dataLen)
	{
		// minimum data should be 12B long: "SIP/x.y XXX "
		if (!data || dataLen < 12)
		{
			return SipResponseLayer::SipStatusCodeUnknown;
		}

		const char* statusCodeData = data + 8;
		if (statusCodeData[3] != ' ')
		{
			return SipResponseLayer::SipStatusCodeUnknown;
		}

		return parseStatusCodePure(statusCodeData, 3);
	}

	SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse) : m_SipResponse(sipResponse)
	{
		m_Version = parseVersion(reinterpret_cast<char*>(m_SipResponse->m_Data), m_SipResponse->getDataLen());
		if (m_Version == "")
		{
			m_StatusCode = SipResponseLayer::SipStatusCodeUnknown;
		}
		else
		{
			m_StatusCode = parseStatusCode(reinterpret_cast<char*>(m_SipResponse->m_Data), m_SipResponse->getDataLen());
		}

		char* endOfFirstLine;
		if ((endOfFirstLine = static_cast<char*>(
		         memchr(reinterpret_cast<char*>(m_SipResponse->m_Data), '\n', m_SipResponse->m_DataLen))) != nullptr)
		{
			m_FirstLineEndOffset = endOfFirstLine - reinterpret_cast<char*>(m_SipResponse->m_Data) + 1;
			m_IsComplete = true;
		}
		else
		{
			m_FirstLineEndOffset = m_SipResponse->getDataLen();
			m_IsComplete = false;
		}

		if (Logger::getInstance().isDebugEnabled(PacketLogModuleSipLayer))
		{
			int statusCode =
			    (m_StatusCode == SipResponseLayer::SipStatusCodeUnknown ? 0 : StatusCodeEnumToInt[m_StatusCode]);
			PCPP_LOG_DEBUG("Version='" << m_Version << "'; Status code=" << statusCode << " '" << getStatusCodeString()
			                           << "'");
		}
	}

	SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse, const std::string& version,
	                                           SipResponseLayer::SipResponseStatusCode statusCode,
	                                           std::string statusCodeString)
	{
		if (statusCode == SipResponseLayer::SipStatusCodeUnknown)
		{
			m_Exception.setMessage("Status code supplied was SipStatusCodeUnknown");
			throw m_Exception;
		}

		if (version == "")
		{
			m_Exception.setMessage("Version supplied was unknown");
			throw m_Exception;
		}

		m_SipResponse = sipResponse;

		m_StatusCode = statusCode;
		m_Version = version;

		std::ostringstream statusCodeAsString;
		statusCodeAsString << StatusCodeEnumToInt[m_StatusCode];
		if (statusCodeString == "")
			statusCodeString = StatusCodeEnumToString[m_StatusCode];
		std::string firstLine = m_Version + " " + statusCodeAsString.str() + " " + statusCodeString + "\r\n";

		m_FirstLineEndOffset = firstLine.length();

		m_SipResponse->m_DataLen = firstLine.length();
		m_SipResponse->m_Data = new uint8_t[m_SipResponse->m_DataLen];
		memcpy(m_SipResponse->m_Data, firstLine.c_str(), m_SipResponse->m_DataLen);

		m_IsComplete = true;
	}

	std::string SipResponseFirstLine::parseVersion(const char* data, size_t dataLen)
	{
		if (!data || dataLen < 8)  // "SIP/x.y "
		{
			PCPP_LOG_DEBUG("SIP response length < 8, cannot identify version");
			return "";
		}

		if (data[0] != 'S' || data[1] != 'I' || data[2] != 'P' || data[3] != '/')
		{
			PCPP_LOG_DEBUG("SIP response does not begin with 'SIP/'");
			return "";
		}

		const char* nextSpace = static_cast<const char*>(memchr(data, ' ', dataLen));
		if (nextSpace == nullptr)
			return "";

		return std::string(data, nextSpace - data);
	}

	std::pair<bool, SipResponseFirstLine::FirstLineData> SipResponseFirstLine::parseFirstLine(const char* data,
	                                                                                          size_t dataLen)
	{
		std::pair<bool, FirstLineData> result{};  // initialize to false and empty strings

		// Minimum data should be 12 bytes long: "SIP/x.y XXX "
		if (data == nullptr || dataLen < 12)
		{
			PCPP_LOG_DEBUG("SIP response length < 12, cannot parse first line");
			return result;
		}

		if (pack4(data, 4) != "SIP/"_packed4)
		{
			PCPP_LOG_DEBUG("SIP response does not begin with 'SIP/'");
			return result;
		}

		const auto dataEndIt = data + dataLen;
		// Find first space (end of version)
		auto firstSpaceIt = std::find(data + 4, dataEndIt, ' ');
		if (firstSpaceIt == dataEndIt)
		{
			PCPP_LOG_DEBUG("No space after version in SIP response line");
			return result;
		}

		// Status code is strictly 3 characters followed by a space
		auto statusCodeIt = firstSpaceIt + 1;
		auto statusCodeEndIt = statusCodeIt + 3;
		if (*statusCodeEndIt != ' ')
		{
			PCPP_LOG_DEBUG("No space after status code in SIP response line");
			return result;
		}

		auto statusCode = parseStatusCodePure(statusCodeIt, 3);
		if (statusCode == SipResponseLayer::SipStatusCodeUnknown)
		{
			PCPP_LOG_DEBUG("Unknown SIP status code");
			return result;
		}

		// Write parsed values to result
		result.first = true;
		result.second.version = std::string(data, firstSpaceIt);
		result.second.statusCode = statusCode;
		return result;
	}

}  // namespace pcpp
