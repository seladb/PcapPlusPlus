#define LOG_MODULE PacketLogModuleHttpLayer

#include "Logger.h"
#include "GeneralUtils.h"
#include "HttpLayer.h"
#include <string.h>
#include <algorithm>
#include <stdlib.h>
#include <exception>
#include <utility>
#include <unordered_map>

namespace pcpp
{


// -------- Class HttpMessage -----------------


HeaderField* HttpMessage::addField(const std::string& fieldName, const std::string& fieldValue)
{
	if (getFieldByName(fieldName) != nullptr)
	{
		PCPP_LOG_ERROR("Field '" << fieldName << "' already exists!");
		return nullptr;
	}

	return TextBasedProtocolMessage::addField(fieldName, fieldValue);
}

HeaderField* HttpMessage::addField(const HeaderField& newField)
{
	if (getFieldByName(newField.getFieldName()) != nullptr)
	{
		PCPP_LOG_ERROR("Field '" << newField.getFieldName() << "' already exists!");
		return nullptr;
	}

	return TextBasedProtocolMessage::addField(newField);
}

HeaderField* HttpMessage::insertField(HeaderField* prevField, const std::string& fieldName, const std::string& fieldValue)
{
	if (getFieldByName(fieldName) != nullptr)
	{
		PCPP_LOG_ERROR("Field '" << fieldName << "' already exists!");
		return nullptr;
	}

	return TextBasedProtocolMessage::insertField(prevField, fieldName, fieldValue);
}

HeaderField* HttpMessage::insertField(HeaderField* prevField, const HeaderField& newField)
{
	if (getFieldByName(newField.getFieldName()) != nullptr)
	{
		PCPP_LOG_ERROR("Field '" << newField.getFieldName() << "' already exists!");
		return nullptr;
	}

	return TextBasedProtocolMessage::insertField(prevField, newField);
}



// -------- Class HttpRequestLayer -----------------

HttpRequestLayer::HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : HttpMessage(data, dataLen, prevLayer, packet)
{
	m_Protocol = HTTPRequest;
	m_FirstLine = new HttpRequestFirstLine(this);
	m_FieldsOffset = m_FirstLine->getSize();
	parseFields();
}

HttpRequestLayer::HttpRequestLayer(HttpMethod method, const std::string& uri, HttpVersion version)
{
	m_Protocol = HTTPRequest;
	m_FirstLine = new HttpRequestFirstLine(this, method, version, uri);
	m_FieldsOffset = m_FirstLine->getSize();
}

HttpRequestLayer::HttpRequestLayer(const HttpRequestLayer& other) : HttpMessage(other)
{
	m_FirstLine = new HttpRequestFirstLine(this);
}

HttpRequestLayer& HttpRequestLayer::operator=(const HttpRequestLayer& other)
{
	HttpMessage::operator=(other);

	if (m_FirstLine != nullptr)
		delete m_FirstLine;

	m_FirstLine = new HttpRequestFirstLine(this);

	return *this;
}


std::string HttpRequestLayer::getUrl() const
{
	HeaderField* hostField = getFieldByName(PCPP_HTTP_HOST_FIELD);
	if (hostField == nullptr)
		return m_FirstLine->getUri();

	return hostField->getFieldValue() + m_FirstLine->getUri();
}

HttpRequestLayer::~HttpRequestLayer()
{
	delete m_FirstLine;
}

std::string HttpRequestLayer::toString() const
{
	static const int maxLengthToPrint = 120;
	std::string result = "HTTP request, ";
	int size = m_FirstLine->getSize() - 2; // the -2 is to remove \r\n at the end of the first line
	if (size <= 0)
	{
		result += std::string("CORRUPT DATA");
		return result;
	}
	if (size <= maxLengthToPrint)
	{
		char* firstLine = new char[size+1];
		strncpy(firstLine, (char*)m_Data, size);
		firstLine[size] = 0;
		result += std::string(firstLine);
		delete[] firstLine;
	}
	else
	{
		char firstLine[maxLengthToPrint+1];
		strncpy(firstLine, (char*)m_Data, maxLengthToPrint-3);
		firstLine[maxLengthToPrint-3] = '.';
		firstLine[maxLengthToPrint-2] = '.';
		firstLine[maxLengthToPrint-1] = '.';
		firstLine[maxLengthToPrint] = 0;
		result += std::string(firstLine);
	}

	return result;
}







// -------- Class HttpRequestFirstLine -----------------


const std::string MethodEnumToString[9] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"TRACE",
		"OPTIONS",
		"CONNECT",
		"PATCH"
};

const std::unordered_map<std::string, HttpRequestLayer::HttpMethod> HttpMethodStringToEnum {
		{"GET", HttpRequestLayer::HttpMethod::HttpGET },
		{"HEAD", HttpRequestLayer::HttpMethod::HttpHEAD },
		{"POST", HttpRequestLayer::HttpMethod::HttpPOST },
		{"PUT", HttpRequestLayer::HttpMethod::HttpPUT },
		{"DELETE", HttpRequestLayer::HttpMethod::HttpDELETE },
		{"TRACE", HttpRequestLayer::HttpMethod::HttpTRACE },
		{"OPTIONS", HttpRequestLayer::HttpMethod::HttpOPTIONS },
		{"CONNECT", HttpRequestLayer::HttpMethod::HttpCONNECT },
		{"PATCH", HttpRequestLayer::HttpMethod::HttpPATCH }
};

const std::string VersionEnumToString[3] = {
		"0.9",
		"1.0",
		"1.1"
};

const std::unordered_map<std::string, HttpVersion> HttpVersionStringToEnum {
		{ "0.9", HttpVersion::ZeroDotNine },
		{ "1.0", HttpVersion::OneDotZero },
		{ "1.1", HttpVersion::OneDotOne }
};


HttpRequestFirstLine::HttpRequestFirstLine(HttpRequestLayer* httpRequest) : m_HttpRequest(httpRequest)
{
	m_Method = parseMethod((char*)m_HttpRequest->m_Data, m_HttpRequest->getDataLen());
	if (m_Method == HttpRequestLayer::HttpMethodUnknown)
	{
		m_UriOffset = -1;
		PCPP_LOG_DEBUG("Couldn't resolve HTTP request method");
		m_IsComplete = false;
		m_Version = HttpVersionUnknown;
		m_VersionOffset = -1;
		m_FirstLineEndOffset = m_HttpRequest->getDataLen();
		return;
	}
	else
		m_UriOffset = MethodEnumToString[m_Method].length() + 1;

	parseVersion();
	if(m_VersionOffset < 0)
	{
		m_IsComplete = false;
		m_FirstLineEndOffset = m_HttpRequest->getDataLen();
		return;
	}

	char* endOfFirstLine;
	if ((endOfFirstLine = (char*)memchr((char*)(m_HttpRequest->m_Data + m_VersionOffset), '\n', m_HttpRequest->m_DataLen-(size_t)m_VersionOffset)) != nullptr)
	{
		m_FirstLineEndOffset = endOfFirstLine - (char*)m_HttpRequest->m_Data + 1;
		m_IsComplete = true;
	}
	else
	{
		m_FirstLineEndOffset = m_HttpRequest->getDataLen();
		m_IsComplete = false;
	}

	if (Logger::getInstance().isDebugEnabled(PacketLogModuleHttpLayer))
	{
		std::string method = m_Method == HttpRequestLayer::HttpMethodUnknown? "Unknown" : MethodEnumToString[m_Method];
		PCPP_LOG_DEBUG(
			"Method='" << method << "'; "
			<< "HTTP version='" << VersionEnumToString[m_Version] << "'; "
			<< "URI='" << getUri() << "'");
	}
}

HttpRequestFirstLine::HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpRequestLayer::HttpMethod method, HttpVersion version, const std::string &uri)
{
	try		// throw(HttpRequestFirstLineException)
	{
		if (method == HttpRequestLayer::HttpMethodUnknown)
		{
			m_Exception.setMessage("Method supplied was HttpMethodUnknown");
			throw m_Exception;
		}

		if (version == HttpVersionUnknown)
		{
			m_Exception.setMessage("Version supplied was HttpVersionUnknown");
			throw m_Exception;
		}

		m_HttpRequest = httpRequest;

		m_Method = method;
		m_Version = version;

		std::string firstLine = MethodEnumToString[m_Method] + " " + uri + " "  + "HTTP/" + VersionEnumToString[m_Version] + "\r\n";

		m_UriOffset =  MethodEnumToString[m_Method].length() + 1;
		m_FirstLineEndOffset = firstLine.length();
		m_VersionOffset = m_UriOffset + uri.length() + 6;

		m_HttpRequest->m_DataLen = firstLine.length();
		m_HttpRequest->m_Data = new uint8_t[m_HttpRequest->m_DataLen];
		memcpy(m_HttpRequest->m_Data, firstLine.c_str(), m_HttpRequest->m_DataLen);

		m_IsComplete = true;
	}
	catch(const HttpRequestFirstLineException&)
	{
		throw;
	}
	catch(...)
	{
		std::terminate();
	}
}

HttpRequestLayer::HttpMethod HttpRequestFirstLine::parseMethod(const char* data, size_t dataLen)
{
	if (!data || dataLen < 4)
	{
		return HttpRequestLayer::HttpMethodUnknown;
	}

	size_t spaceIndex = 0;
	while (spaceIndex < dataLen && data[spaceIndex] != ' ' )
	{
		spaceIndex++;
	}

	if (spaceIndex == 0 || spaceIndex == dataLen)
	{
		return HttpRequestLayer::HttpMethodUnknown;
	}

	auto methodAdEnum = HttpMethodStringToEnum.find(std::string(data, data + spaceIndex));
	if (methodAdEnum == HttpMethodStringToEnum.end())
	{
		return HttpRequestLayer::HttpMethodUnknown;
	}
	return methodAdEnum->second;
}

void HttpRequestFirstLine::parseVersion()
{
	char* data = (char*)(m_HttpRequest->m_Data + m_UriOffset);
	char* verPos = cross_platform_memmem(data, m_HttpRequest->getDataLen() - m_UriOffset, " HTTP/", 6);
	if (verPos == nullptr)
	{
		m_Version = HttpVersionUnknown;
		m_VersionOffset = -1;
		return;
	}

	// verify packet doesn't end before the version, meaning still left place for " HTTP/x.y" (9 chars)
	std::ptrdiff_t actualLen = verPos + 9 - (char*)m_HttpRequest->m_Data;
	if (static_cast<size_t>(actualLen) > m_HttpRequest->getDataLen())
	{
		m_Version = HttpVersionUnknown;
		m_VersionOffset = -1;
		return;
	}

	//skip " HTTP/" (6 chars)
	verPos += 6;
	auto versionAsEnum = HttpVersionStringToEnum.find(std::string(verPos, verPos + 3));
	if (versionAsEnum == HttpVersionStringToEnum.end())
	{
		m_Version = HttpVersionUnknown;
	}
	else
	{
		m_Version = versionAsEnum->second;
	}

	m_VersionOffset = verPos - (char*)m_HttpRequest->m_Data;
}

bool HttpRequestFirstLine::setMethod(HttpRequestLayer::HttpMethod newMethod)
{
	if (newMethod == HttpRequestLayer::HttpMethodUnknown)
	{
		PCPP_LOG_ERROR("Requested method is HttpMethodUnknown");
		return false;
	}

	//extend or shorten layer
	int lengthDifference = MethodEnumToString[newMethod].length() - MethodEnumToString[m_Method].length();
	if (lengthDifference > 0)
	{
		if (!m_HttpRequest->extendLayer(0, lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_HttpRequest->shortenLayer(0, 0-lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;

		}
	}

	if (lengthDifference != 0)
		m_HttpRequest->shiftFieldsOffset(m_HttpRequest->getFirstField(), lengthDifference);

	memcpy(m_HttpRequest->m_Data, MethodEnumToString[newMethod].c_str(), MethodEnumToString[newMethod].length());

	m_Method = newMethod;
	m_UriOffset += lengthDifference;
	m_VersionOffset += lengthDifference;

	return true;
}

std::string HttpRequestFirstLine::getUri() const
{
	std::string result;
	if (m_UriOffset != -1 && m_VersionOffset != -1)
		result.assign((const char*)m_HttpRequest->m_Data + m_UriOffset, m_VersionOffset - 6 - m_UriOffset);

	//else first line is illegal, return empty string

	return result;
}

bool HttpRequestFirstLine::setUri(std::string newUri)
{
	// make sure the new URI begins with "/"
	if (newUri.compare(0, 1, "/") != 0)
		newUri = "/" + newUri;

	//extend or shorten layer
	std::string currentUri = getUri();
	int lengthDifference = newUri.length() - currentUri.length();
	if (lengthDifference > 0)
	{
		if (!m_HttpRequest->extendLayer(m_UriOffset, lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_HttpRequest->shortenLayer(m_UriOffset, 0-lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;
		}
	}

	if (lengthDifference != 0)
		m_HttpRequest->shiftFieldsOffset(m_HttpRequest->getFirstField(), lengthDifference);

	memcpy(m_HttpRequest->m_Data + m_UriOffset, newUri.c_str(), newUri.length());

	m_VersionOffset += lengthDifference;

	return true;
}

void HttpRequestFirstLine::setVersion(HttpVersion newVersion)
{
	if (m_VersionOffset == -1)
		return;

	if (newVersion == HttpVersionUnknown)
		return;

	char* verPos = (char*)(m_HttpRequest->m_Data + m_VersionOffset);
	memcpy(verPos, VersionEnumToString[newVersion].c_str(), 3);

	m_Version = newVersion;
}






// -------- Class HttpResponseLayer -----------------

/**
 * @struct HttpResponseStatusCodeHash
 * @brief The helper structure for hash HttpResponseStatusCode while using std::unordered_map
 */
struct HttpResponseStatusCodeHash
{
	size_t operator()(const HttpResponseStatusCode& status) const
	{
		return std::hash<int>()(static_cast<int>(status));
	}
};

const std::unordered_map<HttpResponseStatusCode, std::string, HttpResponseStatusCodeHash> statusCodeExplanationStringMap = {
    {HttpResponseStatusCode::Http100Continue, "Continue"},
    {HttpResponseStatusCode::Http101SwitchingProtocols, "Switching Protocols"},
    {HttpResponseStatusCode::Http102Processing, "Processing"},
    {HttpResponseStatusCode::Http103EarlyHints, "Early Hints"},
    {HttpResponseStatusCode::Http200OK, "OK"},
    {HttpResponseStatusCode::Http201Created, "Created"},
    {HttpResponseStatusCode::Http202Accepted, "Accepted"},
    {HttpResponseStatusCode::Http203NonAuthoritativeInformation, "Non-Authoritative Information"},
    {HttpResponseStatusCode::Http204NoContent, "No Content"},
    {HttpResponseStatusCode::Http205ResetContent, "Reset Content"},
    {HttpResponseStatusCode::Http206PartialContent, "Partial Content"},
    {HttpResponseStatusCode::Http207MultiStatus, "Multi-Status"},
    {HttpResponseStatusCode::Http208AlreadyReported, "Already Reported"},
    {HttpResponseStatusCode::Http226IMUsed, "IM Used"},
    {HttpResponseStatusCode::Http300MultipleChoices, "Multiple Choices"},
    {HttpResponseStatusCode::Http301MovedPermanently, "Moved Permanently"},
    {HttpResponseStatusCode::Http302, "(various messages)"},
    {HttpResponseStatusCode::Http303SeeOther, "See Other"},
    {HttpResponseStatusCode::Http304NotModified, "Not Modified"},
    {HttpResponseStatusCode::Http305UseProxy, "Use Proxy"},
    {HttpResponseStatusCode::Http306SwitchProxy, "Switch Proxy"},
    {HttpResponseStatusCode::Http307TemporaryRedirect, "Temporary Redirect"},
    {HttpResponseStatusCode::Http308PermanentRedirect, "Permanent Redirect"},
    {HttpResponseStatusCode::Http400BadRequest, "Bad Request"},
    {HttpResponseStatusCode::Http401Unauthorized, "Unauthorized"},
    {HttpResponseStatusCode::Http402PaymentRequired, "Payment Required"},
    {HttpResponseStatusCode::Http403Forbidden, "Forbidden"},
    {HttpResponseStatusCode::Http404NotFound, "Not Found"},
    {HttpResponseStatusCode::Http405MethodNotAllowed, "Method Not Allowed"},
    {HttpResponseStatusCode::Http406NotAcceptable, "Not Acceptable"},
    {HttpResponseStatusCode::Http407ProxyAuthenticationRequired, "Proxy Authentication Required"},
    {HttpResponseStatusCode::Http408RequestTimeout, "Request Timeout"},
    {HttpResponseStatusCode::Http409Conflict, "Conflict"},
    {HttpResponseStatusCode::Http410Gone, "Gone"},
    {HttpResponseStatusCode::Http411LengthRequired, "Length Required"},
    {HttpResponseStatusCode::Http412PreconditionFailed, "Precondition Failed"},
    {HttpResponseStatusCode::Http413RequestEntityTooLarge, "Request Entity Too Large"},
    {HttpResponseStatusCode::Http414RequestURITooLong, "Request-URI Too Long"},
    {HttpResponseStatusCode::Http415UnsupportedMediaType, "Unsupported Media Type"},
    {HttpResponseStatusCode::Http416RequestedRangeNotSatisfiable, "Requested Range Not Satisfiable"},
    {HttpResponseStatusCode::Http417ExpectationFailed, "Expectation Failed"},
    {HttpResponseStatusCode::Http418ImATeapot, "I'm a teapot"},
    {HttpResponseStatusCode::Http419AuthenticationTimeout, "Authentication Timeout"},
    {HttpResponseStatusCode::Http420, "(various messages)"},
    {HttpResponseStatusCode::Http421MisdirectedRequest, "Misdirected Request"},
    {HttpResponseStatusCode::Http422UnprocessableEntity, "Unprocessable Entity"},
    {HttpResponseStatusCode::Http423Locked, "Locked"},
    {HttpResponseStatusCode::Http424FailedDependency, "Failed Dependency"},
    {HttpResponseStatusCode::Http425TooEarly, "Too Early"},
    {HttpResponseStatusCode::Http426UpgradeRequired, "Upgrade Required"},
    {HttpResponseStatusCode::Http428PreconditionRequired, "Precondition Required"},
    {HttpResponseStatusCode::Http429TooManyRequests, "Too Many Requests"},
    {HttpResponseStatusCode::Http431RequestHeaderFieldsTooLarge, "Request Header Fields Too Large"},
    {HttpResponseStatusCode::Http440LoginTimeout, "Login Timeout"},
    {HttpResponseStatusCode::Http444NoResponse, "No Response"},
    {HttpResponseStatusCode::Http449RetryWith, "Retry With"},
    {HttpResponseStatusCode::Http450BlockedByWindowsParentalControls, "Blocked by Windows Parental Controls"},
    {HttpResponseStatusCode::Http451, "(various messages)"},
    {HttpResponseStatusCode::Http494RequestHeaderTooLarge, "Request Header Too Large"},
    {HttpResponseStatusCode::Http495CertError, "Cert Error"},
    {HttpResponseStatusCode::Http496NoCert, "No Cert"},
    {HttpResponseStatusCode::Http497HTTPtoHTTPS, "HTTP to HTTPS"},
    {HttpResponseStatusCode::Http498TokenExpiredInvalid, "Token expired/invalid"},
    {HttpResponseStatusCode::Http499, "(various messages)"},
    {HttpResponseStatusCode::Http500InternalServerError, "Internal Server Error"},
    {HttpResponseStatusCode::Http501NotImplemented, "Not Implemented"},
    {HttpResponseStatusCode::Http502BadGateway, "Bad Gateway"},
    {HttpResponseStatusCode::Http503ServiceUnavailable, "Service Unavailable"},
    {HttpResponseStatusCode::Http504GatewayTimeout, "Gateway Timeout"},
    {HttpResponseStatusCode::Http505HTTPVersionNotSupported, "HTTP Version Not Supported"},
    {HttpResponseStatusCode::Http506VariantAlsoNegotiates, "Variant Also Negotiates"},
    {HttpResponseStatusCode::Http507InsufficientStorage, "Insufficient Storage"},
    {HttpResponseStatusCode::Http508LoopDetected, "Loop Detected"},
    {HttpResponseStatusCode::Http509BandwidthLimitExceeded, "Bandwidth Limit Exceeded"},
    {HttpResponseStatusCode::Http510NotExtended, "Not Extended"},
    {HttpResponseStatusCode::Http511NetworkAuthenticationRequired, "Network Authentication Required"},
    {HttpResponseStatusCode::Http520OriginError, "Origin Error"},
    {HttpResponseStatusCode::Http521WebServerIsDown, "Web server is down"},
    {HttpResponseStatusCode::Http522ConnectionTimedOut, "Connection timed out"},
    {HttpResponseStatusCode::Http523ProxyDeclinedRequest, "Proxy Declined Request"},
    {HttpResponseStatusCode::Http524aTimeoutOccurred, "A timeout occurred"},
    {HttpResponseStatusCode::Http598NetworkReadTimeoutError, "Network read timeout error"},
    {HttpResponseStatusCode::Http599NetworkConnectTimeoutError, "Network connect timeout error"},
    {HttpResponseStatusCode::HttpStatus1xxCodeUnknown, "1XX Status Code Unknown"},
    {HttpResponseStatusCode::HttpStatus2xxCodeUnknown, "2XX Status Code Unknown"},
    {HttpResponseStatusCode::HttpStatus3xxCodeUnknown, "3XX Status Code Unknown"},
    {HttpResponseStatusCode::HttpStatus4xxCodeUnknown, "4XX Status Code Unknown"},
    {HttpResponseStatusCode::HttpStatus5xxCodeUnknown, "5XX Status Code Unknown"},
    {HttpResponseStatusCode::HttpStatusCodeUnknown, "Status Code Unknown"},
};

HttpResponseLayer::HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)  : HttpMessage(data, dataLen, prevLayer, packet)
{
	m_Protocol = HTTPResponse;
	m_FirstLine = new HttpResponseFirstLine(this);
	m_FieldsOffset = m_FirstLine->getSize();
	parseFields();
}

HttpResponseLayer::HttpResponseLayer(HttpVersion version, HttpResponseStatusCode statusCode, std::string statusCodeString)
{
	m_Protocol = HTTPResponse;
	m_FirstLine = new HttpResponseFirstLine(this, version, statusCode, std::move(statusCodeString));
	m_FieldsOffset = m_FirstLine->getSize();
}

HttpResponseLayer::~HttpResponseLayer()
{
	delete m_FirstLine;
}


HttpResponseLayer::HttpResponseLayer(const HttpResponseLayer& other) : HttpMessage(other)
{
	m_FirstLine = new HttpResponseFirstLine(this);
}

HttpResponseLayer& HttpResponseLayer::operator=(const HttpResponseLayer& other)
{
	HttpMessage::operator=(other);

	if (m_FirstLine != nullptr)
		delete m_FirstLine;

	m_FirstLine = new HttpResponseFirstLine(this);

	return *this;
}


HeaderField* HttpResponseLayer::setContentLength(int contentLength, const std::string &prevFieldName)
{
	std::ostringstream contentLengthAsString;
	contentLengthAsString << contentLength;
	std::string contentLengthFieldName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
	HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
	if (contentLengthField == nullptr)
	{
		HeaderField* prevField = getFieldByName(prevFieldName);
		contentLengthField = insertField(prevField, PCPP_HTTP_CONTENT_LENGTH_FIELD, contentLengthAsString.str());
	}
	else
		contentLengthField->setFieldValue(contentLengthAsString.str());

	return contentLengthField;
}

int HttpResponseLayer::getContentLength() const
{
	std::string contentLengthFieldName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
	std::transform(contentLengthFieldName.begin(), contentLengthFieldName.end(), contentLengthFieldName.begin(), ::tolower);
	HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
	if (contentLengthField != nullptr)
		return atoi(contentLengthField->getFieldValue().c_str());
	return 0;
}

std::string HttpResponseLayer::toString() const
{
	static const int maxLengthToPrint = 120;
	std::string result = "HTTP response, ";
	int size = m_FirstLine->getSize() - 2; // the -2 is to remove \r\n at the end of the first line
	if (size <= maxLengthToPrint)
	{
		char* firstLine = new char[size+1];
		strncpy(firstLine, (char*)m_Data, size);
		firstLine[size] = 0;
		result += std::string(firstLine);
		delete[] firstLine;
	}
	else
	{
		char firstLine[maxLengthToPrint+1];
		strncpy(firstLine, (char*)m_Data, maxLengthToPrint-3);
		firstLine[maxLengthToPrint-3] = '.';
		firstLine[maxLengthToPrint-2] = '.';
		firstLine[maxLengthToPrint-1] = '.';
		firstLine[maxLengthToPrint] = 0;
		result += std::string(firstLine);
	}

	return result;
}


// -------- Class HttpResponseFirstLine -----------------


int HttpResponseFirstLine::getStatusCodeAsInt() const
{
	return m_StatusCode.toInt();
}

std::string HttpResponseFirstLine::getStatusCodeString() const
{
	std::string result;
	const int statusStringOffset = 13;
	if (!m_StatusCode.isUnsupportedCode())
	{
		int statusStringEndOffset = m_FirstLineEndOffset - 2;
		if ((*(m_HttpResponse->m_Data + statusStringEndOffset)) != '\r')
			statusStringEndOffset++;
		result.assign((char*)(m_HttpResponse->m_Data + statusStringOffset), statusStringEndOffset-statusStringOffset);
	}

	//else first line is illegal, return empty string

	return result;
}

bool HttpResponseFirstLine::setStatusCode(HttpResponseStatusCode newStatusCode, std::string statusCodeString)
{
	if (m_StatusCode.isUnsupportedCode())
	{
		PCPP_LOG_ERROR("Requested status code is " + m_StatusCode.toString() + statusCodeExplanationStringMap.at(m_StatusCode));
		return false;
	}

	//extend or shorten layer

	size_t statusStringOffset = 13;
	if (statusCodeString == "")
		statusCodeString = statusCodeExplanationStringMap.at(newStatusCode);
	int lengthDifference = statusCodeString.length() - getStatusCodeString().length();
	if (lengthDifference > 0)
	{
		if (!m_HttpResponse->extendLayer(statusStringOffset, lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_HttpResponse->shortenLayer(statusStringOffset, 0-lengthDifference))
		{
			PCPP_LOG_ERROR("Cannot change layer size");
			return false;

		}
	}

	if (lengthDifference != 0)
		m_HttpResponse->shiftFieldsOffset(m_HttpResponse->getFirstField(), lengthDifference);

	// copy status string
	memcpy(m_HttpResponse->m_Data+statusStringOffset, statusCodeString.c_str(), statusCodeString.length());

	// change status code
	memcpy(m_HttpResponse->m_Data+9, newStatusCode.toString().c_str(), 3);

	m_StatusCode = newStatusCode;

	m_FirstLineEndOffset += lengthDifference;

	return true;

}

void HttpResponseFirstLine::setVersion(HttpVersion newVersion)
{
	if (newVersion == HttpVersionUnknown)
		return;

	char* verPos = (char*)(m_HttpResponse->m_Data + 5);
	memcpy(verPos, VersionEnumToString[newVersion].c_str(), 3);

	m_Version = newVersion;
}

HttpResponseStatusCode HttpResponseFirstLine::parseStatusCode(const char* data, size_t dataLen)
{
	// minimum data should be 12B long: "HTTP/x.y XXX"
	if (!data || dataLen < 12)
	{
		return HttpResponseStatusCode::HttpStatusCodeUnknown;
	}

	std::string statusCodeDataString(data + 9, 3);

	for(const auto& pair : statusCodeExplanationStringMap)
	{
		if(int(pair.first) == std::stoi(statusCodeDataString))
		{
			return pair.first;
		}
	}

	switch(statusCodeDataString[0])
	{
	case '1':{
		return HttpResponseStatusCode::HttpStatus1xxCodeUnknown;
	}
	case '2':{
		return HttpResponseStatusCode::HttpStatus2xxCodeUnknown;
	}
	case '3':{
		return HttpResponseStatusCode::HttpStatus3xxCodeUnknown;
	}
	case '4':{
		return HttpResponseStatusCode::HttpStatus4xxCodeUnknown;
	}
	case '5':{
		return HttpResponseStatusCode::HttpStatus5xxCodeUnknown;
	}
	default:
	{
		return HttpResponseStatusCode::HttpStatusCodeUnknown;
	}
	}
}

HttpResponseFirstLine::HttpResponseFirstLine(HttpResponseLayer* httpResponse) : m_HttpResponse(httpResponse)
{
	m_Version = parseVersion((char*)m_HttpResponse->m_Data, m_HttpResponse->getDataLen());
	if (m_Version == HttpVersionUnknown)
	{
		m_StatusCode = HttpResponseStatusCode::HttpStatusCodeUnknown;
	}
	else
	{
		m_StatusCode = parseStatusCode((char*)m_HttpResponse->m_Data, m_HttpResponse->getDataLen());
	}


	char* endOfFirstLine;
	if ((endOfFirstLine = (char*)memchr((char*)(m_HttpResponse->m_Data), '\n', m_HttpResponse->m_DataLen)) != nullptr)
	{
		m_FirstLineEndOffset = endOfFirstLine - (char*)m_HttpResponse->m_Data + 1;
		m_IsComplete = true;
	}
	else
	{
		m_FirstLineEndOffset = m_HttpResponse->getDataLen();
		m_IsComplete = false;
	}

	if (Logger::getInstance().isDebugEnabled(PacketLogModuleHttpLayer))
	{
		std::string version = (m_Version == HttpVersionUnknown ? "Unknown" : VersionEnumToString[m_Version]);
		int statusCode = (m_StatusCode == HttpResponseStatusCode::HttpStatusCodeUnknown ? 0 : m_StatusCode.toInt());
		PCPP_LOG_DEBUG("Version='" << version << "'; Status code=" << statusCode << " '" << getStatusCodeString() << "'");
	}
}


HttpResponseFirstLine::HttpResponseFirstLine(HttpResponseLayer* httpResponse,  HttpVersion version, HttpResponseStatusCode statusCode, std::string statusCodeString)
{
	if (statusCode.isUnsupportedCode())
	{
		m_Exception.setMessage("Status code supplied was " + statusCodeExplanationStringMap.at(statusCode));
		throw m_Exception;
	}

	if (version == HttpVersionUnknown)
	{
		m_Exception.setMessage("Version supplied was HttpVersionUnknown");
		throw m_Exception;
	}

	m_HttpResponse = httpResponse;

	m_StatusCode = statusCode;
	m_Version = version;

	if(statusCodeString == "") {
		statusCodeString = statusCodeExplanationStringMap.at(m_StatusCode);
	}
	std::string firstLine = "HTTP/" + VersionEnumToString[m_Version] + " " + m_StatusCode.toString() + " " +  statusCodeString +  "\r\n";

	m_FirstLineEndOffset = firstLine.length();

	m_HttpResponse->m_DataLen = firstLine.length();
	m_HttpResponse->m_Data = new uint8_t[m_HttpResponse->m_DataLen];
	memcpy(m_HttpResponse->m_Data, firstLine.c_str(), m_HttpResponse->m_DataLen);

	m_IsComplete = true;
}

HttpVersion HttpResponseFirstLine::parseVersion(const char* data, size_t dataLen)
{
	if (!data || dataLen < 8) // "HTTP/x.y"
	{
		PCPP_LOG_DEBUG("HTTP response length < 8, cannot identify version");
		return HttpVersionUnknown;
	}

	if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' || data[4] != '/')
	{
		PCPP_LOG_DEBUG("HTTP response does not begin with 'HTTP/'");
		return HttpVersionUnknown;
	}

	const char* verPos = data + 5;
	auto versionAsEnum = HttpVersionStringToEnum.find(std::string(verPos, verPos + 3));
	if (versionAsEnum == HttpVersionStringToEnum.end())
	{
		return HttpVersionUnknown;
	}
	return versionAsEnum->second;
}

} // namespace pcpp
