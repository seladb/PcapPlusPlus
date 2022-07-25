#define LOG_MODULE PacketLogModuleHttpLayer

#include "Logger.h"
#include "GeneralUtils.h"
#include "HttpLayer.h"
#include <string.h>
#include <algorithm>
#include <stdlib.h>
#include <exception>

namespace pcpp
{


// -------- Class HttpMessage -----------------


HeaderField* HttpMessage::addField(const std::string& fieldName, const std::string& fieldValue)
{
	if (getFieldByName(fieldName) != NULL)
	{
		PCPP_LOG_ERROR("Field '" << fieldName << "' already exists!");
		return NULL;
	}

	return TextBasedProtocolMessage::addField(fieldName, fieldValue);
}

HeaderField* HttpMessage::addField(const HeaderField& newField)
{
	if (getFieldByName(newField.getFieldName()) != NULL)
	{
		PCPP_LOG_ERROR("Field '" << newField.getFieldName() << "' already exists!");
		return NULL;
	}

	return TextBasedProtocolMessage::addField(newField);
}

HeaderField* HttpMessage::insertField(HeaderField* prevField, const std::string& fieldName, const std::string& fieldValue)
{
	if (getFieldByName(fieldName) != NULL)
	{
		PCPP_LOG_ERROR("Field '" << fieldName << "' already exists!");
		return NULL;
	}

	return TextBasedProtocolMessage::insertField(prevField, fieldName, fieldValue);
}

HeaderField* HttpMessage::insertField(HeaderField* prevField, const HeaderField& newField)
{
	if (getFieldByName(newField.getFieldName()) != NULL)
	{
		PCPP_LOG_ERROR("Field '" << newField.getFieldName() << "' already exists!");
		return NULL;
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

HttpRequestLayer::HttpRequestLayer(HttpMethod method, std::string uri, HttpVersion version)
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

	if (m_FirstLine != NULL)
		delete m_FirstLine;

	m_FirstLine = new HttpRequestFirstLine(this);

	return *this;
}


std::string HttpRequestLayer::getUrl() const
{
	HeaderField* hostField = getFieldByName(PCPP_HTTP_HOST_FIELD);
	if (hostField == NULL)
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

const std::string VersionEnumToString[3] = {
		"0.9",
		"1.0",
		"1.1"
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
	if ((endOfFirstLine = (char*)memchr((char*)(m_HttpRequest->m_Data + m_VersionOffset), '\n', m_HttpRequest->m_DataLen-(size_t)m_VersionOffset)) != NULL)
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

HttpRequestFirstLine::HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpRequestLayer::HttpMethod method, HttpVersion version, std::string uri)
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

HttpRequestLayer::HttpMethod HttpRequestFirstLine::parseMethod(char* data, size_t dataLen)
{
	if (dataLen < 4)
	{
		return HttpRequestLayer::HttpMethodUnknown;
	}

	switch (data[0])
	{
	case 'G':
		if (data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
			return HttpRequestLayer::HttpGET;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;

	case 'D':
		if (dataLen < 7)
			return HttpRequestLayer::HttpMethodUnknown;
		else if (data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
			return HttpRequestLayer::HttpDELETE;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;

	case 'C':
		if (dataLen < 8)
			return HttpRequestLayer::HttpMethodUnknown;
		else if (data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ')
			return HttpRequestLayer::HttpCONNECT;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;

	case 'T':
		if (dataLen < 6)
			return HttpRequestLayer::HttpMethodUnknown;
		else if (data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E' && data[5] == ' ')
			return HttpRequestLayer::HttpTRACE;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;


	case 'H':
		if (dataLen < 5)
			return HttpRequestLayer::HttpMethodUnknown;
		else if (data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ')
			return HttpRequestLayer::HttpHEAD;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;

	case 'O':
		if (dataLen < 8)
			return HttpRequestLayer::HttpMethodUnknown;
		else if (data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ')
			return HttpRequestLayer::HttpOPTIONS;
		else
			return HttpRequestLayer::HttpMethodUnknown;
		break;

	case 'P':
		switch (data[1])
		{
		case 'U':
			if (data[2] == 'T' && data[3] == ' ')
				return HttpRequestLayer::HttpPUT;
			else
				return HttpRequestLayer::HttpMethodUnknown;
			break;

		case 'O':
			if (dataLen < 5)
				return HttpRequestLayer::HttpMethodUnknown;
			else if (data[2] == 'S' && data[3] == 'T' && data[4] == ' ')
				return HttpRequestLayer::HttpPOST;
			else
				return HttpRequestLayer::HttpMethodUnknown;
			break;

		case 'A':
			if (dataLen < 6)
				return HttpRequestLayer::HttpMethodUnknown;
			else if (data[2] == 'T' && data[3] == 'C' && data[4] == 'H' && data[5] == ' ')
				return HttpRequestLayer::HttpPATCH;
			else
				return HttpRequestLayer::HttpMethodUnknown;
			break;

		default:
			return HttpRequestLayer::HttpMethodUnknown;
		}
		break;

	default:
		return HttpRequestLayer::HttpMethodUnknown;
	}
}

void HttpRequestFirstLine::parseVersion()
{
	char* data = (char*)(m_HttpRequest->m_Data + m_UriOffset);
	char* verPos = cross_platform_memmem(data, m_HttpRequest->getDataLen() - m_UriOffset, " HTTP/", 6);
	if (verPos == NULL)
	{
		m_Version = HttpVersionUnknown;
		m_VersionOffset = -1;
		return;
	}

	// verify packet doesn't end before the version, meaning still left place for " HTTP/x.y" (9 chars)
	if ((uint16_t)(verPos + 9 - (char*)m_HttpRequest->m_Data) > m_HttpRequest->getDataLen())
	{
		m_Version = HttpVersionUnknown;
		m_VersionOffset = -1;
		return;
	}

	//skip " HTTP/" (6 chars)
	verPos += 6;
	switch (verPos[0])
	{
	case '0':
		if (verPos[1] == '.' && verPos[2] == '9')
			m_Version = ZeroDotNine;
		else
			m_Version = HttpVersionUnknown;
		break;

	case '1':
		if (verPos[1] == '.' && verPos[2] == '0')
			m_Version = OneDotZero;
		else if (verPos[1] == '.' && verPos[2] == '1')
			m_Version = OneDotOne;
		else
			m_Version = HttpVersionUnknown;
		break;

	default:
		m_Version = HttpVersionUnknown;
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



const std::string StatusCodeEnumToString[80] = {
		"Continue",
		"Switching Protocols",
		"Processing",
		"OK",
		"Created",
		"Accepted",
		"Non-Authoritative Information",
		"No Content",
		"Reset Content",
		"Partial Content",
		"Multi-Status",
		"Already Reported",
		"IM Used",
		"Multiple Choices",
		"Moved Permanently",
		"Found",
		"See Other",
		"Not Modified",
		"Use Proxy",
		"Switch Proxy",
		"Temporary Redirect",
		"Permanent Redirect",
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
		"Precondition Failed",
		"Request Entity Too Large",
		"Request-URI Too Long",
		"Unsupported Media Type",
		"Requested Range Not Satisfiable",
		"Expectation Failed",
		"I'm a teapot",
		"Authentication Timeout",
		"Method Failure",
		"Unprocessable Entity",
		"Locked",
		"Failed Dependency",
		"Upgrade Required",
		"Precondition Required",
		"Too Many Requests",
		"Request Header Fields Too Large",
		"Login Timeout",
		"No Response",
		"Retry With",
		"Blocked by Windows Parental Controls",
		"Unavailable For Legal Reasons",
		"Request Header Too Large",
		"Cert Error",
		"No Cert",
		"HTTP to HTTPS",
		"Token expired/invalid",
		"Client Closed Request",
		"Internal Server Error",
		"Not Implemented",
		"Bad Gateway",
		"Service Unavailable",
		"Gateway Timeout",
		"HTTP Version Not Supported",
		"Variant Also Negotiates",
		"Insufficient Storage",
		"Loop Detected",
		"Bandwidth Limit Exceeded",
		"Not Extended",
		"Network Authentication Required",
		"Origin Error",
		"Web server is down",
		"Connection timed out",
		"Proxy Declined Request",
		"A timeout occurred",
		"Network read timeout error",
		"Network connect timeout error"
};


const int StatusCodeEnumToInt[80] = {
		100,
		101,
		102,
		200,
		201,
		202,
		203,
		204,
		205,
		206,
		207,
		208,
		226,
		300,
		301,
		302,
		303,
		304,
		305,
		306,
		307,
		308,
		400,
		401,
		402,
		403,
		404,
		405,
		406,
		407,
		408,
		409,
		410,
		411,
		412,
		413,
		414,
		415,
		416,
		417,
		418,
		419,
		420,
		422,
		423,
		424,
		426,
		428,
		429,
		431,
		440,
		444,
		449,
		450,
		451,
		494,
		495,
		496,
		497,
		498,
		499,
		500,
		501,
		502,
		503,
		504,
		505,
		506,
		507,
		508,
		509,
		510,
		511,
		520,
		521,
		522,
		523,
		524,
		598,
		599
};



HttpResponseLayer::HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)  : HttpMessage(data, dataLen, prevLayer, packet)
{
	m_Protocol = HTTPResponse;
	m_FirstLine = new HttpResponseFirstLine(this);
	m_FieldsOffset = m_FirstLine->getSize();
	parseFields();
}

HttpResponseLayer::HttpResponseLayer(HttpVersion version, HttpResponseLayer::HttpResponseStatusCode statusCode, std::string statusCodeString)
{
	m_Protocol = HTTPResponse;
	m_FirstLine = new HttpResponseFirstLine(this, version, statusCode, statusCodeString);
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

	if (m_FirstLine != NULL)
		delete m_FirstLine;

	m_FirstLine = new HttpResponseFirstLine(this);

	return *this;
}


HeaderField* HttpResponseLayer::setContentLength(int contentLength, const std::string prevFieldName)
{
	std::ostringstream contentLengthAsString;
	contentLengthAsString << contentLength;
	std::string contentLengthFieldName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
	HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
	if (contentLengthField == NULL)
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
	if (contentLengthField != NULL)
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
	return StatusCodeEnumToInt[m_StatusCode];
}

std::string HttpResponseFirstLine::getStatusCodeString() const
{
	std::string result;
	int statusStringOffset = 13;
	if (m_StatusCode != HttpResponseLayer::HttpStatusCodeUnknown)
	{
		int statusStringEndOffset = m_FirstLineEndOffset - 2;
		if ((*(m_HttpResponse->m_Data + statusStringEndOffset)) != '\r')
			statusStringEndOffset++;
		result.assign((char*)(m_HttpResponse->m_Data + statusStringOffset), statusStringEndOffset-statusStringOffset);
	}

	//else first line is illegal, return empty string

	return result;
}

bool HttpResponseFirstLine::setStatusCode(HttpResponseLayer::HttpResponseStatusCode newStatusCode, std::string statusCodeString)
{
	if (newStatusCode == HttpResponseLayer::HttpStatusCodeUnknown)
	{
		PCPP_LOG_ERROR("Requested status code is HttpStatusCodeUnknown");
		return false;
	}

	//extend or shorten layer

	size_t statusStringOffset = 13;
	if (statusCodeString == "")
		statusCodeString = StatusCodeEnumToString[newStatusCode];
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
	std::ostringstream statusCodeAsString;
	statusCodeAsString << StatusCodeEnumToInt[newStatusCode];
	memcpy(m_HttpResponse->m_Data+9, statusCodeAsString.str().c_str(), 3);

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

HttpResponseLayer::HttpResponseStatusCode HttpResponseFirstLine::validateStatusCode(char* data, size_t dataLen, HttpResponseLayer::HttpResponseStatusCode potentialCode)
{
	if (dataLen < 1 || data[0] != ' ')
		return HttpResponseLayer::HttpStatusCodeUnknown;

	return potentialCode;
}

HttpResponseLayer::HttpResponseStatusCode HttpResponseFirstLine::parseStatusCode(char* data, size_t dataLen)
{
	if (parseVersion(data, dataLen) == HttpVersionUnknown)
		return HttpResponseLayer::HttpStatusCodeUnknown;

	// minimum data should be 12B long: "HTTP/x.y XXX"
	if (dataLen < 12)
		return HttpResponseLayer::HttpStatusCodeUnknown;

	char* statusCodeData = data + 9;
	size_t statusCodeDataLen = dataLen - 9;

	switch (statusCodeData[0])
	{
	case '1':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http100Continue);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http101SwitchingProtocols);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http102Processing);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		default:
			return HttpResponseLayer::HttpStatusCodeUnknown;
		};

		break;
	case '2':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http200OK);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http201Created);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http202Accepted);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http203NonAuthoritativeInformation);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http204NoContent);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http205ResetContent);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http206PartialContent);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http207MultiStatus);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http208AlreadyReported);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;
		case '2':
			switch (statusCodeData[2])
			{
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http226IMUsed);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		default:
			return HttpResponseLayer::HttpStatusCodeUnknown;

		};

		break;

	case '3':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http300MultipleChoices);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http301MovedPermanently);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http302);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http303SeeOther);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http304NotModified);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http305UseProxy);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http306SwitchProxy);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http307TemporaryRedirect);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http308PermanentRedirect);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;

		default:
			return HttpResponseLayer::HttpStatusCodeUnknown;
		};

		break;

	case '4':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http400BadRequest);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http401Unauthorized);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http402PaymentRequired);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http403Forbidden);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http404NotFound);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http405MethodNotAllowed);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http406NotAcceptable);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http407ProxyAuthenticationRequired);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http408RequestTimeout);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http409Conflict);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;

		case '1':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http410Gone);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http411LengthRequired);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http412PreconditionFailed);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http413RequestEntityTooLarge);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http414RequestURITooLong);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http415UnsupportedMediaType);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http416RequestedRangeNotSatisfiable);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http417ExpectationFailed);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http418Imateapot);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http419AuthenticationTimeout);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;

		case '2':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http420);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http422UnprocessableEntity);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http423Locked);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http424FailedDependency);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http426UpgradeRequired);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http428PreconditionRequired);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http429TooManyRequests);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;

		case '3':
			return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http431RequestHeaderFieldsTooLarge);

		case '4':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http440LoginTimeout);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http444NoResponse);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http449RetryWith);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		case '5':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http450BlockedByWindowsParentalControls);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http451);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		case '9':
			switch (statusCodeData[2])
			{
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http494RequestHeaderTooLarge);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http495CertError);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http496NoCert);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http497HTTPtoHTTPS);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http498TokenExpiredInvalid);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http499);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		default:
			return HttpResponseLayer::HttpStatusCodeUnknown;
		};

		break;

	case '5':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http500InternalServerError);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http501NotImplemented);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http502BadGateway);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http503ServiceUnavailable);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http504GatewayTimeout);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http505HTTPVersionNotSupported);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http506VariantAlsoNegotiates);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http507InsufficientStorage);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http508LoopDetected);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http509BandwidthLimitExceeded);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;

			};

			break;

		case '1':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http510NotExtended);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http511NetworkAuthenticationRequired);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		case '2':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http520OriginError);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http521WebServerIsDown);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http522ConnectionTimedOut);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http523ProxyDeclinedRequest);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http524aTimeoutOccurred);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		case '9':
			switch (statusCodeData[2])
			{
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http598NetworkReadTimeoutError);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, HttpResponseLayer::Http599NetworkConnectTimeoutError);
			default:
				return HttpResponseLayer::HttpStatusCodeUnknown;
			};

			break;

		default:
			return HttpResponseLayer::HttpStatusCodeUnknown;
		};

		break;

	default:
		return HttpResponseLayer::HttpStatusCodeUnknown;
	}

	return HttpResponseLayer::HttpStatusCodeUnknown;
}

HttpResponseFirstLine::HttpResponseFirstLine(HttpResponseLayer* httpResponse) : m_HttpResponse(httpResponse)
{
	m_Version = parseVersion((char*)m_HttpResponse->m_Data, m_HttpResponse->getDataLen());
	if (m_Version == HttpVersionUnknown)
	{
		m_StatusCode = HttpResponseLayer::HttpStatusCodeUnknown;
	}
	else
	{
		m_StatusCode = parseStatusCode((char*)m_HttpResponse->m_Data, m_HttpResponse->getDataLen());
	}


	char* endOfFirstLine;
	if ((endOfFirstLine = (char*)memchr((char*)(m_HttpResponse->m_Data), '\n', m_HttpResponse->m_DataLen)) != NULL)
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
		int statusCode = (m_StatusCode == HttpResponseLayer::HttpStatusCodeUnknown ? 0 : StatusCodeEnumToInt[m_StatusCode]);
		PCPP_LOG_DEBUG("Version='" << version << "'; Status code=" << statusCode << " '" << getStatusCodeString() << "'");
	}
}


HttpResponseFirstLine::HttpResponseFirstLine(HttpResponseLayer* httpResponse,  HttpVersion version, HttpResponseLayer::HttpResponseStatusCode statusCode, std::string statusCodeString)
{
	if (statusCode == HttpResponseLayer::HttpStatusCodeUnknown)
	{
		m_Exception.setMessage("Status code supplied was HttpStatusCodeUnknown");
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

	std::ostringstream statusCodeAsString;
	statusCodeAsString << StatusCodeEnumToInt[m_StatusCode];
	if (statusCodeString == "")
		statusCodeString = StatusCodeEnumToString[m_StatusCode];
	std::string firstLine = "HTTP/" + VersionEnumToString[m_Version] + " " + statusCodeAsString.str() + " " +  statusCodeString +  "\r\n";

	m_FirstLineEndOffset = firstLine.length();

	m_HttpResponse->m_DataLen = firstLine.length();
	m_HttpResponse->m_Data = new uint8_t[m_HttpResponse->m_DataLen];
	memcpy(m_HttpResponse->m_Data, firstLine.c_str(), m_HttpResponse->m_DataLen);

	m_IsComplete = true;
}

HttpVersion HttpResponseFirstLine::parseVersion(char* data, size_t dataLen)
{
	if (dataLen < 8) // "HTTP/x.y"
	{
		PCPP_LOG_DEBUG("HTTP response length < 8, cannot identify version");
		return HttpVersionUnknown;
	}

	if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' || data[4] != '/')
	{
		PCPP_LOG_DEBUG("HTTP response does not begin with 'HTTP/'");
		return HttpVersionUnknown;
	}

	char* verPos = data + 5;
	switch (verPos[0])
	{
	case '0':
		if (verPos[1] == '.' && verPos[2] == '9')
			return ZeroDotNine;
		else
			return HttpVersionUnknown;
		break;

	case '1':
		if (verPos[1] == '.' && verPos[2] == '0')
			return OneDotZero;
		else if (verPos[1] == '.' && verPos[2] == '1')
			return OneDotOne;
		else
			return HttpVersionUnknown;
		break;

	default:
		return HttpVersionUnknown;
	}
}

} // namespace pcpp
