#define LOG_MODULE PacketLogModuleSipLayer

#include "SipLayer.h"
#include "SdpLayer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include <string.h>
#include <algorithm>
#include <stdlib.h>
#include <exception>

namespace pcpp
{

const std::string SipMethodEnumToString[14] = {
		"INVITE",
		"ACK",
		"BYE",
		"CANCEL",
		"REGISTER",
		"PRACK",
		"OPTIONS",
		"SUBSCRIBE",
		"NOTIFY",
		"PUBLISH",
		"INFO",
		"REFER",
		"MESSAGE",
		"UPDATE"
};




// -------- Class SipLayer -----------------

int SipLayer::getContentLength()
{
	std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
	std::transform(contentLengthFieldName.begin(), contentLengthFieldName.end(), contentLengthFieldName.begin(), ::tolower);
	HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
	if (contentLengthField != NULL)
		return atoi(contentLengthField->getFieldValue().c_str());
	return 0;
}

HeaderField* SipLayer::setContentLength(int contentLength, const std::string prevFieldName)
{
	char contentLengthAsString[20];
	snprintf (contentLengthAsString, sizeof(contentLengthAsString), "%d",contentLength);
	std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
	HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
	if (contentLengthField == NULL)
	{
		HeaderField* prevField = getFieldByName(prevFieldName);
		contentLengthField = insertField(prevField, PCPP_SIP_CONTENT_LENGTH_FIELD, contentLengthAsString);
	}
	else
		contentLengthField->setFieldValue(std::string(contentLengthAsString));

	return contentLengthField;
}

void SipLayer::parseNextLayer()
{
	if (getLayerPayloadSize() == 0)
		return;

	size_t headerLen = getHeaderLen();
	if (getContentLength() > 0)
	{
		m_NextLayer = new SdpLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
	else
	{
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}
}

void SipLayer::computeCalculateFields()
{
	HeaderField* contentLengthField = getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD);
	if (contentLengthField == NULL)
		return;

	size_t headerLen = getHeaderLen();
	if (m_DataLen > headerLen)
	{
		int currentContentLength = getContentLength();
		if (currentContentLength != (int)(m_DataLen - headerLen))
			setContentLength(m_DataLen - headerLen);
	}
}








// -------- Class SipRequestFirstLine -----------------

SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest) : m_SipRequest(sipRequest)
{
	m_Method = parseMethod((char*)m_SipRequest->m_Data, m_SipRequest->getDataLen());
	if (m_Method == SipRequestLayer::SipMethodUnknown)
	{
		m_UriOffset = -1;
		LOG_DEBUG("Couldn't resolve SIP request method");
	}
	else
		m_UriOffset = SipMethodEnumToString[m_Method].length() + 1;

	parseVersion();

	char* endOfFirstLine;
	if ((endOfFirstLine = (char *)memchr((char*)(m_SipRequest->m_Data + m_VersionOffset), '\n', m_SipRequest->m_DataLen-(size_t)m_VersionOffset)) != NULL)
	{
		m_FirstLineEndOffset = endOfFirstLine - (char*)m_SipRequest->m_Data + 1;
		m_IsComplete = true;
	}
	else
	{
		m_FirstLineEndOffset = m_SipRequest->getDataLen();
		m_IsComplete = false;
	}

	LOG_DEBUG("Method='%s'; SIP version='%s'; URI='%s'", SipMethodEnumToString[m_Method].c_str(), m_Version.c_str(), getUri().c_str());
}

SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest, SipRequestLayer::SipMethod method, std::string version, std::string uri)
try		// throw(SipRequestFirstLineException)
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

	std::string firstLine = SipMethodEnumToString[m_Method] + " " + uri + " "  + version + "\r\n";

	m_UriOffset =  SipMethodEnumToString[m_Method].length() + 1;
	m_FirstLineEndOffset = firstLine.length();
	m_VersionOffset = m_UriOffset + uri.length() + 6;

	m_SipRequest->m_DataLen = firstLine.length();
	m_SipRequest->m_Data = new uint8_t[m_SipRequest->m_DataLen];
	memcpy(m_SipRequest->m_Data, firstLine.c_str(), m_SipRequest->m_DataLen);

	m_IsComplete = true;
}
catch(const SipRequestFirstLineException&) {
	throw;
}
catch(...) {
	std::terminate();
}
SipRequestLayer::SipMethod SipRequestFirstLine::parseMethod(char* data, size_t dataLen)
{
	if (dataLen < 4)
	{
		return SipRequestLayer::SipMethodUnknown;
	}

	switch (data[0])
	{
	case 'A':
		if (data[1] == 'C' && data[2] == 'K' && data[3] == ' ')
			return SipRequestLayer::SipACK;
		else
			return SipRequestLayer::SipMethodUnknown;
		break;

	case 'B':
		if (data[1] == 'Y' && data[2] == 'E' && data[3] == ' ')
			return SipRequestLayer::SipBYE;
		else
			return SipRequestLayer::SipMethodUnknown;
		break;

	case 'C':
		if (dataLen < 7)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'A' && data[2] == 'N' && data[3] == 'C' && data[4] == 'E' && data[5] == 'L' && data[6] == ' ')
			return SipRequestLayer::SipCANCEL;
		else
			return SipRequestLayer::SipMethodUnknown;
		break;

	case 'O':
		if (dataLen < 8)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ')
			return SipRequestLayer::SipOPTIONS;
		else
			return SipRequestLayer::SipMethodUnknown;
		break;


	case 'R':
		if (dataLen < 6)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'E' && data[2] == 'F' && data[3] == 'E' && data[4] == 'R' && data[5] == ' ')
			return SipRequestLayer::SipREFER;
		else if (dataLen < 9)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'E' && data[2] == 'G' && data[3] == 'I' && data[4] == 'S' && data[5] == 'T' && data[6] == 'E' && data[7] == 'R' && data[8] == ' ')
			return SipRequestLayer::SipREGISTER;
		else
			return SipRequestLayer::SipMethodUnknown;
		break;

	case 'P':
		if (dataLen < 6)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'K' && data[5] == ' ')
			return SipRequestLayer::SipPRACK;
		else if (dataLen < 8)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'U' && data[2] == 'B' && data[3] == 'L' && data[4] == 'I' && data[5] == 'S' && data[6] == 'H' && data[7] == ' ')
			return SipRequestLayer::SipPUBLISH;
		break;

	case 'S':
		if (dataLen < 10)
			return SipRequestLayer::SipMethodUnknown;

		else if (data[1] == 'U' && data[2] == 'B' && data[3] == 'S' && data[4] == 'C' && data[5] == 'R' && data[6] == 'I' && data[7] == 'B' && data[8] == 'E' && data[9] == ' ')
			return SipRequestLayer::SipSUBSCRIBE;
		break;

	case 'N':
		if (dataLen < 7)
			return SipRequestLayer::SipMethodUnknown;

		else if (data[1] == 'O' && data[2] == 'T' && data[3] == 'I' && data[4] == 'F' && data[5] == 'Y' && data[6] == ' ')
			return SipRequestLayer::SipNOTIFY;
		break;

	case 'I':
		if (data[1] == 'N' && data[2] == 'F' && data[3] == 'O')
			return SipRequestLayer::SipINFO;
		else if (dataLen < 7)
			return SipRequestLayer::SipMethodUnknown;
		else if (data[1] == 'N' && data[2] == 'V' && data[3] == 'I' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
			return SipRequestLayer::SipINVITE;
		break;

	case 'M':
		if (dataLen < 8)
			return SipRequestLayer::SipMethodUnknown;

		else if (data[1] == 'E' && data[2] == 'S' && data[3] == 'S' && data[4] == 'A' && data[5] == 'G' && data[6] == 'E' && data[7] == ' ')
			return SipRequestLayer::SipMESSAGE;
		break;

	case 'U':
		if (dataLen < 7)
			return SipRequestLayer::SipMethodUnknown;

		else if (data[1] == 'P' && data[2] == 'D' && data[3] == 'A' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
			return SipRequestLayer::SipUPDATE;
		break;


	default:
		return SipRequestLayer::SipMethodUnknown;
	}

	return SipRequestLayer::SipMethodUnknown;
}

void SipRequestFirstLine::parseVersion()
{
	char* data = (char*)(m_SipRequest->m_Data + m_UriOffset);
	char* verPos = strstr(data, " SIP/");
	if (verPos == NULL)
	{
		m_Version = "";
		m_VersionOffset = -1;
		return;
	}

	// verify packet doesn't end before the version, meaning still left place for " SIP/x.y" (7 chars)
	if ((uint16_t)(verPos + 7 - (char*)m_SipRequest->m_Data) > m_SipRequest->getDataLen())
	{
		m_Version = "";
		m_VersionOffset = -1;
		return;
	}

	//skip the space char
	verPos++;

	int endOfVerPos = 0;
	while (((verPos+endOfVerPos)[0] != '\r') && ((verPos+endOfVerPos)[0] != '\n'))
		endOfVerPos++;

	m_Version = std::string(verPos, endOfVerPos);

	m_VersionOffset = verPos - (char*)m_SipRequest->m_Data;
}

bool SipRequestFirstLine::setMethod(SipRequestLayer::SipMethod newMethod)
{
	if (newMethod == SipRequestLayer::SipMethodUnknown)
	{
		LOG_ERROR("Requested method is SipMethodUnknown");
		return false;
	}

	//extend or shorten layer
	int lengthDifference = SipMethodEnumToString[newMethod].length() - SipMethodEnumToString[m_Method].length();
	if (lengthDifference > 0)
	{
		if (!m_SipRequest->extendLayer(0, lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_SipRequest->shortenLayer(0, 0-lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
			return false;

		}
	}

	if (lengthDifference != 0)
	{
		m_SipRequest->shiftFieldsOffset(m_SipRequest->getFirstField(), lengthDifference);
		m_SipRequest->m_FieldsOffset += lengthDifference;
	}

	memcpy(m_SipRequest->m_Data, SipMethodEnumToString[newMethod].c_str(), SipMethodEnumToString[newMethod].length());

	m_UriOffset += lengthDifference;
	m_VersionOffset += lengthDifference;
	m_FirstLineEndOffset += lengthDifference;

	m_Method = newMethod;

	return true;
}

std::string SipRequestFirstLine::getUri()
{
	std::string result;
	if (m_UriOffset != -1 && m_VersionOffset != -1)
		result.assign((char*)(m_SipRequest->m_Data + m_UriOffset), m_VersionOffset-1-m_UriOffset);

	//else first line is illegal, return empty string

	return result;
}

bool SipRequestFirstLine::setUri(std::string newUri)
{
	if (newUri == "")
	{
		LOG_ERROR("URI cannot be empty");
		return false;
	}

	//extend or shorten layer
	std::string currentUri = getUri();
	int lengthDifference = newUri.length() - currentUri.length();
	if (lengthDifference > 0)
	{
		if (!m_SipRequest->extendLayer(m_UriOffset, lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_SipRequest->shortenLayer(m_UriOffset, 0-lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
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

SipRequestLayer::SipRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : SipLayer(data, dataLen, prevLayer, packet)
{
	m_Protocol = SIPRequest;
	m_FirstLine = new SipRequestFirstLine(this);
	m_FieldsOffset = m_FirstLine->getSize();
	parseFields();
}

SipRequestLayer::SipRequestLayer(SipMethod method, std::string requestUri, std::string version)
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

	if (m_FirstLine != NULL)
		delete m_FirstLine;

	m_FirstLine = new SipRequestFirstLine(this);

	return *this;
}

SipRequestLayer::~SipRequestLayer()
{
	delete m_FirstLine;
}

std::string SipRequestLayer::toString()
{
	static const int maxLengthToPrint = 120;
	std::string result = "SIP request, ";
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






// -------- Class SipResponseLayer -----------------



const std::string StatusCodeEnumToString[74] = {
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
		"Precondition Failure",
		"Busy Everywhere",
		"Decline",
		"Does Not Exist Anywhere",
		"Not Acceptable",
		"Unwanted"
};


const int StatusCodeEnumToInt[74] = {
		100,
		180,
		181,
		182,
		183,
		199,
		200,
		202,
		204,
		300,
		301,
		302,
		305,
		380,
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
		420,
		421,
		422,
		423,
		424,
		428,
		429,
		430,
		433,
		436,
		437,
		438,
		439,
		440,
		469,
		470,
		480,
		481,
		482,
		483,
		484,
		485,
		486,
		487,
		488,
		489,
		491,
		493,
		494,
		500,
		501,
		502,
		503,
		504,
		505,
		513,
		580,
		600,
		603,
		604,
		606,
		607
};



SipResponseLayer::SipResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : SipLayer(data, dataLen, prevLayer, packet)
{
	m_Protocol = SIPResponse;
	m_FirstLine = new SipResponseFirstLine(this);
	m_FieldsOffset = m_FirstLine->getSize();
	parseFields();
}

SipResponseLayer::SipResponseLayer(SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString, std::string sipVersion)
{
	m_Protocol = SIPResponse;
	m_FirstLine = new SipResponseFirstLine(this, sipVersion, statusCode, statusCodeString);
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

	if (m_FirstLine != NULL)
		delete m_FirstLine;

	m_FirstLine = new SipResponseFirstLine(this);

	return *this;
}

std::string SipResponseLayer::toString()
{
	static const int maxLengthToPrint = 120;
	std::string result = "SIP response, ";
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








// -------- Class SipResponseFirstLine -----------------

int SipResponseFirstLine::getStatusCodeAsInt()
{
	return StatusCodeEnumToInt[m_StatusCode];
}

std::string SipResponseFirstLine::getStatusCodeString()
{
	std::string result;
	int statusStringOffset = 12;
	if (m_StatusCode != SipResponseLayer::SipStatusCodeUnknown)
	{
		int statusStringEndOffset = m_FirstLineEndOffset - 2;
		if ((*(m_SipResponse->m_Data + statusStringEndOffset)) != '\r')
			statusStringEndOffset++;
		result.assign((char*)(m_SipResponse->m_Data + statusStringOffset), statusStringEndOffset-statusStringOffset);
	}

	//else first line is illegal, return empty string

	return result;
}

bool SipResponseFirstLine::setStatusCode(SipResponseLayer::SipResponseStatusCode newStatusCode, std::string statusCodeString)
{
	if (newStatusCode == SipResponseLayer::SipStatusCodeUnknown)
	{
		LOG_ERROR("Requested status code is SipStatusCodeUnknown");
		return false;
	}

	//extend or shorten layer

	size_t statusStringOffset = 12;
	if (statusCodeString == "")
		statusCodeString = StatusCodeEnumToString[newStatusCode];
	int lengthDifference = statusCodeString.length() - getStatusCodeString().length();

	if (lengthDifference > 0)
	{
		if (!m_SipResponse->extendLayer(statusStringOffset, lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
			return false;
		}
	}
	else if (lengthDifference < 0)
	{
		if (!m_SipResponse->shortenLayer(statusStringOffset, 0-lengthDifference))
		{
			LOG_ERROR("Cannot change layer size");
			return false;

		}
	}

	if (lengthDifference != 0)
	{
		m_SipResponse->shiftFieldsOffset(m_SipResponse->getFirstField(), lengthDifference);
		m_SipResponse->m_FieldsOffset += lengthDifference;
	}

	// copy status string
	memcpy(m_SipResponse->m_Data+statusStringOffset, statusCodeString.c_str(), statusCodeString.length());

	// change status code
	char statusCodeAsString[4];
	// convert code to string
	snprintf (statusCodeAsString, sizeof(statusCodeAsString), "%d",StatusCodeEnumToInt[newStatusCode]);

	memcpy(m_SipResponse->m_Data+8, statusCodeAsString, 3);

	m_StatusCode = newStatusCode;
	m_FirstLineEndOffset += lengthDifference;

	return true;

}

void SipResponseFirstLine::setVersion(std::string newVersion)
{
	if (newVersion == "")
		return;

	if (newVersion.length() != m_Version.length())
	{
		LOG_ERROR("Expected version length is %d characters in the format of SIP/x.y", (int)m_Version.length());
		return;
	}

	char* verPos = (char*)m_SipResponse->m_Data;
	memcpy(verPos, newVersion.c_str(), newVersion.length());
	m_Version = newVersion;
}

SipResponseLayer::SipResponseStatusCode SipResponseFirstLine::validateStatusCode(char* data, size_t dataLen, SipResponseLayer::SipResponseStatusCode potentialCode)
{
	if (data[0] != ' ')
		return SipResponseLayer::SipStatusCodeUnknown;

	return potentialCode;
}

SipResponseLayer::SipResponseStatusCode SipResponseFirstLine::parseStatusCode(char* data, size_t dataLen)
{
	// minimum data should be 12B long: "SIP/x.y XXX"
	if (dataLen < 12)
		return SipResponseLayer::SipStatusCodeUnknown;

	char* statusCodeData = data + 8;
	size_t statusCodeDataLen = dataLen - 8;

	switch (statusCodeData[0])
	{
	case '1':
		switch (statusCodeData[1])
		{
		case '0':
			if (statusCodeData[2] == '0')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip100Trying);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;
		case '8':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip180Ringing);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip181CallisBeingForwarded);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip182Queued);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip183SessioninProgress);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			};
			break;

		case '9':
			if (statusCodeData[2] == '9')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip199EarlyDialogTerminated);
			else
				return SipResponseLayer::SipStatusCodeUnknown;
			break;

		default:
			return SipResponseLayer::SipStatusCodeUnknown;
		};

		break;
	case '2':
		if (statusCodeData[1] == '0')
		{
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip200OK);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip202Accepted);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip204NoNotification);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};
		}
		else
			return SipResponseLayer::SipStatusCodeUnknown;

		break;

	case '3':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip300MultipleChoices);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip301MovedPermanently);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip302MovedTemporarily);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip305UseProxy);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};

			break;

		case '8':
			if (statusCodeData[2] == '0')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip380AlternativeService);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;

		default:
			return SipResponseLayer::SipStatusCodeUnknown;
		};

		break;

	case '4':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip400BadRequest);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip401Unauthorized);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip402PaymentRequired);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip403Forbidden);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip404NotFound);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip405MethodNotAllowed);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip406NotAcceptable);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip407ProxyAuthenticationRequired);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip408RequestTimeout);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip409Conflict);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};

			break;

		case '1':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip410Gone);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip411LengthRequired);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip412ConditionalRequestFailed);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip413RequestEntityTooLarge);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip414RequestURITooLong);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip415UnsupportedMediaType);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip416UnsupportedURIScheme);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip417UnknownResourcePriority);
			case '8':
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};

			break;

		case '2':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip420BadExtension);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip421ExtensionRequired);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip422SessionIntervalTooSmall);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip423IntervalTooBrief);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip424BadLocationInformation);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip428UseIdentityHeader);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip429ProvideReferrerIdentity);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};

			break;

		case '3':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip430FlowFailed);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip433AnonymityDisallowed);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip436BadIdentityInfo);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip437UnsupportedCertificate);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip438InvalidIdentityHeader);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip439FirstHopLacksOutboundSupport);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			};

			break;

		case '4':
			if (statusCodeData[2] == '0')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip440MaxBreadthExceeded);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;

		case '6':
			if (statusCodeData[2] == '9')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip469BadInfoPackage);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;

		case '8':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip480TemporarilyUnavailable);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip481Call_TransactionDoesNotExist);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip482LoopDetected);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip483TooManyHops);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip484AddressIncomplete);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip485Ambiguous);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip486BusyHere);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip487RequestTerminated);
			case '8':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip488NotAcceptableHere);
			case '9':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip489BadEvent);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			};

			break;

		case '9':
			switch (statusCodeData[2])
			{
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip491RequestPending);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip493Undecipherable);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip494SecurityAgreementRequired);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			};

			break;

		default:
			return SipResponseLayer::SipStatusCodeUnknown;
		};

		break;

	case '5':
		switch (statusCodeData[1])
		{
		case '0':
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip500ServerInternalError);
			case '1':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip501NotImplemented);
			case '2':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip502BadGateway);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip503ServiceUnavailable);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip504ServerTimeout);
			case '5':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip505VersionNotSupported);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;

			};

			break;

		case '1':
			if (statusCodeData[2] == '3')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip513MessageTooLarge);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;

		case '8':
			if (statusCodeData[2] == '0')
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip580PreconditionFailure);
			else
				return SipResponseLayer::SipStatusCodeUnknown;

			break;

		default:
			return SipResponseLayer::SipStatusCodeUnknown;
		};

		break;

	case '6':
		if (statusCodeData[1] == '0')
		{
			switch (statusCodeData[2])
			{
			case '0':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip600BusyEverywhere);
			case '3':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip603Decline);
			case '4':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip604DoesNotExistAnywhere);
			case '6':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip606NotAcceptable);
			case '7':
				return validateStatusCode(statusCodeData+3, statusCodeDataLen-3, SipResponseLayer::Sip607Unwanted);
			default:
				return SipResponseLayer::SipStatusCodeUnknown;
			};
		}
		else
			return SipResponseLayer::SipStatusCodeUnknown;

		break;

	default:
		return SipResponseLayer::SipStatusCodeUnknown;
	};

	return SipResponseLayer::SipStatusCodeUnknown;
}

SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse) : m_SipResponse(sipResponse)
{
	m_Version = parseVersion((char*)m_SipResponse->m_Data, m_SipResponse->getDataLen());
	if (m_Version == "")
	{
		m_StatusCode = SipResponseLayer::SipStatusCodeUnknown;
	}
	else
	{
		m_StatusCode = parseStatusCode((char*)m_SipResponse->m_Data, m_SipResponse->getDataLen());
	}


	char* endOfFirstLine;
	if ((endOfFirstLine = (char *)memchr((char*)(m_SipResponse->m_Data), '\n', m_SipResponse->m_DataLen)) != NULL)
	{
		m_FirstLineEndOffset = endOfFirstLine - (char*)m_SipResponse->m_Data + 1;
		m_IsComplete = true;
	}
	else
	{
		m_FirstLineEndOffset = m_SipResponse->getDataLen();
		m_IsComplete = false;
	}

	LOG_DEBUG("Version='%s'; Status code=%d '%s'", m_Version.c_str(), StatusCodeEnumToInt[m_StatusCode], getStatusCodeString().c_str());
}


SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse,  std::string version, SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString)
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

	char statusCodeAsString[4];
	snprintf (statusCodeAsString, sizeof(statusCodeAsString), "%d",StatusCodeEnumToInt[m_StatusCode]);
	if (statusCodeString == "")
		statusCodeString = StatusCodeEnumToString[m_StatusCode];
	std::string firstLine = m_Version + " " + std::string(statusCodeAsString) + " " +  statusCodeString +  "\r\n";

	m_FirstLineEndOffset = firstLine.length();

	m_SipResponse->m_DataLen = firstLine.length();
	m_SipResponse->m_Data = new uint8_t[m_SipResponse->m_DataLen];
	memcpy(m_SipResponse->m_Data, firstLine.c_str(), m_SipResponse->m_DataLen);

	m_IsComplete = true;
}

std::string SipResponseFirstLine::parseVersion(char* data, size_t dataLen)
{
	if (dataLen < 7) // "SIP/x.y"
	{
		LOG_DEBUG("SIP response length < 7, cannot identify version");
		return "";
	}

	if (data[0] != 'S' || data[1] != 'I' || data[2] != 'P' || data[3] != '/')
	{
		LOG_DEBUG("SIP response does not begin with 'SIP/'");
		return "";
	}

	char* nextSpace = strchr(data, ' ');
	if (nextSpace - data > (int)dataLen)
		return "";

	return std::string(data, nextSpace - data);
}



}
