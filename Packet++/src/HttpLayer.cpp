#define LOG_MODULE PacketLogModuleHttpLayer

#include "Logger.h"
#include "HttpLayer.h"
#include "PayloadLayer.h"
#include <string.h>

HttpMessage::HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer),
						m_FieldList(NULL), m_LastField(NULL) {}

void HttpMessage::parseFields(int fieldsOffset)
{
	HttpField* firstField = new HttpField(this, fieldsOffset);
	LOG_DEBUG("Added new field: name='%s'; offset in packet=%d; length=%d", firstField->getFieldName().c_str(), firstField->m_NameOffsetInMessage, firstField->getFieldSize());
	LOG_DEBUG("     Field value = %s", firstField->getFieldValue().c_str());

	if (m_FieldList == NULL)
		m_FieldList = firstField;
	else
		m_FieldList->setNextField(firstField);

	// Last field will be empty and contain just "\n" or "\r\n". This field will mark the end of the header
	HttpField* curField = m_FieldList;
	int curOffset = fieldsOffset;
	// last field can be one of:
	// a.) \r\n\r\n or \n\n marking the end of the header
	// b.) the end of the packet
	while (!curField->isEndOfHeader() && curOffset + curField->getFieldSize() < m_DataLen)
	{
		curOffset += curField->getFieldSize();
		HttpField* newField = new HttpField(this, curOffset);
		LOG_DEBUG("Added new field: name='%s'; offset in packet=%d; length=%d", newField->getFieldName().c_str(), newField->m_NameOffsetInMessage, newField->getFieldSize());
		LOG_DEBUG("     Field value = %s", newField->getFieldValue().c_str());
		curField->setNextField(newField);
		curField = curField->getNextField();
	}

	m_LastField = curField;
}

HttpMessage::~HttpMessage()
{
	while (m_FieldList != NULL)
	{
		HttpField* temp = m_FieldList;
		m_FieldList = m_FieldList->getNextField();
		delete temp;
	}
}

HttpField* HttpMessage::getFieldByName(std::string fieldName)
{
	//TODO make it better and more efficient

	HttpField* curField = m_FieldList;
	while (curField != NULL)
	{
		if (curField->getFieldName() == fieldName)
			return curField;
		curField = curField->getNextField();
	}

	return NULL;
}

void HttpMessage::addField(HttpField& newField)
{
	//TODO
}

void HttpMessage::insertField(const HttpField* prevField, HttpField& newField)
{
	//TODO
}

void HttpMessage::removeField(HttpField* fieldToRemove)
{
	//TODO
}

void HttpMessage::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this);
}

size_t HttpMessage::getHeaderLen()
{
	return (m_LastField->m_NewFieldData + m_LastField->m_FieldSize - m_Data);
}

void HttpMessage::computeCalculateFields()
{
	//TODO
}




HttpField::HttpField(HttpMessage* httpMessage, int offsetInMessage) : m_NewFieldData(NULL), m_HttpMessage(httpMessage), m_NameOffsetInMessage(offsetInMessage), m_NextField(NULL)
{
	char* fieldData = (char*)(m_HttpMessage->m_Data + m_NameOffsetInMessage);
	char* fieldEndPtr = strchr(fieldData, '\n');
	if (fieldEndPtr == NULL)
		m_FieldSize = strlen(fieldData);
	else
		m_FieldSize = fieldEndPtr - fieldData + 1;

	if ((*fieldData) == '\r' || (*fieldData) == '\n')
	{
		m_FieldNameSize = -1;
		m_ValueOffsetInMessage = -1;
		m_FieldValueSize = -1;
		m_FieldNameSize = -1;
		m_IsEndOfHeaderField = true;
		return;
	}
	else
		m_IsEndOfHeaderField = false;

	char* fieldValuePtr = strchr(fieldData, ':');
	// could not find the position of ':', meaning field value position is unknown
	if (fieldValuePtr == NULL)
	{
		m_ValueOffsetInMessage = -1;
		m_FieldValueSize = -1;
		m_FieldNameSize = m_FieldSize;
	}
	else
	{
		m_FieldNameSize = fieldValuePtr - fieldData;
		// Http field looks like this: <field_name>:<zero or more spaces><field_Value>
		// So fieldValuePtr give us the position of ':'. Value offset is the first non-space byte forward
		fieldValuePtr++;
		// advance fieldValuePtr 1 byte forward while didn't get to end of packet and fieldValuePtr points to a space char
		while ((size_t)(fieldValuePtr - (char*)m_HttpMessage->m_Data) <= m_HttpMessage->getDataLen() && (*fieldValuePtr) == ' ')
			fieldValuePtr++;

		// reached the end of the packet and value start offset wasn't found
		if ((size_t)(fieldValuePtr - (char*)(m_HttpMessage->m_Data)) > m_HttpMessage->getDataLen())
		{
			m_ValueOffsetInMessage = -1;
			m_FieldValueSize = -1;
		}
		else
		{
			m_ValueOffsetInMessage = fieldValuePtr - (char*)m_HttpMessage->m_Data;
			// couldn't find the end of the field, so assuming the field value length is from m_ValueOffsetInMessage until the end of the packet
			if (fieldEndPtr == NULL)
				m_FieldValueSize = (char*)(m_HttpMessage->m_Data + m_HttpMessage->getDataLen()) - fieldValuePtr;
			else
			{
				m_FieldValueSize = fieldEndPtr - fieldValuePtr;
				// if field ends with \r\n, decrease the value length by 1
				if ((*(--fieldEndPtr)) == '\r')
					m_FieldValueSize--;
			}


		}
	}


}

HttpField::HttpField(std::string name, std::string value) : m_HttpMessage(NULL), m_NameOffsetInMessage(0), m_NextField(NULL)
{
	// Field size is: name_length + ':' + space + value_length + '\n'
	m_FieldSize = name.length() + value.length() + 3;
	m_NewFieldData = new uint8_t[m_FieldSize];
	std::string fieldData = name + ": " + value + "\n";
	memcpy(m_NewFieldData, fieldData.c_str(), m_FieldSize);
	m_ValueOffsetInMessage = name.length() + 2;
	m_FieldNameSize = name.length();
	m_FieldValueSize = value.length();
	m_IsEndOfHeaderField = false;
}

HttpField::~HttpField()
{
	if (m_NewFieldData != NULL)
		delete [] m_NewFieldData;
}

char* HttpField::getFieldData()
{
	if (m_HttpMessage == NULL)
		return (char*)m_NewFieldData;
	else
		return (char*)(m_HttpMessage->m_Data + m_NameOffsetInMessage);
}

std::string HttpField::getFieldName()
{
	std::string result;
	if (m_FieldNameSize != -1)
		result.assign((const char*)getFieldData(), m_FieldNameSize);
	else
		result = "END OF HEADER";

	return result;
}

std::string HttpField::getFieldValue()
{
	std::string result;
	if (m_ValueOffsetInMessage != -1)
		result.assign((const char*)(m_HttpMessage->m_Data + m_ValueOffsetInMessage), m_FieldValueSize);
	return result;
}

void HttpField::setFieldValue(std::string newValue)
{
	//TODO
}




HttpRequestLayer::HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer) : HttpMessage(data, dataLen, prevLayer)
{
	m_Protocol = HTTPRequest;
	m_FirstLine = new HttpRequestFirstLine(this);
	parseFields(m_FirstLine->getSize());
}




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
		LOG_DEBUG("Couldn't resolve HTTP request method");
	}
	else
		m_UriOffset = MethodEnumToString[m_Method].length() + 1;

	parseVersion();

	char* endOfFirstLine;
	if ((endOfFirstLine = strchr((char*)(m_HttpRequest->m_Data + m_VersionOffset), '\n')) != NULL)
	{
		m_FirstLineEndOffset = endOfFirstLine - (char*)m_HttpRequest->m_Data + 1;
		m_IsComplete = true;
	}
	else
	{
		m_FirstLineEndOffset = m_HttpRequest->getDataLen();
		m_IsComplete = false;
	}

	LOG_DEBUG("Method='%s'; HTTP version='%s'; URI='%s'", MethodEnumToString[m_Method].c_str(), VersionEnumToString[m_Version].c_str(), getUri().c_str());
}

//HttpRequestFirstLine::HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpMethod method, std::string uri = "", HttpVersion version)
//{
//
//
//}


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
		else if (data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[5] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ')
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
	char* verPos = strstr(data, " HTTP/");
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

void HttpRequestFirstLine::setMethod()
{
	//TODO
}

std::string HttpRequestFirstLine::getUri()
{
	std::string result;
	if (m_UriOffset != -1 && m_VersionOffset != -1)
		result.assign((char*)(m_HttpRequest->m_Data + m_UriOffset), m_VersionOffset-6-m_UriOffset);

	//else first line is illegal, return empty string

	return result;
}

void HttpRequestFirstLine::setUri(std::string newUri)
{
	//TODO
}

void HttpRequestFirstLine::setVersion(HttpVersion newVersion)
{
	if (m_VersionOffset == -1)
		return;

	char* verPos = (char*)(m_HttpRequest->m_Data + m_VersionOffset);
	memcpy(verPos, VersionEnumToString[newVersion].c_str(), 3);
}


