#include "TextBasedProtocol.h"
#include "Logger.h"
#include "PayloadLayer.h"
#include <cstring>
#include <algorithm>
#include <utility>

namespace pcpp
{

	// this implementation of strnlen is required since mingw doesn't have strnlen
	size_t tbp_my_own_strnlen(const char* s, size_t maxlen)
	{
		if (s == nullptr || maxlen == 0)
			return 0;

		size_t i = 0;
		for (; (i < maxlen) && s[i]; ++i)
			;
		return i;
	}

	// -------- Class TextBasedProtocolMessage -----------------

	TextBasedProtocolMessage::TextBasedProtocolMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet,
	                                                   ProtocolType protocol)
	    : Layer(data, dataLen, prevLayer, packet, protocol), m_FieldList(nullptr), m_LastField(nullptr),
	      m_FieldsOffset(0)
	{}

	TextBasedProtocolMessage::TextBasedProtocolMessage(const TextBasedProtocolMessage& other) : Layer(other)
	{
		copyDataFrom(other);
	}

	TextBasedProtocolMessage& TextBasedProtocolMessage::operator=(const TextBasedProtocolMessage& other)
	{
		Layer::operator=(other);
		HeaderField* curField = m_FieldList;
		while (curField != nullptr)
		{
			HeaderField* temp = curField;
			curField = curField->getNextField();
			delete temp;
		}

		copyDataFrom(other);

		return *this;
	}

	void TextBasedProtocolMessage::copyDataFrom(const TextBasedProtocolMessage& other)
	{
		// copy field list
		if (other.m_FieldList != nullptr)
		{
			m_FieldList = new HeaderField(*(other.m_FieldList));
			HeaderField* curField = m_FieldList;
			curField->attachToTextBasedProtocolMessage(this, other.m_FieldList->m_NameOffsetInMessage);
			HeaderField* curOtherField = other.m_FieldList;
			while (curOtherField->getNextField() != nullptr)
			{
				HeaderField* newField = new HeaderField(*(curOtherField->getNextField()));
				newField->attachToTextBasedProtocolMessage(this, curOtherField->getNextField()->m_NameOffsetInMessage);
				curField->setNextField(newField);
				curField = curField->getNextField();
				curOtherField = curOtherField->getNextField();
			}

			m_LastField = curField;
		}
		else
		{
			m_FieldList = nullptr;
			m_LastField = nullptr;
		}

		m_FieldsOffset = other.m_FieldsOffset;

		// copy map
		for (HeaderField* field = m_FieldList; field != nullptr; field = field->getNextField())
		{
			m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(field->getFieldName(), field));
		}
	}

	void TextBasedProtocolMessage::parseFields()
	{
		char nameValueSeparator = getHeaderFieldNameValueSeparator();
		bool spacesAllowedBetweenNameAndValue = spacesAllowedBetweenHeaderFieldNameAndValue();

		HeaderField* firstField =
		    new HeaderField(this, m_FieldsOffset, nameValueSeparator, spacesAllowedBetweenNameAndValue);
		PCPP_LOG_DEBUG("Added new field: name='" << firstField->getFieldName()
		                                         << "'; offset in packet=" << firstField->m_NameOffsetInMessage
		                                         << "; length=" << firstField->getFieldSize());
		PCPP_LOG_DEBUG("     Field value = " << firstField->getFieldValue());

		if (m_FieldList == nullptr)
			m_FieldList = firstField;
		else
			m_FieldList->setNextField(firstField);

		std::string fieldName = firstField->getFieldName();
		std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
		m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, firstField));

		// Last field will be empty and contain just "\n" or "\r\n". This field will mark the end of the header
		HeaderField* curField = m_FieldList;
		int curOffset = m_FieldsOffset;
		// last field can be one of:
		// a.) \r\n\r\n or \n\n marking the end of the header
		// b.) the end of the packet
		while (!curField->isEndOfHeader() && curOffset + curField->getFieldSize() < m_DataLen)
		{
			curOffset += curField->getFieldSize();
			HeaderField* newField =
			    new HeaderField(this, curOffset, nameValueSeparator, spacesAllowedBetweenNameAndValue);
			if (newField->getFieldSize() > 0)
			{
				PCPP_LOG_DEBUG("Added new field: name='" << newField->getFieldName()
				                                         << "'; offset in packet=" << newField->m_NameOffsetInMessage
				                                         << "; length=" << newField->getFieldSize());
				PCPP_LOG_DEBUG("     Field value = " << newField->getFieldValue());
				curField->setNextField(newField);
				curField = newField;
				fieldName = newField->getFieldName();
				std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
				m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, newField));
			}
			else
			{
				delete newField;
				break;
			}
		}

		m_LastField = curField;
	}

	TextBasedProtocolMessage::~TextBasedProtocolMessage()
	{
		while (m_FieldList != nullptr)
		{
			HeaderField* temp = m_FieldList;
			m_FieldList = m_FieldList->getNextField();
			delete temp;
		}
	}

	HeaderField* TextBasedProtocolMessage::addField(const std::string& fieldName, const std::string& fieldValue)
	{
		HeaderField newField(fieldName, fieldValue, getHeaderFieldNameValueSeparator(),
		                     spacesAllowedBetweenHeaderFieldNameAndValue());
		return addField(newField);
	}

	HeaderField* TextBasedProtocolMessage::addField(const HeaderField& newField)
	{
		return insertField(m_LastField, newField);
	}

	HeaderField* TextBasedProtocolMessage::addEndOfHeader()
	{
		HeaderField endOfHeaderField(PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER, "", '\0', false);
		return insertField(m_LastField, endOfHeaderField);
	}

	HeaderField* TextBasedProtocolMessage::insertField(HeaderField* prevField, const std::string& fieldName,
	                                                   const std::string& fieldValue)
	{
		HeaderField newField(fieldName, fieldValue, getHeaderFieldNameValueSeparator(),
		                     spacesAllowedBetweenHeaderFieldNameAndValue());
		return insertField(prevField, newField);
	}

	HeaderField* TextBasedProtocolMessage::insertField(std::string prevFieldName, const std::string& fieldName,
	                                                   const std::string& fieldValue)
	{
		if (prevFieldName == "")
		{
			return insertField(nullptr, fieldName, fieldValue);
		}
		else
		{
			HeaderField* prevField = getFieldByName(prevFieldName);
			if (prevField == nullptr)
				return nullptr;

			return insertField(prevField, fieldName, fieldValue);
		}
	}

	HeaderField* TextBasedProtocolMessage::insertField(HeaderField* prevField, const HeaderField& newField)
	{
		if (newField.m_TextBasedProtocolMessage != nullptr)
		{
			PCPP_LOG_ERROR("This field is already associated with another message");
			return nullptr;
		}

		if (prevField != nullptr && prevField->getFieldName() == PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
		{
			PCPP_LOG_ERROR("Cannot add a field after end of header");
			return nullptr;
		}

		HeaderField* newFieldToAdd = new HeaderField(newField);

		int newFieldOffset = m_FieldsOffset;
		if (prevField != nullptr)
			newFieldOffset = prevField->m_NameOffsetInMessage + prevField->getFieldSize();

		// extend layer to make room for the new field. Field will be added just before the last field
		if (!extendLayer(newFieldOffset, newFieldToAdd->getFieldSize()))
		{
			PCPP_LOG_ERROR("Cannot extend layer to insert the header");
			delete newFieldToAdd;
			return nullptr;
		}

		HeaderField* curField = m_FieldList;
		if (prevField != nullptr)
			curField = prevField->getNextField();

		// go over all fields after prevField and update their offsets
		shiftFieldsOffset(curField, newFieldToAdd->getFieldSize());

		// copy new field data to message
		memcpy(m_Data + newFieldOffset, newFieldToAdd->m_NewFieldData, newFieldToAdd->getFieldSize());

		// attach new field to message
		newFieldToAdd->attachToTextBasedProtocolMessage(this, newFieldOffset);

		// insert field into fields link list
		if (prevField == nullptr)
		{
			newFieldToAdd->setNextField(m_FieldList);
			m_FieldList = newFieldToAdd;
		}
		else
		{
			newFieldToAdd->setNextField(prevField->getNextField());
			prevField->setNextField(newFieldToAdd);
		}

		// if newField is the last field, update m_LastField
		if (newFieldToAdd->getNextField() == nullptr)
			m_LastField = newFieldToAdd;

		// insert the new field into name to field map
		std::string fieldName = newFieldToAdd->getFieldName();
		std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
		m_FieldNameToFieldMap.insert(std::pair<std::string, HeaderField*>(fieldName, newFieldToAdd));

		return newFieldToAdd;
	}

	bool TextBasedProtocolMessage::removeField(std::string fieldName, int index)
	{
		std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);

		HeaderField* fieldToRemove = nullptr;

		auto range = m_FieldNameToFieldMap.equal_range(fieldName);
		int i = 0;
		for (std::multimap<std::string, HeaderField*>::iterator iter = range.first; iter != range.second; ++iter)
		{
			if (i == index)
			{
				fieldToRemove = iter->second;
				break;
			}

			i++;
		}

		if (fieldToRemove != nullptr)
			return removeField(fieldToRemove);
		else
		{
			PCPP_LOG_ERROR("Cannot find field '" << fieldName << "'");
			return false;
		}
	}

	bool TextBasedProtocolMessage::removeField(HeaderField* fieldToRemove)
	{
		if (fieldToRemove == nullptr)
			return true;

		if (fieldToRemove->m_TextBasedProtocolMessage != this)
		{
			PCPP_LOG_ERROR("Field isn't associated with this message");
			return false;
		}

		std::string fieldName = fieldToRemove->getFieldName();

		// shorten layer and delete this field
		if (!shortenLayer(fieldToRemove->m_NameOffsetInMessage, fieldToRemove->getFieldSize()))
		{
			PCPP_LOG_ERROR("Cannot shorten layer");
			return false;
		}

		// update offsets of all fields after this field
		HeaderField* curField = fieldToRemove->getNextField();
		shiftFieldsOffset(curField, 0 - fieldToRemove->getFieldSize());

		// update fields link list
		if (fieldToRemove == m_FieldList)
			m_FieldList = m_FieldList->getNextField();
		else
		{
			curField = m_FieldList;
			while (curField->getNextField() != fieldToRemove)
				curField = curField->getNextField();

			curField->setNextField(fieldToRemove->getNextField());
		}

		// re-calculate m_LastField if needed
		if (fieldToRemove == m_LastField)
		{
			if (m_FieldList == nullptr)
				m_LastField = nullptr;
			else
			{
				curField = m_FieldList;
				while (curField->getNextField() != nullptr)
					curField = curField->getNextField();
				m_LastField = curField;
			}
		}

		// remove the hash entry for this field
		std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);
		auto range = m_FieldNameToFieldMap.equal_range(fieldName);
		for (std::multimap<std::string, HeaderField*>::iterator iter = range.first; iter != range.second; ++iter)
		{
			if (iter->second == fieldToRemove)
			{
				m_FieldNameToFieldMap.erase(iter);
				break;
			}
		}

		// finally - delete this field
		delete fieldToRemove;

		return true;
	}

	bool TextBasedProtocolMessage::isHeaderComplete() const
	{
		if (m_LastField == nullptr)
			return false;

		return (m_LastField->getFieldName() == PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER);
	}

	void TextBasedProtocolMessage::shiftFieldsOffset(HeaderField* fromField, int numOfBytesToShift)
	{
		while (fromField != nullptr)
		{
			fromField->m_NameOffsetInMessage += numOfBytesToShift;
			if (fromField->m_ValueOffsetInMessage != -1)
				fromField->m_ValueOffsetInMessage += numOfBytesToShift;
			fromField = fromField->getNextField();
		}
	}

	HeaderField* TextBasedProtocolMessage::getFieldByName(std::string fieldName, int index) const
	{
		std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);

		auto range = m_FieldNameToFieldMap.equal_range(fieldName);
		int i = 0;
		for (std::multimap<std::string, HeaderField*>::const_iterator iter = range.first; iter != range.second; ++iter)
		{
			if (i == index)
				return iter->second;

			i++;
		}

		return nullptr;
	}

	int TextBasedProtocolMessage::getFieldCount() const
	{
		int result = 0;

		HeaderField* curField = getFirstField();
		while (curField != nullptr)
		{
			if (!curField->isEndOfHeader())
				result++;
			curField = curField->getNextField();
		}

		return result;
	}

	void TextBasedProtocolMessage::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
	}

	size_t TextBasedProtocolMessage::getHeaderLen() const
	{
		return m_LastField->m_NameOffsetInMessage + m_LastField->m_FieldSize;
	}

	void TextBasedProtocolMessage::computeCalculateFields()
	{
		// nothing to do for now
	}

	// -------- Class HeaderField -----------------

	HeaderField::HeaderField(TextBasedProtocolMessage* TextBasedProtocolMessage, int offsetInMessage,
	                         char nameValueSeparator, bool spacesAllowedBetweenNameAndValue)
	    : m_NewFieldData(nullptr), m_TextBasedProtocolMessage(TextBasedProtocolMessage),
	      m_NameOffsetInMessage(offsetInMessage), m_NextField(nullptr), m_NameValueSeparator(nameValueSeparator),
	      m_SpacesAllowedBetweenNameAndValue(spacesAllowedBetweenNameAndValue)
	{
		char* fieldData = reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data + m_NameOffsetInMessage);
		char* fieldEndPtr = static_cast<char*>(memchr(
		    fieldData, '\n', m_TextBasedProtocolMessage->m_DataLen - static_cast<size_t>(m_NameOffsetInMessage)));
		if (fieldEndPtr == nullptr)
			m_FieldSize = tbp_my_own_strnlen(fieldData, m_TextBasedProtocolMessage->m_DataLen -
			                                                static_cast<size_t>(m_NameOffsetInMessage));
		else
			m_FieldSize = fieldEndPtr - fieldData + 1;

		if (m_FieldSize == 0 || (*fieldData) == '\r' || (*fieldData) == '\n')
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

		char* fieldValuePtr = static_cast<char*>(
		    memchr(fieldData, nameValueSeparator,
		           m_TextBasedProtocolMessage->m_DataLen - static_cast<size_t>(m_NameOffsetInMessage)));
		// could not find the position of the separator, meaning field value position is unknown
		if (fieldValuePtr == nullptr || (fieldEndPtr != nullptr && fieldValuePtr >= fieldEndPtr))
		{
			m_ValueOffsetInMessage = -1;
			m_FieldValueSize = -1;
			m_FieldNameSize = m_FieldSize;
		}
		else
		{
			m_FieldNameSize = fieldValuePtr - fieldData;
			// Header field looks like this: <field_name>[separator]<zero or more spaces><field_Value>
			// So fieldValuePtr give us the position of the separator. Value offset is the first non-space byte forward
			fieldValuePtr++;

			// reached the end of the packet and value start offset wasn't found
			if (static_cast<size_t>(fieldValuePtr - reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data)) >=
			    m_TextBasedProtocolMessage->getDataLen())
			{
				m_ValueOffsetInMessage = -1;
				m_FieldValueSize = -1;
				return;
			}

			if (spacesAllowedBetweenNameAndValue)
			{
				// advance fieldValuePtr 1 byte forward while didn't get to end of packet and fieldValuePtr points to a
				// space char
				while (
				    static_cast<size_t>(fieldValuePtr - reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data)) <
				        m_TextBasedProtocolMessage->getDataLen() &&
				    (*fieldValuePtr) == ' ')
				{
					fieldValuePtr++;
				}
			}

			// reached the end of the packet and value start offset wasn't found
			if (static_cast<size_t>(fieldValuePtr - reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data)) >=
			    m_TextBasedProtocolMessage->getDataLen())
			{
				m_ValueOffsetInMessage = -1;
				m_FieldValueSize = -1;
			}
			else
			{
				m_ValueOffsetInMessage = fieldValuePtr - reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data);
				// couldn't find the end of the field, so assuming the field value length is from m_ValueOffsetInMessage
				// until the end of the packet
				if (fieldEndPtr == nullptr)
				{
					// clang-format off
					m_FieldValueSize = reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data + m_TextBasedProtocolMessage->getDataLen()) - fieldValuePtr;
					// clang-format on
				}
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

	HeaderField::HeaderField(const std::string& name, const std::string& value, char nameValueSeparator,
	                         bool spacesAllowedBetweenNameAndValue)
	{
		m_NameValueSeparator = nameValueSeparator;
		m_SpacesAllowedBetweenNameAndValue = spacesAllowedBetweenNameAndValue;
		initNewField(name, value);
	}

	void HeaderField::initNewField(const std::string& name, const std::string& value)
	{
		m_TextBasedProtocolMessage = nullptr;
		m_NameOffsetInMessage = 0;
		m_NextField = nullptr;

		// first building the name-value separator
		std::string nameValueSeparation(1, m_NameValueSeparator);
		if (m_SpacesAllowedBetweenNameAndValue)
			nameValueSeparation += " ";

		// Field size is: name_length + separator_len + value_length + '\r\n'
		if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
			m_FieldSize = name.length() + nameValueSeparation.length() + value.length() + 2;
		else
			// Field is \r\n (2B)
			m_FieldSize = 2;

		m_NewFieldData = new uint8_t[m_FieldSize];
		std::string fieldData;

		if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
			fieldData = name + nameValueSeparation + value + "\r\n";
		else
			fieldData = "\r\n";

		// copy field data to m_NewFieldData
		memcpy(m_NewFieldData, fieldData.c_str(), m_FieldSize);

		// calculate value offset
		if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
			m_ValueOffsetInMessage = name.length() + nameValueSeparation.length();
		else
			m_ValueOffsetInMessage = 0;
		m_FieldNameSize = name.length();
		m_FieldValueSize = value.length();

		if (name != PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER)
			m_IsEndOfHeaderField = false;
		else
			m_IsEndOfHeaderField = true;
	}

	HeaderField::~HeaderField()
	{
		if (m_NewFieldData != nullptr)
			delete[] m_NewFieldData;
	}

	HeaderField::HeaderField(const HeaderField& other)
	    : m_NameValueSeparator('\0'), m_SpacesAllowedBetweenNameAndValue(false)
	{
		m_NameValueSeparator = other.m_NameValueSeparator;
		m_SpacesAllowedBetweenNameAndValue = other.m_SpacesAllowedBetweenNameAndValue;
		initNewField(other.getFieldName(), other.getFieldValue());
	}

	HeaderField& HeaderField::operator=(const HeaderField& other)
	{
		m_NameValueSeparator = other.m_NameValueSeparator;
		m_SpacesAllowedBetweenNameAndValue = other.m_SpacesAllowedBetweenNameAndValue;
		if (m_NewFieldData != nullptr)
			delete[] m_NewFieldData;
		initNewField(other.getFieldName(), other.getFieldValue());

		return (*this);
	}

	char* HeaderField::getData() const
	{
		if (m_TextBasedProtocolMessage == nullptr)
			return reinterpret_cast<char*>(m_NewFieldData);
		else
			return reinterpret_cast<char*>(m_TextBasedProtocolMessage->m_Data);
	}

	void HeaderField::setNextField(HeaderField* nextField)
	{
		m_NextField = nextField;
	}

	HeaderField* HeaderField::getNextField() const
	{
		return m_NextField;
	}

	std::string HeaderField::getFieldName() const
	{
		std::string result;

		if (m_FieldNameSize != static_cast<size_t>(-1))
			result.assign((getData() + m_NameOffsetInMessage), m_FieldNameSize);

		return result;
	}

	std::string HeaderField::getFieldValue() const
	{
		std::string result;
		if (m_ValueOffsetInMessage != -1)
			result.assign((getData() + m_ValueOffsetInMessage), m_FieldValueSize);
		return result;
	}

	bool HeaderField::setFieldValue(const std::string& newValue)
	{
		// Field isn't linked with any message yet
		if (m_TextBasedProtocolMessage == nullptr)
		{
			std::string name = getFieldName();
			delete[] m_NewFieldData;
			initNewField(name, newValue);
			return true;
		}

		std::string curValue = getFieldValue();
		int lengthDifference = newValue.length() - curValue.length();
		// new value is longer than current value
		if (lengthDifference > 0)
		{
			if (!m_TextBasedProtocolMessage->extendLayer(m_ValueOffsetInMessage, lengthDifference))
			{
				PCPP_LOG_ERROR("Could not extend layer");
				return false;
			}
		}
		// new value is shorter than current value
		else if (lengthDifference < 0)
		{
			if (!m_TextBasedProtocolMessage->shortenLayer(m_ValueOffsetInMessage, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Could not shorten layer");
				return false;
			}
		}

		if (lengthDifference != 0)
			m_TextBasedProtocolMessage->shiftFieldsOffset(getNextField(), lengthDifference);

		// update sizes
		m_FieldValueSize += lengthDifference;
		m_FieldSize += lengthDifference;

		// write new value to field data
		memcpy(getData() + m_ValueOffsetInMessage, newValue.c_str(), newValue.length());

		return true;
	}

	void HeaderField::attachToTextBasedProtocolMessage(TextBasedProtocolMessage* message, int fieldOffsetInMessage)
	{
		if (m_TextBasedProtocolMessage != nullptr && m_TextBasedProtocolMessage != message)
		{
			PCPP_LOG_ERROR("Header field already associated with another message");
			return;
		}

		if (m_NewFieldData == nullptr)
		{
			PCPP_LOG_ERROR("Header field doesn't have new field data");
			return;
		}

		delete[] m_NewFieldData;
		m_NewFieldData = nullptr;
		m_TextBasedProtocolMessage = message;

		int valueAndNameDifference = m_ValueOffsetInMessage - m_NameOffsetInMessage;
		m_NameOffsetInMessage = fieldOffsetInMessage;
		m_ValueOffsetInMessage = m_NameOffsetInMessage + valueAndNameDifference;
	}

}  // namespace pcpp
