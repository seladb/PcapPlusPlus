#ifndef PACKETPP_TEXT_BASED_PROTOCOL_LAYER
#define PACKETPP_TEXT_BASED_PROTOCOL_LAYER

#include <map>
#include "Layer.h"

/// @file

namespace pcpp
{

/** End of header */
#define PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER ""

class TextBasedProtocolMessage;


// -------- Class HeaderField -----------------


/**
 * @class HeaderField
 * A wrapper class for each text-based-protocol header field, e.g "Host", "Cookie", "Content-Length", "Via", "Call-ID", etc.
 * Each field contains a name (e.g "Host") and a value (e.g "www.wikipedia.org"). The user can get and set both of them through dedicated methods.
 * The separator between header fields is either CRLF ("\r\n\") or LF ("\n") in more rare cases, which means every HeaderField instance is
 * responsible for wrapping and parsing a header field from the previous CRLF (not inclusive) until the next CRLF/LF (inclusive)
 * A special case is with the end of a header, meaning 2 consecutive CRLFs ("\r\n\r\n") or consecutive LFs ("\n\n"). PcapPlusPlus treats the first
 * CRLF/LF as part of the last field in the header, and the second CRLF is an HeaderField instance of its own which name and values are an empty string ("")
 * or pcpp::PCPP_END_OF_TEXT_BASED_PROTOCOL_HEADER
 */
class HeaderField
{
	friend class TextBasedProtocolMessage;
public:

	~HeaderField();

	/**
	 * A copy constructor that creates a new instance out of an existing HeaderField instance. The copied instance will not have shared
	 * resources with the original instance, meaning all members and properties are copied
	 * @param[in] other The original instance to copy from
	 */
	HeaderField(const HeaderField& other);

	/**
	 * @return The field length in bytes, meaning count of all characters from the previous CRLF (not inclusive) until the next CRLF (inclusive)
	 * For example: the field "Host: www.wikipedia.org\r\n" will have the length of 25
	 */
	inline size_t getFieldSize() { return m_FieldSize; }

	/**
	 * @return The field name as string. Notice the return data is copied data, so changing it won't change the packet data
	 */
	std::string getFieldName() const;

	/**
	 * @return The field value as string. Notice the return data is copied data, so changing it won't change the packet data
	 */
	std::string getFieldValue() const;

	/**
	 * A setter for field value
	 * @param[in] newValue The new value to set to the field. Old value will be deleted
	 */
	bool setFieldValue(std::string newValue);

	/**
	 * Get an indication whether the field is a field that ends the header (meaning contain only CRLF - see class explanation)
	 * @return True if this is a end-of-header field, false otherwise
	 */
	inline bool isEndOfHeader() { return m_IsEndOfHeaderField; }

private:
	HeaderField(std::string name, std::string value, char nameValueSeperator, bool spacesAllowedBetweenNameAndValue);
	HeaderField(TextBasedProtocolMessage* TextBasedProtocolMessage, int offsetInMessage, char nameValueSeperator, bool spacesAllowedBetweenNameAndValue);
	char* getData();
	inline void setNextField(HeaderField* nextField) { m_NextField = nextField; }
	inline HeaderField* getNextField() { return m_NextField; }
	void initNewField(std::string name, std::string value);
	void attachToTextBasedProtocolMessage(TextBasedProtocolMessage* message, int fieldOffsetInMessage);
	uint8_t* m_NewFieldData;
	TextBasedProtocolMessage* m_TextBasedProtocolMessage;
	int m_NameOffsetInMessage;
	size_t m_FieldNameSize;
	int m_ValueOffsetInMessage;
	size_t m_FieldValueSize;
	size_t m_FieldSize;
	HeaderField* m_NextField;
	bool m_IsEndOfHeaderField;
	char m_NameValueSeperator;
	bool m_SpacesAllowedBetweenNameAndValue;
};




// -------- Class TextBasedProtocolMessage -----------------

/**
 * @class TextBasedProtocolMessage
 * An abstract base class that wraps text-based-protocol header layers (both requests and responses). It is the base class for all those layers.
 * This class is not meant to be instantiated, hence the protected c'tor
 */
class TextBasedProtocolMessage : public Layer
{
	friend class HeaderField;
public:
	~TextBasedProtocolMessage();

	/**
	 * Get a pointer to a header field by name. The search is case insensitive, meaning if a field with name "Host" exists and the
	 * fieldName parameter is "host" (all letter are lower case), this method will return a pointer to "Host" field
	 * @param[in] fieldName The field name
	 * @param[in] index Optional parameter. If the field name appears more than once, this parameter will indicate which field to get.
	 * The default value is 0 (get the first appearance of the field name as appears on the packet)
	 * @return A pointer to an HeaderField instance, or NULL if field doesn't exist
	 */
	HeaderField* getFieldByName(std::string fieldName, int index = 0);

	/**
	 * @return A pointer to the first header field exists in this message, or NULL if no such field exists
	 */
	inline HeaderField* getFirstField() { return m_FieldList; }

	/**
	 * Get the field which appears after a certain field
	 * @param[in] prevField A pointer to the field
	 * @return The field after prevField or NULL if prevField is the last field. If prevField is NULL, this method will return NULL
	 */
	inline HeaderField* getNextField(HeaderField* prevField) { if (prevField != NULL) return prevField->getNextField(); else return NULL; }

	/**
	 * @return The number of header fields currently in the layer (not including CRLF at the end of the header)
	 */
	int getFieldCount();

	/**
	 * Add a new header field to this message. This field will be added last (before the end-of-header field)
	 * @param[in] fieldName The field name
	 * @param[in] fieldValue The field value
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	virtual HeaderField* addField(const std::string& fieldName, const std::string& fieldValue);

	/**
	 * Add a new header field to this message. This field will be added last (before the end-of-header field)
	 * @param[in] newField The header field to add
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	virtual HeaderField* addField(const HeaderField& newField);

	/**
	 * Add the special end-of-header field (see the explanation in HeaderField)
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	HeaderField* addEndOfHeader();

	/**
	 * Insert a new field after an existing field
	 * @param[in] prevField A pointer to the existing field. If it's NULL the new field will be added as first field
	 * @param[in] fieldName The field name
	 * @param[in] fieldValue The field value
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	virtual HeaderField* insertField(HeaderField* prevField, const std::string& fieldName, const std::string& fieldValue);

	/**
	 * Insert a new field after an existing field
	 * @param[in] prevFieldName A name of an existing field. If the field doesn't exist NULL will be returned.
	 * If field name is empty ('') the new field will be added as first field
	 * @param[in] fieldName The field name
	 * @param[in] fieldValue The field value
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	virtual HeaderField* insertField(std::string prevFieldName, const std::string& fieldName, const std::string& fieldValue);

	/**
	 * Insert a new field after an existing field
	 * @param[in] prevField A pointer to the existing field
	 * @param[in] newField The header field to add
	 * @return A pointer to the newly created header field, or NULL if the field could not be created
	 */
	virtual HeaderField* insertField(HeaderField* prevField, const HeaderField& newField);

	/**
	 * Remove a field from the message
	 * @param[in] fieldToRemove A pointer to the field that should be removed
	 * @return True if the field was removed successfully, or false otherwise (for example: if fieldToRemove is NULL, if it doesn't exist
	 * in the message, or if the removal failed)
	 */
	bool removeField(HeaderField* fieldToRemove);

	/**
	 * Remove a field from the message
	 * @param[in] fieldName The name of the field that should be removed
	 * @param[in] index Optional parameter. If the field name appears more than once, this parameter will indicate which field to remove.
	 * The default value is 0 (remove the first appearance of the field name as appears on the packet)
	 * @return True if the field was removed successfully, or false otherwise (for example: if fieldName doesn't exist in the message, or if the removal failed)
	 */
	bool removeField(std::string fieldName, int index = 0);

	/**
	 * Indicate whether the header is complete (ending with end-of-header "\r\n\r\n" or "\n\n") or spread over more packets
	 * @return True if the header is complete or false if not
	 */
	bool isHeaderComplete();

	// implement Layer's abstract methods

	/**
	 * Currently set only PayloadLayer for the rest of the data
	 */
	virtual void parseNextLayer();

	/**
	 * @return The message length
	 */
	size_t getHeaderLen();

	/**
	 * Does nothing for this class
	 */
	virtual void computeCalculateFields();

protected:
	TextBasedProtocolMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	TextBasedProtocolMessage() : m_FieldList(NULL), m_LastField(NULL), m_FieldsOffset(0) {}

	// copy c'tor
	TextBasedProtocolMessage(const TextBasedProtocolMessage& other);
	TextBasedProtocolMessage& operator=(const TextBasedProtocolMessage& other);

	void copyDataFrom(const TextBasedProtocolMessage& other);

	void parseFields();
	void shiftFieldsOffset(HeaderField* fromField, int numOfBytesToShift);

	// abstract methods
	virtual char getHeaderFieldNameValueSeparator() = 0;
	virtual bool spacesAllowedBetweenHeaderFieldNameAndValue() = 0;

	HeaderField* m_FieldList;
	HeaderField* m_LastField;
	int m_FieldsOffset;
	std::multimap<std::string, HeaderField*> m_FieldNameToFieldMap;
};


}


#endif // PACKETPP_TEXT_BASED_PROTOCOL_LAYER
