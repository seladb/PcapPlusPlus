#ifndef PACKETPP_HTTP_LAYER
#define PACKETPP_HTTP_LAYER

#include "Layer.h"
#include <string>
#include <exception>
#include <map>

enum HttpVersion
{
	ZeroDotNine,
	OneDotZero,
	OneDotOne,
	HttpVersionUnknown
};

// some popular HTTP fields

#define HTTP_HOST_FIELD 			"Host"
#define HTTP_CONNECTION_FIELD 		"Connection"
#define HTTP_USER_AGENT_FIELD		"User-Agent"
#define HTTP_REFERER_FIELD			"Referer"
#define HTTP_ACCEPT_FIELD 			"Accept"
#define HTTP_ACCEPT_ENCODING_FIELD	"Accept-Encoding"
#define HTTP_ACCEPT_LANGUAGE_FIELD	"Accept-Language"
#define HTTP_COOKIE_FIELD 			"Cookie"
#define HTTP_CONTENT_LENGTH_FIELD	"Content-Length"


class HttpMessage;




// -------- Class HttpField -----------------

#define END_OF_HTTP_HEADER ""

class HttpField
{
	friend class HttpMessage;
public:
	HttpField(std::string name, std::string value);
	~HttpField();
	// copy c'tor
	HttpField(const HttpField& other);
	inline size_t getFieldSize() { return m_FieldSize; }
	std::string getFieldName() const;
	std::string getFieldValue() const;
	bool setFieldValue(std::string newValue);
	inline bool isEndOfHeader() { return m_IsEndOfHeaderField; }

private:
	HttpField(HttpMessage* httpMessage, int offsetInMessage);
	char* getData();
	inline void setNextField(HttpField* nextField) { m_NextField = nextField; }
	inline HttpField* getNextField() { return m_NextField; }
	void initNewField(std::string name, std::string value);
	void attachToHttpMessage(HttpMessage* message, int fieldOffsetInMessage);
	uint8_t* m_NewFieldData;
	HttpMessage* m_HttpMessage;
	int m_NameOffsetInMessage;
	size_t m_FieldNameSize;
	int m_ValueOffsetInMessage;
	size_t m_FieldValueSize;
	size_t m_FieldSize;
	HttpField* m_NextField;
	bool m_IsEndOfHeaderField;
};




// -------- Class HttpMessage -----------------

// This is the base class for HttpRequestLayer and HttpResponseLayer. It's not meant to be instantiated on its on
// (hence the protected c'tor

class HttpMessage : public Layer
{
	friend class HttpField;
public:
	~HttpMessage();

	HttpField* getFieldByName(std::string fieldName);
	inline HttpField* getFirstField() { return m_FieldList; }
	inline HttpField* getNextField(HttpField* prevField) { if (prevField != NULL) return prevField->getNextField(); else return NULL; }
	HttpField* addField(const std::string& fieldName, const std::string& fieldValue);
	HttpField* addField(const HttpField& newField);
	HttpField* addEndOfHeader();
	HttpField* insertField(HttpField* prevField, const std::string& fieldName, const std::string& fieldValue);
	HttpField* insertField(HttpField* prevField, const HttpField& newField);
	bool removeField(HttpField* fieldToRemove);
	bool removeField(std::string fieldName);

	// implement Layer's abstract methods
	void parseNextLayer();
	size_t getHeaderLen();
	void computeCalculateFields();
protected:
	HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	HttpMessage() : m_FieldList(NULL), m_LastField(NULL), m_FieldsOffset(0) {}
	void parseFields();
	void shiftFieldsOffset(HttpField* fromField, int numOfBytesToShift);

	HttpField* m_FieldList;
	HttpField* m_LastField;
	int m_FieldsOffset;
	std::map<std::string, HttpField*> m_FieldNameToFieldMap;
};




class HttpRequestFirstLine;




// -------- Class HttpRequestLayer -----------------


class HttpRequestLayer : public HttpMessage
{
	friend class HttpRequestFirstLine;
public:
	enum HttpMethod
	{
		HttpGET,
		HttpHEAD,
		HttpPOST,
		HttpPUT,
		HttpDELETE,
		HttpTRACE,
		HttpOPTIONS,
		HttpCONNECT,
		HttpPATCH,
		HttpMethodUnknown
	};

	HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	HttpRequestLayer(HttpMethod method, std::string uri, HttpVersion version);
	~HttpRequestLayer();
	inline HttpRequestFirstLine* getFirstLine() { return m_FirstLine; }
	std::string getUrl();
private:
	HttpRequestFirstLine* m_FirstLine;
};





// -------- Class HttpResponseLayer -----------------


//class HttpResponseLayer : public HttpMessage
//{
//
//};





// -------- Class HttpRequestFirstLine -----------------


class HttpRequestFirstLine
{
	friend class HttpRequestLayer;
public:
	inline HttpRequestLayer::HttpMethod getMethod() { return m_Method; }
	bool setMethod(HttpRequestLayer::HttpMethod newMethod);

	std::string getUri();
	bool setUri(std::string newUri);

	inline HttpVersion getVersion() { return m_Version; }
	void setVersion(HttpVersion newVersion);

	static HttpRequestLayer::HttpMethod parseMethod(char* data, size_t dataLen);
	inline int getSize() { return m_FirstLineEndOffset; }

	inline bool isComplete() { return m_IsComplete; }

	class HttpRequestFirstLineException : public std::exception
	{
	public:
		~HttpRequestFirstLineException() throw() {}
		void setMessage(std::string message) { m_Message = message; }
		virtual const char* what() const throw()
		{
			return m_Message.c_str();
		}
	private:
		std::string m_Message;
	};
private:
	HttpRequestFirstLine(HttpRequestLayer* httpRequest);
	HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpRequestLayer::HttpMethod method, HttpVersion version, std::string uri = "/")
		throw(HttpRequestFirstLineException);

	void parseVersion();
	HttpRequestLayer* m_HttpRequest;
	HttpRequestLayer::HttpMethod m_Method;
	HttpVersion m_Version;
	int m_VersionOffset;
	int m_UriOffset;
	int m_FirstLineEndOffset;
	bool m_IsComplete;
	HttpRequestFirstLineException m_Exception;
};

#endif /* PACKETPP_HTTP_LAYER */
