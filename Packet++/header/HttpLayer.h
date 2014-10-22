#ifndef PACKETPP_HTTP_LAYER
#define PACKETPP_HTTP_LAYER

#include "Layer.h"
#include <string>

enum HttpVersion
{
	ZeroDotNine,
	OneDotZero,
	OneDotOne,
	HttpVersionUnknown
};

class HttpMessage;

class HttpField
{
	friend class HttpMessage;
public:
	HttpField(std::string name, std::string value);
	~HttpField();
	inline size_t getFieldSize() { return m_FieldSize; }
	std::string getFieldName();
	std::string getFieldValue();
	void setFieldValue(std::string newValue);
	inline bool isEndOfHeader() { return m_IsEndOfHeaderField; }
private:
	HttpField(HttpMessage* httpMessage, int offsetInMessage);
	char* getFieldData();
	inline void setNextField(HttpField* nextField) { m_NextField = nextField; }
	inline HttpField* getNextField() { return m_NextField; }
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
	void addField(HttpField& newField);
	void insertField(const HttpField* prevField, HttpField& newField);
	void removeField(HttpField* fieldToRemove);

	// implement Layer's abstract methods
	void parseNextLayer();
	size_t getHeaderLen();
	void computeCalculateFields();
protected:
	HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer);
	void parseFields(int fieldsOffset);

	HttpField* m_FieldList;
	HttpField* m_LastField;
};


class HttpRequestFirstLine;

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

	HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer);
	HttpRequestLayer();
	inline HttpRequestFirstLine* getFirstLine() { return m_FirstLine; }
private:
	HttpRequestFirstLine* m_FirstLine;
};

//class HttpResponseLayer : public HttpMessage
//{
//
//};

class HttpRequestFirstLine
{
	friend class HttpRequestLayer;
public:
	inline HttpRequestLayer::HttpMethod getMethod() { return m_Method; }
	void setMethod();

	std::string getUri();
	void setUri(std::string newUri);

	inline HttpVersion getVersion() { return m_Version; }
	void setVersion(HttpVersion newVersion);

	static HttpRequestLayer::HttpMethod parseMethod(char* data, size_t dataLen);
	inline int getSize() { return m_FirstLineEndOffset; }

	inline bool isComplete() { return m_IsComplete; }
private:
	HttpRequestFirstLine(HttpRequestLayer* httpRequest);
	//HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpMethod method, std::string uri = "", HttpVersion version);

	void parseVersion();
	HttpRequestLayer* m_HttpRequest;
	HttpRequestLayer::HttpMethod m_Method;
	HttpVersion m_Version;
	int m_VersionOffset;
	int m_UriOffset;
	int m_FirstLineEndOffset;
	bool m_IsComplete;
};

#endif /* PACKETPP_HTTP_LAYER */
