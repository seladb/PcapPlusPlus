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

#define HTTP_HOST_FIELD 				"Host"
#define HTTP_CONNECTION_FIELD 			"Connection"
#define HTTP_USER_AGENT_FIELD			"User-Agent"
#define HTTP_REFERER_FIELD				"Referer"
#define HTTP_ACCEPT_FIELD 				"Accept"
#define HTTP_ACCEPT_ENCODING_FIELD		"Accept-Encoding"
#define HTTP_ACCEPT_LANGUAGE_FIELD		"Accept-Language"
#define HTTP_COOKIE_FIELD 				"Cookie"
#define HTTP_CONTENT_LENGTH_FIELD		"Content-Length"
#define HTTP_CONTENT_ENCODING_FIELD 	"Content-Encoding"
#define HTTP_CONTENT_TYPE_FIELD			"Content-Type"
#define HTTP_TRANSFER_ENCODING_FIELD	"Transfer-Encoding"
#define HTTP_SERVER_FIELD				"Server"




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

class HttpResponseFirstLine;


class HttpResponseLayer : public HttpMessage
{
	friend class HttpResponseFirstLine;
public:
	enum HttpResponseStatusCode
	{
		Http100Continue,
		Http101SwitchingProtocols,
		Http102Processing,
		Http200OK,
		Http201Created,
		Http202Accepted,
		Http203NonAuthoritativeInformation, //Non-Authoritative Information
		Http204NoContent,
		http205ResetContent,
		Http206PartialContent,
		Http207MultiStatus,	//Multi-Status
		Http208AlreadyReported,
		Http226IMUsed,
		Http300MultipleChoices,
		Http301MovedPermanently,
		Http302,
		Http303SeeOther,
		Http304NotModified,
		Http305UseProxy,
		Http306SwitchProxy,
		Http307TemporaryRedirect,
		Http308PermanentRedirect,
		Http400BadRequest,
		Http401Unauthorized,
		Http402PaymentRequired,
		Http403Forbidden,
		Http404NotFound,
		Http405MethodNotAllowed,
		Http406NotAcceptable,
		Http407ProxyAuthenticationRequired,
		Http408RequestTimeout,
		Http409Conflict,
		Http410Gone,
		Http411LengthRequired,
		Http412PreconditionFailed,
		Http413RequestEntityTooLarge,
		Http414RequestURITooLong, // Request-URI Too Long
		Http415UnsupportedMediaType,
		Http416RequestedRangeNotSatisfiable,
		Http417ExpectationFailed,
		Http418Imateapot, // I'm a teapot
		Http419AuthenticationTimeout,
		Http420,
		Http422UnprocessableEntity,
		Http423Locked,
		Http424FailedDependency,
		Http426UpgradeRequired,
		Http428PreconditionRequired,
		Http429TooManyRequests,
		Http431RequestHeaderFieldsTooLarge,
		Http440LoginTimeout,
		Http444NoResponse,
		Http449RetryWith,
		Http450BlockedByWindowsParentalControls, // Blocked by Windows Parental Controls
		Http451,
		Http494RequestHeaderTooLarge,
		Http495CertError,
		Http496NoCert,
		Http497HTTPtoHTTPS,
		Http498TokenExpiredInvalid, // Token expired/invalid
		Http499,
		Http500InternalServerError,
		Http501NotImplemented,
		Http502BadGateway,
		Http503ServiceUnavailable,
		Http504GatewayTimeout,
		Http505HTTPVersionNotSupported,
		Http506VariantAlsoNegotiates,
		Http507InsufficientStorage,
		Http508LoopDetected,
		Http509BandwidthLimitExceeded,
		Http510NotExtended,
		Http511NetworkAuthenticationRequired,
		Http520OriginError,
		Http521WebServerIsDown, // Web server is down
		Http522ConnectionTimedOut, // Connection timed out
		Http523ProxyDeclinedRequest,
		Http524aTimeoutOccurred, // A timeout occurred
		Http598NetworkReadTimeoutError, // Network read timeout error
		Http599NetworkConnectTimeoutError, // Network connect timeout error
		HttpStatusCodeUnknown
	};

	HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	HttpResponseLayer(HttpVersion version, HttpResponseLayer::HttpResponseStatusCode statuCode, std::string statusCodeString = "");
	~HttpResponseLayer();
	inline HttpResponseFirstLine* getFirstLine() { return m_FirstLine; }

	HttpField* setContentLength(int contentLength, const std::string prevFieldName = "");
	int getContentLength();

private:
	HttpResponseFirstLine* m_FirstLine;

};





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





// -------- Class HttpResponseFirstLine -----------------

class HttpResponseFirstLine
{
	friend class HttpResponseLayer;
public:
	inline HttpResponseLayer::HttpResponseStatusCode getStatusCode() { return m_StatusCode; }
	int getStatusCodeAsInt();
	std::string getStatusCodeString();
	bool setStatusCode(HttpResponseLayer::HttpResponseStatusCode newStatusCode, std::string statusCodeString = "");

	inline HttpVersion getVersion() { return m_Version; }
	void setVersion(HttpVersion newVersion);

	static HttpResponseLayer::HttpResponseStatusCode parseStatusCode(char* data, size_t dataLen);
	inline int getSize() { return m_FirstLineEndOffset; }

	inline bool isComplete() { return m_IsComplete; }

	class HttpResponseFirstLineException : public std::exception
	{
	public:
		~HttpResponseFirstLineException() throw() {}
		void setMessage(std::string message) { m_Message = message; }
		virtual const char* what() const throw()
		{
			return m_Message.c_str();
		}
	private:
		std::string m_Message;
	};

private:
	HttpResponseFirstLine(HttpResponseLayer* httpResponse);
	HttpResponseFirstLine(HttpResponseLayer* httpResponse,  HttpVersion version, HttpResponseLayer::HttpResponseStatusCode statusCode, std::string statusCodeString = "");

	static HttpVersion parseVersion(char* data, size_t dataLen);
	static HttpResponseLayer::HttpResponseStatusCode validateStatusCode(char* data, size_t dataLen, HttpResponseLayer::HttpResponseStatusCode potentialCode);


	HttpResponseLayer* m_HttpResponse;
	HttpVersion m_Version;
	HttpResponseLayer::HttpResponseStatusCode m_StatusCode;
	int m_FirstLineEndOffset;
	bool m_IsComplete;
	HttpResponseFirstLineException m_Exception;
};


#endif /* PACKETPP_HTTP_LAYER */
