#ifndef PACKETPP_HTTP_LAYER
#define PACKETPP_HTTP_LAYER

#include "Layer.h"
#include <string>
#include <exception>
#include <map>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * An enum for HTTP version
	 */
	enum HttpVersion
	{
		/** HTTP/0.9 */
		ZeroDotNine,
		/** HTTP/1.0 */
		OneDotZero,
		/** HTTP/1.1 */
		OneDotOne,
		/** Unknown HTTP version */
		HttpVersionUnknown
	};

	// some popular HTTP fields

	/** Host field */
#define PCPP_HTTP_HOST_FIELD 				"Host"
	/** Connection field */
#define PCPP_HTTP_CONNECTION_FIELD 			"Connection"
	/** User-Agent field */
#define PCPP_HTTP_USER_AGENT_FIELD			"User-Agent"
	/** Referer field */
#define PCPP_HTTP_REFERER_FIELD				"Referer"
	/** Accept field */
#define PCPP_HTTP_ACCEPT_FIELD 				"Accept"
	/** Accept-Encoding field */
#define PCPP_HTTP_ACCEPT_ENCODING_FIELD		"Accept-Encoding"
	/** Accept-Language field */
#define PCPP_HTTP_ACCEPT_LANGUAGE_FIELD		"Accept-Language"
	/** Cookie field */
#define PCPP_HTTP_COOKIE_FIELD 				"Cookie"
	/** Content-Length field */
#define PCPP_HTTP_CONTENT_LENGTH_FIELD		"Content-Length"
	/** Content-Encoding field */
#define PCPP_HTTP_CONTENT_ENCODING_FIELD 	"Content-Encoding"
	/** Content-Type field */
#define PCPP_HTTP_CONTENT_TYPE_FIELD			"Content-Type"
	/** Transfer-Encoding field */
#define PCPP_HTTP_TRANSFER_ENCODING_FIELD	"Transfer-Encoding"
	/** Server field */
#define PCPP_HTTP_SERVER_FIELD				"Server"




	class HttpMessage;




	// -------- Class HttpField -----------------

	/** End of HTTP header */
#define PCPP_END_OF_HTTP_HEADER ""

	/**
	 * @class HttpField
	 * A wrapper class for each HTTP header field, e.g "Host", "Cookie", "Content-Length", etc.
	 * Each field contains a name (e.g "Host") and a value (e.g "www.wikipedia.org"). The user can get and set both of them through dedicated methods.
	 * The separator between HTTP header fields is either CRLF ("\r\n\") or LF ("\n") in more rare cases, which means every HttpField instance is
	 * responsible for wrapping and parsing a HTTP header field from the previous CRLF (not inclusive) until the next CRLF/LF (inclusive)
	 * A special case is with the end of an HTTP header, meaning 2 consecutive CRLFs ("\r\n\r\n") or consecutive LFs ("\n\n"). PcapPlusPlus treats the first
	 * CRLF/LF as part of the last field in the header, and the second CRLF is an HttpField instance of its own which name and values are an empty string ("")
	 * or pcpp::END_OF_HTTP_HEADER
	 */
	class HttpField
	{
		friend class HttpMessage;
	public:
		/**
		 * A constructor for creating a new HttpField, not from an existing packet. This constructor can be used to create HTTP fields for
		 * a new HTTP message or to add new HTTP fields to a current message.
		 * The constructor that is used for parsing an existing packet is private and used by HttpMessage in the process of parsing the
		 * HTTP header
		 * @param[in] name The field name
		 * @param[in] value The field value
		 */
		HttpField(std::string name, std::string value);

		~HttpField();

		/**
		 * A copy constructor that creates a new instance out of an existing HttpField instance. The copied instance will not have shared
		 * resources with the original instance, meaning all members and properties are copied
		 * @param[in] other The original instance to copy from
		 */
		HttpField(const HttpField& other);

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

	/**
	 * @class HttpMessage
	 * A base class that wraps HTTP header layers (both request and response). It is the base class for HttpRequestLayer and HttpResponseLayer.
	 * This class is not abstract but it's not meant to be instantiated, hence the protected c'tor
	 */
	class HttpMessage : public Layer
	{
		friend class HttpField;
	public:
		~HttpMessage();

		/**
		 * Get a pointer to an HTTP header field by name. The search is case insensitive, meaning if a field with name "Host" exists and the
		 * fieldName parameter is "host" (all letter are lower case), this method will return a pointer to "Host" field
		 * @param[in] fieldName The field name
		 * @return A pointer to an HttpField instance, or NULL if field doesn't exist
		 */
		HttpField* getFieldByName(std::string fieldName);

		/**
		 * @return A pointer to the first HTTP field exists in this HTTP message, or NULL if no fields exist
		 */
		inline HttpField* getFirstField() { return m_FieldList; }

		/**
		 * Get the field which appears after a certain field
		 * @param[in] prevField A pointer to the field
		 * @return The field after prevField or NULL if prevField is the last field. If prevField is NULL, this method will return NULL
		 */
		inline HttpField* getNextField(HttpField* prevField) { if (prevField != NULL) return prevField->getNextField(); else return NULL; }

		/**
		 * Add a new HTTP field to this message. This field will be added last (before the end-of-header field)
		 * @param[in] fieldName The field name
		 * @param[in] fieldValue The field value
		 * @return A pointer to the newly created HTTP field, or NULL if the field could not be created
		 */
		HttpField* addField(const std::string& fieldName, const std::string& fieldValue);

		/**
		 * Add a new HTTP field to this message. This field will be added last (before the end-of-header field)
		 * @param[in] newField The HTTP field to add
		 * @return A pointer to the newly created HTTP field, or NULL if the field could not be created
		 */
		HttpField* addField(const HttpField& newField);

		/**
		 * Add the special end-of-header HTTP field (see the explanation in HttpField)
		 * @return A pointer to the newly created HTTP field, or NULL if the field could not be created
		 */
		HttpField* addEndOfHeader();

		/**
		 * Insert a new field after an existing field
		 * @param[in] prevField A pointer to the existing field. If it's NULL the new field will be added as first field
		 * @param[in] fieldName The field name
		 * @param[in] fieldValue The field value
		 * @return A pointer to the newly created HTTP field, or NULL if the field could not be created
		 */
		HttpField* insertField(HttpField* prevField, const std::string& fieldName, const std::string& fieldValue);

		/**
		 * Insert a new field after an existing field
		 * @param[in] prevField A pointer to the existing field
		 * @param[in] newField The HTTP field to add
		 * @return A pointer to the newly created HTTP field, or NULL if the field could not be created
		 */
		HttpField* insertField(HttpField* prevField, const HttpField& newField);

		/**
		 * Remove a field from the HTTP message
		 * @param[in] fieldToRemove A pointer to the field that should be removed
		 * @return True if the field was removed successfully, or false otherwise (for example: if fieldToRemove is NULL, if it doesn't exist
		 * in the message, or if the removal failed)
		 */
		bool removeField(HttpField* fieldToRemove);

		/**
		 * Remove a field from the HTTP message
		 * @param[in] fieldName The name of the field that should be removed
		 * @return True if the field was removed successfully, or false otherwise (for example: if fieldName doesn't exist in the message, or if the removal failed)
		 */
		bool removeField(std::string fieldName);

		/**
		 * Indicate whether the header is complete (ending with end-of-header "\r\n\r\n" or "\n\n") or spread over more packets
		 * @return True if the header is complete or false if not
		 */
		bool isHeaderComplete();

		// implement Layer's abstract methods

		/**
		 * Currently set only PayloadLayer for the rest of the data
		 */
		void parseNextLayer();

		/**
		 * @return The HTTP header length
		 */
		size_t getHeaderLen();

		/**
		 * Does nothing for this class
		 */
		void computeCalculateFields();

		OsiModelLayer getOsiModelLayer() { return OsiModelApplicationLayer; }

		/**
		 * @return A pointer to a map containing all TCP ports recognize as HTTP
		 */
		static const std::map<uint16_t, bool>* getHTTPPortMap();
	protected:
		HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
		HttpMessage() : m_FieldList(NULL), m_LastField(NULL), m_FieldsOffset(0) {}

		// copy c'tor
		HttpMessage(const HttpMessage& other);
		HttpMessage& operator=(const HttpMessage& other);

		void copyDataFrom(const HttpMessage& other);

		void parseFields();
		void shiftFieldsOffset(HttpField* fromField, int numOfBytesToShift);

		HttpField* m_FieldList;
		HttpField* m_LastField;
		int m_FieldsOffset;
		std::map<std::string, HttpField*> m_FieldNameToFieldMap;
	};




	class HttpRequestFirstLine;




	// -------- Class HttpRequestLayer -----------------

	/**
	 * @class HttpRequestLayer
	 * Represents an HTTP request header and inherits all basic functionality of HttpMessage.
	 * The functionality that is added for this class is the HTTP first line consept. An HTTP request has the following first line:
	 * <i>GET /bla/blabla.asp HTTP/1.1</i>
	 * Since it's not an "ordinary" HTTP field, it requires a special treatment and gets a class of it's own: HttpRequestFirstLine.
	 * Unlike most L2-4 protocols, an HTTP request header can spread over more than 1 packet. PcapPlusPlus currently doesn't support a header
	 * that is spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as HttpRequestLayer (the other packets
	 * won't be recognized as HttpRequestLayer) and 2) the HTTP header for the first packet won't be complete (as it continues in the following
	 * packets), this why PcapPlusPlus can indicate that HTTP request header is complete or not(doesn't end with "\r\n\r\n" or "\n\n") using
	 * HttpMessage#isHeaderComplete()
	 */
	class HttpRequestLayer : public HttpMessage
	{
		friend class HttpRequestFirstLine;
	public:
		/**
		 * HTTP request methods
		 */
		enum HttpMethod
		{
			/** GET */
			HttpGET,
			/** HEAD */
			HttpHEAD,
			/** POST */
			HttpPOST,
			/** PUT */
			HttpPUT,
			/** DELETE */
			HttpDELETE,
			/** TRACE */
			HttpTRACE,
			/** OPTIONS */
			HttpOPTIONS,
			/** CONNECT */
			HttpCONNECT,
			/** PATCH */
			HttpPATCH,
			/** Unknow HTTP method */
			HttpMethodUnknown
		};

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be parsed into HttpField's)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new HTTP request header with only the first line filled. Object will be created without further fields.
		 * The user can then ass fields using addField() methods
		 * @param[in] method The HTTP method used in this HTTP request
		 * @param[in] uri The URI of the first line
		 * @param[in] version HTTP version to be used in this request
		 */
		HttpRequestLayer(HttpMethod method, std::string uri, HttpVersion version);

		~HttpRequestLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor HttpMessage#HttpMessage() and add the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpRequestLayer(const HttpRequestLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator HttpMessage#operator=() and add the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpRequestLayer& operator=(const HttpRequestLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		inline HttpRequestFirstLine* getFirstLine() { return m_FirstLine; }

		/**
		 * The URL is hostname+uri. So given the following URL, for example: "www.cnn.com/main.html", the hostname is "www.cnn.com" and the URI
		 * is "/.main.html". URI and hostname are split to 2 different places inside the HTTP request packet: URI is in the first line and hostname
		 * is in "HOST" field.
		 * This methods concatenates the hostname and URI to the full URL
		 * @return The URL of the HTTP request message
		 */
		std::string getUrl();

		// implement Layer's abstract methods
		std::string toString();

	private:
		HttpRequestFirstLine* m_FirstLine;
	};





	// -------- Class HttpResponseLayer -----------------

	class HttpResponseFirstLine;


	/**
	 * @class HttpResponseLayer
	 * Represents an HTTP response header and inherits all basic functionality of HttpMessage.
	 * The functionality that is added for this class is the HTTP first line concept. An HTTP response has the following first line:
	 * <i>200 OK HTTP/1.1</i>
	 * Since it's not an "ordinary" HTTP field, it requires a special treatment and gets a class of it's own: HttpResponseFirstLine.
	 * Unlike most L2-4 protocols, an HTTP response header can spread over more than 1 packet. PcapPlusPlus currently doesn't support a header
	 * that is spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as HttpResponseLayer (the other packets
	 * won't be recognized as HttpResponseLayer) and 2) the HTTP header for the first packet won't be complete (as it continues in the following
	 * packets), this why PcapPlusPlus can indicate that HTTP response header is complete or not (doesn't end with "\r\n\r\n" or "\n\n") using
	 * HttpMessage#isHeaderComplete()
	 */
	class HttpResponseLayer : public HttpMessage
	{
		friend class HttpResponseFirstLine;
	public:
		/**
		 * Enum for HTTP response status codes
		 */
		enum HttpResponseStatusCode
		{
			/** 100 Continue*/
			Http100Continue,
			/** 101 Switching Protocols*/
			Http101SwitchingProtocols,
			/** 102 Processing */
			Http102Processing,
			/** 200 OK */
			Http200OK,
			/** 201 Created */
			Http201Created,
			/** 202 Accepted */
			Http202Accepted,
			/** 203 Non-Authoritative Information */
			Http203NonAuthoritativeInformation,
			/** 204 No Content*/
			Http204NoContent,
			/** 205 Reset Content*/
			http205ResetContent,
			/** 206 Partial Content */
			Http206PartialContent,
			/** 207 Multi-Status */
			Http207MultiStatus,
			/** 208 Already Reported */
			Http208AlreadyReported,
			/** 226 IM Used */
			Http226IMUsed,
			/** 300 Multiple Choices */
			Http300MultipleChoices,
			/** 301 Moved Permanently */
			Http301MovedPermanently,
			/** 302 (various messages) */
			Http302,
			/** 303 See Other */
			Http303SeeOther,
			/** 304 Not Modified */
			Http304NotModified,
			/** 305 Use Proxy */
			Http305UseProxy,
			/** 306 Switch Proxy */
			Http306SwitchProxy,
			/** 307 Temporary Redirect */
			Http307TemporaryRedirect,
			/** 308 Permanent Redirect, */
			Http308PermanentRedirect,
			/** 400 Bad Request */
			Http400BadRequest,
			/** 401 Unauthorized */
			Http401Unauthorized,
			/** 402 Payment Required */
			Http402PaymentRequired,
			/** 403 Forbidden */
			Http403Forbidden,
			/** 404 Not Found */
			Http404NotFound,
			/** 405 Method Not Allowed */
			Http405MethodNotAllowed,
			/** 406 Not Acceptable */
			Http406NotAcceptable,
			/** 407 Proxy Authentication Required */
			Http407ProxyAuthenticationRequired,
			/** 408 Request Timeout */
			Http408RequestTimeout,
			/** 409 Conflict */
			Http409Conflict,
			/** 410 Gone */
			Http410Gone,
			/** 411 Length Required */
			Http411LengthRequired,
			/** 412 Precondition Failed */
			Http412PreconditionFailed,
			/** 413 RequestEntity Too Large */
			Http413RequestEntityTooLarge,
			/** 414 Request-URI Too Long */
			Http414RequestURITooLong,
			/** 415 Unsupported Media Type */
			Http415UnsupportedMediaType,
			/** 416 Requested Range Not Satisfiable */
			Http416RequestedRangeNotSatisfiable,
			/** 417 Expectation Failed */
			Http417ExpectationFailed,
			/** 418 I'm a teapot */
			Http418Imateapot,
			/** 419 Authentication Timeout */
			Http419AuthenticationTimeout,
			/** 420 (various messages) */
			Http420,
			/** 422 Unprocessable Entity */
			Http422UnprocessableEntity,
			/** 423 Locked */
			Http423Locked,
			/** 424 Failed Dependency */
			Http424FailedDependency,
			/** 426 Upgrade Required */
			Http426UpgradeRequired,
			/** 428 Precondition Required */
			Http428PreconditionRequired,
			/** 429 Too Many Requests */
			Http429TooManyRequests,
			/** 431 Request Header Fields Too Large */
			Http431RequestHeaderFieldsTooLarge,
			/** 440 Login Timeout */
			Http440LoginTimeout,
			/** 444 No Response */
			Http444NoResponse,
			/** 449 Retry With */
			Http449RetryWith,
			/** 450 Blocked by Windows Parental Controls */
			Http450BlockedByWindowsParentalControls,
			/** 451 (various messages) */
			Http451,
			/** 494 Request Header Too Large */
			Http494RequestHeaderTooLarge,
			/** 495 Cert Error */
			Http495CertError,
			/** 496 No Cert */
			Http496NoCert,
			/** 497 HTTP to HTTPS */
			Http497HTTPtoHTTPS,
			/** 498 Token expired/invalid */
			Http498TokenExpiredInvalid,
			/** 499 (various messages) */
			Http499,
			/** 500 Internal Server Error */
			Http500InternalServerError,
			/** 501 Not Implemented */
			Http501NotImplemented,
			/** 502 Bad Gateway */
			Http502BadGateway,
			/** 503 Service Unavailable */
			Http503ServiceUnavailable,
			/** 504 Gateway Timeout */
			Http504GatewayTimeout,
			/** 505 HTTP Version Not Supported */
			Http505HTTPVersionNotSupported,
			/** 506 Variant Also Negotiates */
			Http506VariantAlsoNegotiates,
			/** 507 Insufficient Storage */
			Http507InsufficientStorage,
			/** 508 Loop Detected */
			Http508LoopDetected,
			/** 509 Bandwidth Limit Exceeded */
			Http509BandwidthLimitExceeded,
			/** 510 Not Extended */
			Http510NotExtended,
			/** 511 Network Authentication Required */
			Http511NetworkAuthenticationRequired,
			/** 520 Origin Error */
			Http520OriginError,
			/** 521 Web server is down */
			Http521WebServerIsDown,
			/** 522 Connection timed out */
			Http522ConnectionTimedOut,
			/** 523 Proxy Declined Request */
			Http523ProxyDeclinedRequest,
			/** 524 A timeout occurred */
			Http524aTimeoutOccurred,
			/** 598 Network read timeout error */
			Http598NetworkReadTimeoutError,
			/** 599 Network connect timeout error */
			Http599NetworkConnectTimeoutError,
			/** Unknown status code */
			HttpStatusCodeUnknown
		};


		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be parsed into HttpField's)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new HTTP response header with only the first line filled. Object will be created without further fields.
		 * The user can then ass fields using addField() methods
		 * @param[in] version HTTP version to be used
		 * @param[in] statuCode Status code to be used
		 * @param[in] statusCodeString Most status codes have their default string, e.g 200 is usually "OK", 404 is usually "Not Found", etc.
		 * But the user can set a non-default status code string and it will be written in the header first line. Empty string ("") means using the
		 * default status code string
		 */
		HttpResponseLayer(HttpVersion version, HttpResponseLayer::HttpResponseStatusCode statuCode, std::string statusCodeString = "");

		~HttpResponseLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor HttpMessage#HttpMessage() and add the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpResponseLayer(const HttpResponseLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator HttpMessage#operator=() and adds the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpResponseLayer& operator=(const HttpResponseLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		inline HttpResponseFirstLine* getFirstLine() { return m_FirstLine; }

		/**
		 * The length of the body of many HTTP response messages is determined by a HTTP header field called "Content-Length". This method sets
		 * The content-length field value. The method supports several cases:
		 * - If the "Content-Length" field exists - the method will only replace the existing value with the new value
		 * - If the "Content-Length" field doesn't exist - the method will create this field and put the value in it. Here are also 2 cases:
		 * 		- If prevFieldName is specified - the new "Content-Length" field will be created after it
		 * 		- If prevFieldName isn't specified or doesn't exist - the new "Content-Length" field will be created as the last field before
		 * 		  end-of-header field
		 * @param[in] contentLength The content length value to set
		 * @param[in] prevFieldName Optional field, if specified and "Content-Length" field doesn't exist, it will be created after it
		 * @return A pointer to the "Content-Length" field, or NULL if creation failed for some reason
		 */
		HttpField* setContentLength(int contentLength, const std::string prevFieldName = "");

		/**
		 * The length of the body of many HTTP response messages is determined by a HTTP header field called "Content-Length". This method
		 * parses this field, extracts its value and return it. If this field doesn't exist the method will return 0
		 * @return HTTP response body length determined by "Content-Length" field
		 */
		int getContentLength();

		// implement Layer's abstract methods

		std::string toString();

	private:
		HttpResponseFirstLine* m_FirstLine;

	};





	// -------- Class HttpRequestFirstLine -----------------

	/**
	 * @class HttpRequestFirstLine
	 * Represents an HTTP request header first line. The first line includes 3 parameters: HTTP method (e.g GET, POST, etc.),
	 * URI (e.g /main/index.html) and HTTP version (e.g HTTP/1.1). All these parameters are included in this class, and the user
	 * can retrieve or set them.
	 * This class cannot be instantiated by users, it's created inside HttpRequestLayer and user can get a pointer to an instance of it. All "get"
	 * methods of this class will retrieve the actual data of the HTTP request and the "set" methods will change the packet data.
	 * Since HTTP is a textual protocol, most fields aren't of fixed size and this also applies to the first line parameters. So most "set" methods
	 * of this class need in most cases to shorten or extend the data in HttpRequestLayer. These methods will return a false value if this
	 * action failed
	 */
	class HttpRequestFirstLine
	{
		friend class HttpRequestLayer;
	public:
		/**
		 * @return The HTTP method
		 */
		inline HttpRequestLayer::HttpMethod getMethod() { return m_Method; }

		/**
		 * Set the HTTP method
		 * @param[in] newMethod The method to set
		 * @return False if newMethod is HttpRequestLayer#HttpMethodUnknown or if shortening/extending the HttpRequestLayer data failed. True otherwise
		 */
		bool setMethod(HttpRequestLayer::HttpMethod newMethod);

		/**
		 * @return A copied version of the URI (notice changing the return value won't change the actual data of the packet)
		 */
		std::string getUri();

		/**
		 * Set the URI
		 * @param[in] newUri The URI to set
		 * @return False if shortening/extending the HttpRequestLayer data failed. True otherwise
		 */
		bool setUri(std::string newUri);

		/**
		 * @return The HTTP version
		 */
		inline HttpVersion getVersion() { return m_Version; }

		/**
		 * Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same size
		 * (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		 * @param[in] newVersion The HTTP version to set
		 */
		void setVersion(HttpVersion newVersion);

		/**
		 * A static method for parsing the HTTP method out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed HTTP method
		 */
		static HttpRequestLayer::HttpMethod parseMethod(char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the HTTP first line
		 */
		inline int getSize() { return m_FirstLineEndOffset; }

		/**
		 * As explained in HttpRequestLayer, an HTTP header can spread over more than 1 packet, so when looking at a single packet
		 * the header can be partial. Same goes for the first line - it can spread over more than 1 packet. This method returns an indication
		 * whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		inline bool isComplete() { return m_IsComplete; }

		/**
		 * @class HttpRequestFirstLineException
		 * This exception can be thrown while constructing HttpRequestFirstLine (the constructor is private, so the construction happens
		 * only in HttpRequestLayer). This kind of exception will be thrown if trying to construct with HTTP method of
		 * HttpRequestLayer#HttpMethodUnknown or with undefined HTTP version ::HttpVersionUnknown
		 */
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

	/**
	 * @class HttpResponseFirstLine
	 * Represents an HTTP response header first line. The first line includes 2 parameters: status code (e.g 200 OK, 404 Not Found, etc.),
	 * and HTTP version (e.g HTTP/1.1). These 2 parameters are included in this class, and the user can retrieve or set them.
	 * This class cannot be instantiated by users, it's created inside HttpResponseLayer and user can get a pointer to an instance of it. The "get"
	 * methods of this class will retrieve the actual data of the HTTP response and the "set" methods will change the packet data.
	 * Since HTTP is a textual protocol, most fields aren't of fixed size and this also applies to the first line parameters. So most "set" methods
	 * of this class need in most cases to shorten or extend the data in HttpResponseLayer. These methods will return a false value if this
	 * action failed
	 */
	class HttpResponseFirstLine
	{
		friend class HttpResponseLayer;
	public:
		/**
		 * @return The status code as HttpResponseLayer::HttpResponseStatusCode enum
		 */
		inline HttpResponseLayer::HttpResponseStatusCode getStatusCode() { return m_StatusCode; }

		/**
		 * @return The status code number as integer (e.g 200, 404, etc.)
		 */
		int getStatusCodeAsInt();

		/**
		 * @return The status code message (e.g "OK", "Not Found", etc.)
		 */
		std::string getStatusCodeString();

		/**
		 * Set the status code
		 * @param[in] newStatusCode The new status code to set
		 * @param[in] statusCodeString An optional parameter: set a non-default status code message (e.g "Bla Bla" instead of "Not Found"). If
		 * this parameter isn't supplied or supplied as empty string (""), the default message for the status code will be set
		 */
		bool setStatusCode(HttpResponseLayer::HttpResponseStatusCode newStatusCode, std::string statusCodeString = "");

		/**
		 * @return The HTTP version
		 */
		inline HttpVersion getVersion() { return m_Version; }

		/**
		 * Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same size
		 * (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		 * @param[in] newVersion The HTTP version to set
		 */
		void setVersion(HttpVersion newVersion);

		/**
		 * A static method for parsing the HTTP status code out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed HTTP status code as enum
		 */
		static HttpResponseLayer::HttpResponseStatusCode parseStatusCode(char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the HTTP first line
		 */
		inline int getSize() { return m_FirstLineEndOffset; }

		/**
		 * As explained in HttpResponseLayer, an HTTP header can spread over more than 1 packet, so when looking at a single packet
		 * the header can be partial. Same goes for the first line - it can spread over more than 1 packet. This method returns an indication
		 * whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		inline bool isComplete() { return m_IsComplete; }

		/**
		 * @class HttpResponseFirstLineException
		 * This exception can be thrown while constructing HttpResponseFirstLine (the constructor is private, so the construction happens
		 * only in HttpResponseLayer). This kind of exception will be thrown if trying to construct with HTTP status code of
		 * HttpResponseLayer#HttpStatusCodeUnknown or with undefined HTTP version ::HttpVersionUnknown
		 */
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

} // namespace pcpp

#endif /* PACKETPP_HTTP_LAYER */
