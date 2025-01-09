#pragma once

#include "DeprecationUtils.h"
#include "TextBasedProtocol.h"
#include <string>
#include <exception>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// An enum for HTTP version
	enum HttpVersion
	{
		/// HTTP/0.9
		ZeroDotNine,
		/// HTTP/1.0
		OneDotZero,
		/// HTTP/1.1
		OneDotOne,
		/// Unknown HTTP version
		HttpVersionUnknown
	};

	// some popular HTTP fields

	/// Host field
#define PCPP_HTTP_HOST_FIELD "Host"
	/// Connection field
#define PCPP_HTTP_CONNECTION_FIELD "Connection"
	/// User-Agent field
#define PCPP_HTTP_USER_AGENT_FIELD "User-Agent"
	/// Referer field
#define PCPP_HTTP_REFERER_FIELD "Referer"
	/// Accept field
#define PCPP_HTTP_ACCEPT_FIELD "Accept"
	/// Accept-Encoding field
#define PCPP_HTTP_ACCEPT_ENCODING_FIELD "Accept-Encoding"
	/// Accept-Language field
#define PCPP_HTTP_ACCEPT_LANGUAGE_FIELD "Accept-Language"
	/// Cookie field
#define PCPP_HTTP_COOKIE_FIELD "Cookie"
	/// Content-Length field
#define PCPP_HTTP_CONTENT_LENGTH_FIELD "Content-Length"
	/// Content-Encoding field
#define PCPP_HTTP_CONTENT_ENCODING_FIELD "Content-Encoding"
	/// Content-Type field
#define PCPP_HTTP_CONTENT_TYPE_FIELD "Content-Type"
	/// Transfer-Encoding field
#define PCPP_HTTP_TRANSFER_ENCODING_FIELD "Transfer-Encoding"
	/// Server field
#define PCPP_HTTP_SERVER_FIELD "Server"

	// -------- classes to be defined later -----------------

	class HttpRequestFirstLine;
	class HttpResponseFirstLine;

	// -------- Class HttpMessage -----------------

	/// @class HttpMessage
	/// Represents a general HTTP message. It's an abstract class and cannot be instantiated. It's inherited by
	/// HttpRequestLayer and HttpResponseLayer
	class HttpMessage : public TextBasedProtocolMessage
	{
	public:
		~HttpMessage() override = default;

		/// A static method that checks whether the port is considered as HTTP
		/// @param[in] port The port number to be checked
		/// @return True if the port matches those associated with the HTTP protocol
		static bool isHttpPort(uint16_t port)
		{
			return port == 80 || port == 8080;
		}

		// overridden methods

		HeaderField* addField(const std::string& fieldName, const std::string& fieldValue) override;
		HeaderField* addField(const HeaderField& newField) override;
		HeaderField* insertField(HeaderField* prevField, const std::string& fieldName,
		                         const std::string& fieldValue) override;
		HeaderField* insertField(HeaderField* prevField, const HeaderField& newField) override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	protected:
		HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : TextBasedProtocolMessage(data, dataLen, prevLayer, packet, protocol)
		{}
		HttpMessage() : TextBasedProtocolMessage()
		{}
		HttpMessage(const HttpMessage& other) : TextBasedProtocolMessage(other)
		{}
		HttpMessage& operator=(const HttpMessage& other)
		{
			TextBasedProtocolMessage::operator=(other);
			return *this;
		}

		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() const override
		{
			return ':';
		}
		bool spacesAllowedBetweenHeaderFieldNameAndValue() const override
		{
			return true;
		}
	};

	// -------- Class HttpRequestLayer -----------------

	/// @class HttpRequestLayer
	/// Represents an HTTP request header and inherits all basic functionality of HttpMessage and
	/// TextBasedProtocolMessage. The functionality that is added for this class is the HTTP first line concept. An HTTP
	/// request has the following first line: <i>GET /bla/blabla.asp HTTP/1.1</i> Since it's not an "ordinary" HTTP
	/// field, it requires a special treatment and gets a class of it's own: HttpRequestFirstLine. Unlike most L2-4
	/// protocols, an HTTP request header can spread over more than 1 packet. PcapPlusPlus currently doesn't support a
	/// header that is spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as
	/// HttpRequestLayer (the other packets won't be recognized as HttpRequestLayer) and 2) the HTTP header for the
	/// first packet won't be complete (as it continues in the following packets), this why PcapPlusPlus can indicate
	/// that HTTP request header is complete or not(doesn't end with "\r\n\r\n" or "\n\n") using
	/// HttpMessage#isHeaderComplete()
	class HttpRequestLayer : public HttpMessage
	{
		friend class HttpRequestFirstLine;

	public:
		/// HTTP request methods
		enum HttpMethod
		{
			/// GET
			HttpGET,
			/// HEAD
			HttpHEAD,
			/// POST
			HttpPOST,
			/// PUT
			HttpPUT,
			/// DELETE
			HttpDELETE,
			/// TRACE
			HttpTRACE,
			/// OPTIONS
			HttpOPTIONS,
			/// CONNECT
			HttpCONNECT,
			/// PATCH
			HttpPATCH,
			/// Unknown HTTP method
			HttpMethodUnknown
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that allocates a new HTTP request header with only the first line filled. Object will be
		/// created without further fields. The user can then add fields using addField() methods
		/// @param[in] method The HTTP method used in this HTTP request
		/// @param[in] uri The URI of the first line
		/// @param[in] version HTTP version to be used in this request
		HttpRequestLayer(HttpMethod method, const std::string& uri, HttpVersion version);

		~HttpRequestLayer() override;

		/// A copy constructor for this layer. This copy constructor inherits base copy constructor
		/// HttpMessage#HttpMessage() and add the functionality of copying the first line as well
		/// @param[in] other The instance to copy from
		HttpRequestLayer(const HttpRequestLayer& other);

		/// An assignment operator overload for this layer. This method inherits base assignment operator
		/// HttpMessage#operator=() and add the functionality of copying the first line as well
		/// @param[in] other The instance to copy from
		/// @return A reference to the assignee
		HttpRequestLayer& operator=(const HttpRequestLayer& other);

		/// @return A pointer to the first line instance for this message
		HttpRequestFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		/// The URL is hostname+uri. So given the following URL, for example: "www.cnn.com/main.html", the hostname is
		/// "www.cnn.com" and the URI is "/.main.html". URI and hostname are split to 2 different places inside the HTTP
		/// request packet: URI is in the first line and hostname is in "HOST" field. This methods concatenates the
		/// hostname and URI to the full URL
		/// @return The URL of the HTTP request message
		std::string getUrl() const;

		// implement Layer's abstract methods
		std::string toString() const override;

	private:
		HttpRequestFirstLine* m_FirstLine;
	};

	// -------- Class HttpResponseStatusCode -----------------

	/// @struct HttpResponseStatusCode
	/// @brief The enum wrapper class of HTTP response status codes
	class HttpResponseStatusCode
	{
	public:
		/// @brief Define enum types and the corresponding int values
		enum Value : int
		{
			/// 100 Continue
			Http100Continue = 100,
			/// 101 Switching Protocols
			Http101SwitchingProtocols = 101,
			/// 102 Processing
			Http102Processing = 102,
			/// 103 Early Hints
			Http103EarlyHints = 103,
			/// 104-199 Unassigned

			/// 200 OK
			Http200OK = 200,
			/// 201 Created
			Http201Created = 201,
			/// 202 Accepted
			Http202Accepted = 202,
			/// 203 Non-Authoritative Information
			Http203NonAuthoritativeInformation = 203,
			/// 204 No Content
			Http204NoContent = 204,
			/// 205 Reset Content
			Http205ResetContent = 205,
			/// 206 Partial Content
			Http206PartialContent = 206,
			/// 207 Multi-Status
			Http207MultiStatus = 207,
			/// 208 Already Reported
			Http208AlreadyReported = 208,
			/// 209-225 Unassigned
			/// 226 IM Used
			Http226IMUsed = 226,
			/// 227-299 Unassigned

			/// 300 Multiple Choices
			Http300MultipleChoices = 300,
			/// 301 Moved Permanently
			Http301MovedPermanently = 301,
			/// 302 (various messages)
			Http302 = 302,
			/// 303 See Other
			Http303SeeOther = 303,
			/// 304 Not Modified
			Http304NotModified = 304,
			/// 305 Use Proxy
			Http305UseProxy = 305,
			/// 306 Switch Proxy
			Http306SwitchProxy = 306,
			/// 307 Temporary Redirect
			Http307TemporaryRedirect = 307,
			/// 308 Permanent Redirect,
			Http308PermanentRedirect = 308,
			/// 309-399 Unassigned

			/// 400 Bad Request
			Http400BadRequest = 400,
			/// 401 Unauthorized
			Http401Unauthorized = 401,
			/// 402 Payment Required
			Http402PaymentRequired = 402,
			/// 403 Forbidden
			Http403Forbidden = 403,
			/// 404 Not Found
			Http404NotFound = 404,
			/// 405 Method Not Allowed
			Http405MethodNotAllowed = 405,
			/// 406 Not Acceptable
			Http406NotAcceptable = 406,
			/// 407 Proxy Authentication Required
			Http407ProxyAuthenticationRequired = 407,
			/// 408 Request Timeout
			Http408RequestTimeout = 408,
			/// 409 Conflict
			Http409Conflict = 409,
			/// 410 Gone
			Http410Gone = 410,
			/// 411 Length Required
			Http411LengthRequired = 411,
			/// 412 Precondition Failed
			Http412PreconditionFailed = 412,
			/// 413 RequestEntity Too Large
			Http413RequestEntityTooLarge = 413,
			/// 414 Request-URI Too Long
			Http414RequestURITooLong = 414,
			/// 415 Unsupported Media Type
			Http415UnsupportedMediaType = 415,
			/// 416 Requested Range Not Satisfiable
			Http416RequestedRangeNotSatisfiable = 416,
			/// 417 Expectation Failed
			Http417ExpectationFailed = 417,
			/// 418 I'm a teapot
			Http418ImATeapot = 418,
			/// 419 Authentication Timeout
			Http419AuthenticationTimeout = 419,
			/// 420 (various messages)
			Http420 = 420,
			/// 421 Misdirected Request
			Http421MisdirectedRequest = 421,
			/// 422 Unprocessable Entity
			Http422UnprocessableEntity = 422,
			/// 423 Locked
			Http423Locked = 423,
			/// 424 Failed Dependency
			Http424FailedDependency = 424,
			/// 425 Too Early
			Http425TooEarly = 425,
			/// 426 Upgrade Required
			Http426UpgradeRequired = 426,
			/// 427 Unassigned
			/// 428 Precondition Required
			Http428PreconditionRequired = 428,
			/// 429 Too Many Requests
			Http429TooManyRequests = 429,
			/// 430 Unassigned
			/// 431 Request Header Fields Too Large
			Http431RequestHeaderFieldsTooLarge = 431,
			/// 432-439 unassigned
			/// 440 Login Timeout
			Http440LoginTimeout = 440,
			/// 441-443 unassigned
			/// 444 No Response
			Http444NoResponse = 444,
			/// 445-448 unassigned
			/// 449 Retry With
			Http449RetryWith = 449,
			/// 450 Blocked by Windows Parental Controls
			Http450BlockedByWindowsParentalControls = 450,
			/// 451 (various messages)
			Http451 = 451,
			/// 452-493 unassigned
			/// 494 Request Header Too Large
			Http494RequestHeaderTooLarge = 494,
			/// 495 Cert Error
			Http495CertError = 495,
			/// 496 No Cert
			Http496NoCert = 496,
			/// 497 HTTP to HTTPS
			Http497HTTPtoHTTPS = 497,
			/// 498 Token expired/invalid
			Http498TokenExpiredInvalid = 498,
			/// 499 (various messages)
			Http499 = 499,

			/// 500 Internal Server Error
			Http500InternalServerError = 500,
			/// 501 Not Implemented
			Http501NotImplemented = 501,
			/// 502 Bad Gateway
			Http502BadGateway = 502,
			/// 503 Service Unavailable
			Http503ServiceUnavailable = 503,
			/// 504 Gateway Timeout
			Http504GatewayTimeout = 504,
			/// 505 HTTP Version Not Supported
			Http505HTTPVersionNotSupported = 505,
			/// 506 Variant Also Negotiates
			Http506VariantAlsoNegotiates = 506,
			/// 507 Insufficient Storage
			Http507InsufficientStorage = 507,
			/// 508 Loop Detected
			Http508LoopDetected = 508,
			/// 509 Bandwidth Limit Exceeded
			Http509BandwidthLimitExceeded = 509,
			/// 510 Not Extended
			Http510NotExtended = 510,
			/// 511 Network Authentication Required
			Http511NetworkAuthenticationRequired = 511,
			/// 512-519 unassigned
			/// 520 Origin Error
			Http520OriginError = 520,
			/// 521 Web server is down
			Http521WebServerIsDown = 521,
			/// 522 Connection timed out
			Http522ConnectionTimedOut = 522,
			/// 523 Proxy Declined Request
			Http523ProxyDeclinedRequest = 523,
			/// 524 A timeout occurred
			Http524aTimeoutOccurred = 524,
			/// 525-597 unassigned
			/// 598 Network read timeout error
			Http598NetworkReadTimeoutError = 598,
			/// 599 Network connect timeout error
			Http599NetworkConnectTimeoutError = 599,

			// clang-format off
			/// Unknown status code
			HttpStatus1xxCodeUnknown = 900001, // 1xx: Informational - Request received, continuing process
			HttpStatus2xxCodeUnknown = 900002, // 2xx: Success - The action was successfully received, understood, and accepted
			HttpStatus3xxCodeUnknown = 900003, // 3xx: Redirection - Further action must be taken in order to complete the request
			HttpStatus4xxCodeUnknown = 900004, // 4xx: Client Error - The request contains bad syntax or cannot be fulfilled
			HttpStatus5xxCodeUnknown = 900005, // 5xx: Server Error - The server failed to fulfill an apparently valid request
			HttpStatusCodeUnknown = 999999,    // other arbitrary number
			// clang-format on
		};

		HttpResponseStatusCode() = default;

		// cppcheck-suppress noExplicitConstructor
		/// @brief Construct HttpResponseStatusCode from Value enum
		/// @param[in] statusCode the status code enum
		HttpResponseStatusCode(Value statusCode) : m_Value(statusCode)
		{}

		/// @brief Construct HttpResponseStatusCode from the code number and the customized message
		/// @param[in] statusCodeNumber the status code in number, e.g. 200, 404
		/// @param[in] statusMessage the status message, optional, leave empty to use a default message
		explicit HttpResponseStatusCode(const int& statusCodeNumber, const std::string& statusMessage = "");

		/// @brief Construct HttpResponseStatusCode from Value enum and the customized message
		/// @param[in] statusCode the status code enum
		/// @param[in] statusMessage the customized status message, optional
		explicit HttpResponseStatusCode(const Value& statusCode, const std::string& statusMessage);

		// Allow switch and comparisons.
		operator Value() const
		{
			return m_Value;
		}
		// Prevent usage: if(httpResponseStatusCode)
		explicit operator bool() const = delete;

		/// @brief get status code number as string
		std::string toString() const
		{
			return std::to_string(m_Value);
		}

		/// @brief get status code number as int
		int toInt() const
		{
			return static_cast<int>(m_Value);
		}

		/// @brief get status code message, e.g. "OK", "Not Found"
		std::string getMessage() const;
		/// @return If this HttpResponseStatusCode a valid code
		/// @note Any unknown or error code has an extreme large enum value
		bool isUnsupportedCode() const
		{
			return m_Value > 599;
		}

	private:
		Value m_Value = HttpStatusCodeUnknown;
		std::string m_CustomizedMessage;
	};

	// -------- Class HttpResponseLayer -----------------

	/// @class HttpResponseLayer
	/// Represents an HTTP response header and inherits all basic functionality of HttpMessage and
	/// TextBasedProtocolMessage. The functionality that is added for this class is the HTTP first line concept. An HTTP
	/// response has the following first line: <i>200 OK HTTP/1.1</i> Since it's not an "ordinary" HTTP field, it
	/// requires a special treatment and gets a class of it's own: HttpResponseFirstLine. Unlike most L2-4 protocols, an
	/// HTTP response header can spread over more than 1 packet. PcapPlusPlus currently doesn't support a header that is
	/// spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as HttpResponseLayer
	/// (the other packets won't be recognized as HttpResponseLayer) and 2) the HTTP header for the first packet won't
	/// be complete (as it continues in the following packets), this why PcapPlusPlus can indicate that HTTP response
	/// header is complete or not (doesn't end with "\r\n\r\n" or "\n\n") using HttpMessage#isHeaderComplete()
	class HttpResponseLayer : public HttpMessage
	{
		friend class HttpResponseFirstLine;

	public:
		// backward compatibility
		using HttpResponseStatusCode = pcpp::HttpResponseStatusCode;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that allocates a new HTTP response header with only the first line filled. Object will be
		/// created without further fields. The user can then add fields using addField() methods
		/// @param[in] version HTTP version to be used
		/// @param[in] statusCode Status code to be used
		/// @param[in] statusCodeString Most status codes have their default string, e.g 200 is usually "OK", 404 is
		/// usually "Not Found", etc. But the user can set a non-default status code string and it will be written in
		/// the header first line. Empty string ("") means using the default status code string
		/// @deprecated Use other constructors instead.
		PCPP_DEPRECATED("Use other constructors instead")
		explicit HttpResponseLayer(HttpVersion version, const HttpResponseStatusCode& statusCode,
		                           const std::string& statusCodeString);

		/// A constructor that allocates a new HTTP response header with only the first line filled. Object will be
		/// created without further fields. The user can then add fields using addField() methods
		/// @param[in] version HTTP version to be used
		/// @param[in] statusCode Status code to be used
		explicit HttpResponseLayer(HttpVersion version, const HttpResponseStatusCode& statusCode);

		~HttpResponseLayer() override;

		/// A copy constructor for this layer. This copy constructor inherits base copy constructor
		/// HttpMessage#HttpMessage() and adds the functionality of copying the first line as well
		/// @param[in] other The instance to copy from
		HttpResponseLayer(const HttpResponseLayer& other);

		/// An assignment operator overload for this layer. This method inherits base assignment operator
		/// HttpMessage#operator=() and adds the functionality of copying the first line as well
		/// @param[in] other The instance to copy from
		/// @return A reference to the assignee
		HttpResponseLayer& operator=(const HttpResponseLayer& other);

		/// @return A pointer to the first line instance for this message
		HttpResponseFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		/// The length of the body of many HTTP response messages is determined by a HTTP header field called
		/// "Content-Length". This method sets The content-length field value. The method supports several cases:
		///   - If the "Content-Length" field exists - the method will only replace the existing value with the new
		///   value
		///   - If the "Content-Length" field doesn't exist - the method will create this field and put the value in it.
		/// Here are also 2 cases:
		///   - If prevFieldName is specified - the new "Content-Length" field will be created after it
		///   - If prevFieldName isn't specified or doesn't exist - the new "Content-Length" field will be created as
		///   the last field before end-of-header field
		///
		/// @param[in] contentLength The content length value to set
		/// @param[in] prevFieldName Optional field, if specified and "Content-Length" field doesn't exist, it will be
		/// created after it
		/// @return A pointer to the "Content-Length" field, or nullptr if creation failed for some reason
		HeaderField* setContentLength(int contentLength, const std::string& prevFieldName = "");

		/// The length of the body of many HTTP response messages is determined by a HTTP header field called
		/// "Content-Length". This method parses this field, extracts its value and return it. If this field doesn't
		/// exist the method will return 0
		/// @return HTTP response body length determined by "Content-Length" field
		int getContentLength() const;

		// implement Layer's abstract methods

		std::string toString() const override;

	private:
		HttpResponseFirstLine* m_FirstLine;
	};

	// -------- Class HttpRequestFirstLine -----------------

	/// @class HttpRequestFirstLine
	/// Represents an HTTP request header first line. The first line includes 3 parameters: HTTP method (e.g GET, POST,
	/// etc.), URI (e.g /main/index.html) and HTTP version (e.g HTTP/1.1). All these parameters are included in this
	/// class, and the user can retrieve or set them. This class cannot be instantiated by users, it's created inside
	/// HttpRequestLayer and user can get a pointer to an instance of it. All "get" methods of this class will retrieve
	/// the actual data of the HTTP request and the "set" methods will change the packet data. Since HTTP is a textual
	/// protocol, most fields aren't of fixed size and this also applies to the first line parameters. So most "set"
	/// methods of this class need in most cases to shorten or extend the data in HttpRequestLayer. These methods will
	/// return a false value if this action failed
	class HttpRequestFirstLine
	{
		friend class HttpRequestLayer;

	public:
		/// @return The HTTP method
		HttpRequestLayer::HttpMethod getMethod() const
		{
			return m_Method;
		}

		/// Set the HTTP method
		/// @param[in] newMethod The method to set
		/// @return False if newMethod is HttpRequestLayer#HttpMethodUnknown or if shortening/extending the
		/// HttpRequestLayer data failed. True otherwise
		bool setMethod(HttpRequestLayer::HttpMethod newMethod);

		/// @return A copied version of the URI (notice changing the return value won't change the actual data of the
		/// packet)
		std::string getUri() const;

		/// Set the URI
		/// @param[in] newUri The URI to set
		/// @return False if shortening/extending the HttpRequestLayer data failed. True otherwise
		bool setUri(std::string newUri);

		/// @return The HTTP version
		HttpVersion getVersion() const
		{
			return m_Version;
		}

		/// Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same
		/// size (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		/// @param[in] newVersion The HTTP version to set
		void setVersion(HttpVersion newVersion);

		/// A static method for parsing the HTTP method out of raw data
		/// @param[in] data The raw data
		/// @param[in] dataLen The raw data length
		/// @return The parsed HTTP method
		static HttpRequestLayer::HttpMethod parseMethod(const char* data, size_t dataLen);

		/// @return The size in bytes of the HTTP first line
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/// As explained in HttpRequestLayer, an HTTP header can spread over more than 1 packet, so when looking at a
		/// single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		/// packet. This method returns an indication whether the first line is partial
		/// @return False if the first line is partial, true if it's complete
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/// @class HttpRequestFirstLineException
		/// This exception can be thrown while constructing HttpRequestFirstLine (the constructor is private, so the
		/// construction happens only in HttpRequestLayer). This kind of exception will be thrown if trying to construct
		/// with HTTP method of HttpRequestLayer#HttpMethodUnknown or with undefined HTTP version ::HttpVersionUnknown
		class HttpRequestFirstLineException : public std::exception
		{
		public:
			~HttpRequestFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		HttpRequestFirstLine(HttpRequestLayer* httpRequest);
		HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpRequestLayer::HttpMethod method, HttpVersion version,
		                     const std::string& uri = "/");

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

	/// @class HttpResponseFirstLine
	/// Represents an HTTP response header first line. The first line includes 2 parameters: status code (e.g 200 OK,
	/// 404 Not Found, etc.), and HTTP version (e.g HTTP/1.1). These 2 parameters are included in this class, and the
	/// user can retrieve or set them. This class cannot be instantiated by users, it's created inside HttpResponseLayer
	/// and user can get a pointer to an instance of it. The "get" methods of this class will retrieve the actual data
	/// of the HTTP response and the "set" methods will change the packet data. Since HTTP is a textual protocol, most
	/// fields aren't of fixed size and this also applies to the first line parameters. So most "set" methods of this
	/// class need in most cases to shorten or extend the data in HttpResponseLayer. These methods will return a false
	/// value if this action failed
	class HttpResponseFirstLine
	{
		friend class HttpResponseLayer;

	public:
		/// @return The status code as HttpResponseStatusCode enum
		HttpResponseStatusCode getStatusCode() const
		{
			return m_StatusCode;
		}

		/// @return The status code number as integer (e.g 200, 404, etc.)
		int getStatusCodeAsInt() const;

		/// @return The status code message (e.g "OK", "Not Found", etc.)
		std::string getStatusCodeString() const;

		/// Set the status code
		/// @param[in] newStatusCode The new status code to set
		/// @param[in] statusCodeString An optional parameter: set a non-default status code message (e.g "Bla Bla"
		/// instead of "Not Found"). If this parameter isn't supplied or supplied as empty string (""), the default
		/// message for the status code will be set
		/// @return True if setting the status code was completed successfully, false otherwise
		/// @deprecated Use the other overload instead.
		PCPP_DEPRECATED("Use the other overload instead")
		bool setStatusCode(const HttpResponseStatusCode& newStatusCode, const std::string& statusCodeString);

		/// Set the status code
		/// @param[in] newStatusCode The new status code to set
		/// @return True if setting the status code was completed successfully, false otherwise
		bool setStatusCode(const HttpResponseStatusCode& newStatusCode);

		/// @return The HTTP version
		HttpVersion getVersion() const
		{
			return m_Version;
		}

		/// Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same
		/// size (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		/// @param[in] newVersion The HTTP version to set
		void setVersion(HttpVersion newVersion);

		/// A static method for parsing the HTTP status code out of raw data
		/// @param[in] data The raw data
		/// @param[in] dataLen The raw data length
		/// @return The parsed HTTP status code as enum
		static HttpResponseStatusCode parseStatusCode(const char* data, size_t dataLen);

		/// A static method for parsing the HTTP version out of raw first line data (e.g "HTTP/x.y")
		/// @param[in] data The raw data
		/// @param[in] dataLen The raw data length
		/// @return The parsed HTTP status code as enum
		static HttpVersion parseVersion(const char* data, size_t dataLen);

		/// @return The size in bytes of the HTTP first line
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/// As explained in HttpResponseLayer, an HTTP header can spread over more than 1 packet, so when looking at a
		/// single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		/// packet. This method returns an indication whether the first line is partial
		/// @return False if the first line is partial, true if it's complete
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/// @class HttpResponseFirstLineException
		/// This exception can be thrown while constructing HttpResponseFirstLine (the constructor is private, so the
		/// construction happens only in HttpResponseLayer). This kind of exception will be thrown if trying to
		/// construct with a HTTP status code that is not in HttpResponseStatusCode or with undefined HTTP version
		/// ::HttpVersionUnknown
		class HttpResponseFirstLineException : public std::exception
		{
		public:
			~HttpResponseFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		HttpResponseFirstLine(HttpResponseLayer* httpResponse);
		HttpResponseFirstLine(HttpResponseLayer* httpResponse, HttpVersion version,
		                      const HttpResponseStatusCode& statusCode);

		HttpResponseLayer* m_HttpResponse;
		HttpVersion m_Version;
		HttpResponseStatusCode m_StatusCode;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		HttpResponseFirstLineException m_Exception;
	};

}  // namespace pcpp
