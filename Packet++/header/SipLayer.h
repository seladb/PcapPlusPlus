#ifndef PACKETPP_SIP_LAYER
#define PACKETPP_SIP_LAYER

#include "TextBasedProtocol.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
// some popular SIP header fields

/** From field */
#define PCPP_SIP_FROM_FIELD                "From"
/** To field */
#define PCPP_SIP_TO_FIELD                  "To"
/** Via field */
#define PCPP_SIP_VIA_FIELD                 "Via"
/** Call-ID field */
#define PCPP_SIP_CALL_ID_FIELD             "Call-ID"
/** Content-Type field */
#define PCPP_SIP_CONTENT_TYPE_FIELD        "Content-Type"
/** Content-Length field */
#define PCPP_SIP_CONTENT_LENGTH_FIELD      "Content-Length"
/** Content-Disposition field */
#define PCPP_SIP_CONTENT_DISPOSITION_FIELD "Content-Disposition"
/** Content-Encoding field */
#define PCPP_SIP_CONTENT_ENCODING_FIELD    "Content-Encoding"
/** Content-Language field */
#define PCPP_SIP_CONTENT_LANGUAGE_FIELD    "Content-Language"
/** CSeq field */
#define PCPP_SIP_CSEQ_FIELD                "CSeq"
/** Contact field */
#define PCPP_SIP_CONTACT_FIELD             "Contact"
/** Max-Forwards field */
#define PCPP_SIP_MAX_FORWARDS_FIELD        "Max-Forwards"
/** User-Agent field */
#define PCPP_SIP_USER_AGENT_FIELD          "User-Agent"
/** Accept field */
#define PCPP_SIP_ACCEPT_FIELD              "Accept"
/** Accept-Encoding field */
#define PCPP_SIP_ACCEPT_ENCODING_FIELD     "Accept-Encoding"
/** Accept-Language field */
#define PCPP_SIP_ACCEPT_LANGUAGE_FIELD     "Accept-Language"
/** Allow field */
#define PCPP_SIP_ALLOW_FIELD               "Allow"
/** Authorization field */
#define PCPP_SIP_AUTHORIZATION_FIELD       "Authorization"
/** Date field */
#define PCPP_SIP_DATE_FIELD                "Date"
/** MIME-Version field */
#define PCPP_SIP_MIME_VERSION_FIELD        "MIME-Version"
/** Reason field */
#define PCPP_SIP_REASON_FIELD              "Reason"
/** Supported field */
#define PCPP_SIP_SUPPORTED_FIELD           "Supported"
/** Server field */
#define PCPP_SIP_SERVER_FIELD              "Server"
/** WWW-Authenticate fild */
#define PCPP_SIP_WWW_AUTHENTICATE_FIELD    "WWW-Authenticate"
/** Retry-After field */
#define PCPP_SIP_RETRY_AFTER_FIELD         "Retry-After"
/** Record-Route field */
#define PCPP_SIP_RECORD_ROUTE_FIELD        "Record-Route"


	/**
	 * @class SipLayer
	 * Represents a general SIP message. It's an abstract class and cannot be instantiated. It's inherited by SipRequestLayer and SipResponseLayer
	 */
	class SipLayer : public TextBasedProtocolMessage
	{
	public:

		/**
		 * The length of the body of many SIP response messages is determined by a SIP header field called "Content-Length". This method
		 * parses this field, extracts its value and return it. If this field doesn't exist 0 is returned
		 * @return SIP response body length determined by "Content-Length" field
		 */
		int getContentLength();

		/**
		 * The length of the body of many SIP messages is determined by a header field called "Content-Length". This method sets
		 * The content-length field value. The method supports several cases:
		 * - If the "Content-Length" field exists - the method will only replace the existing value with the new value
		 * - If the "Content-Length" field doesn't exist - the method will create this field and put the value in it. Here are also 2 cases:
		 * 		- If prevFieldName is specified - the new "Content-Length" field will be created after it
		 * 		- If prevFieldName isn't specified or doesn't exist - the new "Content-Length" field will be created as the last field before
		 * 		  end-of-header field
		 *
		 * @param[in] contentLength The content length value to set
		 * @param[in] prevFieldName Optional parameter, if specified and "Content-Length" field doesn't exist, it will be created after this field
		 * @return A pointer to the "Content-Length" field, or NULL if creation failed
		 */
		HeaderField* setContentLength(int contentLength, const std::string prevFieldName = "");

		// Overridden methods

		OsiModelLayer getOsiModelLayer() { return OsiModelSesionLayer; }

		/**
		 * Currently identifies only SDP if content-length field exists and set to a value greater than zero.
		 * If content-length field doesn't exist or set to zero and still there is data after this layer, a PayloadLayer will be created
		 */
		void parseNextLayer();

		/**
		 * Set the content-length only if a content-length field already exists and if its current value is different than the total length of the next layer(s)
		 */
		void computeCalculateFields();

	protected:
		SipLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : TextBasedProtocolMessage(data, dataLen, prevLayer, packet) {}
		SipLayer() : TextBasedProtocolMessage() {}
		SipLayer(const SipLayer& other) : TextBasedProtocolMessage(other) {}
		SipLayer& operator=(const SipLayer& other) { TextBasedProtocolMessage::operator=(other); return *this; }

		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() { return ':'; }
		bool spacesAllowedBetweenHeaderFieldNameAndValue() { return true; }
	};



	class SipRequestFirstLine;


	/**
	 * @class SipRequestLayer
	 * Represents a SIP request header and inherits all basic functionality of SipLayer and TextBasedProtocolMessage.
	 * The functionality that is added for this class is the SIP first line concept. A SIP request has the following first line:
	 * <i>INVITE sip:bla@bla.com:12345 SIP/2.0</i>
	 * Since it's not an "ordinary" header field, it requires a special treatment and gets a class of it's own: SipRequestFirstLine.
	 * In most cases a SIP request will be contained in a single packet but for cases it is not, only the first packet will be identified as SIP
	 * request layer. You can find out whether the header is complete by using SipLayer#isHeaderComplete()
	 */
	class SipRequestLayer : public SipLayer
	{
		friend class SipRequestFirstLine;

	public:
		/**
		 * SIP request methods
		 */
		enum SipMethod
		{
			/** INVITE */
			SipINVITE,
			/** ACK */
			SipACK,
			/** BYE */
			SipBYE,
			/** CANCEL */
			SipCANCEL,
			/** REFISTER */
			SipREGISTER,
			/** PRACK */
			SipPRACK,
			/** OPTIONS */
			SipOPTIONS,
			/** SUBSCRIBE */
			SipSUBSCRIBE,
			/** NOTIFY */
			SipNOTIFY,
			/** PUBLISH */
			SipPUBLISH,
			/** INFO */
			SipINFO,
			/** REFER */
			SipREFER,
			/** MESSAGE */
			SipMESSAGE,
			/** UPDATE */
			SipUPDATE,
			/** Unknown SIP method */
			SipMethodUnknown
		};

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SipRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new SIP request with only the first line filled. The request will be created without further fields.
		 * The user can then add fields using addField() or insertField() methods
		 * @param[in] method The SIP method to be used in this SIP request
		 * @param[in] requestUri The URI of the request
		 * @param[in] version SIP version to be used in this request. Default is "SIP/2.0"
		 */
		SipRequestLayer(SipMethod method, std::string requestUri, std::string version = "SIP/2.0");

		~SipRequestLayer();

		/**
		 * A copy constructor for this layer. Inherits base copy constructor SipLayer and adds the functionality
		 * of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SipRequestLayer(const SipRequestLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator SipLayer#operator=() and adds the functionality
		 * of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SipRequestLayer& operator=(const SipRequestLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		inline SipRequestFirstLine* getFirstLine() { return m_FirstLine; }

		// implement Layer's abstract methods

		std::string toString();

	private:
		SipRequestFirstLine* m_FirstLine;
	};




	class SipResponseFirstLine;


	/**
	 * @class SipResponseLayer
	 * Represents an SIP response message and inherits all basic functionality of SipLayer and TextBasedProtocolMessage.
	 * The functionality that is added for this class is the SIP first line concept. A SIP response has the following first line:
	 * <i>200 OK SIP/2.0</i>
	 * Since it's not an "ordinary" header field, it requires a special treatment and gets a class of it's own: SipResponseFirstLine.
	 * In most cases a SIP response will be contained in a single packet but for cases it is not, only the first packet will be identified as SIP
	 * response layer. You can find out whether the header is complete by using SipLayer#isHeaderComplete()
	 */
	class SipResponseLayer : public SipLayer
	{
		friend class SipResponseFirstLine;
	public:

		/**
		 * Enum for SIP response status codes. List is taken from Wikipedia: https://en.wikipedia.org/wiki/List_of_SIP_response_codes
		 */
		enum SipResponseStatusCode
		{
			/** Extended search being performed may take a significant time so a forking proxy must send a 100 Trying response */
			Sip100Trying,
			/** Destination user agent received INVITE, and is alerting user of call */
			Sip180Ringing,
			/** Servers can optionally send this response to indicate a call is being forwarded */
			Sip181CallisBeingForwarded,
			/** Indicates that the destination was temporarily unavailable, so the server has queued the call until the destination is available. A server may send multiple 182 responses to update progress of the queue */
			Sip182Queued,
			/** This response may be used to send extra information for a call which is still being set up */
			Sip183SessioninProgress,
			/** Can be used by User Agent Server to indicate to upstream SIP entities (including the User Agent Client (UAC)) that an early dialog has been terminated */
			Sip199EarlyDialogTerminated,
			/** Indicates the request was successful */
			Sip200OK,
			/** Indicates that the request has been accepted for processing, but the processing has not been completed */
			Sip202Accepted,
			/** Indicates the request was successful, but the corresponding response will not be received */
			Sip204NoNotification,
			/** The address resolved to one of several options for the user or client to choose between, which are listed in the message body or the message's Contact fields */
			Sip300MultipleChoices,
			/** The original Request-URI is no longer valid, the new address is given in the Contact header field, and the client should update any records of the original Request-URI with the new value */
			Sip301MovedPermanently,
			/** The client should try at the address in the Contact field. If an Expires field is present, the client may cache the result for that period of time */
			Sip302MovedTemporarily,
			/** The Contact field details a proxy that must be used to access the requested destination */
			Sip305UseProxy,
			/** The call failed, but alternatives are detailed in the message body */
			Sip380AlternativeService,
			/** The request could not be understood due to malformed syntax */
			Sip400BadRequest,
			/** The request requires user authentication. This response is issued by UASs and registrars */
			Sip401Unauthorized,
			/** Reserved for future use */
			Sip402PaymentRequired,
			/** The server understood the request, but is refusing to fulfill it */
			Sip403Forbidden,
			/** The server has definitive information that the user does not exist at the domain specified in the Request-URI. This status is also returned if the domain in the Request-URI does not match any of the domains handled by the recipient of the request */
			Sip404NotFound,
			/** The method specified in the Request-Line is understood, but not allowed for the address identified by the Request-URI */
			Sip405MethodNotAllowed,
			/** The resource identified by the request is only capable of generating response entities that have content characteristics but not acceptable according to the Accept header field sent in the request */
			Sip406NotAcceptable,
			/** The request requires user authentication. This response is issued by proxys */
			Sip407ProxyAuthenticationRequired,
			/** Couldn't find the user in time. The server could not produce a response within a suitable amount of time, for example, if it could not determine the location of the user in time. The client MAY repeat the request without modifications at any later time */
			Sip408RequestTimeout,
			/** User already registered */
			Sip409Conflict,
			/** The user existed once, but is not available here any more */
			Sip410Gone,
			/** The server will not accept the request without a valid Content-Length */
			Sip411LengthRequired,
			/** The given precondition has not been met */
			Sip412ConditionalRequestFailed,
			/** Request body too large */
			Sip413RequestEntityTooLarge,
			/** The server is refusing to service the request because the Request-URI is longer than the server is willing to interpret */
			Sip414RequestURITooLong,
			/** Request body in a format not supported */
			Sip415UnsupportedMediaType,
			/** Request-URI is unknown to the server */
			Sip416UnsupportedURIScheme,
			/** There was a resource-priority option tag, but no Resource-Priority header */
			Sip417UnknownResourcePriority,
			/** Bad SIP Protocol Extension used, not understood by the server */
			Sip420BadExtension,
			/** The server needs a specific extension not listed in the Supported header */
			Sip421ExtensionRequired,
			/** The received request contains a Session-Expires header field with a duration below the minimum timer */
			Sip422SessionIntervalTooSmall,
			/** Expiration time of the resource is too short */
			Sip423IntervalTooBrief,
			/** The request's location content was malformed or otherwise unsatisfactory */
			Sip424BadLocationInformation,
			/** The server policy requires an Identity header, and one has not been provided */
			Sip428UseIdentityHeader,
			/** The server did not receive a valid Referred-By token on the request */
			Sip429ProvideReferrerIdentity,
			/** A specific flow to a user agent has failed, although other flows may succeed. This response is intended for use between proxy devices, and should not be seen by an endpoint (and if it is seen by one, should be treated as a 400 Bad Request response) */
			Sip430FlowFailed,
			/** The request has been rejected because it was anonymous */
			Sip433AnonymityDisallowed,
			/** The request has an Identity-Info header, and the URI scheme in that header cannot be dereferenced */
			Sip436BadIdentityInfo,
			/** The server was unable to validate a certificate for the domain that signed the request */
			Sip437UnsupportedCertificate,
			/** The server obtained a valid certificate that the request claimed was used to sign the request, but was unable to verify that signature */
			Sip438InvalidIdentityHeader,
			/** The first outbound proxy the user is attempting to register through does not support the "outbound" feature of RFC 5626, although the registrar does */
			Sip439FirstHopLacksOutboundSupport,
			/** If a SIP proxy determines a response context has insufficient Incoming Max-Breadth to carry out a desired parallel fork, and the proxy is unwilling/unable to compensate by forking serially or sending a redirect, that proxy MUST return a 440 response. A client receiving a 440 response can infer that its request did not reach all possible destinations */
			Sip440MaxBreadthExceeded,
			/** If a SIP UA receives an INFO request associated with an Info Package that the UA has not indicated willingness to receive, the UA MUST send a 469 response, which contains a Recv-Info header field with Info Packages for which the UA is willing to receive INFO requests */
			Sip469BadInfoPackage,
			/** The source of the request did not have the permission of the recipient to make such a request */
			Sip470ConsentNeeded,
			/** Callee currently unavailable */
			Sip480TemporarilyUnavailable,
			/** Server received a request that does not match any dialog or transaction */
			Sip481Call_TransactionDoesNotExist,
			/** Server has detected a loop */
			Sip482LoopDetected,
			/** Max-Forwards header has reached the value '0' */
			Sip483TooManyHops,
			/** Request-URI incomplete */
			Sip484AddressIncomplete,
			/** Request-URI is ambiguous */
			Sip485Ambiguous,
			/** Callee is busy */
			Sip486BusyHere,
			/** Request has terminated by bye or cancel */
			Sip487RequestTerminated,
			/** Some aspect of the session description or the Request-URI is not acceptable */
			Sip488NotAcceptableHere,
			/** The server did not understand an event package specified in an Event header field */
			Sip489BadEvent,
			/** Server has some pending request from the same dialog */
			Sip491RequestPending,
			/** Request contains an encrypted MIME body, which recipient can not decrypt */
			Sip493Undecipherable,
			/** The server has received a request that requires a negotiated security mechanism, and the response contains a list of suitable security mechanisms for the requester to choose between, or a digest authentication challenge */
			Sip494SecurityAgreementRequired,
			/** The server could not fulfill the request due to some unexpected condition */
			Sip500ServerInternalError,
			/** The server does not have the ability to fulfill the request, such as because it does not recognize the request method. (Compare with 405 Method Not Allowed, where the server recognizes the method but does not allow or support it.) */
			Sip501NotImplemented,
			/** The server is acting as a gateway or proxy, and received an invalid response from a downstream server while attempting to fulfill the request */
			Sip502BadGateway,
			/** The server is undergoing maintenance or is temporarily overloaded and so cannot process the request. A "Retry-After" header field may specify when the client may reattempt its request */
			Sip503ServiceUnavailable,
			/** The server attempted to access another server in attempting to process the request, and did not receive a prompt response */
			Sip504ServerTimeout,
			/** The SIP protocol version in the request is not supported by the server */
			Sip505VersionNotSupported,
			/** The request message length is longer than the server can process */
			Sip513MessageTooLarge,
			/** The server is unable or unwilling to meet some constraints specified in the offer */
			Sip580PreconditionFailure,
			/** All possible destinations are busy. Unlike the 486 response, this response indicates the destination knows there are no alternative destinations (such as a voicemail server) able to accept the call */
			Sip600BusyEverywhere,
			/** The destination does not wish to participate in the call, or cannot do so, and additionally the destination knows there are no alternative destinations (such as a voicemail server) willing to accept the call */
			Sip603Decline,
			/** The server has authoritative information that the requested user does not exist anywhere */
			Sip604DoesNotExistAnywhere,
			/** The user's agent was contacted successfully but some aspects of the session description such as the requested media, bandwidth, or addressing style were not acceptable */
			Sip606NotAcceptable,
			/** The called party did not want this call from the calling party. Future attempts from the calling party are likely to be similarly rejected */
			Sip607Unwanted,
			/** Unknown SIP status code */
			SipStatusCodeUnknown
		};

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SipResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new SIP response with only the first line filled. The request will be created without further fields.
		 * The user can then add fields using addField() or insertField() methods
		 * @param[in] statusCode SIP status code to set
		 * @param[in] statusCodeString Most status codes have their default string, e.g 200 is usually "OK" etc.
		 * But the user can set a non-default status code string and it will be written in the header first line. Empty string ("") means using the
		 * default status code string. Also, the default is using the default status code string
		 * @param[in] sipVersion SIP version to set, default is SIP/2.0
		 *
		 */
		SipResponseLayer(SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString = "", std::string sipVersion = "SIP/2.0");

		virtual ~SipResponseLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor SipLayer and adds the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		SipResponseLayer(const SipResponseLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator SipLayer#operator=() and adds the functionality
		 * of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		SipResponseLayer& operator=(const SipResponseLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		inline SipResponseFirstLine* getFirstLine() { return m_FirstLine; }

		// implement Layer's abstract methods

		std::string toString();

	private:
		SipResponseFirstLine* m_FirstLine;
	};



	/**
	 * @class SipRequestFirstLine
	 * Represents an SIP request first line. The first line includes 3 parameters: SIP method (e.g INVITE, ACK, BYE, etc.),
	 * URI (e.g sip:bla@bla.com:12345) and SIP version (usually SIP/2.0). All these parameters are included in this class, and the user
	 * can retrieve or set them.
	 * This class cannot be instantiated by users, it's created inside SipRequestLayer and user can get a pointer to an instance of it. All "getters"
	 * of this class retrieve the actual data of the SIP request and the "setters" actually change the packet data.
	 * Since SIP is a textual protocol, most fields aren't of fixed size and this also applies to the first line parameters. So many "setter" methods
	 * of this class may need to shorten or extend the data in SipRequestLayer. These methods will return a false value if this action failed
	 */
	class SipRequestFirstLine
	{
		friend class SipRequestLayer;
	public:

		/**
		 * @return The SIP request method
		 */
		inline SipRequestLayer::SipMethod getMethod() { return m_Method; }

		/**
		 * Set the SIP request method
		 * @param[in] newMethod The method to set
		 * @return False if newMethod is SipRequestLayer#SipMethodUnknown or if shortening/extending the SipRequestLayer data failed. True otherwise
		 */
		bool setMethod(SipRequestLayer::SipMethod newMethod);

		/**
		 * @return A copied version of the URI (notice changing the return value won't change the actual data of the packet)
		 */
		std::string getUri();

		/**
		 * Set the URI
		 * @param[in] newUri The URI to set
		 * @return False if shortening/extending the SipRequestLayer data failed. True otherwise
		 */
		bool setUri(std::string newUri);

		/**
		 * @return The SIP version
		 */
		inline std::string getVersion() { return m_Version; }

		/**
		 * A static method for parsing the SIP method out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed SIP method
		 */
		static SipRequestLayer::SipMethod parseMethod(char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the SIP request first line
		 */
		inline int getSize() { return m_FirstLineEndOffset; }

		/**
		 * As explained in SipRequestLayer, a SIP message can sometimes spread over more than 1 packet, so when looking at a single packet
		 * the header can be partial. Same goes for the first line - it can spread over more than 1 packet. This method returns an indication
		 * whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		inline bool isComplete() { return m_IsComplete; }

		/**
		 * @class SipRequestFirstLineException
		 * This exception can be thrown while constructing SipRequestFirstLine (the constructor is private, so the construction happens
		 * only in SipRequestLayer). This kind of exception is thrown if trying to construct with SIP method of
		 * SipRequestLayer#SipMethodUnknown or with empty SIP version
		 */
		class SipRequestFirstLineException : public std::exception
		{
		public:
			~SipRequestFirstLineException() throw() {}
			void setMessage(std::string message) { m_Message = message; }
			virtual const char* what() const throw()
			{
				return m_Message.c_str();
			}
		private:
			std::string m_Message;
		};

	private:
		SipRequestFirstLine(SipRequestLayer* sipRequest);
		SipRequestFirstLine(SipRequestLayer* sipRequest, SipRequestLayer::SipMethod method, std::string version, std::string uri);
			//throw(SipRequestFirstLineException); // Deprecated in C++17

		void parseVersion();

		SipRequestLayer* m_SipRequest;
		SipRequestLayer::SipMethod m_Method;
		std::string m_Version;
		int m_VersionOffset;
		int m_UriOffset;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		SipRequestFirstLineException m_Exception;
	};




	/**
	 * @class SipResponseFirstLine
	 * Represents an SIP response message first line. The first line includes 2 parameters: status code (e.g 100 Trying ,200 OK, etc.),
	 * and SIP version (usually SIP/2.0). These 2 parameters are included in this class, and the user can retrieve or set them.
	 * This class cannot be instantiated by users, it's created inside SipResponseLayer and user can get a pointer to an instance of it. The "getter"
	 * methods of this class will retrieve the actual data of the SIP response and the "setter" methods will change the packet data.
	 * Since SIP is a textual protocol, most fields aren't of fixed size and this also applies to the first line parameters. So most "setter" methods
	 * of this class may need to shorten or extend the data in SipResponseLayer. These methods will return a false value if this action failed
	 */
	class SipResponseFirstLine
	{
		friend class SipResponseLayer;
	public:
		/**
		 * @return The status code as SipResponseLayer#SipResponseStatusCode enum
		 */
		inline SipResponseLayer::SipResponseStatusCode getStatusCode() { return m_StatusCode; }

		/**
		 * @return The status code number as integer (e.g 200, 100, etc.)
		 */
		int getStatusCodeAsInt();

		/**
		 * @return The status code message (e.g "OK", "Trying", etc.)
		 */
		std::string getStatusCodeString();

		/**
		 * Set the status code
		 * @param[in] newStatusCode The new status code to set
		 * @param[in] statusCodeString An optional parameter: set a non-default status code message (e.g "Bla Bla" instead of "Not Found"). If
		 * this parameter isn't supplied or supplied as empty string (""), the default message for the status code will be set
		 */
		bool setStatusCode(SipResponseLayer::SipResponseStatusCode newStatusCode, std::string statusCodeString = "");

		/**
		 * @return The SIP version
		 */
		inline std::string getVersion() { return m_Version; }

		/**
		 * Set the SIP version. The version to set is expected to be in the format of SIP/x.y otherwise an error will be written to log
		 * @param[in] newVersion The SIP version to set
		 */
		void setVersion(std::string newVersion);

		/**
		 * A static method for parsing the SIP status code out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed SIP status code as enum
		 */
		static SipResponseLayer::SipResponseStatusCode parseStatusCode(char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the SIP response first line
		 */
		inline int getSize() { return m_FirstLineEndOffset; }

		/**
		 * As explained in SipResponseLayer, A SIP message can sometimes spread over more than 1 packet, so when looking at a single packet
		 * the header can be partial. Same goes for the first line - it can spread over more than 1 packet. This method returns an indication
		 * whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		inline bool isComplete() { return m_IsComplete; }

		/**
		 * @class SipResponseFirstLineException
		 * This exception can be thrown while constructing SipResponseFirstLine (the constructor is private, so the construction happens
		 * only in SipResponseLayer). This kind of exception will be thrown if trying to construct with SIP status code of
		 * SipResponseLayer#SipStatusCodeUnknown or with an empty SIP version
		 */
		class SipResponseFirstLineException : public std::exception
		{
		public:
			~SipResponseFirstLineException() throw() {}
			void setMessage(std::string message) { m_Message = message; }
			virtual const char* what() const throw()
			{
				return m_Message.c_str();
			}
		private:
			std::string m_Message;
		};

	private:
		SipResponseFirstLine(SipResponseLayer* sipResponse);
		SipResponseFirstLine(SipResponseLayer* sipResponse,  std::string version, SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString = "");

		static std::string parseVersion(char* data, size_t dataLen);
		static SipResponseLayer::SipResponseStatusCode validateStatusCode(char* data, size_t dataLen, SipResponseLayer::SipResponseStatusCode potentialCode);


		SipResponseLayer* m_SipResponse;
		std::string m_Version;
		SipResponseLayer::SipResponseStatusCode m_StatusCode;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		SipResponseFirstLineException m_Exception;
	};

}

#endif // PACKETPP_SIP_LAYER
