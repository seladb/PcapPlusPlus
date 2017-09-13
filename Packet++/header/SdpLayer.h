#ifndef PACKETPP_SDP_LAYER
#define PACKETPP_SDP_LAYER

#include "IpAddress.h"
#include "TextBasedProtocol.h"
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/** Protocol version (v) */
#define PCPP_SDP_PROTOCOL_VERSION_FIELD "v"
/** Originator and session identifier (o) */
#define PCPP_SDP_ORIGINATOR_FIELD       "o"
/** Session name (s) */
#define PCPP_SDP_SESSION_NAME_FIELD     "s"
/** Session title, media title or short information (i) */
#define PCPP_SDP_INFO_FIELD             "i"
/** URI of description (u) */
#define PCPP_SDP_URI_FIELD              "u"
/** Email address with optional name of contacts (e) */
#define PCPP_SDP_EMAIL_FIELD            "e"
/** Phone number with optional name of contacts (p) */
#define PCPP_SDP_PHONE_FIELD            "p"
/** Connection information (c) */
#define PCPP_SDP_CONNECTION_INFO_FIELD  "c"
/** Bandwidth information (b) */
#define PCPP_SDP_BANDWIDTH_FIELD        "b"
/** Time the session is active (t) */
#define PCPP_SDP_TIME_FIELD             "t"
/** Repeat times (r) */
#define PCPP_SDP_REPEAT_TIMES_FIELD     "r"
/** Time zone adjustments (z) */
#define PCPP_SDP_TIME_ZONE_FIELD        "z"
/** Encryption key (k) */
#define PCPP_SDP_ENCRYPTION_KEY_FIELD   "k"
/** Media attribute (a) */
#define PCPP_SDP_MEDIA_ATTRIBUTE_FIELD  "a"
/** Media name and transport address (m) */
#define PCPP_SDP_MEDIA_NAME_FIELD       "m"

	/**
	 * @class SdpLayer
	 * Represents a SDP (Session Description Protocol) message. SDP is a text-based protocol described by a series of fields, one per line (lines are separated by CRLF).
	 * The form of each field is as follows:<BR>
	 * @code
	 * [character]=[value]
	 * @endcode
	 * Each character represents a certain type of field. All field type are represented as macros in SdpLayer.h file
	 * (for example: PCPP_SDP_ORIGINATOR_FIELD is a macro for the originator field (o=) ).<BR>
	 * For more details about SDP structure please refer to its Wikipedia page: https://en.wikipedia.org/wiki/Session_Description_Protocol
	 */
	class SdpLayer : public TextBasedProtocolMessage
	{
	public:

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * An empty c'tor which initialize an empty message with no fields
		 */
		SdpLayer();

		/**
		 * A c'tor which initializes a message with the minimum required fields.<BR>
		 * After this c'tor the message will look like this:
		 *
		 * @code
		 * v=0
		 * o=[username] [sessionID] [sessionVersion] IN IP4 [ipAddress]
		 * s=[sessionName]
		 * c=IN IP4 [ipAddress]
		 * t=[startTime] [endTime]
		 * @endcode
		 *
		 * @param[in] username User's login on the originating host
		 * @param[in] sessionID A globally unique identifier for the session
		 * @param[in] sessionVersion A version number for this session description
		 * @param[in] ipAddress The address of the machine from which the session is created
		 * @param[in] sessionName A textual session name
		 * @param[in] startTime The start time of the session
		 * @param[in] stopTime The stop time of the session
		 */
		SdpLayer(std::string username, long sessionID, long sessionVersion, IPv4Address ipAddress, std::string sessionName, long startTime, long stopTime);

		~SdpLayer() {}

		/**
		 * A copy constructor for this layer. Inherits the base copy constructor and doesn't add
		 * anything else
		 * @param[in] other The instance to copy from
		 */
		SdpLayer(const SdpLayer& other) : TextBasedProtocolMessage(other) {}

		/**
		 * An assignment operator overload for this layer. Inherits the base assignment operator
		 * and doesn't add anything else
		 * @param[in] other The instance to copy from
		 */
		SdpLayer& operator=(const SdpLayer& other) { TextBasedProtocolMessage::operator=(other); return *this; }

		/**
		 * The 'originator' field (o=) contains the IP address of the the machine from which the session is created.
		 * This IP address can be used to track the RTP data relevant for the call. This method extracts this IP address from the 'originator' field and returns it.
		 * A value of IPv4Address#Zero will be returned in the following cases: (1) if 'originator' field doesn't exist; (2) if it doesn't contain the IP address;
		 * (3) if it contains a non-IPv4 address
		 * @return Te IP address of the the machine from which the session is created
		 */
		IPv4Address getOwnerIPv4Address();

		/**
		 * The 'media-description' field (m=) contains the transport port to which the media stream is sent. This port can be used to track the RTP data relevant for the call.
		 * This method extracts this port from the 'media-description' field and returns it. Since a SDP message can contain several 'media-description' fields, one for each media type
		 * (e.g audio, image, etc.), the user is required to provide the media type. A value of 0 will be returned in the following cases: (1) if 'media-description' field doesn't
		 * exist; (2) if provided media type was not found; (3) if 'media-description' field didn't contain a port
		 * @param[in] mediaType The media type to search in
		 * @return The transport port to which the media stream is sent
		 */
		uint16_t getMediaPort(std::string mediaType);

		/**
		 * Adds a 'media-description' field (m=) with all necessary data and attribute fields (a=) with data relevant for this media.<BR>
		 * After this method is run the following block of fields will be added at the end of the message:
		 *
		 * @code
		 * m=[mediaType] [mediaPort] [mediaProtocol] [mediaFormat]
		 * a=[1st media attribute]
		 * a=[2nd media attribute]
		 * ...
		 * @endcode
		 *
		 * @param[in] mediaType The media type, usually "audio", "video", "text" or "image"
		 * @param[in] mediaPort The transport port to which the media stream is sent
		 * @param[in] mediaProtocol The transport protocol, usually "udp", "RTP/AVP" or "RTP/SAVP"
		 * @param[in] mediaFormat A space-separated list of media format description. For example: "8 96"
		 * @param[in] mediaAttributes A vector of media attributes. Each string in this vector will be
		 * translated into a 'media-attribute' field (a=)
		 * @return True if all fields were added properly or false if at least one field was failed to be added
		 */
		bool addMediaDescription(std::string mediaType, uint16_t mediaPort, std::string mediaProtocol, std::string mediaFormat, std::vector<std::string> mediaAttributes);

		// overridden methods

		OsiModelLayer getOsiModelLayer() { return OsiModelSesionLayer; }

		std::string toString();

	protected:

		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() { return '='; }
		bool spacesAllowedBetweenHeaderFieldNameAndValue() { return false; }

	};
}

#endif // PACKETPP_SDP_LAYER
