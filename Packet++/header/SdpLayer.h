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
	 * Represents a SDP message
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

		SdpLayer();

		SdpLayer(std::string username, long sessionID, long sessionVersion, IPv4Address ipAddress, std::string sessionName, long startTime, long stopTime);

		~SdpLayer() {}

		/**
		 * A copy constructor for this layer. Inherits base copy constructor SipLayer and adds the functionality
		 * of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SdpLayer(const SdpLayer& other) : TextBasedProtocolMessage(other) {}

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator SipLayer#operator=() and adds the functionality
		 * of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SdpLayer& operator=(const SdpLayer& other) { TextBasedProtocolMessage::operator=(other); return *this; }

		IPv4Address getOwnerIPv4Address();

		uint16_t getMediaPort(std::string mediaType);

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
