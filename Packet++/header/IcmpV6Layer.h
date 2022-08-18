#ifndef PACKETPP_ICMPV6_LAYER
#define PACKETPP_ICMPV6_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * An enum representing the available ICMPv6 message types
 */
enum class ICMPv6MessageType : int
{
	/** Unknown ICMPv6 message */
	ICMPv6_UNKNOWN_MESSAGE = 0,
	/** Destination Unreachable Message */
	ICMPv6_DESTINATION_UNREACHABLE = 1,
	/** Packet Too Big Message */
	ICMPv6_PACKET_TOO_BIG = 2,
	/** Time Exceeded Message */
	ICMPv6_TIME_EXCEEDED = 3,
	/** Parameter Problem Message */
	ICMPv6_PARAMETER_PROBLEM = 4,
	/** Private Experimentation Message */
	ICMPv6_PRIVATE_EXPERIMENTATION1 = 100,
	/** Private Experimentation Message */
	ICMPv6_PRIVATE_EXPERIMENTATION2 = 101,
	/** Reserved for expansion of ICMPv6 error messages */
	ICMPv6_RESERVED_EXPANSION_ERROR = 127,
	/** Echo Request Message */
	ICMPv6_ECHO_REQUEST = 128,
	/** Echo Reply Message */
	ICMPv6_ECHO_REPLY = 129,
	/** Multicast Listener Query Message */
	ICMPv6_MULTICAST_LISTENER_QUERY = 130,
	/** Multicast Listener Report Message */
	ICMPv6_MULTICAST_LISTENER_REPORT = 131,
	/** Multicast Listener Done Message */
	ICMPv6_MULTICAST_LISTENER_DONE = 132,
	/** Router Solicitation Message */
	ICMPv6_ROUTER_SOLICITATION = 133,
	/** Router Advertisement Message */
	ICMPv6_ROUTER_ADVERTISEMENT = 134,
	/** Neighbor Solicitation Message */
	ICMPv6_NEIGHBOR_SOLICITATION = 135,
	/** Neighbor Advertisement Message */
	ICMPv6_NEIGHBOR_ADVERTISEMENT = 136,
	/** Redirect Message */
	ICMPv6_REDIRECT_MESSAGE = 137,
	/** Router Renumbering Message */
	ICMPv6_ROUTER_RENUMBERING = 138,
	/** Node Information Query Message */
	ICMPv6_ICMP_NODE_INFORMATION_QUERY = 139,
	/** Node Information Reply Message*/
	ICMPv6_ICMP_NODE_INFORMATION_RESPONSE = 140,
	/** Inverse Neighbor Discovery Solicitation Message */
	ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE = 141,
	/** Inverse Neighbor Discovery Advertisement Message */
	ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE = 142,
	/** Multicast Listener Report Message */
	ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS = 143,
	/** Home Agent Address Discovery Request Message */
	ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE = 144,
	/** Home Agent Address Discovery Reply Message */
	ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE = 145,
	/** Mobile Prefix Solicitation Message */
	ICMPv6_MOBILE_PREFIX_SOLICITATION = 146,
	/** Mobile Prefix Advertisement Message */
	ICMPv6_MOBILE_PREFIX_ADVERTISEMENT = 147,
	/** Certification Path Solicitation Message */
	ICMPv6_CERTIFICATION_PATH_SOLICITATION = 148,
	/** Certification Path Advertisement Message */
	ICMPv6_CERTIFICATION_PATH_ADVERTISEMENT = 149,
	/** ICMP Experimental Mobility Subtype Format and Registry Message */
	ICMPv6_EXPERIMENTAL_MOBILITY = 150,
	/** Multicast Router Advertisement Message */
	ICMPv6_MULTICAST_ROUTER_ADVERTISEMENT = 151,
	/** Multicast Router Solicitation Message */
	ICMPv6_MULTICAST_ROUTER_SOLICITATION = 152,
	/** Multicast Router Termination Message*/
	ICMPv6_MULTICAST_ROUTER_TERMINATION = 153,
	/** RPL Control Message */
	ICMPv6_RPL_CONTROL_MESSAGE = 155,
	/** Private Experimentation Message */
	ICMPv6_PRIVATE_EXPERIMENTATION3 = 200,
	/** Private Experimentation Message */
	ICMPv6_PRIVATE_EXPERIMENTATION4 = 201,
	/** Reserved for expansion of ICMPv6 informational messages */
	ICMPv6_RESERVED_EXPANSION_INFORMATIONAL = 255
};

/**
 * @struct icmpv6hdr
 * Represents an ICMPv6 protocol header
 */
#pragma pack(push, 1)
struct icmpv6hdr
{
	/** Type of the message. Values in the range from 0 to 127 (high-order bit is 0) indicate an error message,
	while values in the range from 128 to 255 (high-order bit is 1) indicate an information message. */
	uint8_t type;
	/** The code field value depends on the message type and provides an additional level of message granularity */
	uint8_t code;
	/** The checksum field provides a minimal level of integrity verification for the ICMP message */
	uint16_t checksum;
};
#pragma pack(pop)

/**
 * @struct icmpv6_echo_hdr
 * ICMP echo request/reply message structure
 */
#pragma pack(push, 1)
typedef struct icmpv6_echo_hdr : icmpv6hdr
{
	/** the echo request identifier */
	uint16_t id;
	/** the echo request sequence number */
	uint16_t sequence;
} icmpv6_echo_hdr;
#pragma pack(pop)

/**
 * @class IcmpV6Layer
 * Base class for ICMPv6 protocol layers which provides common logic for ICMPv6 messages.
 */
class IcmpV6Layer : public Layer
{
public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param data A pointer to the raw data
	 * @param dataLen Size of the data in bytes
	 * @param prevLayer A pointer to the previous layer
	 * @param packet A pointer to the Packet instance where layer will be stored in
	 */
	IcmpV6Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: Layer(data, dataLen, prevLayer, packet) { m_Protocol = ICMPv6; }

	/**
	 * A constructor that allocates a new ICMPv6 layer with type, code and data
	 * @param[in] msgType Message type of the ICMPv6 layer
	 * @param[in] code Code field of the ICMPv6 layer
	 * @param[in] data A pointer to the payload to set
	 * @param[in] dataLen The length of the payload
	 */
	IcmpV6Layer(ICMPv6MessageType msgType, uint8_t code, const uint8_t *data, size_t dataLen);

	virtual ~IcmpV6Layer() {}

	/**
	 * A static method that creates an ICMPv6 layer from packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored
	 * @return Layer* A newly allocated ICMPv6 layer
	 */
	static Layer *parseIcmpV6Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

	/**
	 * @param[in] type Type to check
	 * @return True if the layer if of the given type, false otherwise
	 */
	bool isMessageOfType(ICMPv6MessageType type) const { return getMessageType() == type; }

	/**
	 * @return Get the ICMPv6 Message Type
	 */
	ICMPv6MessageType getMessageType() const;

	/**
	 * @return Get the code header field
	 */
	uint8_t getCode() const;

	/**
	 * @return Get the checksum header field in host representation
	 */
	uint16_t getChecksum() const;

	/**
	 * Does nothing for this layer. ICMPv6 is the last layer.
	 */
	void parseNextLayer() {}

	/**
	 * @return The size of the ICMPv6 message
	 */
	size_t getHeaderLen() const { return m_DataLen; }

	/**
	 * Calculate ICMPv6 checksum field
	 */
	void computeCalculateFields();

	OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

	std::string toString() const;

protected:
	IcmpV6Layer() = default;

private:
	void calculateChecksum();
	icmpv6hdr *getIcmpv6Header() const { return (icmpv6hdr *)m_Data; }
};

/**
 * @class ICMPv6EchoLayer
 * Represents an ICMPv6 echo request/reply protocol layer
 */
class ICMPv6EchoLayer : public IcmpV6Layer
{
public:
	/**
	 * An enum representing ICMPv6 echo message types
	 */
	enum ICMPv6EchoType
	{
		/** Echo Request Type */
		REQUEST,
		/** Echo Reply Type */
		REPLY
	};

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	ICMPv6EchoLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: IcmpV6Layer(data, dataLen, prevLayer, packet)	{}

	/**
	 * A constructor for a new echo request/reply layer
	 * @param[in] echoType The type of the echo message
	 * @param[in] id Echo request identifier
	 * @param[in] sequence Echo request sequence number
	 * @param[in] data A pointer to echo request payload to set
	 * @param[in] dataLen The length of the echo request payload
	 */
	ICMPv6EchoLayer(ICMPv6EchoType echoType, uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen);

	virtual ~ICMPv6EchoLayer() {}

	/**
	 * @return Identifier in host representation
	 */
	uint16_t getIdentifier() const;

	/**
	 * @return Sequence number in host representation
	 */
	uint16_t getSequenceNr() const;

	/**
	 * @return Size of the data in bytes
	 */
	size_t getEchoDataLen() const { return m_DataLen - sizeof(icmpv6_echo_hdr); }

	/**
	 * @return Pointer to the beginning of the data
	 */
	uint8_t *getEchoDataPtr() const { return m_Data + sizeof(icmpv6_echo_hdr); }

	std::string toString() const;

private:
	icmpv6_echo_hdr *getEchoHeader() const { return (icmpv6_echo_hdr *)m_Data; }
};

} // namespace pcpp
#endif /* PACKETPP_ICMPV6_LAYER */
