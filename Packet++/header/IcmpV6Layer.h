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
 * @struct icmpv6hdr
 * Represents an ICMPv6 protocol header
 */
#pragma pack(push, 1)
struct icmpv6hdr
{
	/** Type of the message
	Values in the range from 0 to 127 (high-order bit is 0) indicate an error message,
	while values in the range from 128 to 255 (high-order bit is 1) indicate an information message. */
	uint8_t type;
	/** The code field value depends on the message type and provides an additional level of message granularity */
	uint8_t code;
	/** The checksum field provides a minimal level of integrity verification for the ICMP message */
	uint16_t checksum;
};
#pragma pack(pop)

/**
 * An enum representing the available ICMPv6 message types
 */
enum ICMPv6MessageTypes
{
	/* ICMPv6 Error Messages */
	ICMPv6_DESTINATION_UNREACHABLE = 1,
	ICMPv6_PACKET_TOO_BIG = 2,
	ICMPv6_TIME_EXCEEDED = 3,
	ICMPv6_PARAMETER_PROBLEM = 4,
	ICMPv6_PRIVATE_EXPERIMENTATION1 = 100,
	ICMPv6_PRIVATE_EXPERIMENTATION2 = 101,
	ICMPv6_RESERVED_EXPANSION_ERROR = 127,

	/* ICMPv6 Informational Messages */
	ICMPv6_ECHO_REQUEST = 128,
	ICMPv6_ECHO_REPLY = 129,
	ICMPv6_MULTICAST_LISTENER_QUERY = 130,
	ICMPv6_MULTICAST_LISTENER_REPORT = 131,
	ICMPv6_MULTICAST_LISTENER_DONE = 132,
	ICMPv6_ROUTER_SOLICITATION = 133,
	ICMPv6_ROUTER_ADVERTISEMENT = 134,
	ICMPv6_NEIGHBOR_SOLICITATION = 135,
	ICMPv6_NEIGHBOR_ADVERTISEMENT = 136,
	ICMPv6_REDIRECT_MESSAGE = 137,
	ICMPv6_ROUTER_RENUMBERING = 138,
	ICMPv6_ICMP_NODE_INFORMATION_QUERY = 139,
	ICMPv6_ICMP_NODE_INFORMATION_RESPONSE = 140,
	ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE = 141,
	ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE = 142,
	ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS = 143,
	ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE = 144,
	ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE = 145,
	ICMPv6_MOBILE_PREFIX_SOLICITATION = 146,
	ICMPv6_MOBILE_PREFIX_ADVERTISEMENT = 147,
	ICMPv6_CERTIFICATION_PATH_SOLICITATION = 148,
	ICMPv6_CERTIFICATION_PATH_ADVERTISEMENT = 149,
	ICMPv6_MULTICAST_ROUTER_ADVERTISEMENT = 151,
	ICMPv6_MULTICAST_ROUTER_SOLICITATION = 152,
	ICMPv6_MULTICAST_ROUTER_TERMINATION = 153,
	ICMPv6_RPL_CONTROL_MESSAGE = 155,
	ICMPv6_PRIVATE_EXPERIMENTATION3 = 200,
	ICMPv6_PRIVATE_EXPERIMENTATION4 = 201,
	ICMPv6_RESERVED_EXPANSION_INFORMATIONAL = 255
};

/**
 * @class IcmpV6Layer
 * Represents an ICMPv6 protocol layer
 */
class IcmpV6Layer : public Layer
{
  public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref icmpv6hdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IcmpV6Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = ICMPv6;
	}

	/**
	 * A constructor that allocates a new ICMPv6 header
	 * @param[in] type Message type ICMPv6
	 * @param[in] code Code field
	 */
	IcmpV6Layer(ICMPv6MessageTypes type, uint8_t code);

	virtual ~IcmpV6Layer() {}

	/**
	 * Get a pointer to the basic ICMPv6 header. Notice this points directly to the data, so every change will change
	 * the actual packet data
	 * @return A pointer to the @ref icmpv6hdr
	 */
	icmpv6hdr *getIcmpv6Header() const { return (icmpv6hdr *)m_Data; }

	/**
	 * @return The length of the ICMPv6 header
	 */
	size_t getHeaderLen() const
	{
		return sizeof(icmpv6hdr);
	}

	/**
	 * Identifies next layer and tries to create it
	 */
	void parseNextLayer();

	/**
	 * @return Get the Message Type
	 */
	ICMPv6MessageTypes getMessageType() const;

	/**
	 * @return Get the checksum header field in host representation
	 */
	uint16_t getChecksum() const;

	/**
	 * @return Get the code header field
	 */
	uint8_t getCode() const;

	/**
	 * Calculate ICMPv6 checksum field
	 */
	void computeCalculateFields();

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

	/**
	 * A static method that validates the input data
	 * @param[in] data The pointer to the beginning of a byte stream of an ICMPv6 layer
	 * @param[in] dataLen The length of the byte stream
	 * @return True if the data is valid and can represent an ICMPv6 layer
	 */
	static bool isDataValid(const uint8_t *data, size_t dataLen);

  private:
	void calculateChecksum();
};

} // namespace pcpp
#endif /* PACKETPP_ICMPV6_LAYER */
