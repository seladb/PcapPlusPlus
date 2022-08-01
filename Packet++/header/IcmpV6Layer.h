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
enum ICMPv6MessageType
{
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
 * @struct icmpv6_echo_request
 * ICMPv6 echo request/reply message structure
 */
typedef struct icmpv6_echo_request
{
	/** a pointer to the header data */
	icmpv6_echo_hdr *header;
	/** most echo requests/replies contain some payload data. This is the data length */
	size_t dataLength;
	/** most echo requests/replies contain some payload data. This is a pointer to this data */
	uint8_t *data;
} icmpv6_echo_request;

/**
 * @typedef icmpv6_echo_reply
 * ICMPv6 echo reply message structure, same as icmpv6_echo_request
 */
typedef icmpv6_echo_request icmpv6_echo_reply;

/**
 * @class IcmpV6Layer
 * Abstract base class for ICMPv6 protocol layers.
 */
class IcmpV6Layer : public Layer
{
  public:
	virtual ~IcmpV6Layer() {}

	/**
	 * A static method that determines the ICMPv6 protocol type of ICMPv6 layer raw data by looking at the
	 * icmpv6hdr#type field
	 * @param[in] data The pointer to the beginning of an ICMPv6 byte stream
	 * @param[in] dataLen The length of the byte stream
	 * @return The specific ProtocolType or UnknownProtocol if it can not be determined
	 */
	static ProtocolType getIcmpv6Version(uint8_t *data, size_t dataLen);

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
	 * Identifies next layer and tries to create it
	 */
	void parseNextLayer();

	/**
	 * @return The length of the ICMPv6 header
	 */
	size_t getHeaderLen() const;

	/**
	 * Calculate ICMPv6 checksum field
	 */
	void computeCalculateFields();

	OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

  protected:
	IcmpV6Layer() = default;

	IcmpV6Layer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: Layer(data, dataLen, prevLayer, packet) {}

	bool cleanIcmpLayer();

  private:
	void calculateChecksum();
	icmpv6hdr *getIcmpv6Header() const { return (icmpv6hdr *)m_Data; }
};

class ICMPv6EchoRequestLayer : public IcmpV6Layer
{
  public:
	ICMPv6EchoRequestLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: IcmpV6Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = ICMPv6EchoRequest;
	}

	ICMPv6EchoRequestLayer();

	virtual ~ICMPv6EchoRequestLayer() {}

	/**
	 * @return ICMP echo request data.
	 */
	icmpv6_echo_request *getEchoRequestData();

	/**
	 * Set echo request message data
	 * @param[in] id Echo request identifier
	 * @param[in] sequence Echo request sequence
	 * @param[in] data A pointer to echo request payload to set
	 * @param[in] dataLen The length of the echo request payload
	 * @return A pointer to the echo request data that have been set or NULL if something went wrong
	 * (an appropriate error log is printed in such cases)
	 */
	icmpv6_echo_request *setEchoRequestData(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen);

	std::string toString() const;

  private:
	icmpv6_echo_request m_EchoData;
	bool setEchoData(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen);
};

class ICMPv6EchoReplyLayer : public IcmpV6Layer
{
  public:
	ICMPv6EchoReplyLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: IcmpV6Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = ICMPv6EchoReply;
	}

	ICMPv6EchoReplyLayer();

	virtual ~ICMPv6EchoReplyLayer()	{}

	/**
	 * @return ICMPv6 echo reply data.
	 */
	icmpv6_echo_reply *getEchoReplyData();

	/**
	 * Set echo reply message data
	 * @param[in] id Echo reply identifier
	 * @param[in] sequence Echo reply sequence
	 * @param[in] data A pointer to echo reply payload to set
	 * @param[in] dataLen The length of the echo reply payload
	 * @return A pointer to the echo reply data that have been set or NULL if something went wrong
	 * (an appropriate error log is printed in such cases)
	 */
	icmpv6_echo_reply *setEchoReplyData(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen);

	std::string toString() const;

  private:
	icmpv6_echo_reply m_EchoData;
	bool setEchoData(uint16_t id, uint16_t sequence, const uint8_t *data, size_t dataLen);
};

} // namespace pcpp
#endif /* PACKETPP_ICMPV6_LAYER */
