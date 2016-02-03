#ifndef PACKETPP_IPV4_LAYER
#define PACKETPP_IPV4_LAYER

#include "Layer.h"
#include "IpAddress.h"

/// @file

/**
 * @struct iphdr
 * Represents an IPv4 protocol header
 */
#pragma pack(push, 1)
struct iphdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	/** IP header length, has the value of 5 for IPv4 */
	uint8_t internetHeaderLength:4,
	/** IP version number, has the value of 4 for IPv4 */
			ipVersion:4;
#else
	/** IP version number, has the value of 4 for IPv4 */
	uint8_t ipVersion:4,
	/** IP header length, has the value of 5 for IPv4 */
			internetHeaderLength:4;
#endif
	/** type of service, same as Differentiated Services Code Point (DSCP)*/
	uint8_t typeOfService;
	/** Entire packet (fragment) size, including header and data, in bytes */
	uint16_t totalLength;
	/** Identification field. Primarily used for uniquely identifying the group of fragments of a single IP datagram*/
	uint16_t ipId;
	 /** Fragment offset field, measured in units of eight-byte blocks (64 bits) */
	uint16_t fragmentOffset;
	/** An eight-bit time to live field helps prevent datagrams from persisting (e.g. going in circles) on an internet.  In practice, the field has become a hop count */
	uint8_t timeToLive;
	/** Defines the protocol used in the data portion of the IP datagram. Must be one of ::IPProtocolTypes */
	uint8_t protocol;
	/** Error-checking of the header */
	uint16_t headerChecksum;
	/** IPv4 address of the sender of the packet */
	uint32_t ipSrc;
	/** IPv4 address of the receiver of the packet */
	uint32_t ipDst;
	/*The options start here. */
};
#pragma pack(pop)

/**
 * An enum for all possible IPv4 and IPv6 protocol types
 */
enum IPProtocolTypes
{
	/** Dummy protocol for TCP		*/
	PACKETPP_IPPROTO_IP = 0,
	/** IPv6 Hop-by-Hop options		*/
	PACKETPP_IPPROTO_HOPOPTS = 0,
	/** Internet Control Message Protocol	*/
	PACKETPP_IPPROTO_ICMP = 1,
	/** Internet Gateway Management Protocol */
	PACKETPP_IPPROTO_IGMP = 2,
	/** IPIP tunnels (older KA9Q tunnels use 94) */
	PACKETPP_IPPROTO_IPIP = 4,
	/** Transmission Control Protocol	*/
	PACKETPP_IPPROTO_TCP = 6,
	/** Exterior Gateway Protocol		*/
	PACKETPP_IPPROTO_EGP = 8,
	/** PUP protocol				*/
	PACKETPP_IPPROTO_PUP = 12,
	/** User Datagram Protocol		*/
	PACKETPP_IPPROTO_UDP = 17,
	/** XNS IDP protocol			*/
	PACKETPP_IPPROTO_IDP = 22,
	/** IPv6 header				*/
	PACKETPP_IPPROTO_IPV6 = 41,
	/** IPv6 Routing header			*/
	PACKETPP_IPPROTO_ROUTING = 43,
	/** IPv6 fragmentation header		*/
	PACKETPP_IPPROTO_FRAGMENT = 44,
	/** GRE protocol */
	PACKETPP_IPPROTO_GRE = 47,
	/** encapsulating security payload	*/
	PACKETPP_IPPROTO_ESP = 50,
	/** authentication header		*/
	PACKETPP_IPPROTO_AH = 51,
	/** ICMPv6				*/
	PACKETPP_IPPROTO_ICMPV6 = 58,
	/** IPv6 no next header			*/
	PACKETPP_IPPROTO_NONE = 59,
	/** IPv6 Destination options		*/
	PACKETPP_IPPROTO_DSTOPTS = 60,
	/** Raw IP packets			*/
	PACKETPP_IPPROTO_RAW = 255,
	/** Maximum value */
	PACKETPP_IPPROTO_MAX
};

/**
 * @class IPv4Layer
 * Represents an IPv4 protocol layer
 */
class IPv4Layer : public Layer
{
public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref iphdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = IPv4; }

	/**
	 * A constructor that allocates a new IPv4 header with empty fields
	 */
	IPv4Layer();

	/**
	 * A constructor that allocates a new IPv4 header with source and destination IPv4 addresses
	 * @param[in] srcIP Source IPv4 address
	 * @param[in] dstIP Destination IPv4 address
	 */
	IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP);

	/**
	 * Get a pointer to the IPv4 header. Notice this points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the @ref iphdr
	 */
	inline iphdr* getIPv4Header() { return (iphdr*)m_Data; };

	/**
	 * Get the source IP address in the form of IPv4Address
	 * @return An IPv4Address containing the source address
	 */
	inline IPv4Address getSrcIpAddress() { return IPv4Address(getIPv4Header()->ipSrc); }

	/**
	 * Set the source IP address
	 * @param[in] ipAddr The IP address to set
	 */
	inline void setSrcIpAddress(const IPv4Address& ipAddr) { getIPv4Header()->ipSrc = ipAddr.toInt(); }

	/**
	 * Get the destination IP address in the form of IPv4Address
	 * @return An IPv4Address containing the destination address
	 */
	inline IPv4Address getDstIpAddress() { return IPv4Address(getIPv4Header()->ipDst); }

	/**
	 * Set the dest IP address
	 * @param[in] ipAddr The IP address to set
	 */
	inline void setDstIpAddress(const IPv4Address& ipAddr) { getIPv4Header()->ipDst = ipAddr.toInt(); }


	// implement abstract methods

	/**
	 * Currently identifies the following next layers: UdpLayer, TcpLayer. Otherwise sets PayloadLayer
	 */
	void parseNextLayer();

	/**
	 * @return Size of @ref iphdr
	 */
	inline size_t getHeaderLen() { return sizeof(iphdr); }

	/**
	 * Calculate the following fields:
	 * - iphdr#internetHeaderLength = 5
	 * - iphdr#ipVersion = 4;
	 * - iphdr#totalLength = total packet length
	 * - iphdr#headerChecksum = calculated
	 * - iphdr#protocol = calculated if next layer is known: ::PACKETPP_IPPROTO_TCP for TCP, ::PACKETPP_IPPROTO_UDP for UDP, ::PACKETPP_IPPROTO_ICMP for ICMP
	 */
	void computeCalculateFields();

	std::string toString();

private:
	void initLayer();
};

#endif /* PACKETPP_IPV4_LAYER */
