#ifndef PACKETPP_IPV4_LAYER
#define PACKETPP_IPV4_LAYER

#include "Layer.h"
#include "IpAddress.h"

#pragma pack(push, 1)
struct iphdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t internetHeaderLength:4,
			ipVersion:4;
#else
	uint8_t ipVersion:4,
			internetHeaderLength:4;
#endif
	uint8_t typeOfService;
	uint16_t totalLength;
	uint16_t ipId;
	uint16_t fragmentOffset;
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t headerChecksum;
	uint32_t ipSrc;
	uint32_t ipDst;
	/*The options start here. */
};
#pragma pack(pop)

enum IPProtocolTypes
{
	PACKETPP_IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
	PACKETPP_IPPROTO_HOPOPTS = 0,		/* IPv6 Hop-by-Hop options		*/
	PACKETPP_IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
	PACKETPP_IPPROTO_IGMP = 2,		/* Internet Gateway Management Protocol */
	PACKETPP_IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
	PACKETPP_IPPROTO_TCP = 6,		/* Transmission Control Protocol	*/
	PACKETPP_IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
	PACKETPP_IPPROTO_PUP = 12,		/* PUP protocol				*/
	PACKETPP_IPPROTO_UDP = 17,		/* User Datagram Protocol		*/
	PACKETPP_IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
	PACKETPP_IPPROTO_IPV6 = 41,		/* IPv6 header				*/
	PACKETPP_IPPROTO_ROUTING = 43,		/* IPv6 Routing header			*/
	PACKETPP_IPPROTO_FRAGMENT = 44,	/* IPv6 fragmentation header		*/
	PACKETPP_IPPROTO_ESP = 50,		/* encapsulating security payload	*/
	PACKETPP_IPPROTO_AH = 51,		/* authentication header		*/
	PACKETPP_IPPROTO_ICMPV6 = 58,		/* ICMPv6				*/
	PACKETPP_IPPROTO_NONE = 59,		/* IPv6 no next header			*/
	PACKETPP_IPPROTO_DSTOPTS = 60,		/* IPv6 Destination options		*/
	PACKETPP_IPPROTO_RAW = 255,		/* Raw IP packets			*/
	PACKETPP_IPPROTO_MAX
};

class IPv4Layer : public Layer
{
public:
	IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { m_Protocol = IPv4; }
	IPv4Layer();
	IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP);

	inline iphdr* getIPv4Header() { return (iphdr*)m_Data; };
	inline IPv4Address getSrcIpAddress() { return IPv4Address(getIPv4Header()->ipSrc); }
	inline IPv4Address getDstIpAddress() { return IPv4Address(getIPv4Header()->ipDst); }

	// implement abstract methods
	void parseNextLayer();
	inline size_t getHeaderLen() { return sizeof(iphdr); }
	void computeCalculateFields();

private:
	void initLayer();
};

#endif /* PACKETPP_IPV4_LAYER */
