#ifndef PACKETPP_IPV6_LAYER
#define PACKETPP_IPV6_LAYER

#include "Layer.h"
#include "IpAddress.h"

#pragma pack(push, 1)
struct ip6_hdr {
    #if (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t trafficClass:4,
            ipVersion:4;
    uint8_t flowLabel[3];
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    #else
	uint32_t ipVersion:4,
            trafficClass:8,
            flowLabel:20;
    uint32_t payloadLength:16,
            nextHeader:8,
            hopLimit:8;
    #endif
    uint8_t ipSrc[16], ipDst[16];
};
#pragma pack(pop)

class IPv6Layer : public Layer
{
public:
	IPv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer) : Layer(data, dataLen, prevLayer) { m_Protocol = IPv6; }
	IPv6Layer();
	IPv6Layer(const IPv6Address& srcIP, const IPv6Address& dstIP);

	inline ip6_hdr* getIPv6Header() { return (ip6_hdr*)m_Data; };
	inline IPv6Address getSrcIpAddress() { return IPv6Address(getIPv6Header()->ipSrc); }
	inline IPv6Address getDstIpAddress() { return IPv6Address(getIPv6Header()->ipDst); }

	// implement abstract methods
	void parseNextLayer();
	inline size_t getHeaderLen() { return sizeof(ip6_hdr); }
	void computeCalculateFields();

private:
	void initLayer();
};

#endif /* PACKETPP_IPV6_LAYER */
