#ifndef PACKETPP_IPV6_LAYER
#define PACKETPP_IPV6_LAYER

#include "Layer.h"
#include "IpAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct ip6_hdr
	 * Represents an IPv6 protocol header
	 */
#pragma pack(push, 1)
	struct ip6_hdr {
		#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Traffic class */
		uint8_t trafficClass:4,
		/** IP version number, has the value of 6 for IPv6 */
				ipVersion:4;
		#else
		/** IP version number, has the value of 6 for IPv6 */
		uint8_t ipVersion:4,
		/** Traffic class */
				trafficClass:4;
		#endif
		/** Flow label */
		uint8_t flowLabel[3];
		/** The size of the payload in octets, including any extension headers */
		uint16_t payloadLength;
		/** Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes */
		uint8_t nextHeader;
		/** Replaces the time to live field of IPv4 */
		uint8_t hopLimit;
		/** Source address */
		uint8_t ipSrc[16];
		/** Destination address */
		uint8_t ipDst[16];
	};
#pragma pack(pop)


	/**
	 * @class IPv6Layer
	 * Represents an IPv6 protocol layer
	 */
	class IPv6Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ip6_hdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IPv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = IPv6; }

		/**
		 * A constructor that allocates a new IPv6 header with empty fields
		 */
		IPv6Layer();

		/**
		 * A constructor that allocates a new IPv6 header with source and destination IPv6 addresses
		 * @param[in] srcIP Source IPv6 address
		 * @param[in] dstIP Destination IPv6 address
		 */
		IPv6Layer(const IPv6Address& srcIP, const IPv6Address& dstIP);

		/**
		 * Get a pointer to the IPv6 header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref ip6_hdr
		 */
		inline ip6_hdr* getIPv6Header() { return (ip6_hdr*)m_Data; };

		/**
		 * Get the source IP address in the form of IPv6Address
		 * @return An IPv6Address containing the source address
		 */
		inline IPv6Address getSrcIpAddress() { return IPv6Address(getIPv6Header()->ipSrc); }

		/**
		 * Get the destination IP address in the form of IPv6Address
		 * @return An IPv6Address containing the destination address
		 */
		inline IPv6Address getDstIpAddress() { return IPv6Address(getIPv6Header()->ipDst); }

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref ip6_hdr
		 */
		inline size_t getHeaderLen() { return sizeof(ip6_hdr); }

		/**
		 * Calculate the following fields:
		 * - ip6_hdr#payloadLength = size of payload (all data minus header size)
		 * - ip6_hdr#ipVersion = 6
		 * - ip6_hdr#nextHeader = calculated if next layer is known: ::PACKETPP_IPPROTO_TCP for TCP, ::PACKETPP_IPPROTO_UDP for UDP, ::PACKETPP_IPPROTO_ICMP for ICMP
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }

	private:
		void initLayer();
	};

} // namespace pcpp

#endif /* PACKETPP_IPV6_LAYER */
