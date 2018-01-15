#ifndef PACKETPP_IPV6_LAYER
#define PACKETPP_IPV6_LAYER

#include "Layer.h"
#include "IPv6Extensions.h"
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
		IPv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

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
		 * A copy constructor that copies the entire header from the other IPv6Layer (including IPv6 extensions)
		 */
		IPv6Layer(const IPv6Layer& other);

		/**
		 * A destrcutor for this layer
		 */
		~IPv6Layer();

		/**
		 * An assignment operator that first delete all data from current layer and then copy the entire header from the other IPv6Layer (including IPv6 extensions)
		 */
		IPv6Layer& operator=(const IPv6Layer& other);

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

		size_t getExtensionCount();

		template<class TIPv6Extension>
		TIPv6Extension* getExtensionOfType();

		template<class TIPv6Extension>
		TIPv6Extension* addExtension(const TIPv6Extension& extensionHeader);

		void removeAllExtensions();

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref ip6_hdr
		 */
		inline size_t getHeaderLen() { return sizeof(ip6_hdr) + m_ExtensionsLen; }

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
		void parseExtensions();
		void deleteExtensions();

		IPv6Extension* m_FirstExtension;
		IPv6Extension* m_LastExtension;
		size_t m_ExtensionsLen;
	};


	template<class TIPv6Extension>
	TIPv6Extension* IPv6Layer::getExtensionOfType()
	{
		IPv6Extension* curExt = m_FirstExtension;
		while (curExt != NULL && dynamic_cast<TIPv6Extension*>(curExt) == NULL)
			curExt = curExt->getNextHeader();

		return (TIPv6Extension*)curExt;
	}

	template<class TIPv6Extension>
	TIPv6Extension* IPv6Layer::addExtension(const TIPv6Extension& extensionHeader)
	{
		int offsetToAddHeader = (int)getHeaderLen();
		if (!extendLayer(offsetToAddHeader, extensionHeader.getExtensionLen()))
		{
			return NULL;
		}

		TIPv6Extension* newHeader = new TIPv6Extension(this, (size_t)offsetToAddHeader);
		(*newHeader) = extensionHeader;

		if (m_FirstExtension != NULL)
		{
			newHeader->getBaseHeader()->nextHeader = m_LastExtension->getBaseHeader()->nextHeader;
			m_LastExtension->getBaseHeader()->nextHeader = newHeader->getExtensionType();
			m_LastExtension->setNextHeader(newHeader);
			m_LastExtension = newHeader;
		}
		else
		{
			m_FirstExtension = newHeader;
			m_LastExtension = newHeader;
			newHeader->getBaseHeader()->nextHeader = getIPv6Header()->nextHeader;
			getIPv6Header()->nextHeader = newHeader->getExtensionType();
		}

		m_ExtensionsLen += newHeader->getExtensionLen();

		return newHeader;
	}

} // namespace pcpp

#endif /* PACKETPP_IPV6_LAYER */
