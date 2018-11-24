#ifndef PCAPPP_PROTOCOL_TYPES
#define PCAPPP_PROTOCOL_TYPES

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * An enum representing all protocols supported by PcapPlusPlus
	 */
	enum ProtocolType
	{
		/**
		 * Unknown protocol (or unsupported by PcapPlusPlus)
		 */
		UnknownProtocol = 0x00,

		/**
		 * Ethernet protocol
		 */
		Ethernet = 0x01,

		/**
		 * IPv4 protocol
		 */
		IPv4 = 0x02,

		/**
		 * IPv6 protocol
		 */
		IPv6 = 0x04,

		/**
		 * IP protocol (aggregation bitmask of IPv4 and IPv6 protocols)
		 */
		IP = 0x06,

		/**
		 * TCP protocol
		 */
		TCP = 0x08,

		/**
		 * UDP protocol
		 */
		UDP = 0x10,

		/**
		 * HTTP request protocol
		 */
		HTTPRequest = 0x20,

		/**
		 * HTTP response protocol
		 */
		HTTPResponse = 0x40,

		/**
		 * HTTP protocol (aggregation bitmask of HTTP request and HTTP response protocols)
		 */
		HTTP = 0x20 | 0x40,

		/**
		 * ARP protocol
		 */
		ARP = 0x80,

		/**
		 * VLAN protocol
		 */
		VLAN = 0x100,

		/**
		 * ICMP protocol (currently not supported by PcapPlusPlus)
		 */
		ICMP = 0x200,

		/**
		 * PPPoE session protocol
		 */
		PPPoESession = 0x400,

		/**
		 * PPPoE discovery protocol
		 */
		PPPoEDiscovery = 0x800,

		/**
		 * PPPoE protocol (aggregation bitmask of PPPoESession and PPPoEDiscovery protocols)
		 */
		PPPoE = 0x400 | 0x800,

		/**
		 * DNS protocol
		 */
		DNS = 0x1000,

		/**
		 * MPLS protocol
		 */
		MPLS = 0x2000,

		/**
		 * GRE version 0 protocol
		 */
		GREv0 = 0x4000,

		/**
		 * GRE version 1 protocol
		 */
		GREv1 = 0x8000,

		/**
		 * GRE protocol (aggregation bitmask of GREv0 and GREv1 protocols)
		 */
		GRE = 0x4000 | 0x8000,

		/**
		 * PPP for PPTP protocol
		 */
		PPP_PPTP = 0x10000,

		/**
		 * SSL/TLS protocol
		 */
		SSL = 0x20000,

		/**
		 * SLL (Linux cooked capture) protocol
		 */
		SLL = 0x40000,

		/**
		 * DHCP/BOOTP protocol
		 */
		DHCP = 0x80000,

		/**
		 * Null/Loopback protocol
		 */
		NULL_LOOPBACK = 0x100000,

		/**
		 * IGMP protocol
		 */
		IGMP = 0xE00000,

		/**
		 * IGMPv1 protocol
		 */
		IGMPv1 = 0x200000,

		/**
		 * IGMPv2 protocol
		 */
		IGMPv2 = 0x400000,

		/**
		 * IGMPv3 protocol
		 */
		IGMPv3 = 0x800000,

		/**
		 * Generic payload (no specific protocol)
		 */
		GenericPayload = 0x1000000,

		/**
		 * VXLAN protocol
		 */
		VXLAN = 0x2000000,

		/**
		 * SIP request protocol
		 */
		SIPRequest = 0x4000000,

		/**
		 * SIP response protocol
		 */
		SIPResponse = 0x8000000,

		/**
		 * SIP protocol (aggregation bitmask of SIPRequest and SIPResponse protocols)
		 */
		SIP = 0x4000000 | 0x8000000,

		/**
		 * SDP protocol
		 */
		SDP = 0x10000000,

		/**
		 * Packet trailer
		 */
		PacketTrailer = 0x20000000,

		/**
		 * RADIUS protocol
		 */
		Radius = 0x40000000
	};


	/**
	 * An enum representing OSI model layers
	 */
	enum OsiModelLayer
	{
		/** Physical layer (layer 1) */
		OsiModelPhysicalLayer = 1,
		/** Data link layer (layer 2) */
		OsiModelDataLinkLayer = 2,
		/** Network layer (layer 3) */
		OsiModelNetworkLayer = 3,
		/** Transport layer (layer 4) */
		OsiModelTransportLayer = 4,
		/** Session layer (layer 5) */
		OsiModelSesionLayer = 5,
		/** Presentation layer (layer 6) */
		OsiModelPresentationLayer = 6,
		/** Application layer (layer 7) */
		OsiModelApplicationLayer = 7,
		/** Unknown / null layer */
		OsiModelLayerUnknown = 8
	};

} //namespace pcpp

#endif
