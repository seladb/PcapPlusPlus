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
		Unknown = 0x00,

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
		SLL = 0x40000

	};

} //namespace pcpp

#endif
