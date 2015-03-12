#ifndef PCAPPP_PROTOCOL_TYPES
#define PCAPPP_PROTOCOL_TYPES

/// @file

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
	HTTP = 0x20 & 0x40,

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
	ICMP = 0x200
};

#endif
