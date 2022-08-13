#ifndef PCAPPP_PROTOCOL_TYPES
#define PCAPPP_PROTOCOL_TYPES

#include <stdint.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @typedef ProtocolType
	 * Representing all protocols supported by PcapPlusPlus
	 */
	typedef uint64_t ProtocolType;

	/**
	 * Unknown protocol (or unsupported by PcapPlusPlus)
	 */
	const ProtocolType UnknownProtocol = 0x00;

	/**
	 * Ethernet protocol
	 */
	const ProtocolType Ethernet = 0x01;

	/**
	 * IPv4 protocol
	 */
	const ProtocolType IPv4 = 0x02;

	/**
	 * IPv6 protocol
	 */
	const ProtocolType IPv6 = 0x04;

	/**
	 * IP protocol (aggregation bitmask of IPv4 and IPv6 protocols)
	 */
	const ProtocolType IP = 0x06;

	/**
	 * TCP protocol
	 */
	const ProtocolType TCP = 0x08;

	/**
	 * UDP protocol
	 */
	const ProtocolType UDP = 0x10;

	/**
	 * HTTP request protocol
	 */
	const ProtocolType HTTPRequest = 0x20;

	/**
	 * HTTP response protocol
	 */
	const ProtocolType HTTPResponse = 0x40;

	/**
	 * HTTP protocol (aggregation bitmask of HTTP request and HTTP response protocols)
	 */
	const ProtocolType HTTP = 0x60;

	/**
	 * ARP protocol
	 */
	const ProtocolType ARP = 0x80;

	/**
	 * VLAN protocol
	 */
	const ProtocolType VLAN = 0x100;

	/**
	 * ICMP protocol
	 */
	const ProtocolType ICMP = 0x200;

	/**
	 * PPPoE session protocol
	 */
	const ProtocolType PPPoESession = 0x400;

	/**
	 * PPPoE discovery protocol
	 */
	const ProtocolType PPPoEDiscovery = 0x800;

	/**
	 * PPPoE protocol (aggregation bitmask of PPPoESession and PPPoEDiscovery protocols)
	 */
	const ProtocolType PPPoE = 0xc00;

	/**
	 * DNS protocol
	 */
	const ProtocolType DNS = 0x1000;

	/**
	 * MPLS protocol
	 */
	const ProtocolType MPLS = 0x2000;

	/**
	 * GRE version 0 protocol
	 */
	const ProtocolType GREv0 = 0x4000;

	/**
	 * GRE version 1 protocol
	 */
	const ProtocolType GREv1 = 0x8000;

	/**
	 * GRE protocol (aggregation bitmask of GREv0 and GREv1 protocols)
	 */
	const ProtocolType GRE = 0xc000;

	/**
	 * PPP for PPTP protocol
	 */
	const ProtocolType PPP_PPTP = 0x10000;

	/**
	 * SSL/TLS protocol
	 */
	const ProtocolType SSL = 0x20000;

	/**
	 * SLL (Linux cooked capture) protocol
	 */
	const ProtocolType SLL = 0x40000;

	/**
	 * DHCP/BOOTP protocol
	 */
	const ProtocolType DHCP = 0x80000;

	/**
	 * Null/Loopback protocol
	 */
	const ProtocolType NULL_LOOPBACK = 0x100000;

	/**
	 * IGMP protocol
	 */
	const ProtocolType IGMP = 0xE00000;

	/**
	 * IGMPv1 protocol
	 */
	const ProtocolType IGMPv1 = 0x200000;

	/**
	 * IGMPv2 protocol
	 */
	const ProtocolType IGMPv2 = 0x400000;

	/**
	 * IGMPv3 protocol
	 */
	const ProtocolType IGMPv3 = 0x800000;

	/**
	 * Generic payload (no specific protocol)
	 */
	const ProtocolType GenericPayload = 0x1000000;

	/**
	 * VXLAN protocol
	 */
	const ProtocolType VXLAN = 0x2000000;

	/**
	 * SIP request protocol
	 */
	const ProtocolType SIPRequest = 0x4000000;

	/**
	 * SIP response protocol
	 */
	const ProtocolType SIPResponse = 0x8000000;

	/**
	 * SIP protocol (aggregation bitmask of SIPRequest and SIPResponse protocols)
	 */
	const ProtocolType SIP = 0xc000000;

	/**
	 * SDP protocol
	 */
	const ProtocolType SDP = 0x10000000;

	/**
	 * Packet trailer
	 */
	const ProtocolType PacketTrailer = 0x20000000;

	/**
	 * RADIUS protocol
	 */
	const ProtocolType Radius = 0x40000000;

	/**
	 * GTPv1 protocol
	 */
	const ProtocolType GTPv1 = 0x80000000;

	/**
	 * GTP protocol (currently the same as GTPv1)
	 */
	const ProtocolType GTP = 0x80000000;

	/**
	 * IEEE 802.3 Ethernet protocol
	 */
	const ProtocolType EthernetDot3 = 0x100000000;

	/**
	 * Border Gateway Protocol (BGP) version 4 protocol
	 */
	const ProtocolType BGP = 0x200000000;

	/**
	 * SSH version 2 protocol
	 */
	const ProtocolType SSH = 0x400000000;

	/**
	 * IPSec Authentication Header (AH) protocol
	 */
	const ProtocolType AuthenticationHeader = 0x800000000;

	/**
	 * IPSec Encapsulating Security Payload (ESP) protocol
	 */
	const ProtocolType ESP = 0x1000000000;

	/**
	 * IPSec protocol (aggregation bitmask of AH and ESP protocols)
	 */
	const ProtocolType IPSec = 0x1800000000;

	/**
	 * Dynamic Host Configuration Protocol version 6 (DHCPv6) protocol
	 */
	const ProtocolType DHCPv6 = 0x2000000000;

	/**
	 * Network Time (NTP) Protocol
	 */
	const ProtocolType NTP = 0x4000000000;

	/**
	 * Telnet Protocol
	 */
	const ProtocolType Telnet = 0x8000000000;

  	/**
   	 * File Transfer (FTP) Protocol
	 */
	const ProtocolType FTP = 0x10000000000;

	/**
	 * ICMPv6 protocol
	 */
	const ProtocolType ICMPv6 = 0x20000000000;

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
