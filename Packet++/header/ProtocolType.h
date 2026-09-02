#pragma once

#include <stdint.h>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @defgroup ProtocolTypes ProtocolType and ProtocolTypeFamily
	/// In the PcapPlusPlus library, specific protocols are identified by a `ProtocolType` value, which is an 8-bit
	/// unsigned integer. Each Layer class has a ProtocolType that can be used to identify the protocol of that layer.
	///
	/// As there are some situations where multiple protocols can be grouped together (e.g. IPv4 and IPv6 into IP),
	/// PcapPlusPlus also defines ProtocolTypeFamily, which is a group of multiple protocol types. In functions where a
	/// ProtocolTypeFamily parameter is expected, a single ProtocolType value can be passed instead. The library will
	/// treat it as a family containing only that single protocol.
	///
	/// @internal
	///
	/// A ProtocolTypeFamily pack is represented as a 32-bit unsigned integer. Each octet in the 32-bit value is a
	/// ProtocolType, allowing for up to 4 protocols to be packed into a single ProtocolTypeFamily value. For example,
	/// the ProtocolTypeFamily for IP is represented as 0x203, which contains both IPv4 (0x02) and IPv6 (0x03)
	/// protocols. A single ProtocolType casted to ProtocolTypeFamily will result the value '0x000000xx' where 'xx' is
	/// the value of the ProtocolType.
	///
	/// @endinternal

	/// @addtogroup ProtocolTypes
	/// @{

	/// @typedef ProtocolType
	/// Representing all protocols supported by PcapPlusPlus
	using ProtocolType = uint8_t;

	/// @typedef ProtocolTypeFamily
	/// Representing a family of protocols
	using ProtocolTypeFamily = uint32_t;

	/// Unknown protocol (or unsupported by PcapPlusPlus)
	const ProtocolType UnknownProtocol = 0;

	/// Ethernet protocol
	const ProtocolType Ethernet = 1;

	/// IPv4 protocol
	const ProtocolType IPv4 = 2;

	/// IPv6 protocol
	const ProtocolType IPv6 = 3;

	/// IP protocol family (IPv4 and IPv6 protocols)
	const ProtocolTypeFamily IP = 0x203;

	/// TCP protocol
	const ProtocolType TCP = 4;

	/// UDP protocol
	const ProtocolType UDP = 5;

	/// HTTP request protocol
	const ProtocolType HTTPRequest = 6;

	/// HTTP response protocol
	const ProtocolType HTTPResponse = 7;

	/// HTTP protocol family (HTTP request and HTTP response protocols)
	const ProtocolTypeFamily HTTP = 0x607;

	/// ARP protocol
	const ProtocolType ARP = 8;

	/// VLAN protocol
	const ProtocolType VLAN = 9;

	/// ICMP protocol
	const ProtocolType ICMP = 10;

	/// PPPoE session protocol
	const ProtocolType PPPoESession = 11;

	/// PPPoE discovery protocol
	const ProtocolType PPPoEDiscovery = 12;

	/// PPPoE protocol family (PPPoESession and PPPoEDiscovery protocols)
	const ProtocolTypeFamily PPPoE = 0xb0c;

	/// DNS protocol
	const ProtocolType DNS = 13;

	/// MPLS protocol
	const ProtocolType MPLS = 14;

	/// GRE version 0 protocol
	const ProtocolType GREv0 = 15;

	/// GRE version 1 protocol
	const ProtocolType GREv1 = 16;

	/// GRE protocol family (GREv0 and GREv1 protocols)
	const ProtocolTypeFamily GRE = 0xf10;

	/// PPP for PPTP protocol
	const ProtocolType PPP_PPTP = 17;

	/// SSL/TLS protocol
	const ProtocolType SSL = 18;

	/// SLL (Linux cooked capture) protocol
	const ProtocolType SLL = 19;

	/// DHCP/BOOTP protocol
	const ProtocolType DHCP = 20;

	/// Null/Loopback protocol
	const ProtocolType NULL_LOOPBACK = 21;

	/// IGMPv1 protocol
	const ProtocolType IGMPv1 = 22;

	/// IGMPv2 protocol
	const ProtocolType IGMPv2 = 23;

	/// IGMPv3 protocol
	const ProtocolType IGMPv3 = 24;

	/// IGMP protocol family (IGMPv1, IGMPv2, IGMPv3)
	const ProtocolTypeFamily IGMP = 0x161718;

	/// Generic payload (no specific protocol)
	const ProtocolType GenericPayload = 25;

	/// VXLAN protocol
	const ProtocolType VXLAN = 26;

	/// SIP request protocol
	const ProtocolType SIPRequest = 27;

	/// SIP response protocol
	const ProtocolType SIPResponse = 28;

	/// SIP protocol family (SIPRequest and SIPResponse protocols)
	const ProtocolTypeFamily SIP = 0x1b1c;

	/// SDP protocol
	const ProtocolType SDP = 29;

	/// Packet trailer
	const ProtocolType PacketTrailer = 30;

	/// RADIUS protocol
	const ProtocolType Radius = 31;

	/// GTPv1 protocol
	const ProtocolType GTPv1 = 32;

	/// GTP protocol family (GTPv1 and GTPv2)
	const ProtocolTypeFamily GTP = 0x2039;

	/// IEEE 802.3 Ethernet protocol
	const ProtocolType EthernetDot3 = 33;

	/// Border Gateway Protocol (BGP) version 4 protocol
	const ProtocolType BGP = 34;

	/// SSH version 2 protocol
	const ProtocolType SSH = 35;

	/// IPSec Authentication Header (AH) protocol
	const ProtocolType AuthenticationHeader = 36;

	/// IPSec Encapsulating Security Payload (ESP) protocol
	const ProtocolType ESP = 37;

	/// IPSec protocol family (AH and ESP protocols)
	const ProtocolTypeFamily IPSec = 0x2425;

	/// Dynamic Host Configuration Protocol version 6 (DHCPv6) protocol
	const ProtocolType DHCPv6 = 38;

	/// Network Time (NTP) Protocol
	const ProtocolType NTP = 39;

	/// Telnet Protocol
	const ProtocolType Telnet = 40;

	/// File Transfer (FTP) Protocol - Control channel
	const ProtocolType FTPControl = 41;

	/// ICMPv6 protocol
	const ProtocolType ICMPv6 = 42;

	/// Spanning Tree Protocol
	const ProtocolType STP = 43;

	/// Logical Link Control (LLC)
	const ProtocolType LLC = 44;

	/// SOME/IP Base protocol
	const ProtocolType SomeIP = 45;

	/// Wake On LAN (WOL) Protocol
	const ProtocolType WakeOnLan = 46;

	/// NFLOG (Linux Netfilter NFLOG) Protocol
	const ProtocolType NFLOG = 47;

	/// TPKT protocol
	const ProtocolType TPKT = 48;

	/// VRRP version 2 protocol
	const ProtocolType VRRPv2 = 49;

	/// VRRP version 3 protocol
	const ProtocolType VRRPv3 = 50;

	/// VRRP protocol family (VRRPv2 and VRRPv3 protocols)
	const ProtocolTypeFamily VRRP = 0x3132;

	/// COTP protocol
	const ProtocolType COTP = 51;

	/// SLL2 protocol
	const ProtocolType SLL2 = 52;

	/// S7COMM protocol
	const ProtocolType S7COMM = 53;

	/// SMTP protocol
	const ProtocolType SMTP = 54;

	/// LDAP protocol
	const ProtocolType LDAP = 55;

	/// WireGuard protocol
	const ProtocolType WireGuard = 56;

	/// GTPv2 protocol
	const ProtocolType GTPv2 = 57;

	/// Cisco HDLC protocol
	const ProtocolType CiscoHDLC = 58;

	/// Diagnostic over IP protocol (DOIP)
	const ProtocolType DOIP = 59;

	/// File Transfer Protocol (FTP) Data channel
	const ProtocolType FTPData = 60;

	/// Modbus protocol
	const ProtocolType Modbus = 61;

	/// PostgreSQL protocol
	const ProtocolType Postgres = 62;

	/// MySQL protocol
	const ProtocolType MySQL = 63;

	/// FTP protocol family (FTPControl and FtpData protocols)
	const ProtocolTypeFamily FTP = 0x3c29;

	/// @}

	inline const char* protocolTypeToString(ProtocolType protocolType)
	{
	    switch (protocolType)
	    {
	        case UnknownProtocol:       return "UnknownProtocol";
	        case Ethernet:              return "Ethernet";
	        case IPv4:                  return "IPv4";
	        case IPv6:                  return "IPv6";
	        case TCP:                   return "TCP";
	        case UDP:                   return "UDP";
	        case HTTPRequest:            return "HTTPRequest";
	        case HTTPResponse:           return "HTTPResponse";
	        case ARP:                   return "ARP";
	        case VLAN:                  return "VLAN";
	        case ICMP:                  return "ICMP";
	        case PPPoESession:          return "PPPoESession";
	        case PPPoEDiscovery:        return "PPPoEDiscovery";
	        case DNS:                   return "DNS";
	        case MPLS:                  return "MPLS";
	        case GREv0:                 return "GREv0";
	        case GREv1:                 return "GREv1";
	        case PPP_PPTP:              return "PPP_PPTP";
	        case SSL:                   return "SSL";
	        case SLL:                   return "SLL";
	        case DHCP:                  return "DHCP";
	        case NULL_LOOPBACK:         return "NULL_LOOPBACK";
	        case IGMPv1:                return "IGMPv1";
	        case IGMPv2:                return "IGMPv2";
	        case IGMPv3:                return "IGMPv3";
	        case GenericPayload:        return "GenericPayload";
	        case VXLAN:                 return "VXLAN";
	        case SIPRequest:            return "SIPRequest";
	        case SIPResponse:           return "SIPResponse";
	        case SDP:                   return "SDP";
	        case PacketTrailer:         return "PacketTrailer";
	        case Radius:                return "Radius";
	        case GTPv1:                 return "GTPv1";
	        case EthernetDot3:          return "EthernetDot3";
	        case BGP:                   return "BGP";
	        case SSH:                   return "SSH";
	        case AuthenticationHeader:  return "AuthenticationHeader";
	        case ESP:                   return "ESP";
	        case DHCPv6:                return "DHCPv6";
	        case NTP:                   return "NTP";
	        case Telnet:                return "Telnet";
	        case FTPControl:            return "FTPControl";
	        case ICMPv6:                return "ICMPv6";
	        case STP:                   return "STP";
	        case LLC:                   return "LLC";
	        case SomeIP:                return "SomeIP";
	        case WakeOnLan:             return "WakeOnLan";
	        case NFLOG:                 return "NFLOG";
	        case TPKT:                  return "TPKT";
	        case VRRPv2:                return "VRRPv2";
	        case VRRPv3:                return "VRRPv3";
	        case COTP:                  return "COTP";
	        case SLL2:                 return "SLL2";
	        case S7COMM:               return "S7COMM";
	        case SMTP:                 return "SMTP";
	        case LDAP:                 return "LDAP";
	        case WireGuard:            return "WireGuard";
	        case GTPv2:                return "GTPv2";
	        case CiscoHDLC:            return "CiscoHDLC";
	        case DOIP:                 return "DOIP";
	        case FTPData:              return "FTPData";
	        case Modbus:               return "Modbus";
	        case Postgres:             return "Postgres";
	        case MySQL:                return "MySQL";
	        default:                   return "Unknown";
	    }
	}

	/// An enum representing OSI model layers
	enum OsiModelLayer
	{
		/// Physical layer (layer 1)
		OsiModelPhysicalLayer = 1,
		/// Data link layer (layer 2)
		OsiModelDataLinkLayer = 2,
		/// Network layer (layer 3)
		OsiModelNetworkLayer = 3,
		/// Transport layer (layer 4)
		OsiModelTransportLayer = 4,
		/// Session layer (layer 5)
		OsiModelSesionLayer = 5,
		/// Presentation layer (layer 6)
		OsiModelPresentationLayer = 6,
		/// Application layer (layer 7)
		OsiModelApplicationLayer = 7,
		/// Unknown / null layer
		OsiModelLayerUnknown = 8
	};

	namespace internal
	{
		/// @brief Check if a protocol family contains a specific protocol
		/// @param family A protocol type family value.
		/// @param protocol A protocol type value to check against the family.
		/// @return True if the protocol is part of the family, false otherwise.
		/// @ingroup ProtocolTypes
		constexpr bool protoFamilyContainsProtocol(ProtocolTypeFamily family, ProtocolType protocol)
		{
			auto const protocolToFamily = static_cast<ProtocolTypeFamily>(protocol);
			return (protocolToFamily == (family & 0xff) || protocolToFamily << 8 == (family & 0xff00) ||
			        protocolToFamily << 16 == (family & 0xff0000) || protocolToFamily << 24 == (family & 0xff000000));
		}
	}  // namespace internal
}  // namespace pcpp
