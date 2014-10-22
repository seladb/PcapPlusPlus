#ifndef PCAPPP_PROTOCOL_TYPES
#define PCAPPP_PROTOCOL_TYPES

enum ProtocolType
{
	Unknown = 0x00,
	Ethernet = 0x01,
	IPv4 = 0x02,
	IPv6 = 0x04,
	IP = 0x06,
	TCP = 0x08,
	UDP = 0x10,
	HTTPRequest = 0x20,
	HTTPResponse = 0x40,
	HTTP = 0x20 & 0x40,
	ARP = 0x80,
	VLAN = 0x100,
	ICMP = 0x200
};

#endif
