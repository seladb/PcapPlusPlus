#include "ParserConfig.h"

namespace pcpp
{
	PortMapper PortMapper::makeDefaultPortMapper()
	{
		PortMapper mapper;
		// Add HTTP port mappings
		mapper.addPortMapping(PortPair::fromDst(80), HTTPRequest, false);
		mapper.addPortMapping(PortPair::fromSrc(80), HTTPResponse, false);
		mapper.addPortMapping(PortPair::fromDst(8080), HTTPRequest, false);
		mapper.addPortMapping(PortPair::fromSrc(8080), HTTPResponse, false);

		// SSL and TLS port mappings
		mapper.addPortMapping(PortPair::fromDst(443), SSL, true);  // HTTPS
		mapper.addPortMapping(PortPair::fromDst(261), SSL, true);  // NSIIOPS
		mapper.addPortMapping(PortPair::fromDst(448), SSL, true);  // DDM-SSL
		mapper.addPortMapping(PortPair::fromDst(465), SSL, true);  // SMTPS
		mapper.addPortMapping(PortPair::fromDst(563), SSL, true);  // NNTPS
		mapper.addPortMapping(PortPair::fromDst(614), SSL, true);  // SSHELL
		mapper.addPortMapping(PortPair::fromDst(636), SSL, true);  // LDAPS
		mapper.addPortMapping(PortPair::fromDst(989), SSL, true);  // FTPS - data
		mapper.addPortMapping(PortPair::fromDst(990), SSL, true);  // FTPS - control
		mapper.addPortMapping(PortPair::fromDst(992), SSL, true);  // Telnet over TLS/SSL
		mapper.addPortMapping(PortPair::fromDst(993), SSL, true);  // IMAPS
		mapper.addPortMapping(PortPair::fromDst(994), SSL, true);  // IRCS
		mapper.addPortMapping(PortPair::fromDst(995), SSL, true);  // POP3S

		// SIP port mappings
		mapper.addPortMapping(PortPair::fromDst(5060), SIP, true);  // SIP over UDP / TCP
		mapper.addPortMapping(PortPair::fromDst(5061), SIP, true);  // SIP over TLS

		// BGP port mappings
		mapper.addPortMapping(PortPair::fromDst(179), BGP, true);  // BGP over TCP

		// SSH port mappings
		mapper.addPortMapping(PortPair::fromDst(22), SSH, true);  // SSH over TCP

		// DNS port mappings
		mapper.addPortMapping(PortPair::fromDst(53), DNS, true);    // DNS over TCP/UDP
		mapper.addPortMapping(PortPair::fromDst(5353), DNS, true);  // mDNS
		mapper.addPortMapping(PortPair::fromDst(5355), DNS, true);  // LLMNR

		// Telnet port mappings
		mapper.addPortMapping(PortPair::fromDst(23), Telnet, true);  // Telnet over TCP

		// FTP port mappings
		// FTP Control parses to FTPRequest and FTPResponse, but only one FTP protocol type is defined.
		// The specific parsing determined based on if the port is src or dst.
		// A port pairing (21, 21) for example is UB.
		mapper.addPortMapping(PortPair{ 21, 21 }, UnknownProtocol, false);  // Symmetrical connection is UB
		mapper.addPortMapping(PortPair::fromSrc(21), FTP, false);           // FTP control
		mapper.addPortMapping(PortPair::fromDst(21), FTP, false);           // FTP control
		// TODO: FTP data needs a separate ProtocolType
		// mapper.addPortMapping(PortPair::fromDst(20), FTP, false);  // FTP data

		// SomeIP port mappings
		mapper.addPortMapping(PortPair::fromDst(30490), SomeIP, true);  // SomeIP over UDP or TCP

		// Tpkt port mappings
		mapper.addPortMapping(PortPair::fromDst(102), TPKT, true);  // TPKT over TCP

		// Smtp port mappings
		// NOTE: Symmetrical mapping but decodes to SMTPRequest and SMTPResponse
		// A port pairing (25, 25) for example is UB.
		mapper.addPortMapping(PortPair{ 25, 25 }, UnknownProtocol, false);  // Symmetrical connection is UB
		mapper.addPortMapping(PortPair::fromDst(25), SMTP, true);           // SMTP over TCP
		mapper.addPortMapping(PortPair::fromDst(587), SMTP, true);          // SMTP over TCP (submission)

		// LDAP port mappings
		mapper.addPortMapping(PortPair::fromDst(389), LDAP, true);  // LDAP over TCP

		// GTP port mappings
		mapper.addPortMapping(PortPair::fromDst(2152), GTPv1, true);  // GTP-U over UDP

		// Note: GTP v1 and v2 both utilize port (2123) for GTP-C over UDP / TCP.
		//   Parser implementations must determine the version based on the packet content.
		mapper.addPortMapping(PortPair::fromDst(2123), GTP, true);  // GTP-C over UDP / TCP (v2 only)

		// DHCP port mappings
		mapper.addPortMapping(PortPair{ 67, 67 }, DHCP, true);  // DHCP over UDP
		mapper.addPortMapping(PortPair{ 68, 67 }, DHCP, true);  // DHCP over UDP (client to server)

		// DHCPv6 port mappings
		mapper.addPortMapping(PortPair::fromDst(546), DHCPv6, true);  // DHCPv6 over UDP
		mapper.addPortMapping(PortPair::fromDst(547), DHCPv6, true);  // DHCPv6 over UDP

		// VXLAN port mappings
		mapper.addPortMapping(PortPair::fromDst(4789), VXLAN, false);  // VXLAN over UDP

		// Radius port mappings
		mapper.addPortMapping(PortPair::fromDst(1812), Radius, true);  // RADIUS over UDP
		mapper.addPortMapping(PortPair::fromDst(1813), Radius, true);  // RADIUS accounting over UDP
		mapper.addPortMapping(PortPair::fromDst(3799), Radius, true);  // RADIUS over TCP

		// NTP port mappings
		mapper.addPortMapping(PortPair::fromDst(123), NTP, true);  // NTP over UDP

		// Wake-on-LAN port mappings
		mapper.addPortMapping(PortPair::fromDst(9), WakeOnLan, false);  // Wake-on-LAN over UDP
		mapper.addPortMapping(PortPair::fromDst(7), WakeOnLan, false);  // Wake-on-LAN over UDP
		// Would result in Pair (0, 0) which is invalid for the mapper.
		// mapper.addPortMapping(PortPair::fromDst(0), WakeOnLan, false);  // Wake-on-LAN over UDP (broadcast)

		// WireGuard port mappings
		mapper.addPortMapping(PortPair::fromDst(51820), WireGuard, true);  // WireGuard over UDP

		return mapper;
	}

	void PortMapper::addPortMapping(PortPair port, ProtocolTypeFamily protocol, bool symmetrical)
	{
		if (port == PortPair())
		{
			throw std::invalid_argument("PortPair cannot be empty (both src and dst ports are 0)");
		}

		auto insertResult = m_PortToProtocolMap.insert({ port, protocol });
		if (!insertResult.second)
		{
			PCPP_LOG_WARN("Port " << port << " is already mapped to protocol "
			                      << std::to_string(insertResult.first->second) << ", updating to " << protocol);
		}
		insertResult.first->second = protocol;  // Update the protocol if it already exists

		if (symmetrical && (port.hasWildcards() || port.portSrc() != port.portDst()))
		{
			// Add the symmetrical mapping
			addPortMapping(port.withSwappedPorts(), protocol, false);
		}
	}

	void PortMapper::removePortMapping(PortPair port, bool symmetrical)
	{
		auto it = m_PortToProtocolMap.find(port);
		if (it != m_PortToProtocolMap.end())
		{
			m_PortToProtocolMap.erase(it);
		}
		else
		{
			PCPP_LOG_DEBUG("Port " << port << " not found in port mapper, nothing to remove");
		}

		if (symmetrical && (port.hasWildcards() || port.portSrc() != port.portDst()))
		{
			// Remove the symmetrical mapping
			removePortMapping(port.withSwappedPorts(), false);
		}
	}

	ProtocolTypeFamily PortMapper::getProtocolByPortPair(PortPair port) const
	{
		auto it = m_PortToProtocolMap.find(port);
		if (it != m_PortToProtocolMap.end())
		{
			return it->second;
		}

		return UnknownProtocol;  // Return UnknownProtocol if exact match not found
	}

	std::array<ProtocolTypeFamily, 3> PortMapper::getProtocolMappingsMatrixForPortPair(PortPair port) const
	{
		std::array<ProtocolTypeFamily, 3> protocols = { UnknownProtocol, UnknownProtocol, UnknownProtocol };
		// Check for exact match
		auto it = m_PortToProtocolMap.find(port);
		if (it != m_PortToProtocolMap.end())
		{
			protocols[0] = it->second;  // Full match
			return protocols;
		}

		// Check for src port match
		it = m_PortToProtocolMap.find(port.withAnyDst());
		if (it != m_PortToProtocolMap.end())
		{
			protocols[1] = it->second;  // Src port match
		}

		// Check for dst port match
		it = m_PortToProtocolMap.find(port.withAnySrc());
		if (it != m_PortToProtocolMap.end())
		{
			protocols[2] = it->second;  // Dst port match
		}
		return protocols;
	}

	ParserConfiguration ParserConfiguration::makeDefaultConfiguration()
	{
		ParserConfiguration config;
		config.portMapper = PortMapper::makeDefaultPortMapper();
		return config;
	}
}  // namespace pcpp
