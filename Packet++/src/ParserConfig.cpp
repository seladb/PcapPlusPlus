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
		return mapper;
	}

	void PortMapper::addPortMapping(PortPair port, ProtocolType protocol, bool symmetrical)
	{
		if (port == PortPair())
		{
			throw std::invalid_argument("PortPair cannot be empty (both src and dst ports are 0)");
		}

		auto insertResult = m_PortToProtocolMap.insert({ port, protocol });
		insertResult.first->second = protocol;  // Update the protocol if it already exists
		if (!insertResult.second)
		{
			PCPP_LOG_WARN("Port " << port << " is already mapped to protocol " << insertResult.first->second
			                      << ", updating to " << protocol);
		}

		if (symmetrical && port.portSrc != port.portDst)
		{
			// Add the symmetrical mapping
			PortPair symmetricalPort = { port.portDst, port.portSrc };
			addPortMapping(symmetricalPort, protocol, false);
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

		if (symmetrical && port.portSrc != port.portDst)
		{
			// Remove the symmetrical mapping
			PortPair symmetricalPort = { port.portDst, port.portSrc };
			removePortMapping(symmetricalPort, false);
		}
	}

	ProtocolType PortMapper::getProtocolByPortPair(PortPair port, bool exact) const
	{
		// Order of precedence:
		// 1. Check for exact match of port pair
		// 1.a If exact is true, return the protocol type if found, go to step 4 if not found
		// 2. If not found, check for src port match
		// 3. If not found, check for dst port match
		// 4. If still not found, return UnknownProtocol

		auto it = m_PortToProtocolMap.find(port);
		if (it != m_PortToProtocolMap.end())
		{
			return it->second;
		}

		if (exact)
			return UnknownProtocol;  // Return UnknownProtocol if exact match not found

		// Check for src port match
		it = m_PortToProtocolMap.find(PortPair::fromSrc(port.portSrc));
		if (it != m_PortToProtocolMap.end())
		{
			return it->second;
		}

		// Check for dst port match
		it = m_PortToProtocolMap.find(PortPair::fromDst(port.portDst));
		if (it != m_PortToProtocolMap.end())
		{
			return it->second;
		}

		return UnknownProtocol;  // Return UnknownProtocol if port not found
	}

	ParserConfiguration ParserConfiguration::makeDefaultConfiguration()
	{
		ParserConfiguration config;
		config.portMapper = PortMapper::makeDefaultPortMapper();
		return config;
	}
}