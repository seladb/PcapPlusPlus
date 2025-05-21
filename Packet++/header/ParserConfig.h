#pragma once

#include <memory>
#include <vector>
#include <unordered_map>

#include "ProtocolType.h"

namespace pcpp
{
	class PortRule
	{
	public:
		virtual ~PortRule() = default;

		/// @brief Check if the port rule matches a specific source or destination port
		/// @param srcPort The source port to check
		/// @return True if the port rule matches the source port, false otherwise
		virtual bool matchesSrcPort(uint16_t srcPort) const = 0;

		/// @brief Check if the port rule matches a specific destination port
		/// @param dstPort The destination port to check
		/// @return True if the port rule matches the destination port, false otherwise
		virtual bool matchesDstPort(uint16_t dstPort) const = 0;

		/// @brief Check if the port rule matches a specific combination of source and destination ports
		/// @param srcPort The source port to check
		/// @param dstPort The destination port to check
		/// @return True if the port rule matches the combination of source and destination ports, false otherwise
		virtual bool matches(uint16_t srcPort, uint16_t dstPort) const = 0;
	};

	// TODO: Better Name?
	class SinglePortRule : public PortRule
	{
	public:
		SinglePortRule(uint16_t port) : port(port)
		{}

		bool matchesSrcPort(uint16_t srcPort) const override
		{
			return srcPort == port;
		}
		bool matchesDstPort(uint16_t dstPort) const override
		{
			return dstPort == port;
		}
		bool matches(uint16_t srcPort, uint16_t dstPort) const override
		{
			return matchesSrcPort(srcPort) || matchesDstPort(dstPort);
		}

		uint16_t port;
	};

	class PortMapper
	{
	public:
		PortMapper() = default;

		/// @brief Add or replace a port rule for a specific protocol
		/// @param protocol The protocol type to associate with the port rule
		/// @param portRule The port rule to associate with the protocol
		void addPortRule(ProtocolType protocol, std::unique_ptr<PortRule> portRule)
		{
			m_ProtocolToPortRuleMap[protocol] = std::move(portRule);
		}

		/// @brief Remove the port rule for a specific protocol
		/// @param protocol The protocol type to remove the port rule for
		void removePortRule(ProtocolType protocol)
		{
			m_ProtocolToPortRuleMap.erase(protocol);
		}

		/// @brief Get the port rule for a specific protocol
		/// @param protocol The protocol type to get the port rule for
		/// @return A pointer to the port rule associated with the protocol, or nullptr if not found
		const PortRule* getPortRule(ProtocolType protocol) const
		{
			auto it = m_ProtocolToPortRuleMap.find(protocol);
			return it != m_ProtocolToPortRuleMap.end() ? it->second.get() : nullptr;
		}

	private:
		std::unordered_map<ProtocolType, std::unique_ptr<PortRule>> m_ProtocolToPortRuleMap;
	};

	struct ParserConfiguration
	{
		ParserConfiguration() = default;

		PortMapper portMapper;
	};
}  // namespace pcpp