#pragma once

#include <memory>
#include <vector>
#include <stdexcept>
#include <unordered_map>

#include "Logger.h"
#include "ProtocolType.h"

namespace pcpp
{
	struct PortPair
	{
		static constexpr uint16_t AnyPort = 0;

		uint16_t portSrc = AnyPort;  ///< Source port number
		uint16_t portDst = AnyPort;  ///< Destination port number

		constexpr static PortPair fromSrc(uint16_t portSrc)
		{
			return { portSrc, AnyPort };
		}

		constexpr static PortPair fromDst(uint16_t portDst)
		{
			return { AnyPort, portDst };
		}
	};

	class PortMapper
	{
	public:
		/// @brief Create an empty PortMapper.
		PortMapper() = default;
		/// @brief Create a PortMapper with a predefined mapping of ports to protocol types.
		/// @param portToProtocolMap An unordered map where keys are port numbers and values are ProtocolType values.
		PortMapper(std::unordered_map<PortPair, ProtocolType> portToProtocolMap)
		    : m_PortToProtocolMap(std::move(portToProtocolMap))
		{}

		/// @brief Add a port mapping to the port mapper.
		/// @param port The port number to map.
		/// @param protocol The ProtocolType to associate with the port.
		/// @param symmetrical If true, the mapping is considered symmetrical (both src and dst ports are the same).
		void addPortMapping(PortPair port, ProtocolType protocol, bool symmetrical = false)
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

		/// @brief Remove a port mapping from the port mapper.
		/// @param port The port number to remove from the mapping.
		void removePortMapping(PortPair port)
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
		}

		/// @brief Get the protocol type associated with a specific port.
		/// 
		/// The method checks for an exact match of the port pair first.
		/// If `exact` is false, it will also check for a match on either the source or destination port.
		/// 
		/// @param port The port number to look up.
		/// @param exact If true, only an exact match of the port pair is considered. If false, src or dst port matches
		/// @return The ProtocolType associated with the port, or UnknownProtocol if not found.
		ProtocolType getProtocolByPortPair(PortPair port, bool exact = true) const
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

		/// @brief Check if a port matches a specific protocol type.
		/// @param port The port number to check.
		/// @param protocol The ProtocolType to match against.
		/// @return True if the port matches the protocol type, false otherwise.
		bool matchesPortAndProtocol(PortPair port, ProtocolType protocol) const
		{
			return getProtocolByPortPair(port) == protocol;
		}

		static PortMapper makeDefaultPortMapper()
		{
			PortMapper mapper;
			// Add HTTP port mappings
			mapper.addPortMapping(PortPair::fromDst(80), HTTPRequest, false);
			mapper.addPortMapping(PortPair::fromSrc(80), HTTPResponse, false);
			mapper.addPortMapping(PortPair::fromDst(8080), HTTPRequest, false);
			mapper.addPortMapping(PortPair::fromSrc(8080), HTTPResponse, false);
			return mapper;
		}

	private:
		std::unordered_map<PortPair, ProtocolType> m_PortToProtocolMap;
	};

	struct ParserConfiguration
	{
		ParserConfiguration() = default;

		PortMapper portMapper;

		/// @brief Creates a new instance of ParserConfiguration with default settings.
		/// 
		/// Prefer using `getDefault()` to obtain the default configuration if a new instance is not required.
		/// 
		/// @return A ParserConfiguration instance with default port mappings.
		static ParserConfiguration makeDefaultConfiguration()
		{
			ParserConfiguration config;
			config.portMapper = PortMapper::makeDefaultPortMapper();
			return config;
		}

		/// @brief Get the default parser configuration.
		/// 
		/// The returned reference can be used to configure the parser globally.
		/// 
		/// @return A reference to the default ParserConfiguration instance.
		static inline ParserConfiguration& getDefault()
		{
			static ParserConfiguration defaultConfig = makeDefaultConfiguration();
			return defaultConfig;
		}
	};
}  // namespace pcpp