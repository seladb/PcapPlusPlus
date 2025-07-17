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

		constexpr bool operator==(const PortPair& other) const noexcept
		{
			return portSrc == other.portSrc && portDst == other.portDst;
		}

		friend std::ostream& operator<<(std::ostream& os, PortPair const pair)
		{
			os << "PortPair(src: " << pair.portSrc << ", dst: " << pair.portDst << ")";
			return os;
		}
	};
}  // namespace pcpp

namespace std
{
	template <> struct hash<pcpp::PortPair>
	{
		size_t operator()(const pcpp::PortPair& portPair) const noexcept
		{
			return std::hash<uint32_t>()(portPair.portDst << 16 | portPair.portSrc);
		}
	};
}  // namespace std

namespace pcpp
{
	class PortMapper
	{
	public:
		/// @brief Create an empty PortMapper.
		PortMapper() = default;

		/// @brief Add a port mapping to the port mapper.
		/// @param port The port number to map.
		/// @param protocol The ProtocolType to associate with the port.
		/// @param symmetrical If true, the mapping is considered symmetrical (both src and dst ports are the
		/// interchangeable).
		void addPortMapping(PortPair port, ProtocolType protocol, bool symmetrical = false);

		/// @brief Remove a port mapping from the port mapper.
		/// @param port The port number to remove from the mapping.
		/// @param symmetrical If true, the mapping is considered symmetrical (both src and dst ports are the
		/// interchangeable).
		void removePortMapping(PortPair port, bool symmetrical = false);

		/// @brief Get the protocol type associated with a specific port.
		///
		/// The method checks for an exact match of the port pair first.
		/// If `exact` is false, it will also check for a match on either the source or destination port.
		///
		/// @param port The port number to look up.
		/// @param exact If true, only an exact match of the port pair is considered. If false, src or dst port matches
		/// @return The ProtocolType associated with the port, or UnknownProtocol if not found.
		ProtocolType getProtocolByPortPair(PortPair port, bool exact = true) const;

		/// @brief Check if a port matches a specific protocol type.
		/// @param port The port number to check.
		/// @param protocol The ProtocolType to match against.
		/// @return True if the port matches the protocol type, false otherwise.
		bool matchesPortAndProtocol(PortPair port, ProtocolType protocol) const
		{
			return getProtocolByPortPair(port) == protocol;
		}

		static PortMapper makeDefaultPortMapper();

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
		static ParserConfiguration makeDefaultConfiguration();

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

		/// @brief Reset the default parser configuration to its initial state.
		static inline void resetDefault()
		{
			getDefault() = makeDefaultConfiguration();
		}
	};
}  // namespace pcpp
