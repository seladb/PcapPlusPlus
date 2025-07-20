#pragma once

#include <array>
#include <memory>
#include <vector>
#include <stdexcept>
#include <unordered_map>

#include "Logger.h"
#include "ProtocolType.h"

namespace pcpp
{
	/// @brief A structure representing a pair of ports.
	struct PortPair
	{
		/// @brief Represents a value that indicates any port can be matched.
		static constexpr uint16_t AnyPort = 0;

		uint16_t portSrc = AnyPort;  ///< Source port number
		uint16_t portDst = AnyPort;  ///< Destination port number

		/// @brief Constructs a PortPair with the specified source port and destination port set to AnyPort.
		/// @param portSrc Source port number.
		/// @return A PortPair with the specified source port and destination port set to AnyPort.
		constexpr static PortPair fromSrc(uint16_t portSrc)
		{
			return { portSrc, AnyPort };
		}

		/// @brief Constructs a PortPair with the specified destination port and source port set to AnyPort.
		/// @param portDst Destination port number.
		/// @return A PortPair with the specified destination port and source port set to AnyPort.
		constexpr static PortPair fromDst(uint16_t portDst)
		{
			return { AnyPort, portDst };
		}

		constexpr PortPair onlyDest() const
		{
			return fromDst(portDst);
		}

		constexpr PortPair onlySrc() const
		{
			return fromSrc(portSrc);
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
	/// @brief Specialization of std::hash for PortPair.
	template <> struct hash<pcpp::PortPair>
	{
		size_t operator()(const pcpp::PortPair& portPair) const noexcept
		{
			return std::hash<uint32_t>()(static_cast<uint32_t>(portPair.portDst) << 16 | portPair.portSrc);
		}
	};
}  // namespace std

namespace pcpp
{
	/// @brief A class that maps port pairs to protocol types.
	class PortMapper
	{
	public:
		/// @brief Create an empty PortMapper.
		PortMapper() = default;

		/// @brief Add a port mapping to the port mapper.
		/// @param port The port number to map.
		/// @param protocolFamily The ProtocolTypeFamily to associate with the port.
		/// @param symmetrical If true, the mapping is considered symmetrical (both src and dst ports are the
		/// interchangeable).
		void addPortMapping(PortPair port, ProtocolTypeFamily protocolFamily, bool symmetrical = false);

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
		/// @return The ProtocolTypeFamily associated with the port, or UnknownProtocol if not found.
		ProtocolTypeFamily getProtocolByPortPair(PortPair port, bool exact = true) const;

		/// @brief Get the protocol mappings that correspond to a specific port pair.
		///
		/// The method returns an array of ProtocolType values associated with the port pair.
		///
		/// The elements in the array represent the following mappings:
		///             Src Port  |   Dst Port  |  Match Type
		/// - Index 0:  Original  |   Original  |  Full Match
		/// - Index 1:  Original  |   Any Port  |  Src Port Match
		/// - Index 2:  Any Port  |   Original  |  Dst Port Match
		///
		/// If the comparison
		///
		/// If a port pair is not found, the corresponding index in the array will contain UnknownProtocol.
		/// If a port pair is not mapped to any protocol, the array will contain UnknownProtocol in all indices.
		///
		/// @param port The port pair to look up.
		/// @return An array of ProtocolTypeFamily values representing the protocols associated with the port pair.
		std::array<ProtocolTypeFamily, 3> getProtocolMappingsMatrixForPortPair(PortPair port) const;

		/// @brief Get the protocol mappings that correspond to a specific port pair.
		/// 
		/// See `getProtocolMappingsMatrixForPortPair(PortPair port)` for details.
		/// 
		/// @param portSrc The source port number.
		/// @param portDst The destination port number.
		/// @return An array of ProtocolTypeFamily values representing the protocols associated with the port pair.
		std::array<ProtocolTypeFamily, 3> getProtocolMappingsMatrixForPortPair(uint16_t portSrc, uint16_t portDst) const
		{
			return getProtocolMappingsMatrixForPortPair({ portSrc, portDst });
		}

		/// @brief Check if a port matches a specific protocol type.
		/// @param port The port number to check.
		/// @param protocol The ProtocolTypeFamily to match against.
		/// @return True if the port matches the protocol type, false otherwise.
		bool matchesPortAndProtocol(PortPair port, ProtocolTypeFamily protocolFamily) const
		{
			return getProtocolByPortPair(port) == protocolFamily;
		}

		/// @brief Creates a default PortMapper with common port mappings.
		/// @return A PortMapper instance with default port mappings.
		static PortMapper makeDefaultPortMapper();

	private:
		std::unordered_map<PortPair, ProtocolTypeFamily> m_PortToProtocolMap;
	};

	/// @brief A parser configuration that can be used to configure the behavior of the packet parser.
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
