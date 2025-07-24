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
	/// @brief Represents a pair of ports, typically used for network protocol matching.
	class PortPair
	{
	public:
		/// @brief Represents a value that indicates any port can be matched.
		static constexpr struct AnyPortWildcard
		{
		} AnyPort = {};

		constexpr PortPair() = default;

		constexpr PortPair(uint16_t portSrc, uint16_t portDst)
		    : m_PortSrc(portSrc), m_PortDst(portDst), m_PortSrcSet(true), m_PortDstSet(true)
		{}

		constexpr PortPair(uint16_t portSrc, AnyPortWildcard)
		    : m_PortSrc(portSrc), m_PortDst(0), m_PortSrcSet(true), m_PortDstSet(false)
		{}

		constexpr PortPair(AnyPortWildcard, uint16_t portDst)
		    : m_PortSrc(0), m_PortDst(portDst), m_PortSrcSet(false), m_PortDstSet(true)
		{}

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

		/// @brief Returns a PortPair with the source port replaced by AnyPort wildcard.
		/// @return A new PortPair with the source port set to AnyPort.
		constexpr PortPair withAnySrc() const
		{
			return fromDst(m_PortDst);
		}

		/// @brief Returns a PortPair with the destination port replaced by AnyPort wildcard.
		/// @return A new PortPair with the destination port set to AnyPort.
		constexpr PortPair withAnyDst() const
		{
			return fromSrc(m_PortSrc);
		}

		/// @brief Returns a PortPair with the source and destination ports reversed.
		/// @return A new PortPair with the source and destination ports swapped.
		constexpr PortPair withSwappedPorts() const noexcept
		{
			PortPair reversed;
			reversed.m_PortSrc = m_PortDst;
			reversed.m_PortSrcSet = m_PortDstSet;
			reversed.m_PortDst = m_PortSrc;
			reversed.m_PortDstSet = m_PortSrcSet;
			return reversed;
		}

		constexpr bool isSrcPortSet() const noexcept
		{
			return m_PortSrcSet;
		}

		constexpr bool isDstPortSet() const noexcept
		{
			return m_PortDstSet;
		}

		constexpr bool hasWildcards() const noexcept
		{
			return !(isSrcPortSet() && isDstPortSet());
		}

		constexpr uint16_t portSrc() const noexcept
		{
			return m_PortSrc;
		}

		constexpr uint16_t portDst() const noexcept
		{
			return m_PortDst;
		}

		constexpr void setSrcPort(uint16_t portSrc) noexcept
		{
			m_PortSrc = portSrc;
			m_PortSrcSet = true;
		}

		constexpr void setSrcPort(AnyPortWildcard) noexcept
		{
			m_PortSrc = 0;
			m_PortSrcSet = false;
		}

		constexpr void setDstPort(uint16_t portDst) noexcept
		{
			m_PortDst = portDst;
			m_PortDstSet = true;
		}

		constexpr void setDstPort(AnyPortWildcard) noexcept
		{
			m_PortDst = 0;
			m_PortDstSet = false;
		}

		constexpr bool operator==(const PortPair& other) const noexcept
		{
			return comparePort(m_PortSrc, other.m_PortSrc, m_PortSrcSet, other.m_PortSrcSet) &&
			       comparePort(m_PortDst, other.m_PortDst, m_PortDstSet, other.m_PortDstSet);
		}

		constexpr bool operator!=(const PortPair& other) const noexcept
		{
			return !(*this == other);
		}

		friend std::ostream& operator<<(std::ostream& os, PortPair const pair)
		{
			os << "PortPair(src: ";
			if (pair.m_PortSrcSet)
			{
				os << pair.m_PortSrc;
			}
			else
			{
				os << "AnyPort";
			}

			os << ", dst: ";
			if (pair.m_PortDstSet)
			{
				os << pair.m_PortDst;
			}
			else
			{
				os << "AnyPort";
			}
			os << ')';
			return os;
		}

	private:
		constexpr static bool comparePort(uint16_t port1, uint16_t port2, bool isSet1, bool isSet2) noexcept
		{
			// If both ports are set, compare them directly
			// If one of the ports is not set, return false.
			// If both ports are not set, return true.

			if (isSet1 && isSet2)
			{
				return port1 == port2;
			}
			return !isSet1 && !isSet2;  // Both ports are wildcard
		}

		uint16_t m_PortSrc = 0;     ///< Source port number
		uint16_t m_PortDst = 0;     ///< Destination port number
		bool m_PortSrcSet = false;  ///< Indicates if the src port is set, on false consider the port as wildcard
		bool m_PortDstSet = false;  ///< Indicates if the dst port is set, on false consider the port as wildcard
	};

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
		/// @param port The port number to look up.
		/// @return The ProtocolTypeFamily associated with the port, or UnknownProtocol if not found.
		ProtocolTypeFamily getProtocolByPortPair(PortPair port) const;

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
		/// @param protocolFamily The ProtocolTypeFamily to match against.
		/// @return True if the port matches the protocol type, false otherwise.
		bool matchesPortAndProtocol(PortPair port, ProtocolTypeFamily protocolFamily) const
		{
			return getProtocolByPortPair(port) == protocolFamily;
		}

		/// @brief Creates a default PortMapper with common port mappings.
		/// @return A PortMapper instance with default port mappings.
		static PortMapper makeDefaultPortMapper();

	private:
		struct PackedPortPairHasher
		{
			std::size_t operator()(const PortPair& portPair) const noexcept
			{
				return static_cast<std::size_t>(splitMix64(encodePair(portPair)));
			}

			constexpr uint64_t encodePair(const PortPair& portPair) const noexcept
			{
				// Encodes the port pair as a uint64_t
				// 30 bits unused, 2 bits wildcard flags, 16 bits for src port, 16 bits for dst port,
				uint64_t srcPort = portPair.portSrc();
				uint64_t dstPort = static_cast<uint64_t>(portPair.portDst()) << 16;
				uint64_t srcPortSet = static_cast<uint64_t>(portPair.isSrcPortSet() ? 1 : 0) << 32;
				uint64_t dstPortSet = static_cast<uint64_t>(portPair.isDstPortSet() ? 1 : 0) << 33;

				return srcPort | dstPort | srcPortSet | dstPortSet;
			}

			constexpr uint64_t splitMix64(uint64_t key) const noexcept
			{
				uint64_t z = key + 0x9E3779B97F4A7C15ULL;
				z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
				z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
				return z ^ (z >> 31);
			}
		};

		// todo: profile lookup performance.
		std::unordered_map<PortPair, ProtocolTypeFamily, PackedPortPairHasher> m_PortToProtocolMap;
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
