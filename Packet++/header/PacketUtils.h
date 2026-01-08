#pragma once

#include "Packet.h"
#include "IpAddress.h"
#include "IPv4Layer.h"
#include <type_traits>
#include <utility>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// A struct that represent a single buffer
	template <typename T> struct ScalarBuffer
	{
		/// The pointer to the buffer
		T* buffer;

		/// Buffer length
		size_t len;
	};

	/// Computes the checksum for a vector of buffers
	/// @param[in] vec The vector of buffers
	/// @param[in] vecSize Number of ScalarBuffers in vector
	/// @return The checksum result
	uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize);

	/// Computes the checksum for Pseudo header
	/// @param[in] dataPtr Data pointer
	/// @param[in] dataLen Data length
	/// @param[in] ipAddrType IP address type(IPv4/IPv6) type @ref IPAddress::AddressType
	/// @param[in] protocolType Current protocol type @ref IPProtocolTypes
	/// @param[in] srcIPAddress Source IP Address
	/// @param[in] dstIPAddress Destination IP Address
	/// @return The checksum result
	uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen, IPAddress::AddressType ipAddrType,
	                                  uint8_t protocolType, IPAddress srcIPAddress, IPAddress dstIPAddress);

	/// Computes Fowler-Noll-Vo (FNV-1) 32/64 bit hash function on an array of byte buffers. The hash is calculated on
	/// each byte in each byte buffer, as if all byte buffers were one long byte buffer
	/// @param[in] vec An array of byte buffers (ScalarBuffer of type uint8_t)
	/// @param[in] vecSize The length of vec
	/// @return The 32/64 bit hash value
	template <typename T = uint32_t> T fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize);

	/// Computes Fowler-Noll-Vo (FNV-1) 32/64 bit hash function on a byte buffer
	/// @param[in] buffer The byte buffer
	/// @param[in] bufSize The size of the byte buffer
	/// @return The 32/64 bit hash value
	template <typename T = uint32_t> T fnvHash(uint8_t* buffer, size_t bufSize);

	/// An interface that abstracts information about a TCP/UDP connection.
	/// Used by @ref ConnectionHashable.
	struct IHashableConnectionInfo
	{
		virtual ~IHashableConnectionInfo() = default;
		/// @return Determine whether the object contains an IP version 4 address
		virtual bool isIPv4() const = 0;
		/// @return Determine whether the object contains an IP version 6 address
		virtual bool isIPv6() const = 0;
		/// Returns a view of the IPv4/IPv6 address of the sender/client of a packet/connection
		/// as a 4/16-byte raw C-style array.
		/// @return A non-owning pointer to 4/16-byte array representing the IPv4/IPv6 address
		virtual const uint8_t* ipSrc() const = 0;
		/// Returns a view of the IPv4/IPv6 address of the receiver/server of a packet/connection
		/// as a 4/16-byte raw C-style array.
		/// @return A non-owning pointer to 4/16-byte array representing the IPv4/IPv6 address
		virtual const uint8_t* ipDst() const = 0;
		/// @return OSI layer 4 protocol type @ref IPProtocolTypes
		virtual IPProtocolTypes ipProtocol() const = 0;
		/// @return Source/client TCP/UDP port
		virtual uint16_t portSrc() const = 0;
		/// @return Destination/server TCP/UDP port
		virtual uint16_t portDst() const = 0;
		/// Estimates the equality of two IHashableConnectionInfo objects
		/// @param[in] other The object to compare with
		/// @param[in] ignoreDirection Also check for the equality with the object whose source and destination swapped
		/// @return True if the objects are equal, false otherwise
		bool equals(IHashableConnectionInfo const& other, bool ignoreDirection) const;
	};

	class IPv6Layer;

	/// @ref IHashableConnectionInfo adapter for a @ref Packet
	struct PacketHashable : public IHashableConnectionInfo
	{
		/// A constructor that creates an instance of the class out of a Packet*.
		PacketHashable(Packet const* packet);
		PacketHashable(PacketHashable const&) = default;
		PacketHashable& operator=(PacketHashable const&) = default;
		PacketHashable(PacketHashable&&) noexcept = default;
		PacketHashable& operator=(PacketHashable&&) noexcept = default;
		// IHashableConnectionInfo interface implementation
		~PacketHashable() override = default;
		bool isIPv4() const override;
		bool isIPv6() const override;
		const uint8_t* ipSrc() const override;
		const uint8_t* ipDst() const override;
		IPProtocolTypes ipProtocol() const override;
		uint16_t portSrc() const override;
		uint16_t portDst() const override;

	private:
		IPv4Layer const* m_ipv4Layer{};
		IPv6Layer const* m_ipv6Layer{};
		uint16_t m_portSrc{};
		uint16_t m_portDst{};
	};

	/// A method that is given a packet and calculates a hash value by the packet's 5-tuple. Supports IPv4, IPv6,
	/// TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't
	/// TCP/UDP) the value of 0 will be returned
	/// @param[in] packet The packet to calculate hash for
	/// @param[in] directionUnique Make hash value unique for each direction
	/// @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	template <typename T = uint32_t> T hash5Tuple(Packet* packet, bool const& directionUnique = false);

	/// A method that is given an IHashableConnectionInfo object and calculates a hash value by the object's 5-tuple.
	/// Supports IPv4, IPv6, TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't
	/// IPv4/6 or aren't TCP/UDP) the value of 0 will be returned.
	/// @param[in] target The IHashableConnectionInfo object to calculate hash for
	/// @param[in] directionUnique Make hash value unique for each direction
	/// @return The hash value calculated for this target or 0 if the target doesn't contain 5-tuple
	template <typename T> T hash5Tuple(const IHashableConnectionInfo& target, bool const& directionUnique = false);

	/// A method that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst). Supports
	/// IPv4 and IPv6. For packets which aren't IPv4/6 the value of 0 will be returned
	/// @param[in] packet The packet to calculate hash for
	/// @return The hash value calculated for this packet or 0 if the packet isn't IPv4/6
	template <typename T = uint32_t> T hash2Tuple(Packet* packet);

	/// @struct ConnectionHashable
	/// A struct that could be used as a key for std::unordered_map or std::unordered_set to track the connections.
	struct ConnectionHashable
	{
		/// A constructor that creates an instance of the ConnectionHashable out of a IHashableConnectionInfo object.
		/// An instance of ConnectionHashable is only valid as long as the IHashableConnectionInfo object is not
		/// deleted. An instance of ConnectionHashable created from a temporary object should only be used for lookups
		/// in an unordered_map or unordered_set, and should not be used for insertion.
		inline ConnectionHashable(IHashableConnectionInfo const* info) : m_info{ info }
		{}

		using hash_type = std::conditional_t<sizeof(size_t) == sizeof(uint32_t), uint32_t,
		                                     std::conditional_t<sizeof(size_t) == sizeof(uint64_t), uint64_t, void>>;
		static_assert(!std::is_void<hash_type>::value, "");

		inline size_t operator()() const
		{
			return hash5Tuple<hash_type>(*m_info, false);
		}

		friend inline bool operator==(ConnectionHashable const& lhs, ConnectionHashable const& rhs)
		{
			return lhs.m_info->equals(*rhs.m_info, true);
		}

	private:
		IHashableConnectionInfo const* m_info;
	};
}  // namespace pcpp

template <> struct std::hash<pcpp::ConnectionHashable>
{
	inline size_t operator()(pcpp::ConnectionHashable const& obj) const
	{
		return obj();
	}
};
