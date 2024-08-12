#pragma once

#include "Packet.h"
#include "IpAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * A struct that represent a single buffer
	 */
	template <typename T> struct ScalarBuffer
	{
		/**
		 * The pointer to the buffer
		 */
		T* buffer;

		/**
		 * Buffer length
		 */
		size_t len;
	};

	/**
	 * Computes the checksum for a vector of buffers
	 * @param[in] vec The vector of buffers
	 * @param[in] vecSize Number of ScalarBuffers in vector
	 * @return The checksum result
	 */
	uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize);

	/**
	 * Computes the checksum for Pseudo header
	 * @param[in] dataPtr Data pointer
	 * @param[in] dataLen Data length
	 * @param[in] ipAddrType IP address type(IPv4/IPv6) type @ref IPAddress::AddressType
	 * @param[in] protocolType Current protocol type @ref IPProtocolTypes
	 * @param[in] srcIPAddress Source IP Address
	 * @param[in] dstIPAddress Destination IP Address
	 * @return The checksum result
	 */
	uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen, IPAddress::AddressType ipAddrType,
	                                  uint8_t protocolType, IPAddress srcIPAddress, IPAddress dstIPAddress);

	/**
	 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on an array of byte buffers. The hash is calculated on each
	 * byte in each byte buffer, as if all byte buffers were one long byte buffer
	 * @param[in] vec An array of byte buffers (ScalarBuffer of type uint8_t)
	 * @param[in] vecSize The length of vec
	 * @return The 32bit hash value
	 */
	uint32_t fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize);

	/**
	 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on a byte buffer
	 * @param[in] buffer The byte buffer
	 * @param[in] bufSize The size of the byte buffer
	 * @return The 32bit hash value
	 */
	uint32_t fnvHash(uint8_t* buffer, size_t bufSize);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 5-tuple. Supports IPv4, IPv6,
	 * TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't
	 * TCP/UDP) the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @param[in] directionUnique Make hash value unique for each direction
	 * @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	 */
	uint32_t hash5Tuple(Packet* packet, bool const& directionUnique = false);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst). Supports
	 * IPv4 and IPv6. For packets which aren't IPv4/6 the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet isn't IPv4/6
	 */
	uint32_t hash2Tuple(Packet* packet);

}  // namespace pcpp
