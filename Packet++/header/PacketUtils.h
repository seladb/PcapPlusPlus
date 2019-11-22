#ifndef PACKETPP_PACKET_UTILS
#define PACKETPP_PACKET_UTILS

#include "Packet.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * A function that is given a packet and calculates a hash value by the packet's 5-tuple. Supports IPv4, IPv6,
	 * TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't
	 * TCP/UDP) the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	 */
	uint32_t hash5Tuple(const Packet* packet);

	/**
	 * A function that is given a packet and calculates a hash value by the packet's 5-tuple.
	 * For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't TCP/UDP) the result is undefined.
	 * It is an optimized version of hash5Tuple which can be used if IPv4/6 and TCP/UDP layers are already found.
	 * @param[in] packet The packet to calculate hash for. The user checks that the IPv4/6 and TCP/UDP layers are present
	 * @param[in] networkLayer A pointer to IPv4/6 layer and the user takes care that it really points to IPv4/6 layer in packet
	 * @param[in] transportLayer A pointer to TCP/UDP layer and the user takes care that it really points to TCP/UDP layer in packet
	 * @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	 */
	uint32_t hash5Tuple(const Packet* packet, const Layer* networkLayer, const Layer* transportLayer);

	/**
	 * A function that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst). Supports
	 * IPv4 and IPv6. For packets which aren't IPv4/6 the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet isn't IPv4/6
	 */
	uint32_t hash2Tuple(const Packet* packet);

} // namespace pcpp

#endif /* PACKETPP_PACKET_UTILS */
