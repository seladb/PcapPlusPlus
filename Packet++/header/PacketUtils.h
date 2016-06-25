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
	 * A method that is given a packet and calculates a hash value by the packet's 5-tuple. Supports IPv4, IPv6,
	 * TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't
	 * TCP/UDP) the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	 */
	uint32_t hash5Tuple(Packet* packet);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst). Supports
	 * IPv4 and IPv6. For packets which aren't IPv4/6 the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet isn't IPv4/6
	 */
	uint32_t hash2Tuple(Packet* packet);

} // namespace pcpp

#endif /* PACKETPP_PACKET_UTILS */
