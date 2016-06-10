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
	 * A method that is given a packet and calculates a hash value by the packet's 5-tuple
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet
	 */
	uint32_t hash5Tuple(Packet* packet);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst)
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet
	 */
	uint32_t hash2Tuple(Packet* packet);

} // namespace pcpp

#endif /* PACKETPP_PACKET_UTILS */
