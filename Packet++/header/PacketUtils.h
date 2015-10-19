#ifndef PACKETPP_PACKET_UTILS
#define PACKETPP_PACKET_UTILS

#include "Packet.h"

/// @file

/**
 * A method that is given a packet and calculates a hash value by the packet's 5-tuple
 * @param[in] packet The packet to calculate hash for
 * @return The hash value calculated for this packet
 */
size_t hash5Tuple(Packet* packet);

#endif /* PACKETPP_PACKET_UTILS */
