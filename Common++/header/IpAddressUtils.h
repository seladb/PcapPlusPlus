#pragma once

#include "IpAddress.h"
#include "IpUtils.h" // Just needing in_addr and in6_addr.

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	bool operator==(const IPv4Address& lhs, const in_addr& rhs);
	inline bool operator!=(const IPv4Address& lhs, const in_addr& rhs) { return !(lhs == rhs); }
	inline bool operator==(const in_addr& lhs, const IPv4Address& rhs) { return rhs == lhs; }
	inline bool operator!=(const in_addr& lhs, const IPv4Address& rhs) { return !(lhs == rhs); }

	bool operator==(const IPv6Address& lhs, const in6_addr& rhs);
	inline bool operator!=(const IPv6Address& lhs, const in6_addr& rhs) { return !(lhs == rhs); }
	inline bool operator==(const in6_addr& lhs, const IPv6Address& rhs) { return rhs == lhs; }
	inline bool operator!=(const in6_addr& lhs, const IPv6Address& rhs) { return !(lhs == rhs); }
		
	bool operator==(const IPAddress& lhs, const in_addr& rhs);
	inline bool operator!=(const IPAddress& lhs, const in_addr& rhs) { return !(lhs == rhs); }
	inline bool operator==(const in_addr& lhs, const IPAddress& rhs) { return rhs == lhs; }
	inline bool operator!=(const in_addr& lhs, const IPAddress& rhs) { return !(lhs == rhs); }

	bool operator==(const IPAddress& lhs, const in6_addr& rhs);
	inline bool operator!=(const IPAddress& lhs, const in6_addr& rhs) { return !(lhs == rhs); }
	inline bool operator==(const in6_addr& lhs, const IPAddress& rhs) { return rhs == lhs; }
	inline bool operator!=(const in6_addr& lhs, const IPAddress& rhs) { return !(lhs == rhs); }
}