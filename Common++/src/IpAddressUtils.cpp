#include "IpAddressUtils.h"

#include "IpAddress.h"
#include "IpUtils.h"  // Just needing in_addr and in6_addr.

namespace pcpp
{
	bool operator==(const IPv4Address& lhs, const in_addr& rhs)
	{
		return lhs.toInt() == rhs.s_addr;
	}

	bool operator==(const IPv6Address& lhs, const in6_addr& rhs)
	{
		return memcmp(lhs.toBytes(), &rhs, sizeof(struct in6_addr)) == 0;
	}

	bool operator==(const IPAddress& lhs, const in_addr& rhs)
	{
		if (lhs.isIPv4())
		{
			return lhs.getIPv4() == rhs;
		}
		return false;
	}

	bool operator==(const IPAddress& lhs, const in6_addr& rhs)
	{
		if (lhs.isIPv6())
		{
			return lhs.getIPv6() == rhs;
		}
		return false;
	}
}  // namespace pcpp
