#define LOG_MODULE CommonLogModuleIpUtils

#include <errno.h>

#include "Logger.h"
#include "IpUtils.h"
#include "IpAddresses.h"

// for AF_INET, AF_INET6
#if !defined(WIN32) && !defined(WINx64) && !defined(PCAPPP_MINGW_ENV)
#include <sys/socket.h>
#endif


namespace pcpp
{

namespace experimental
{

	std::string IPv4Address::toString() const
	{
		char addrBuffer[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
			return std::string(addrBuffer);

		return std::string();
	}


	bool matchSubnet(const IPv4Address& addr, const char* subnet, const char* subnetMask)
	{
		int errorCode;

		IPv4Address subnetAsIpAddr = makeIPv4Address(subnet, errorCode);
		if (errorCode != 0)
		{
			LOG_ERROR("Subnet '%s' is in illegal format", subnet);
			return false;
		}

		IPv4Address maskAsIpAddr = makeIPv4Address(subnetMask, errorCode);
		if (errorCode != 0)
		{
			LOG_ERROR("Subnet mask '%s' is in illegal format", subnetMask);
			return false;
		}

		return matchSubnet(addr, subnetAsIpAddr, maskAsIpAddr);
	}


	bool matchSubnet(const IPv4Address& addr, const IPv4Address& subnet, const IPv4Address& subnetMask)
	{
		uint32_t thisAddrAfterMask = addr.toUInt() & subnetMask.toUInt();
		uint32_t subnetAddrAfterMask = subnet.toUInt() & subnetMask.toUInt();
		return thisAddrAfterMask == subnetAddrAfterMask;
	}


	IPv4Address makeIPv4Address(const char* addrAsString, int& errorCode)
	{
		uint8_t buf[sizeof(in_addr)];

		if (inet_pton(AF_INET, addrAsString, buf) > 0)
		{
			errorCode = 0;
			return IPv4Address(buf);
		}

		errorCode = EINVAL;
		return IPv4Address(); // unspecified address
	}


	// Unspecified/zero address
	const IPv6Address IPv6Address::Zero;

	std::string IPv6Address::toString() const
	{
		char addrBuffer[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
			return std::string(addrBuffer);

		return std::string();
	}


	IPv6Address makeIPv6Address(const char* addrAsString, int& errorCode)
	{
		uint8_t buf[sizeof(in6_addr)];

		if (inet_pton(AF_INET6, addrAsString, buf) > 0)
		{
			errorCode = 0;
			return IPv6Address(buf);
		}

		errorCode = EINVAL;
		return IPv6Address(); // unspecified address
	}


	IPAddress makeAddress(const char* addrAsString, int& errorCode)
	{
		IPv6Address ipv6Addr = makeIPv6Address(addrAsString, errorCode);
		if (errorCode != 0) // not IPv6
		{
			IPv4Address ipv4Addr = makeIPv4Address(addrAsString, errorCode);
			if (errorCode == 0)
				return IPAddress(ipv4Addr);

			return IPAddress(); // IPv4, unspecified
		}
		return IPAddress(ipv6Addr);
	}

} // namespace experimental

} // namespace pcpp
