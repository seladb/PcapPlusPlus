#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X || FREEBSD
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

#include "IpUtils.h"
#include "IpAddresses.h"

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


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const
	{
		uint32_t maskAsInt = subnetMask.toUInt();
		uint32_t thisAddrAfterMask = toUInt() & maskAsInt;
		uint32_t subnetAddrAfterMask = subnet.toUInt() & maskAsInt;
		return thisAddrAfterMask == subnetAddrAfterMask;
	}

} // namespace experimental

} // namespace pcpp
