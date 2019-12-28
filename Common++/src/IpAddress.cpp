#define LOG_MODULE CommonLogModuleIpUtils

#include <errno.h>

#include "Logger.h"
#include "IpUtils.h"
#include "IpAddress.h"

// for AF_INET, AF_INET6
#if !defined(WIN32) && !defined(WINx64) && !defined(PCAPPP_MINGW_ENV)
#include <sys/socket.h>
#endif


namespace pcpp
{

	const IPv4Address IPv4Address::Zero;
	const IPv6Address IPv6Address::Zero;


	std::string IPv4Address::toString() const
	{
		char addrBuffer[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
			return std::string(addrBuffer);

		return std::string();
	}


	IPv4Address::IPv4Address(const std::string& addrAsString)
	{
		if (inet_pton(AF_INET, addrAsString.data(), m_Bytes) <= 0)
			memset(m_Bytes, 0, sizeof(m_Bytes));
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const
	{
		IPv4Address maskAsIpAddr(subnetMask);
		if (maskAsIpAddr.isUnspecified())
		{
			LOG_ERROR("Subnet mask '%s' is in illegal format", subnetMask.c_str());
			return false;
		}

		return matchSubnet(subnet, maskAsIpAddr);
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const
	{
		uint32_t subnetMaskAsUInt = subnetMask.toUInt();
		uint32_t thisAddrAfterMask = toUInt() & subnetMaskAsUInt;
		uint32_t subnetAddrAfterMask = subnet.toUInt() & subnetMaskAsUInt;
		return thisAddrAfterMask == subnetAddrAfterMask;
	}



	std::string IPv6Address::toString() const
	{
		char addrBuffer[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, toBytes(), addrBuffer, sizeof(addrBuffer)) != NULL)
			return std::string(addrBuffer);

		return std::string();
	}


	IPv6Address::IPv6Address(const std::string& addrAsString)
	{
		if(inet_pton(AF_INET6, addrAsString.data(), m_Bytes) <= 0)
			memset(m_Bytes, 0, sizeof(m_Bytes));
	}


	IPAddress::IPAddress(const std::string& addrAsString) : m_Type(IPv6AddressType), m_IPv6(addrAsString)
	{
		if (m_IPv6.isUnspecified()) // not IPv6
		{
			m_Type = IPv4AddressType;
			m_IPv4 = IPv4Address(addrAsString);
		}
	}


	void IPv6Address::copyTo(uint8_t** arr, size_t& length) const
	{
		const size_t addrLen = sizeof(m_Bytes);
		length = addrLen;
		*arr = new uint8_t[addrLen];
		memcpy(*arr, m_Bytes, addrLen);
	}


} // namespace pcpp
