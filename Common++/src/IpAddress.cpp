#define LOG_MODULE CommonLogModuleIpUtils

#include <algorithm>
#include <cmath>
#include <errno.h>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include "Logger.h"
#include "IpUtils.h"
#include "IpAddress.h"

// for AF_INET, AF_INET6
#if !defined(_WIN32)
#include <sys/socket.h>
#endif


namespace pcpp
{

	const IPv4Address IPv4Address::Zero;
	const IPv6Address IPv6Address::Zero;

	const IPv4Address IPv4Address::MulticastRangeLowerBound("224.0.0.0");
	const IPv4Address IPv4Address::MulticastRangeUpperBound("239.255.255.255");
	const IPv6Address IPv6Address::MulticastRangeLowerBound("ff00:0000:0000:0000:0000:0000:0000:0000");

	std::string IPv4Address::toString() const
	{
		char addrBuffer[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, toBytes(), addrBuffer, sizeof(addrBuffer)) != nullptr)
			return std::string(addrBuffer);

		return std::string();
	}

	bool IPv4Address::isMulticast() const
	{
		return !operator<(MulticastRangeLowerBound) && (operator<(MulticastRangeUpperBound) || operator==(MulticastRangeUpperBound));
	}

	IPv4Address::IPv4Address(const std::string& addrAsString)
	{
		if (inet_pton(AF_INET, addrAsString.data(), m_Bytes) <= 0)
			memset(m_Bytes, 0, sizeof(m_Bytes));
	}


	bool IPv4Address::matchSubnet(const std::string& subnet) const
	{
		std::stringstream ss(subnet);
		std::string subnetOnly, subnetPrefixStr;
		std::getline(ss, subnetOnly, '/');
		std::getline(ss, subnetPrefixStr);

		if (subnetPrefixStr.empty() || !std::all_of(subnetPrefixStr.begin(), subnetPrefixStr.end(), ::isdigit)) {
			PCPP_LOG_ERROR("subnet prefix '" << subnetPrefixStr << "' must be an integer");
			return false;
		}

		uint32_t subnetPrefix;
		try {
			subnetPrefix = std::stoi(subnetPrefixStr);
		} catch (const std::invalid_argument&) {
			PCPP_LOG_ERROR("Subnet prefix in '" << subnet << "' must be an integer");
			return false;
		} catch (const std::out_of_range&) {
			PCPP_LOG_ERROR("Subnet prefix in '" << subnet << "' must be between 0 and 32");
			return false;
		}

		if (subnetPrefix > 32)
		{
			PCPP_LOG_ERROR("Subnet prefix '" << subnetPrefix << "' must be between 0 and 32");
			return false;
		}

		uint32_t subnetMask = pow(2, subnetPrefix) - 1;

		IPv4Address subnetAsIpAddr(subnetOnly);
		IPv4Address maskAsIpAddr(subnetMask);

		if (!maskAsIpAddr.isValid() || !subnetAsIpAddr.isValid())
		{
			PCPP_LOG_ERROR("Subnet '" << subnet << "' is in illegal format");
			return false;
		}

		return matchSubnet(subnetAsIpAddr, maskAsIpAddr);
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const
	{
		IPv4Address maskAsIpAddr(subnetMask);
		if (!maskAsIpAddr.isValid())
		{
			PCPP_LOG_ERROR("Subnet mask '" << subnetMask << "' is in illegal format");
			return false;
		}

		return matchSubnet(subnet, maskAsIpAddr);
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const
	{
		uint32_t subnetMaskAsUInt = subnetMask.toInt();
		uint32_t thisAddrAfterMask = toInt() & subnetMaskAsUInt;
		uint32_t subnetAddrAfterMask = subnet.toInt() & subnetMaskAsUInt;
		return thisAddrAfterMask == subnetAddrAfterMask;
	}

	std::string IPv6Address::toString() const
	{
		char addrBuffer[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, toBytes(), addrBuffer, sizeof(addrBuffer)) != nullptr)
			return std::string(addrBuffer);

		return std::string();
	}

	bool IPv6Address::isMulticast() const
	{
		return !operator<(MulticastRangeLowerBound);
	}

	IPv6Address::IPv6Address(const std::string& addrAsString)
	{
		if(inet_pton(AF_INET6, addrAsString.data(), m_Bytes) <= 0)
			memset(m_Bytes, 0, sizeof(m_Bytes));
	}


	IPAddress::IPAddress(const std::string& addrAsString) : m_Type(IPv6AddressType), m_IPv6(addrAsString)
	{
		if (!m_IPv6.isValid()) // not IPv6
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

	bool IPv6Address::matchSubnet(const IPv6Address& subnet, uint8_t prefixLength) const
	{
		if(prefixLength == 0 || prefixLength > 128)
		{
			PCPP_LOG_ERROR("subnet prefixLength '" << (int)prefixLength << "' illegal");
			return false;
		}
		uint8_t compareByteCount = prefixLength / 8;
		uint8_t compareBitCount = prefixLength % 8;
		bool result = false;
		const uint8_t* subnetBytes = subnet.toBytes();
		if(compareByteCount > 0)
		{
			result = memcmp(subnetBytes, m_Bytes, compareByteCount) == 0;
		}
		if((result || prefixLength < 8) && compareBitCount > 0)
		{
			uint8_t subSubnetByte = subnetBytes[compareByteCount] >> (8 - compareBitCount);
			uint8_t subThisByte =  m_Bytes[compareByteCount]  >> (8 - compareBitCount);
			result = subSubnetByte == subThisByte;
		}
		return result;
	}


} // namespace pcpp
