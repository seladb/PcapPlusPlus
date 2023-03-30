#define LOG_MODULE CommonLogModuleIpUtils

#include <algorithm>
#include <cmath>
#include <errno.h>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <bitset>
#include "Logger.h"
#include "IpUtils.h"
#include "IpAddress.h"
#include "EndianPortable.h"

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

	// ~~~~~~~~~~~
	// IPv4Address
	// ~~~~~~~~~~~


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


	bool IPv4Address::matchNetwork(const IPv4Network& network) const
	{
		return network.includes(*this);
	}


	bool IPv4Address::matchNetwork(const std::string& network) const
	{
		try
		{
			auto ipv4Network = IPv4Network(network);
			return ipv4Network.includes(*this);
		}
		catch (const std::invalid_argument& e)
		{
			PCPP_LOG_ERROR(e.what());
			return false;
		}
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const
	{
		try
		{
			auto ipv4Network = IPv4Network(subnet, subnetMask);
			return ipv4Network.includes(*this);
		}
		catch (const std::invalid_argument& e)
		{
			PCPP_LOG_ERROR(e.what());
			return false;
		}
	}


	bool IPv4Address::matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const
	{
		try
		{
			auto ipv4Network = IPv4Network(subnet, subnetMask.toString());
			return ipv4Network.includes(*this);
		}
		catch (const std::invalid_argument& e)
		{
			PCPP_LOG_ERROR(e.what());
			return false;
		}
	}


	// ~~~~~~~~~~~
	// IPv6Address
	// ~~~~~~~~~~~


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


	// ~~~~~~~~~~~
	// IPv4Network
	// ~~~~~~~~~~~


	bool IPv4Network::isValidNetmask(const std::string& netmask)
	{
		if (netmask == "0.0.0.0")
		{
			return true;
		}

		auto mask = IPv4Address(netmask);
		if (!mask.isValid())
		{
			return false;
		}

		uint32_t maskAsInt = be32toh(mask.toInt());
		std::bitset<32> bitset(maskAsInt);
		auto bitsetCount = bitset.count();

		if (bitsetCount == 32)
		{
			return true;
		}
		else
		{
			return maskAsInt << bitsetCount == 0;
		}
	}


	void IPv4Network::initFromAddressAndPrefixLength(const IPv4Address& address, uint8_t prefixLen)
	{
		m_Mask = be32toh(0xffffffff ^ (prefixLen < 32 ? 0xffffffff >> prefixLen: 0));
		m_NetworkPrefix = address.toInt() & m_Mask;
	}


	void IPv4Network::initFromAddressAndNetmask(const IPv4Address& address, const std::string& netmask)
	{
		IPv4Address netmaskAddr(netmask);
		m_Mask = netmaskAddr.toInt();
		m_NetworkPrefix = address.toInt() & m_Mask;
	}


	IPv4Network::IPv4Network(const IPv4Address& address, uint8_t prefixLen)
	{
		if (!address.isValid())
		{
			throw std::invalid_argument("address is not a valid IPv4 address");
		}

		if (prefixLen > 32)
		{
			throw std::invalid_argument("prefixLen must be an integer between 0 and 32");
		}

		initFromAddressAndPrefixLength(address, prefixLen);
	}


	IPv4Network::IPv4Network(const IPv4Address& address, const std::string& netmask)
	{
		if (!address.isValid())
		{
			throw std::invalid_argument("address is not a valid IPv4 address");
		}

		if (!isValidNetmask(netmask))
		{
			throw std::invalid_argument("netmask is not valid");
		}

		initFromAddressAndNetmask(address, netmask);
	}


	IPv4Network::IPv4Network(const std::string& addressAndNetmask)
	{
		std::stringstream stream(addressAndNetmask);
		std::string networkPrefixStr, netmaskStr;
		std::getline(stream, networkPrefixStr, '/');
		std::getline(stream, netmaskStr);

		if (netmaskStr.empty())
		{
			throw std::invalid_argument("The input should be in the format of <address>/<netmask> or <address>/<prefixLength>");
		}

		auto networkPrefix = IPv4Address(networkPrefixStr);
		if (!networkPrefix.isValid())
		{
			throw std::invalid_argument("The input doesn't contain a valid IPv4 network prefix");
		}

		if (std::all_of(netmaskStr.begin(), netmaskStr.end(), ::isdigit))
		{
			uint32_t prefixLen = std::stoi(netmaskStr);
			if (prefixLen > 32)
			{
				throw std::invalid_argument("Prefix length must be an integer between 0 and 32");
			}

			initFromAddressAndPrefixLength(networkPrefix, prefixLen);
		}
		else
		{
			if (!isValidNetmask(netmaskStr))
			{
				throw std::invalid_argument("Netmask is not valid");
			}

			initFromAddressAndNetmask(networkPrefix, netmaskStr);
		}
	}


	uint8_t IPv4Network::getPrefixLen() const
	{
		std::bitset<32> bitset(m_Mask);
		return bitset.count();
	}


	IPv4Address IPv4Network::getLowestAddress() const
	{
		std::bitset<32> bitset(m_Mask);
		return bitset.count() < 32 ? m_NetworkPrefix + htobe32(1) : m_NetworkPrefix;
	}


	IPv4Address IPv4Network::getHighestAddress() const
	{
		auto tempAddress = static_cast<uint32_t >(m_NetworkPrefix | ~m_Mask);
		std::bitset<32> bitset(m_Mask);
		return bitset.count() < 32 ? tempAddress - htobe32(1) : tempAddress;
	}


	uint64_t IPv4Network::getTotalAddressCount() const
	{
		std::bitset<32> bitset(static_cast<uint32_t>(~m_Mask));
		return 1ULL << bitset.count();
	}


	bool IPv4Network::includes(const IPv4Address& address) const
	{
		if (!address.isValid())
		{
			return false;
		}
		return (address.toInt() & m_Mask) == m_NetworkPrefix;
	}


	bool IPv4Network::includes(const IPv4Network& network) const
	{
		uint32_t lowestAddress = network.m_NetworkPrefix;
		uint32_t highestAddress = network.m_NetworkPrefix | ~network.m_Mask;
		return ((lowestAddress & m_Mask) == m_NetworkPrefix && (highestAddress & m_Mask) == m_NetworkPrefix);
	}

	std::string IPv4Network::toString() const
	{
		std::ostringstream stream;
		stream << getNetworkPrefix() << "/" << static_cast<int>(getPrefixLen());
		return stream.str();
	}

} // namespace pcpp
