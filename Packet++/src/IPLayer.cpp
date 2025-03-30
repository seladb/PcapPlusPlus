#include "IPLayer.h"

namespace pcpp
{
	IPAddress::AddressType IPLayer::getIPVersion(uint8_t const* data, size_t dataLen)
	{
		// The data requires at least 1 byte of valid buffer
		if (data == nullptr || dataLen < 1)
		{
			return IPAddress::AddressType::Unknown;
		}

		// The first 4 bits of the first byte of the IP header represent the IP version
		uint8_t version = data[0] >> 4;

		switch (version)
		{
		case 4:
			return IPAddress::AddressType::IPv4;
		case 6:
			return IPAddress::AddressType::IPv6;
		default:
			return IPAddress::AddressType::Unknown;
		}
	}
}  // namespace pcpp
