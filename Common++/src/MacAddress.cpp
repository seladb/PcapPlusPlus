#include "MacAddress.h"

namespace pcpp
{

	MacAddress MacAddress::Zero(0, 0, 0, 0, 0, 0);

	MacAddress MacAddress::Broadcast(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

	std::string MacAddress::toString() const
	{
		char str[19];
		if (snprintf(str, sizeof str, "%02x:%02x:%02x:%02x:%02x:%02x", m_Address[0], m_Address[1], m_Address[2],
		             m_Address[3], m_Address[4], m_Address[5]) < 0)
		{
			throw std::runtime_error("Conversion of MAC address to string failed");
		}
		return str;
	}

	MacAddress::MacAddress(const uint8_t* addr, size_t size)
	{
		if (addr == nullptr)
		{
			throw std::invalid_argument("Address pointer is null");
		}

		if (size < 6)
		{
			throw std::out_of_range("Buffer size is smaller than MAC address size (6 bytes)");
		}

		std::copy(addr, addr + 6, m_Address.begin());
	}

	MacAddress::MacAddress(const std::string& address)
	{
		constexpr size_t validMacAddressLength = 17;
		unsigned int values[6];
		if (address.size() != validMacAddressLength ||
		    // NOLINTNEXTLINE(cert-err34-c)
		    sscanf(address.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4],
		           &values[5]) != 6)
		{
			throw std::invalid_argument("Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");
		}
		for (int i = 0; i < 6; ++i)
		{
			m_Address[i] = values[i];
		}
	}

	size_t MacAddress::copyTo(uint8_t* buffer, size_t size) const
	{
		const size_t requiredSize = m_Address.size();
		if (buffer == nullptr)
		{
			if (size != 0)
			{
				throw std::invalid_argument("Buffer is null but size is not zero");
			}
			return requiredSize;
		}
		if (size < m_Address.size())
		{
			return requiredSize;
		}
		std::copy(m_Address.begin(), m_Address.end(), buffer);
		return requiredSize;
	}

	bool MacAddress::copyToNewBuffer(uint8_t** buffer, size_t& size) const
	{
		if (buffer == nullptr)
		{
			throw std::invalid_argument("Buffer pointer is null");
		}

		size = copyTo(nullptr, 0);          // Get the required size
		*buffer = new uint8_t[size];        // Allocate memory for the buffer
		if (copyTo(*buffer, size) != size)  // Copy the address to the newly allocated buffer
		{
			delete[] *buffer;  // Clean up if copy fails
			*buffer = nullptr;
			size = 0;
			return false;
		}

		return true;
	}
}  // namespace pcpp
