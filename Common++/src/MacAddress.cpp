#include "MacAddress.h"

namespace pcpp
{

	MacAddress MacAddress::Zero(0, 0, 0, 0, 0, 0);

	std::string MacAddress::toString() const
	{
		char str[19];
		snprintf(str, sizeof str, "%02x:%02x:%02x:%02x:%02x:%02x", m_Address[0], m_Address[1], m_Address[2],
		         m_Address[3], m_Address[4], m_Address[5]);
		return std::string(str);
	}

	MacAddress::MacAddress(const std::string& address)
	{
		constexpr size_t validMacAddressLength = 17;
		unsigned int values[6];
		if (address.size() != validMacAddressLength ||
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

}  // namespace pcpp
