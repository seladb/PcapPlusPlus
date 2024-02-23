#include <stdio.h>
#include <stdlib.h>

#include "MacAddress.h"

namespace pcpp
{

MacAddress MacAddress::Zero(0,0,0,0,0,0);

std::string MacAddress::toString() const
{
	char str[19];
	snprintf(str, sizeof str, "%02x:%02x:%02x:%02x:%02x:%02x", m_Address[0], m_Address[1], m_Address[2], m_Address[3], m_Address[4], m_Address[5]);
	return std::string(str);
}

void MacAddress::init(const char* addr)
{
	// Check if the address is in string format or bytes format
	if(addr[2] != ':')
	{
		// The address is in bytes format
		memcpy(m_Address, addr, sizeof(m_Address));
		m_IsValid = true;
		return;
	}

	// The address is in string format
    int values[6];
    if (sscanf(addr, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6)
	{
        // Successfully parsed the MAC address
        for (int i = 0; i < 6; ++i)
		{
            m_Address[i] = static_cast<unsigned int>(values[i]);
        }

		// check the end of the string
		if (addr[17] == '\0')
		{
			m_IsValid = true;
			return;
		}
    }

	// Failed to parse the MAC address
	memset(m_Address, 0, sizeof(m_Address));
	m_IsValid = false;
	return;
}

} // namespace pcpp
