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
	const unsigned int addrLen = sizeof m_Address;
	unsigned int i = 0;

	for(; *addr != 0 && i < addrLen; ++i)
	{
		char byte[3];
		memset(byte, 0, sizeof byte);
		byte[0] = *addr++;
		if(*addr == '\0') break;
		byte[1] = *addr++;
		if(*addr != '\0') // holds the ":" char or end of string
			++addr; // ignore the ":" char
		m_Address[i] = static_cast<uint8_t>(strtol(byte, NULL, 16));

		// The strtol function returns zero value in two cases: when an error occures or the string '00' is converted.
		// This code verifies that it's the second case.
		if(m_Address[i] == 0 && (byte[0] != '0' || byte[1] != '0'))
		{
			m_IsValid = false;
			return;
		}
	}

	m_IsValid = (i == addrLen && *addr == '\0');
}

} // namespace pcpp
