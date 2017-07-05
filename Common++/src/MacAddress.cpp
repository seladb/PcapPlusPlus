#include "MacAddress.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"

namespace pcpp
{

MacAddress MacAddress::Zero(0,0,0,0,0,0);

MacAddress::MacAddress(uint8_t* addr)
{
	memcpy(m_Address, addr, 6);
	m_IsValid = true;
}

MacAddress::MacAddress(const char* addr)
{
	init(addr);
}

MacAddress::MacAddress(const std::string& addr)
{
	init(addr.c_str());
}

MacAddress::MacAddress(uint8_t firstOctest, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet, uint8_t fifthOctet, uint8_t sixthOctet)
{
	m_Address[0] = firstOctest;
	m_Address[1] = secondOctet;
	m_Address[2] = thirdOctet;
	m_Address[3] = fourthOctet;
	m_Address[4] = fifthOctet;
	m_Address[5] = sixthOctet;
	m_IsValid = true;
}

MacAddress::MacAddress(const MacAddress& other)
{
	memcpy(m_Address, other.m_Address, 6);
	m_IsValid = true;
}

MacAddress& MacAddress::operator=(const MacAddress& other)
{
	memcpy(m_Address, other.m_Address, 6);
	m_IsValid = other.m_IsValid;

	return *this;
}

std::string MacAddress::toString()
{
	char str[19];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",m_Address[0], m_Address[1], m_Address[2], m_Address[3], m_Address[4],m_Address[5]);
	return std::string(str);
}

void MacAddress::copyTo(uint8_t** arr)
{
	(*arr) = new uint8_t[6];
	memcpy((*arr), m_Address, 6);
}

void MacAddress::copyTo(uint8_t* arr) const
{
	memcpy(arr, m_Address, 6);
}


void MacAddress::init(const char* addr)
{
	int i = 0;
	while((*addr) != 0)
	{
		char byte[3];
		memset(byte, 0, 3);
		byte[0] = (*addr); addr++;
		if ((*addr) == 0) break;
		byte[1] = (*addr); addr++;
		if ((*addr) != 0) // holds the ":" char or end of string
			addr++; // ignore the ":" char
		m_Address[i] = (uint8_t)strtol(byte, NULL, 16);
		i++;
	}

	if (i != 6)
		m_IsValid = false;
	else
		m_IsValid = true;
}

} // namespace pcpp
