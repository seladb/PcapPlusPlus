#ifndef PCAPPP_MACADDRESS
#define PCAPPP_MACADDRESS

#include <stdint.h>
#include <string>
#include <memory>

using namespace std;

class MacAddress
{
public:
	MacAddress(uint8_t* addr);
	MacAddress(const char* addr);
	MacAddress(const string& addr);
	MacAddress(uint8_t firstOctest, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet, uint8_t fifthOctet, uint8_t sixthOctet);
	// copy c'tor
	MacAddress(const MacAddress& other);

	inline bool operator==(const MacAddress& other)
			{
				for (int i = 0; i < 6; i++)
					if (m_Address[i] != other.m_Address[i])
						return false;
				return true;
			}
	inline bool operator!=(const MacAddress& other) {return !operator==(other);}

	bool isValid() { return m_IsValid; }
	string toString();
	void copyTo(uint8_t** arr);
	void copyTo(uint8_t* arr) const;

	static MacAddress Zero;
private:
	uint8_t m_Address[6];
	bool m_IsValid;
	void init(const char* addr);
};

#endif /* PCAPPP_MACADDRESS */
