#ifndef PCAPPP_IPADDRESS
#define PCAPPP_IPADDRESS

#include <memory>
#include <stdint.h>
#include <string>

using namespace std;

#define MAX_ADDR_STRING_LEN 40 //xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx

class IPAddress
{
protected:
	bool m_IsValid;
	char m_AddressAsString[MAX_ADDR_STRING_LEN];
public:
	enum AddressType {
		IPv4AddressType,
		IPv6AddressType
	};

	virtual ~IPAddress();
	virtual AddressType getType() = 0;
	string toString() const { return string(m_AddressAsString); }
	bool isValid() { return m_IsValid; }
	static auto_ptr<IPAddress> fromString(char* addressAsString);
	static auto_ptr<IPAddress> fromString(string addressAsString);
};

struct in_addr;

class IPv4Address : public IPAddress
{
private:
	in_addr* m_pInAddr;
	void init(char* addressAsString);
public:
	IPv4Address(const IPv4Address& other);
	IPv4Address(uint32_t addressAsInt); //TODO: consider endianess?
	IPv4Address(char* addressAsString);
	IPv4Address(string addressAsString);
	IPv4Address(in_addr* inAddr);
	~IPv4Address();
	AddressType getType() { return IPv4AddressType; }
	uint32_t toInt() const;
	in_addr* toInAddr() { return m_pInAddr; }
	bool operator==(const IPv4Address& other) const { return toInt() == other.toInt(); }
	bool matchSubnet(const IPv4Address& subnet, const string& subnetMask);
};

struct in6_addr;

class IPv6Address : public IPAddress
{
private:
	in6_addr* m_pInAddr;
	void init(char* addressAsString);
public:
	IPv6Address(const IPv6Address& other);
	~IPv6Address();
	IPv6Address(uint8_t* addressAsUintArr);
	IPv6Address(char* addressAsString);
	IPv6Address(string addressAsString);
	AddressType getType() { return IPv6AddressType; }
	in6_addr* toIn6Addr() { return m_pInAddr; }
	void copyTo(uint8_t** arr, size_t& length);
	void copyTo(uint8_t* arr) const;
	bool operator==(const IPv6Address& other);
};


#endif /* PCAPPP_IPADDRESS */
