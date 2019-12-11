#ifndef PCAPPP_IP_ADDRESSES
#define PCAPPP_IP_ADDRESSES

#include <stdint.h>
#include <string.h>
#include <string>

#ifdef LINUX
#include <in.h>
#include <arpa/inet.h>
#endif
#ifdef MAC_OS_X
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifdef FREEBSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/// @file


namespace pcpp
{

namespace experimental
{

	class IPv4Address
	{
	public:
		/**
		 * A default constructor that creates an instance of the class with unspecified address (zero address)
		 */
		IPv4Address() { m_InAddr.s_addr = 0; }

		/**
		 * A constructor that creates an instance of the class out of 4-byte integer value. 
		 * @param[in] addrAsInt The address as 4-byte integer in network byte order
		 */
		IPv4Address(uint32_t addrAsInt) { memcpy(&m_InAddr, &addrAsInt, sizeof(addrAsInt)); }

		/**
		 * A constructor that creates an instance of the class out of 4-byte array.
		 * @param[in] bytes The address as 4-byte array in network byte order
		 */
		IPv4Address(const uint8_t bytes[4]) { memcpy(&m_InAddr, bytes, sizeof(m_InAddr)); }

		/**
		 * Converts the IPv4 address into a 4B integer
		 * @return a 4B integer in network byte order representing the IPv4 address
		 */
		uint32_t toUInt() const { return m_InAddr.s_addr; }

		/**
		 * Returns a pointer to 4-byte array representing the IPv4 address
		 */
		const uint8_t* toBytes() const { return reinterpret_cast<const uint8_t*>(&m_InAddr.s_addr); }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const;

		/**
		 * Determine whether the address is unspecified
		 */
		bool isUnspecified() const { return toUInt() == 0; }

		/**
		 * Checks whether the address matches a subnet.
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask The subnet mask to compare the address with the subnet
		 *
		 */
		bool matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const;

		/**
		 * Overload of the equal-to operator
		 */
		bool operator==(const IPv4Address& rhs) const {	return toUInt() == rhs.toUInt(); }

		/**
		 * Overload of the not-equal-to operator
		 */
		bool operator!=(const IPv4Address& rhs) const	{	return !(*this == rhs);	}

	private:
		in_addr m_InAddr;
	}; // class IPv4Address


	// IPv4Address creation



	class IPv6Address
	{

	};

	///**
	// * @class IPAddress
	// * The class is a version-independent representation for an IP address
	// */
	class IPAddress
	{
	public:

	private:
		enum { IPv4, IPv6 };

		uint8_t m_Family;
		IPv4Address m_IPv4;
		IPv6Address m_IPv6;
	};



	// implementation of inline methods


} // namespace experimental

} // namespace pcpp

#endif /* PCAPPP_IPADDRESS */
