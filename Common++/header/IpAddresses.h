#ifndef PCAPPP_IP_ADDRESSES
#define PCAPPP_IP_ADDRESSES

#include <stdint.h>
#include <string.h>
#include <string>

// TODO: remove when migration has completed
#include "IpAddress.h"

// for in_addr, in6_addr
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

/// @file


namespace pcpp
{

namespace experimental
{
	// The implementation of the classes is based on document N4771 "Working Draft, C++ Extensions for Networking"
	// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/n4771.pdf

	/**
	 * @class IPv4Address
	 * Represents an IPv4 address (of type XXX.XXX.XXX.XXX)
	 */
	class IPv4Address
	{
	public:
		/**
		 * A default constructor that creates an instance of the class with unspecified/zero address
		 */
		IPv4Address() { memset(&m_InAddr, 0, sizeof(m_InAddr)); }

		/**
		 * A constructor that creates an instance of the class out of 4-byte integer value. 
		 * @param[in] addrAsInt The address as 4-byte integer in network byte order
		 */
		IPv4Address(uint32_t addrAsInt) { memcpy(&m_InAddr, &addrAsInt, sizeof(m_InAddr)); }

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
		const uint8_t* toBytes() const { return reinterpret_cast<const uint8_t*>(&m_InAddr); }

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
		 * Overload of the equal-to operator
		 */
		bool operator==(const IPv4Address& rhs) const { return toUInt() == rhs.toUInt(); }

		/**
		 * Overload of the not-equal-to operator
		 */
		bool operator!=(const IPv4Address& rhs) const	{ return !(*this == rhs); }


		// Following methods are placed for backward compatibility and will be deleted in the future

		/**
		 * Clone the object
		 * Notice this method is deprecated and will be deleted in the future
		 * @return A newly allocated instance which is a clone of the current instance
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future")]]
		#endif
		IPv4Address* clone() const { return new IPv4Address(*this); }

		/**
		 * Converts the IPv4 address into a 4B integer
		 * Notice this method is deprecated and will be deleted in the future. Prefer toUInt method
		 * @return a 4B integer representing the IPv4 address
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is replaced by toUInt() method. It will be deleted in the future")]]
		#endif
		uint32_t toInt() const { return toUInt(); }

		/**
		 * Returns a in_addr struct pointer representing the IPv4 address
		 * Notice this method is deprecated and will be deleted in the future. Prefer toBytes method
		 * @return a in_addr struct pointer representing the IPv4 address
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is replaced by toBytes() method. It will be deleted in the future")]]
		#endif
		const in_addr* toInAddr() const { return &m_InAddr; }

		/**
		 * Checks whether the address matches a subnet.
		 * Notice this method is deprecated and will be deleted in the future. Prefer one of the functions matchSubnet
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask A string representing the subnet mask to compare the address with the subnet
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is deprecated and will be deleted in the future. Prefer one of the functions matchSubnet")]]
		#endif
		bool matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const;

		/**
		 * Checks whether the address matches a subnet.
		 * Notice this method is deprecated and will be deleted in the future. Prefer one of the functions matchSubnet
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask The subnet mask to compare the address with the subnet
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is deprecated and will be deleted in the future. Prefer one of the functions matchSubnet")]]
		#endif
		bool matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const;

		/**
		 * A static value representing a zero value of IPv4 address, meaning address of value "0.0.0.0"
		 * Notice this value can be omitted in the user code because the default constructor creates an instance with an unspecified/zero address.
		 * In order to check whether the address is zero the method isUnspecified can be used
		 */
		static const IPv4Address Zero;

	private:
		in_addr m_InAddr;
	}; // class IPv4Address


	// Creation of IPv4Address

	/**
	 * A function that creates an instance of the class IPv4Address out of 4-byte array.
	 * @param[in] bytes The address as 4-byte array in network byte order
	 * @return An instance of class IPv4Address
	 */
	inline IPv4Address makeIPv4Address(uint32_t addrAsInt) { return IPv4Address(addrAsInt); }

	/**
	 * A function that creates an instance of the class IPv4Address out of 4-byte array.
	 * @param[in] bytes The address as 4-byte array in network byte order
	 * @return An instance of class IPv4Address
	 */
	inline IPv4Address makeIPv4Address(const uint8_t bytes[4]) { return IPv4Address(bytes); }

	/**
	 * A function that creates an instance of the class out of string (char*) value
	 * If the string doesn't represent a valid IPv4 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The string (char*) representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPv4Address. If an error occured the return address will be an unspecified/zero
	 */
	IPv4Address makeIPv4Address(const char* addrAsString, int& errorCode);

	/**
	 * A function that creates an instance of the class out of std::string value
	 * If the string doesn't represent a valid IPv4 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The std::string representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPv4Address. If an error occured the return address will be an unspecified/zero
	 */
	inline IPv4Address makeIPv4Address(const std::string& addrAsString, int& errorCode) {	return makeIPv4Address(addrAsString.c_str(), errorCode); }


	// Helper functions

	/**
	 * Checks whether the address matches a subnet.
	 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
	 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
	 * @param[in] addr The address to be checked
	 * @param[in] subnet A string representing the subnet to be verified
	 * @param[in] subnetMask A string representing the subnet mask to compare the address with the subnet
	 */
	bool matchSubnet(const IPv4Address& addr, const char* subnet, const char* subnetMask);

	/**
	 * Checks whether the address matches a subnet.
	 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
	 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
	 * @param[in] addr The address to be checked
	 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
	 * (it'll be ignored if subnet mask is correct)
	 * @param[in] subnetMask The subnet mask to compare the address with the subnet
	 */
	bool matchSubnet(const IPv4Address& addr, const IPv4Address& subnet, const IPv4Address& subnetMask);




	/**
	 * @class IPv6Address
	 * Represents an IPv6 address (of type xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx).
	 */
	class IPv6Address
	{
	public:
		/**
		 * A default constructor that creates an instance of the class with unspecified/zero address
		 */
		IPv6Address() { memset(&m_In6Addr, 0, sizeof(m_In6Addr)); }

		/**
		 * A constructor that creates an instance of the class out of 16-byte array.
		 * @param[in] bytes The address as 16-byte array in network byte order
		 */
		IPv6Address(const uint8_t bytes[16]) { memcpy(&m_In6Addr, bytes, sizeof(m_In6Addr)); }

		/**
		 * Returns a pointer to 16-byte array representing the IPv6 address
		 */
		const uint8_t* toBytes() const { return m_In6Addr.s6_addr; }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const;

		/**
		 * Determine whether the address is unspecified
		 */
		bool isUnspecified() const { return *this == Zero; }

		/**
		 * Overload of the equal-to operator
		 */
		bool operator==(const IPv6Address& rhs) const { return memcmp(toBytes(), rhs.toBytes(), sizeof(m_In6Addr)) == 0; }

		/**
		 * Overload of the not-equal-to operator
		 */
		bool operator!=(const IPv6Address &rhs) const { return !(*this == rhs); }


		// Following methods are placed for backward compatibility and will be deleted in the future

		/**
		 * Clone the object
		 * Notice this method is deprecated and will be deleted in the future
		 * @return A newly allocated instance which is a clone of the current instance
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future")]]
		#endif
		IPv6Address *clone() const { return new IPv6Address(*this); }

		/**
		 * Returns a in6_addr struct pointer representing the IPv6 address
		 * Notice this method is deprecated and will be deleted in the future. Prefer toBytes method
		 * @return a in6_addr struct pointer representing the IPv6 address
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is replaced by toBytes() method. It will be deleted in the future")]]
		#endif
		const in6_addr* toIn6Addr() const { return &m_In6Addr; }

		/**
		 * Allocates a byte array and copies address value into it. Array deallocation is user responsibility
		 * Notice this method is deprecated and will be deleted in the future
		 * @param[in] arr A pointer to where array will be allocated
		 * @param[out] length Returns the length in bytes of the array that was allocated
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future")]]
		#endif
		void copyTo(uint8_t** arr, size_t& length) const;

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * Notice this method is deprecated and will be deleted in the future
		 * This method assumes array allocated size is at least 16 (the size of an IPv6 address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future")]]
		#endif
		void copyTo(uint8_t* arr) const;

		/**
		 * A static value representing a zero value of IPv6 address, meaning address of value "0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
		 * Notice this value can be omitted in the user code because the default constructor creates an instance with an unspecified/zero address.
		 * In order to check whether the address is zero the method isUnspecified can be used
		 */
		static const IPv6Address Zero;

	private:
		in6_addr m_In6Addr;
	}; // class IPv6Address


	// Creation of IPv6Address

	/**
	 * A function that creates an instance of the class IPv6Address out of 16-byte array.
	 * @param[in] bytes The address as 16-byte array in network byte order
	 * @return An instance of class IPv6Address
	 */
	inline IPv6Address makeIPv6Address(const uint8_t bytes[16]) { return IPv6Address(bytes); }

	/**
	 * A function that creates an instance of the class out of string (char*) value
	 * If the string doesn't represent a valid IPv6 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The string (char*) representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPv6Address. If an error occured the return address will be an unspecified/zero
	 */
	IPv6Address makeIPv6Address(const char* addrAsString, int& errorCode);

	/**
	 * A function that creates an instance of the class out of std::string value
	 * If the string doesn't represent a valid IPv6 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The std::string representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPv6Address. If an error occured the return address will be an unspecified/zero
	 */
	inline IPv6Address makeIPv6Address(const std::string& addrAsString, int& errorCode) {	return makeIPv6Address(addrAsString.c_str(), errorCode); }



	///**
	// * @class IPAddress
	// * The class is a version-independent representation for an IP address
	// */
	class IPAddress
	{
	public:
		/**
		 * An enum representing the address type: IPv4 or IPv6
		 */
		enum AddressType
		{
			/**
			 * IPv4 address type
			 */
			IPv4AddressType,
			/**
			 * IPv6 address type
			 */
			IPv6AddressType
		};

		/**
		 * A default constructor that creates an instance of the class with unspecified IPv4 address
		 */
		IPAddress() : m_Type(IPv4AddressType) {}

		/**
		 * A constructor that creates an instance of the class out of IPv4Address.
		 * @param[in] addr A const reference to instance of IPv4Address
		 */
		IPAddress(const IPv4Address& addr) : m_Type(IPv4AddressType), m_IPv4(addr) {}

		/**
		 * A constructor that creates an instance of the class out of IPv6Address.
		 * @param[in] addr A const reference to instance of IPv6Address
		 */
		IPAddress(const IPv6Address& addr) : m_Type(IPv6AddressType), m_IPv6(addr) {}

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv4Address
		 */
		inline IPAddress& operator=(const IPv4Address& addr);

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv6Address
		 */
		inline IPAddress& operator=(const IPv6Address& addr);

		/**
		 * Gets the address type: IPv4 or IPv6
		 * @return The address type
		 */
		AddressType getType() const { return static_cast<AddressType>(m_Type); }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const { return (getType() == IPv4AddressType) ? m_IPv4.toString() : m_IPv6.toString();	}

		/**
		 * Determine whether the address is unspecified
		 */
		bool isUnspecified() const { return (getType() == IPv4AddressType) ? m_IPv4.isUnspecified() : m_IPv6.isUnspecified(); }

		/**
		 * Determine whether the object contains an IP version 4 address
		 */
		bool isIPv4() const { return getType() == IPv4AddressType; }

		/**
		 * Determine whether the object contains an IP version 6 address
		 */
		bool isIPv6() const { return getType() == IPv6AddressType; }

		/**
		 * Get a reference to IPv4 address instance
		 * @return The const reference to IPv4Address instance
		 */
		const IPv4Address& getIPv4() const { return m_IPv4; }

		/**
		 * Get a reference to IPv6 address instance
		 * @return The const reference to IPv6Address instance
		 */
		const IPv6Address& getIPv6() const { return m_IPv6; }

		/**
		 * Overload of the equal-to operator
		 */
		inline bool operator==(const IPAddress& rhs) const;

		/**
		 * Overload of the not-equal-to operator
		 */
		bool operator!=(const IPAddress& rhs) const { return !(*this == rhs); }


		// Following methods are placed for backward compatibility and will be deleted in the future

		/**
		 * Clone the object
		 * Notice this method is deprecated and will be deleted in the future
		 * @return A newly allocated instance which is a clone of the current instance
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future")]]
		#endif
		IPAddress *clone() const { return new IPAddress(*this); }

		/**
		 * Compare between this IP address and another IP address
		 * Notice this method is deprecated and will be deleted in the future. Prefer an equal-to operator
		 * @return True if addresses match or false otherwise
		 */
		#if __cplusplus > 201402L || _MSC_VER >= 1900
		[[deprecated("This method is now unnecessary and added for backward compatibility. It will be deleted in the future. Prefer an equal-to operator")]]
		#endif
		bool equals(const IPAddress* other) const { return *this == *other; }

	private:
		uint8_t m_Type;
		IPv4Address m_IPv4;
		IPv6Address m_IPv6;
	};


	// implementation of inline methods

	bool IPAddress::operator==(const IPAddress& rhs) const
	{
		if (isIPv4())
			return rhs.isIPv4() ? (m_IPv4 == rhs.m_IPv4) : false;

		return m_IPv6 == rhs.m_IPv6;
	}

	IPAddress& IPAddress::operator=(const IPv4Address& addr)
	{
		m_Type = IPv4AddressType;
		m_IPv4 = addr;
		return *this;
	}

	IPAddress& IPAddress::operator=(const IPv6Address& addr)
	{
		m_Type = IPv6AddressType;
		m_IPv6 = addr;
		return *this;
	}


	// Creation of IPAddress

	/**
	 * A function that creates an instance of the class out of string (char*) value
	 * If the string doesn't represent a valid IPv6 or IPv4 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The string (char*) representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPAddress. If an error occured the return value will contain an unspecified IPv4Address address
	 */
	IPAddress makeAddress(const char* addrAsString, int& errorCode);

	/**
	 * A function that creates an instance of the class out of std::string value
	 * If the string doesn't represent a valid IPv6 or IPv4 address an errorCode will be set to non-zero value
	 * @param[in] addressAsString The std::string representation of the address
	 * @param[out] errorCode Contains 0 if a string represents a valid address, otherwise a non-zero value
	 * @return An instance of class IPAddress. If an error occured the return value will contain an unspecified IPv4Address address
	 */
	inline IPAddress makeAddress(const std::string& addrAsString, int& errorCode) { return makeAddress(addrAsString.c_str(), errorCode); }

} // namespace experimental


	// TODO: remove following functions when migration has completed
	inline bool operator==(const IPv4Address& lhs, const pcpp::experimental::IPv4Address& rhs) { return lhs.toInt() == rhs.toUInt();	}
	inline bool operator==(const pcpp::experimental::IPv4Address& lhs, const IPv4Address& rhs) { return rhs == lhs; }
	inline bool operator!=(const IPv4Address &lhs, const pcpp::experimental::IPv4Address &rhs) { return !(lhs == rhs); }
	inline bool operator!=(const pcpp::experimental::IPv4Address &lhs, const IPv4Address &rhs) { return !(lhs == rhs); }

	inline bool operator==(const IPv6Address& lhs, const pcpp::experimental::IPv6Address& rhs) { return memcmp(lhs.toIn6Addr()->s6_addr, rhs.toBytes(), 16) == 0; }
	inline bool operator==(const pcpp::experimental::IPv6Address& lhs, const IPv6Address& rhs) { return rhs == lhs; }
	inline bool operator!=(const IPv6Address& lhs, const pcpp::experimental::IPv6Address& rhs) { return !(lhs == rhs); }
	inline bool operator!=(const pcpp::experimental::IPv6Address& lhs, const IPv6Address& rhs) { return !(lhs == rhs); }

} // namespace pcpp

#endif /* PCAPPP_IPADDRESS */
