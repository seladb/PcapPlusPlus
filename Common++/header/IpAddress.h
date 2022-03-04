#ifndef PCAPPP_IP_ADDRESSES
#define PCAPPP_IP_ADDRESSES

#include <stdint.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <ostream>

/// @file


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
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
		IPv4Address() { memset(m_Bytes, 0, sizeof(m_Bytes)); }

		/**
		 * A constructor that creates an instance of the class out of 4-byte integer value.
		 * @param[in] addrAsInt The address as 4-byte integer in network byte order
		 */
		IPv4Address(uint32_t addrAsInt) { memcpy(m_Bytes, &addrAsInt, sizeof(m_Bytes)); }

		/**
		 * A constructor that creates an instance of the class out of 4-byte array.
		 * @param[in] bytes The address as 4-byte array in network byte order
		 */
		IPv4Address(const uint8_t bytes[4]) { memcpy(m_Bytes, bytes, sizeof(m_Bytes)); }

		/**
		 * A constructor that creates an instance of the class out of std::string value
		 * If the string doesn't represent a valid IPv4 address, an instance will store an unspecified address
		 * @param[in] addrAsString The std::string representation of the address
		 */
		IPv4Address(const std::string& addrAsString);

		/**
		 * Converts the IPv4 address into a 4B integer
		 * @return a 4B integer in network byte order representing the IPv4 address
		 */
		inline uint32_t toInt() const;

		/**
		 * Returns a pointer to 4-byte array representing the IPv4 address
		 */
		const uint8_t* toBytes() const { return m_Bytes; }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const;

		/**
		 * Determine whether the address is a multicast address
		 * @return True if an address is multicast
		 */
		bool isMulticast() const;

		/**
		 * Determine whether the address is valid (it's not an unspecified/zero)
		 * @return True if an address is not unspecified/zero
		 */
		bool isValid() const { return toInt() != 0; }

		/**
		 * Overload of the equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		bool operator==(const IPv4Address& rhs) const { return toInt() == rhs.toInt(); }

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		bool operator<(const IPv4Address& rhs) const
		{
			uint32_t intVal = toInt();
			std::reverse((uint8_t*)(&intVal), (uint8_t*)(&intVal) + sizeof(intVal));

			uint32_t rhsIntVal = rhs.toInt();
			std::reverse((uint8_t*)(&rhsIntVal), (uint8_t*)(&rhsIntVal) + sizeof(rhsIntVal));

			return intVal < rhsIntVal;
		}

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPv4Address& rhs) const	{ return !(*this == rhs); }

		/**
		 * Checks whether the address matches a subnet.
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask A string representing the subnet mask to compare the address with the subnet
		 */
		bool matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const;

		/**
		 * Checks whether the address matches a subnet.
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask The subnet mask to compare the address with the subnet
		 */
		bool matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const;

		/**
		 * A static value representing a zero value of IPv4 address, meaning address of value "0.0.0.0"
		 * Notice this value can be omitted in the user code because the default constructor creates an instance with an unspecified/zero address.
		 * In order to check whether the address is zero the method isValid can be used
		 */
		static const IPv4Address Zero;

		/**
		 * A static values representing the lower and upper bound of IPv4 multicast ranges. The bounds are inclusive.
		 * MulticastRangeLowerBound is initialized to "224.0.0.0".
		 * MulticastRangeUpperBound is initialized to "239.255.255.255".
		 * In order to check whether the address is a multicast address the isMulticast method can be used.
		 */
		static const IPv4Address MulticastRangeLowerBound;
		static const IPv4Address MulticastRangeUpperBound;

	private:
		uint8_t m_Bytes[4];
	}; // class IPv4Address


	// Implementation of inline methods

	uint32_t IPv4Address::toInt() const
	{
		uint32_t addr;
		memcpy(&addr, m_Bytes, sizeof(m_Bytes));
		return addr;
	}

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
		IPv6Address() { memset(m_Bytes, 0, sizeof(m_Bytes)); }

		/**
		 * A constructor that creates an instance of the class out of 16-byte array.
		 * @param[in] bytes The address as 16-byte array in network byte order
		 */
		IPv6Address(const uint8_t bytes[16]) { memcpy(m_Bytes, bytes, sizeof(m_Bytes)); }

		/**
		 * A constructor that creates an instance of the class out of std::string value
		 * If the string doesn't represent a valid IPv6 address, an instance will store an unspecified address
		 * @param[in] addrAsString The std::string representation of the address
		 */
		IPv6Address(const std::string& addrAsString);

		/**
		 * Returns a pointer to 16-byte array representing the IPv6 address
		 */
		const uint8_t* toBytes() const { return m_Bytes; }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const;

		/**
		 * Determine whether the address is a multicast address
		 * @return True if an address is multicast
		 */
		bool isMulticast() const;

		/**
		 * Determine whether the address is unspecified
		 */
		bool isValid() const { return *this != Zero; }

		/**
		 * Overload of the equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		bool operator==(const IPv6Address& rhs) const { return memcmp(toBytes(), rhs.toBytes(), sizeof(m_Bytes)) == 0; }

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		bool operator<(const IPv6Address& rhs) const { return memcmp(toBytes(), rhs.toBytes(), sizeof(m_Bytes)) < 0; }

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPv6Address &rhs) const { return !(*this == rhs); }


		/**
		 * Allocates a byte array and copies address value into it. Array deallocation is user responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 * @param[out] length Returns the length in bytes of the array that was allocated
		 */
		void copyTo(uint8_t** arr, size_t& length) const;

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 16 (the size of an IPv6 address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copyTo(uint8_t* arr) const { memcpy(arr, m_Bytes, sizeof(m_Bytes)); }

		/**
		  * Checks whether the address matches a subnet.
		  * For example: if subnet is 2001:3CA1:010F:001A::, prefixLength is 64, and address is 2001:3CA1:010F:001A:121B:0000:0000:0010, then the method will return true
		  * Another example: if subnet is 2001:3CA1:010F:001A::, prefixLength is 70 and address is 2001:3CA1:010F:001A:121B:0000:0000:0010 then the method will return false
		  * @param[in] subnet The subnet to be verified
		  * @param[in] prefixLength How many bits to use in the mask
		  */
		bool matchSubnet(const IPv6Address& subnet, uint8_t prefixLength) const;

		/**
		 * A static value representing a zero value of IPv6 address, meaning address of value "0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
		 * Notice this value can be omitted in the user code because the default constructor creates an instance with an unspecified/zero address.
		 * In order to check whether the address is zero the method isValid can be used
		 */
		static const IPv6Address Zero;

		/**
		 * A static value representing the lower bound of IPv6 multicast ranges. The bound is inclusive.
		 * MulticastRangeLowerBound is initialized to "ff00:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0".
		 * In order to check whether the address is a multicast address the isMulticast method can be used.
		 */
		static const IPv6Address MulticastRangeLowerBound;

	private:
		uint8_t m_Bytes[16];
	}; // class IPv6Address


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
		 * A constructor that creates an instance of the class out of std::string value
		 * If the string doesn't represent a valid IPv4 or IPv6 address, an instance will store an unspecified address
		 * @param[in] addrAsString The std::string representation of the address
		 */
		IPAddress(const std::string& addrAsString);

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv4Address
		 * @return A reference to the assignee
		 */
		inline IPAddress& operator=(const IPv4Address& addr);

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv6Address
		 * @return A reference to the assignee
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
		 * @return Determine whether the address is unspecified
		 */
		bool isValid() const { return (getType() == IPv4AddressType) ? m_IPv4.isValid() : m_IPv6.isValid(); }

		/**
		 * @return Determine whether the object contains an IP version 4 address
		 */
		bool isIPv4() const { return getType() == IPv4AddressType; }

		/**
		 * @return Determine whether the object contains an IP version 6 address
		 */
		bool isIPv6() const { return getType() == IPv6AddressType; }

		/**
		 * Determine whether the address is a multicast address
		 * @return True if an address is multicast
		 */
		bool isMulticast() const { return (getType() == IPv4AddressType) ? m_IPv4.isMulticast() : m_IPv6.isMulticast(); }

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
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		inline bool operator==(const IPAddress& rhs) const;

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		inline bool operator<(const IPAddress& rhs) const;

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPAddress& rhs) const { return !(*this == rhs); }

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

		return rhs.isIPv6() ? m_IPv6 == rhs.m_IPv6 : false;
	}

	bool IPAddress::operator<(const IPAddress& rhs) const
	{
		if(isIPv4())
		{
			// treat IPv4 as less than IPv6
			// If current obj is IPv4 and other is IPv6 return true
			return rhs.isIPv4() ? (m_IPv4 < rhs.m_IPv4) : true;
		}
		return rhs.isIPv6() ? m_IPv6 < rhs.m_IPv6 : false;
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

} // namespace pcpp

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPv4Address& ipv4Address)
{
	os << ipv4Address.toString();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPv6Address& ipv6Address)
{
	os << ipv6Address.toString();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPAddress& ipAddress)
{
	os << ipAddress.toString();
	return os;
}

#endif /* PCAPPP_IPADDRESS */
