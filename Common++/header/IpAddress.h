#ifndef PCAPPP_IP_ADDRESSES
#define PCAPPP_IP_ADDRESSES

#include <stdint.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <ostream>

#ifndef PCPP_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define PCPP_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define PCPP_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: DEPRECATED feature is not implemented for this compiler")
#define PCPP_DEPRECATED
#endif
#endif

/// @file


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	// forward declarations
	class IPv4Network;

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
		 * @param subnet An IPv4Network subnet object
		 * @return True if the address matches the subnet or false otherwise
		 */
		bool matchSubnet(const IPv4Network& subnet) const;

		/**
		 * Checks whether the address matches a subnet.
		 * For example: this method will return true for address 10.1.1.9 and subnet which is one of:
		 * 10.1.1.1/24, 10.1.1.1/255.255.255.0
		 * Another example: this method will return false for address 11.1.1.9 and subnet which is one of:
		 * 10.1.1.1/16, 10.1.1.1/255.255.0.0
		 * @param[in] subnet A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IP address and Y is a number between 0 and 32
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IP address and Y.Y.Y.Y is a valid subnet mask
		 *	@return True if the address matches the subnet or false if it doesn't or if the subnet is invalid
		 */
		bool matchSubnet(const std::string& subnet) const;

		/**
		 * @deprecated This method is deprecated, please use matchSubnet(const IPv4Network& subnet)
		 */
		PCPP_DEPRECATED bool matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const;

		/**
		 * @deprecated This method is deprecated, please use matchSubnet(const IPv4Network& subnet)
		 */
		PCPP_DEPRECATED bool matchSubnet(const IPv4Address& subnet, const IPv4Address& subnetMask) const;

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


	/**
	 * @class IPAddress
	 * The class is a version-independent representation for an IP address
	 */
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


	/**
	 * @class IPv4Network
	 * A class representing IPv4 network definition
	 */
	class IPv4Network
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number between 0 and 32 representing the prefix length. If another value is provided
		 * std::invalid_argument exception is thrown
		 */
		IPv4Network(const IPv4Address& address, uint8_t prefixLen);

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a subnet mask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param subnetMask A string representing a subnet mask in the format of X.X.X.X, for example: 255.255.0.0.
		 * Please notice that subnets that start with zeros are invalid, for example: 0.0.255.255. The only subnet mask
		 * starting with zeros that is valid is 0.0.0.0. If the subnet is invalid std::invalid_argument
		 * exception is thrown
		 */
		IPv4Network(const IPv4Address& address, const std::string& subnetMask);

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a subnet mask
		 * @param addressAndSubnet A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y is a number between
		 *    0 and 32 representing the network prefix
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y.Y.Y.Y is
		 *    a valid subnet mask
		 *  For any invalid value std::invalid_argument is thrown
		 */
		IPv4Network(const std::string& addressAndSubnet);

		/**
		 * @return The prefix length, for example: the prefix length of 10.10.10.10/255.0.0.0 is 8
		 */
		uint8_t getPrefixLen() const;

		/**
		 * @return The prefix length, for example: the subnet mask of 10.10.10.10/8 is 255.0.0.0
		 */
		std::string getSubnetMask() const { return IPv4Address(m_Mask).toString(); }

		/**
		 * @return The network prefix, for example: the network prefix of 10.10.10.10/16 is 10.10.0.0
		*/
		IPv4Address getNetworkPrefix() const { return IPv4Address(m_NetworkPrefix); }

		/**
		 * @return The lowest IPv4 address in this network, for example: the lowest address in 10.10.10.10/16 is
		 * 10.10.0.0
		 */
		IPv4Address getLowestAddress() const;

		/**
		 * @return The highest IPv4 address in this network, for example: the highest address in 10.10.10.10/16 is
		 * 10.10.255.255
		 */
		IPv4Address getHighestAddress() const;

		/**
		 * @return The number of addresses in this network, for example: the number of addresses in 10.10.0.0/8 is 256
		 */
		uint64_t getTotalAddressCount() const;

		/**
		 * @param address An IPv4 address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPv4Address& address) const;

		/**
		 * @param network An IPv4 network
		 * @return True is the input network is included within this network, false otherwise, for example:
		 * 10.10.10.10/16 includes 10.10.10.10/24 but doesn't include 10.10.10.10/8
		 */
		bool includes(const IPv4Network& network) const;

	private:
		uint32_t m_NetworkPrefix;
		uint32_t m_Mask;

		bool isValidSubnetMask(const std::string& subnetMask);
		void initFromAddressAndPrefixLength(const IPv4Address& address, uint8_t prefixLen);
		void initFromAddressAndSubnetMask(const IPv4Address& address, const std::string& subnetMask);
	};

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
