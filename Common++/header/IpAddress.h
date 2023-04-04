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
	class IPv6Network;

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
		 * Checks whether the address matches a network.
		 * @param network An IPv4Network network
		 * @return True if the address matches the network or false otherwise
		 */
		bool matchNetwork(const IPv4Network& network) const;

		/**
		 * Checks whether the address matches a network.
		 * For example: this method will return true for address 10.1.1.9 and network which is one of:
		 * 10.1.1.1/24, 10.1.1.1/255.255.255.0
		 * Another example: this method will return false for address 11.1.1.9 and network which is one of:
		 * 10.1.1.1/16, 10.1.1.1/255.255.0.0
		 * @param[in] network A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IP address and Y is a number between 0 and 32
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IP address and Y.Y.Y.Y is a valid netmask
		 *	@return True if the address matches the network or false if it doesn't or if the network is invalid
		 */
		bool matchNetwork(const std::string& network) const;

		/**
		 * @deprecated This method is deprecated, please use matchNetwork(const IPv4Network& network)
		 */
		PCPP_DEPRECATED bool matchSubnet(const IPv4Address& subnet, const std::string& subnetMask) const;

		/**
		 * @deprecated This method is deprecated, please use matchNetwork(const IPv4Network& network)
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
		 * Checks whether the address matches a network.
		 * @param network An IPv6Network network
		 * @return True if the address matches the network or false otherwise
		 */
		bool matchNetwork(const IPv6Network& network) const;

		/**
		 * Checks whether the address matches a network.
		 * For example: this method will return true for address d6e5:83dc:0c58:bc5d:1449:5898:: and network
		 * which is one of:
		 * d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		 * Another example: this method will return false for address d6e5:83dc:: and network which is one of:
		 * d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		 * @param[in] network A string in one of these formats:
		 *  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address and Y is a number between 0 and 128
		 *  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address and IPV6_NETMASK is a valid
		 *    IPv6 netmask
		 *	@return True if the address matches the network or false if it doesn't or if the network is invalid
		 */
		bool matchNetwork(const std::string& network) const;

		/**
		  * @deprecated This method is deprecated, please use matchNetwork(const IPv6Network& network)
		  */
		PCPP_DEPRECATED bool matchSubnet(const IPv6Address& subnet, uint8_t prefixLength) const;

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
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in the format of X.X.X.X, for example: 255.255.0.0.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0.0.255.255. The only netmask
		 * starting with zeros that is valid is 0.0.0.0. If the netmask is invalid std::invalid_argument
		 * exception is thrown
		 */
		IPv4Network(const IPv4Address& address, const std::string& netmask);

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y is a number between
		 *    0 and 32 representing the network prefix
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y.Y.Y.Y is
		 *    a valid netmask
		 *  For any invalid value std::invalid_argument is thrown
		 */
		IPv4Network(const std::string& addressAndNetmask);

		/**
		 * @return The prefix length, for example: the prefix length of 10.10.10.10/255.0.0.0 is 8
		 */
		uint8_t getPrefixLen() const;

		/**
		 * @return The netmask, for example: the netmask of 10.10.10.10/8 is 255.0.0.0
		 */
		std::string getNetmask() const { return IPv4Address(m_Mask).toString(); }

		/**
		 * @return The network prefix, for example: the network prefix of 10.10.10.10/16 is 10.10.0.0
		*/
		IPv4Address getNetworkPrefix() const { return IPv4Address(m_NetworkPrefix); }

		/**
		 * @return The lowest non-reserved IPv4 address in this network, for example: the lowest address
		 * in 10.10.10.10/16 is 10.10.0.1
		 */
		IPv4Address getLowestAddress() const;

		/**
		 * @return The highest non-reserved IPv4 address in this network, for example: the highest address
		 * in 10.10.10.10/16 is 10.10.255.254
		 */
		IPv4Address getHighestAddress() const;

		/**
		 * @return The number of addresses in this network including reserved addresses, for example:
		 * the number of addresses in 10.10.0.0/24 is 256
		 */
		uint64_t getTotalAddressCount() const;

		/**
		 * @param address An IPv4 address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPv4Address& address) const;

		/**
		 * @param network An IPv4 network
		 * @return True is the input network is completely included within this network, false otherwise, for example:
		 * 10.10.10.10/16 includes 10.10.10.10/24 but doesn't include 10.10.10.10/8
		 */
		bool includes(const IPv4Network& network) const;

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * 192.168.0.0/16
		 */
		std::string toString() const;

	private:
		uint32_t m_NetworkPrefix;
		uint32_t m_Mask;

		bool isValidNetmask(const std::string& netmask);
		void initFromAddressAndPrefixLength(const IPv4Address& address, uint8_t prefixLen);
		void initFromAddressAndNetmask(const IPv4Address& address, const std::string& netmask);
	};


	/**
	 * @class IPv6Network
	 * A class representing IPv6 network definition
	 */
	class IPv6Network
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number between 0 and 128 representing the prefix length. If another value is provided
		 * std::invalid_argument exception is thrown
		 */
		IPv6Network(const IPv6Address& address, uint8_t prefixLen);

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in valid IPv6 format, for example: ffff:ffff::.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0:ffff::. The only netmask
		 * starting with zeros that is valid is all zeros (::). If the netmask is invalid std::invalid_argument
		 * exception is thrown
		 */
		IPv6Network(const IPv6Address& address, const std::string& netmask);

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address representing the network prefix and Y is
		 *    a number between 0 and 128 representing the network prefix
		 *  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address representing the network prefix
		 *    and IPV6_NETMASK is a valid IPv6 netmask
		 *  For any invalid value std::invalid_argument is thrown
		 */
		IPv6Network(const std::string& addressAndNetmask);

		/**
		 * @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16
		 */
		uint8_t getPrefixLen() const;

		/**
		 * @return The netmask, for example: the netmask of 3546::/16 is ffff::
		 */
		std::string getNetmask() const { return IPv6Address(m_Mask).toString(); }

		/**
		 * @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::
		*/
		IPv6Address getNetworkPrefix() const { return IPv6Address(m_NetworkPrefix); }

		/**
		* @return The lowest non-reserved IPv6 address in this network, for example: the lowest address in 3546::/16 is
		* 3546::1
		*/
		IPv6Address getLowestAddress() const;

		/**
		 * @return The highest IPv6 address in this network, for example: the highest address in 3546::/16 is
		 * 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff
		 */
		IPv6Address getHighestAddress() const;

		/**
		 * @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256.
		 * If the number of addresses exceeds the size of uint64_t a std::out_of_range exception is thrown
		 */
		uint64_t getTotalAddressCount() const;

		/**
		 * @param address An IPv6 address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPv6Address& address) const;

		/**
		 * @param network An IPv6 network
		 * @return True is the input network is completely included within this network, false otherwise, for example:
		 * 3546::/64 includes 3546::/120 but doesn't include 3546::/16
		 */
		bool includes(const IPv6Network& network) const;

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * fda7:9f81:6c23:275::/64
		 */
		std::string toString() const;

	private:
		uint8_t m_NetworkPrefix[16];
		uint8_t m_Mask[16];

		bool isValidNetmask(const std::string& netmask);
		void initFromAddressAndPrefixLength(const IPv6Address& address, uint8_t prefixLen);
		void initFromAddressAndNetmask(const IPv6Address& address, const std::string& netmask);
	};


	/**
	 * @class IPNetwork
	 * A class representing version independent IP network definition, both IPv4 and IPv6 are included
	 */
	class IPNetwork
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number representing the prefix length. If the value isn't in the range allowed for the
		 * network (0 - 32 for IPv4 networks or 0 - 128 for IPv6 networks) and std::invalid_argument exception is thrown
		 */
		IPNetwork(const IPAddress& address, uint8_t prefixLen)
		{
			if (address.isIPv4())
			{
				m_IPv4Network = new IPv4Network(address.getIPv4(), prefixLen);
				m_IPv6Network = nullptr;
			}
			else
			{
				m_IPv6Network = new IPv6Network(address.getIPv6(), prefixLen);
				m_IPv4Network = nullptr;
			}
		}

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in valid format, for example: ffff:ffff:: for IPv6 networks
		 * or 255.255.0.0 for IPv4 networks.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0:ffff:: or 0.255.255.255.
		 * The only netmask starting with zeros that is valid is all zeros (:: or 0.0.0.0).
		 * If the netmask is invalid std::invalid_argument exception is thrown
		 */
		IPNetwork(const IPAddress& address, const std::string& netmask)
		{
			if (address.isIPv4())
			{
				m_IPv4Network = new IPv4Network(address.getIPv4(), netmask);
				m_IPv6Network = nullptr;
			}
			else
			{
				m_IPv6Network = new IPv6Network(address.getIPv6(), netmask);
				m_IPv4Network = nullptr;
			}
		}

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - IP_ADDRESS/Y where IP_ADDRESS is a valid IP address representing the network prefix and Y is
		 *    a number representing the network prefix
		 *  - IP_ADDRESS/NETMASK where IP_ADDRESS is a valid IP address representing the network prefix and NETMASK
		 *    is a valid netmask for this type of network (IPv4 or IPv6 network)
		 *  For any invalid value std::invalid_argument is thrown
		 */
		IPNetwork(const std::string& addressAndNetmask)
		{
			try
			{
				m_IPv4Network = new IPv4Network(addressAndNetmask);
				m_IPv6Network = nullptr;
			}
			catch (const std::invalid_argument&)
			{
				m_IPv6Network = new IPv6Network(addressAndNetmask);
				m_IPv4Network = nullptr;
			}
		}

		/**
		 * A copy c'tor for this class
		 * @param other The instance to copy from
		 */
		IPNetwork(const IPNetwork& other)
		{
			m_IPv4Network = nullptr;
			m_IPv6Network = nullptr;

			if (other.m_IPv4Network)
			{
				m_IPv4Network = new IPv4Network(*other.m_IPv4Network);
			}

			if (other.m_IPv6Network)
			{
				m_IPv6Network = new IPv6Network(*other.m_IPv6Network);
			}
		}

		/**
		 * A destructor for this class
		 */
		~IPNetwork()
		{
			if (m_IPv4Network)
			{
				delete m_IPv4Network;
			}

			if (m_IPv6Network)
			{
				delete m_IPv6Network;
			}
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPNetwork to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPNetwork& other)
		{
			if (other.isIPv4Network())
			{
				return this->operator=(*other.m_IPv4Network);
			}
			else
			{
				return this->operator=(*other.m_IPv6Network);
			}
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPv4Network to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPv4Network& other)
		{
			if (m_IPv4Network)
			{
				delete m_IPv4Network;
				m_IPv4Network = nullptr;
			}

			if (m_IPv6Network)
			{
				delete m_IPv6Network;
				m_IPv6Network = nullptr;
			}

			m_IPv4Network = new IPv4Network(other);

			return *this;
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPv6Network to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPv6Network& other)
		{
			if (m_IPv4Network)
			{
				delete m_IPv4Network;
				m_IPv4Network = nullptr;
			}

			if (m_IPv6Network)
			{
				delete m_IPv6Network;
				m_IPv6Network = nullptr;
			}

			m_IPv6Network = new IPv6Network(other);

			return *this;
		}

		/**
		 * @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16, the prefix length of
		 * 10.10.10.10/255.0.0.0 is 8
		 */
		uint8_t getPrefixLen() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getPrefixLen() : m_IPv6Network->getPrefixLen());
		}

		/**
 		* @return The netmask, for example: the netmask of 3546::/16 is ffff::, the netmask of 10.10.10.10/8 is 255.0.0.0
 		*/
		std::string getNetmask() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getNetmask() : m_IPv6Network->getNetmask());
		}

		/**
		 * @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::, the network prefix
		 * of 10.10.10.10/16 is 10.10.0.0
		*/
		IPAddress getNetworkPrefix() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getNetworkPrefix()) : IPAddress(m_IPv6Network->getNetworkPrefix()));
		}

		/**
		* @return The lowest non-reserved IP address in this network, for example: the lowest address in 3546::/16 is
		* 3546::1, the lowest address in 10.10.10.10/16 is 10.10.0.1
		*/
		IPAddress getLowestAddress() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getLowestAddress()) : IPAddress(m_IPv6Network->getLowestAddress()));
		}

		/**
		 * @return The highest non-reserved IP address in this network, for example: the highest address in 3546::/16 is
		 * 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the highest address in 10.10.10.10/16 is 10.10.255.254
		 */
		IPAddress getHighestAddress() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getHighestAddress()) : IPAddress(m_IPv6Network->getHighestAddress()));
		}

		/**
		 * @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256,
		 * the number of addresses in 10.10.0.0/24 is 256. If the number of addresses exceeds the size of uint64_t
		 * a std::out_of_range exception is thrown
		 */
		uint64_t getTotalAddressCount() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getTotalAddressCount() : m_IPv6Network->getTotalAddressCount());
		}

		/**
		 * @return True if this is an IPv4 network, false otherwise
		 */
		bool isIPv4Network() const
		{
			return m_IPv4Network != nullptr;
		}

		/**
		 * @return True if this is an IPv6 network, false otherwise
		 */
		bool isIPv6Network() const
		{
			return m_IPv6Network != nullptr;
		}

		/**
		 * @param address An IP address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPAddress& address) const
		{
			if (m_IPv4Network != nullptr)
			{
				if (address.isIPv6())
				{
					return false;
				}

				return m_IPv4Network->includes(address.getIPv4());
			}
			else
			{
				if (address.isIPv4())
				{
					return false;
				}

				return m_IPv6Network->includes(address.getIPv6());
			}
		}

		/**
		 * @param network An IP network
		 * @return True is the input network is completely included within this network, false otherwise
		 */
		bool includes(const IPNetwork& network) const
		{
			if (m_IPv4Network != nullptr)
			{
				if (network.isIPv6Network())
				{
					return false;
				}

				return m_IPv4Network->includes(*network.m_IPv4Network);
			}
			else
			{
				if (network.isIPv4Network())
				{
					return false;
				}

				return m_IPv6Network->includes(*network.m_IPv6Network);
			}
		}

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * fda7:9f81:6c23:275::/64 or 192.168.0.0/16
		 */
		std::string toString() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->toString() : m_IPv6Network->toString());
		}

	private:
		IPv4Network* m_IPv4Network;
		IPv6Network* m_IPv6Network;
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

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPv4Network& network)
{
	os << network.toString();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPv6Network& network)
{
	os << network.toString();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const pcpp::IPNetwork& network)
{
	os << network.toString();
	return os;
}

#endif /* PCAPPP_IPADDRESS */
