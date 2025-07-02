#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <ostream>
#include <array>
#include <memory>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	// forward declarations
	class IPv4Network;
	class IPv6Network;

	// The implementation of the classes is based on document N4771 "Working Draft, C++ Extensions for Networking"
	// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/n4771.pdf

	/// @class IPv4Address
	/// Represents an IPv4 address (of type XXX.XXX.XXX.XXX)
	class IPv4Address
	{
	public:
		/// A default constructor that creates an instance of the class with the zero-initialized address
		IPv4Address() = default;

		/// A constructor that creates an instance of the class out of 4-byte integer value.
		/// @param[in] addrAsInt The address as 4-byte integer in network byte order
		IPv4Address(const uint32_t addrAsInt)
		{
			memcpy(m_Bytes.data(), &addrAsInt, sizeof(addrAsInt));
		}

		/// A constructor that creates an instance of the class out of 4-byte array.
		/// @param[in] bytes The address as 4-byte array in network byte order
		IPv4Address(const uint8_t bytes[4])
		{
			memcpy(m_Bytes.data(), bytes, 4 * sizeof(uint8_t));
		}

		/// A constructor that creates an instance of the class out of a 4-byte standard array.
		/// @param[in] bytes The address as 4-byte standard array in network byte order
		IPv4Address(const std::array<uint8_t, 4>& bytes) : m_Bytes(bytes)
		{}

		/// A constructor that creates an instance of the class out of std::string value.
		/// @param[in] addrAsString The std::string representation of the address
		/// @throws std::invalid_argument The provided string does not represent a valid IPv4 address.
		IPv4Address(const std::string& addrAsString);

		/// @return A 4-byte integer in network byte order representing the IPv4 address
		inline uint32_t toInt() const;

		/// @return A non-owning pointer to 4-byte C-style array representing the IPv4 address
		const uint8_t* toBytes() const
		{
			return m_Bytes.data();
		}

		/// @return A reference to a 4-byte standard array representing the IPv4 address
		const std::array<uint8_t, 4>& toByteArray() const
		{
			return m_Bytes;
		}

		/// @return A string representation of the address
		std::string toString() const;

		/// @return True if an address is multicast, false otherwise.
		bool isMulticast() const;

		/// Overload of the equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are equal, false otherwise
		bool operator==(const IPv4Address& rhs) const
		{
			return toInt() == rhs.toInt();
		}

		/// Overload of the less-than operator
		/// @param[in] rhs The object to compare with
		/// @return True if the address value is lower than the other address value, false otherwise
		bool operator<(const IPv4Address& rhs) const
		{
			uint32_t intVal = toInt();
			std::reverse(reinterpret_cast<uint8_t*>(&intVal), reinterpret_cast<uint8_t*>(&intVal) + sizeof(intVal));

			uint32_t rhsIntVal = rhs.toInt();
			std::reverse(reinterpret_cast<uint8_t*>(&rhsIntVal),
			             reinterpret_cast<uint8_t*>(&rhsIntVal) + sizeof(rhsIntVal));

			return intVal < rhsIntVal;
		}

		/// Overload of the not-equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are not equal, false otherwise
		bool operator!=(const IPv4Address& rhs) const
		{
			return !(*this == rhs);
		}

		/// Checks whether the address matches a network.
		/// @param network An IPv4Network network
		/// @return True if the address matches the network or false otherwise
		bool matchNetwork(const IPv4Network& network) const;

		/// Checks whether the address matches a network.
		/// For example: this method will return true for address 10.1.1.9 and network which is one of:
		/// 10.1.1.1/24, 10.1.1.1/255.255.255.0
		/// Another example: this method will return false for address 11.1.1.9 and network which is one of:
		/// 10.1.1.1/16, 10.1.1.1/255.255.0.0
		/// @param[in] network A string in one of these formats:
		///  - X.X.X.X/Y where X.X.X.X is a valid IP address and Y is a number between 0 and 32
		///  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IP address and Y.Y.Y.Y is a valid netmask
		/// @return True if the address matches the network or false if it doesn't or if the network is invalid
		bool matchNetwork(const std::string& network) const;

		/// A static method that checks whether a string represents a valid IPv4 address
		/// @param[in] addrAsString The std::string representation of the address
		/// @return True if the address is valid, false otherwise
		static bool isValidIPv4Address(const std::string& addrAsString);

		/// A static value representing a zero value of IPv4 address, meaning address of value "0.0.0.0".
		static const IPv4Address Zero;

		/// A static values representing the lower and upper bound of IPv4 multicast ranges. The bounds are inclusive.
		/// MulticastRangeLowerBound is initialized to "224.0.0.0".
		/// MulticastRangeUpperBound is initialized to "239.255.255.255".
		/// In order to check whether the address is a multicast address the isMulticast method can be used.
		static const IPv4Address MulticastRangeLowerBound;
		static const IPv4Address MulticastRangeUpperBound;

	private:
		std::array<uint8_t, 4> m_Bytes = { 0 };
	};  // class IPv4Address

	// Implementation of inline methods

	uint32_t IPv4Address::toInt() const
	{
		uint32_t addr = 0;
		memcpy(&addr, m_Bytes.data(), m_Bytes.size() * sizeof(uint8_t));
		return addr;
	}

	/// @class IPv6Address
	/// Represents an IPv6 address (of type xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx).
	class IPv6Address
	{
	public:
		/// A default constructor that creates an instance of the class with the zero-initialized address.
		IPv6Address() = default;

		/// A constructor that creates an instance of the class out of 16-byte array.
		/// @param[in] bytes The address as 16-byte array in network byte order
		IPv6Address(const uint8_t bytes[16])
		{
			memcpy(m_Bytes.data(), bytes, 16 * sizeof(uint8_t));
		}

		/// A constructor that creates an instance of the class out of a 16-byte standard array.
		/// @param[in] bytes The address as 16-byte standard array in network byte order
		IPv6Address(const std::array<uint8_t, 16>& bytes) : m_Bytes(bytes)
		{}

		/// A constructor that creates an instance of the class out of std::string value.
		/// @param[in] addrAsString The std::string representation of the address
		/// @throws std::invalid_argument The provided string does not represent a valid IPv6 address.
		IPv6Address(const std::string& addrAsString);

		/// Returns a view of the IPv6 address as a 16-byte raw C-style array
		/// @return A non-owning pointer to 16-byte array representing the IPv6 address
		const uint8_t* toBytes() const
		{
			return m_Bytes.data();
		}

		/// Returns a view of the IPv6 address as a std::array of bytes
		/// @return A reference to a 16-byte standard array representing the IPv6 address
		const std::array<uint8_t, 16>& toByteArray() const
		{
			return m_Bytes;
		}

		/// Returns a std::string representation of the address
		/// @return A string representation of the address
		std::string toString() const;

		/// Determine whether the address is a multicast address
		/// @return True if an address is multicast
		bool isMulticast() const;

		/// Overload of the equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are equal, false otherwise
		bool operator==(const IPv6Address& rhs) const
		{
			return memcmp(toBytes(), rhs.toBytes(), sizeof(m_Bytes)) == 0;
		}

		/// Overload of the less-than operator
		/// @param[in] rhs The object to compare with
		/// @return True if the address value is lower than the other address value, false otherwise
		bool operator<(const IPv6Address& rhs) const
		{
			return memcmp(toBytes(), rhs.toBytes(), sizeof(m_Bytes)) < 0;
		}

		/// Overload of the not-equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are not equal, false otherwise
		bool operator!=(const IPv6Address& rhs) const
		{
			return !(*this == rhs);
		}

		/// Allocates a byte array and copies address value into it. Array deallocation is user responsibility
		/// @param[in] arr A pointer to where array will be allocated
		/// @param[out] length Returns the length in bytes of the array that was allocated
		void copyTo(uint8_t** arr, size_t& length) const;

		/// Gets a pointer to an already allocated byte array and copies the address value to it.
		/// This method assumes array allocated size is at least 16 (the size of an IPv6 address)
		/// @param[in] arr A pointer to the array which address will be copied to
		void copyTo(uint8_t* arr) const
		{
			memcpy(arr, m_Bytes.data(), m_Bytes.size() * sizeof(uint8_t));
		}

		/// Checks whether the address matches a network.
		/// @param network An IPv6Network network
		/// @return True if the address matches the network or false otherwise
		bool matchNetwork(const IPv6Network& network) const;

		/// Checks whether the address matches a network.
		/// For example: this method will return true for address d6e5:83dc:0c58:bc5d:1449:5898:: and network
		/// which is one of:
		/// d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		/// Another example: this method will return false for address d6e5:83dc:: and network which is one of:
		/// d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		/// @param[in] network A string in one of these formats:
		///  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address and Y is a number between 0 and 128
		///  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address and IPV6_NETMASK is a valid
		///    IPv6 netmask
		/// @return True if the address matches the network or false if it doesn't or if the network is invalid
		bool matchNetwork(const std::string& network) const;

		/// A static method that checks whether a string represents a valid IPv6 address
		/// @param[in] addrAsString The std::string representation of the address
		/// @return True if the address is valid, false otherwise
		static bool isValidIPv6Address(const std::string& addrAsString);

		/// A static value representing a zero value of IPv6 address, meaning address of value
		/// "0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0".
		static const IPv6Address Zero;

		/// A static value representing the lower bound of IPv6 multicast ranges. The bound is inclusive.
		/// MulticastRangeLowerBound is initialized to "ff00:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0".
		/// In order to check whether the address is a multicast address the isMulticast method can be used.
		static const IPv6Address MulticastRangeLowerBound;

	private:
		std::array<uint8_t, 16> m_Bytes = { 0 };
	};  // class IPv6Address

	/// @class IPAddress
	/// The class is a version-independent representation for an IP address
	class IPAddress
	{
	public:
		/// An enum representing the address type: IPv4 or IPv6
		enum AddressType : uint8_t
		{
			/// IPv4 address type
			IPv4AddressType,
			/// IPv6 address type
			IPv6AddressType
		};

		/// A default constructor that creates an instance of the class with unspecified IPv4 address
		IPAddress() : m_Type(IPv4AddressType)
		{}

		/// A constructor that creates an instance of the class out of IPv4Address.
		/// @param[in] addr A const reference to instance of IPv4Address
		IPAddress(const IPv4Address& addr) : m_Type(IPv4AddressType), m_IPv4(addr)
		{}

		/// A constructor that creates an instance of the class out of IPv6Address.
		/// @param[in] addr A const reference to instance of IPv6Address
		IPAddress(const IPv6Address& addr) : m_Type(IPv6AddressType), m_IPv6(addr)
		{}

		/// A constructor that creates an instance of the class out of std::string value
		/// @param[in] addrAsString The std::string representation of the address
		/// @throws std::invalid_argument The provided string does not represent a valid IPv4 or IPv6 address.
		IPAddress(const std::string& addrAsString);

		/// Overload of an assignment operator.
		/// @param[in] addr A const reference to instance of IPv4Address
		/// @return A reference to the assignee
		inline IPAddress& operator=(const IPv4Address& addr);

		/// Overload of an assignment operator.
		/// @param[in] addr A const reference to instance of IPv6Address
		/// @return A reference to the assignee
		inline IPAddress& operator=(const IPv6Address& addr);

		/// Gets the address type: IPv4 or IPv6
		/// @return The address type
		AddressType getType() const
		{
			return static_cast<AddressType>(m_Type);
		}

		/// Returns a std::string representation of the address
		/// @return A string representation of the address
		std::string toString() const
		{
			return (getType() == IPv4AddressType) ? m_IPv4.toString() : m_IPv6.toString();
		}

		/// @return Determine whether the object contains an IP version 4 address
		bool isIPv4() const
		{
			return getType() == IPv4AddressType;
		}

		/// @return Determine whether the object contains an IP version 6 address
		bool isIPv6() const
		{
			return getType() == IPv6AddressType;
		}

		/// Determine whether the address is a multicast address
		/// @return True if an address is multicast
		bool isMulticast() const
		{
			return (getType() == IPv4AddressType) ? m_IPv4.isMulticast() : m_IPv6.isMulticast();
		}

		/// Get a reference to IPv4 address instance
		/// @return The const reference to IPv4Address instance
		const IPv4Address& getIPv4() const
		{
			return m_IPv4;
		}

		/// Get a reference to IPv6 address instance
		/// @return The const reference to IPv6Address instance
		const IPv6Address& getIPv6() const
		{
			return m_IPv6;
		}

		/// @return True if the address is zero, false otherwise
		bool isZero() const
		{
			return (getType() == IPv4AddressType) ? m_IPv4 == IPv4Address::Zero : m_IPv6 == IPv6Address::Zero;
		}

		/// Overload of the equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are equal, false otherwise
		inline bool operator==(const IPAddress& rhs) const;

		/// Overload of the less-than operator
		/// @param[in] rhs The object to compare with
		/// @return True if the address value is lower than the other address value, false otherwise
		inline bool operator<(const IPAddress& rhs) const;

		/// Overload of the not-equal-to operator
		/// @param[in] rhs The object to compare with
		/// @return True if the addresses are not equal, false otherwise
		bool operator!=(const IPAddress& rhs) const
		{
			return !(*this == rhs);
		}

	private:
		uint8_t m_Type;
		IPv4Address m_IPv4;
		IPv6Address m_IPv6;
	};

	// implementation of inline methods

	bool IPAddress::operator==(const IPAddress& rhs) const
	{
		if (isIPv4())
		{
			return rhs.isIPv4() ? (m_IPv4 == rhs.m_IPv4) : false;
		}

		return rhs.isIPv6() ? m_IPv6 == rhs.m_IPv6 : false;
	}

	bool IPAddress::operator<(const IPAddress& rhs) const
	{
		if (isIPv4())
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

	/// @class IPv4Network
	/// A class representing IPv4 network definition
	class IPv4Network
	{
	public:
		/// A constructor that creates an instance of the class out of an address and a full prefix length,
		/// essentially making a network of consisting of only 1 address.
		/// @param address An address representing the network prefix.
		explicit IPv4Network(const IPv4Address& address) : IPv4Network(address, 32U)
		{}

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a prefix length
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param prefixLen A number between 0 and 32 representing the prefix length.
		/// @throws std::invalid_argument Prefix length is out of acceptable range.
		IPv4Network(const IPv4Address& address, uint8_t prefixLen);

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a netmask
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param netmask A string representing a netmask in the format of X.X.X.X, for example: 255.255.0.0.
		/// Please notice that netmasks that start with zeros are invalid, for example: 0.0.255.255. The only netmask
		/// starting with zeros that is valid is 0.0.0.0.
		/// @throws std::invalid_argument The provided netmask is invalid.
		IPv4Network(const IPv4Address& address, const std::string& netmask);

		/// A constructor that creates an instance of the class out of a string representing the network prefix and
		/// a prefix length or a netmask
		/// @param addressAndNetmask A string in one of these formats:
		///  - X.X.X.X/Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y is a number between
		///    0 and 32 representing the network prefix
		///  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y.Y.Y.Y is
		///    a valid netmask
		/// @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		IPv4Network(const std::string& addressAndNetmask);

		/// @return The prefix length, for example: the prefix length of 10.10.10.10/255.0.0.0 is 8
		uint8_t getPrefixLen() const;

		/// @return The netmask, for example: the netmask of 10.10.10.10/8 is 255.0.0.0
		std::string getNetmask() const
		{
			return IPv4Address(m_Mask).toString();
		}

		/// @return The network prefix, for example: the network prefix of 10.10.10.10/16 is 10.10.0.0
		IPv4Address getNetworkPrefix() const
		{
			return m_NetworkPrefix;
		}

		/// @return The lowest non-reserved IPv4 address in this network, for example: the lowest address
		/// in 10.10.10.10/16 is 10.10.0.1
		IPv4Address getLowestAddress() const;

		/// @return The highest non-reserved IPv4 address in this network, for example: the highest address
		/// in 10.10.10.10/16 is 10.10.255.254
		IPv4Address getHighestAddress() const;

		/// @return The number of addresses in this network including reserved addresses, for example:
		/// the number of addresses in 10.10.0.0/24 is 256
		uint64_t getTotalAddressCount() const;

		/// @param address An IPv4 address
		/// @return True is the address belongs to the network, false otherwise or if the address isn't valid
		bool includes(const IPv4Address& address) const;

		/// @param network An IPv4 network
		/// @return True is the input network is completely included within this network, false otherwise, for example:
		/// 10.10.10.10/16 includes 10.10.10.10/24 but doesn't include 10.10.10.10/8
		bool includes(const IPv4Network& network) const;

		/// @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		/// 192.168.0.0/16
		std::string toString() const;

	private:
		uint32_t m_NetworkPrefix{};
		uint32_t m_Mask{};

		static bool isValidNetmask(const IPv4Address& netmaskAddress);
		void initFromAddressAndPrefixLength(const IPv4Address& address, uint8_t prefixLen);
		void initFromAddressAndNetmask(const IPv4Address& address, const IPv4Address& netmaskAddress);
	};

	/// @class IPv6Network
	/// A class representing IPv6 network definition
	class IPv6Network
	{
	public:
		/// A constructor that creates an instance of the class out of an address and a full prefix length,
		/// essentially making a network of consisting of only 1 address.
		/// @param address An address representing the network prefix.
		explicit IPv6Network(const IPv6Address& address) : IPv6Network(address, 128U)
		{}

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a prefix length
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param prefixLen A number between 0 and 128 representing the prefix length.
		/// @throws std::invalid_argument Prefix length is out of acceptable range.
		IPv6Network(const IPv6Address& address, uint8_t prefixLen);

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a netmask
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param netmask A string representing a netmask in valid IPv6 format, for example: ffff:ffff::.
		/// Please notice that netmasks that start with zeros are invalid, for example: 0:ffff::. The only netmask
		/// starting with zeros that is valid is all zeros (::).
		/// @throws std::invalid_argument The provided netmask is invalid.
		IPv6Network(const IPv6Address& address, const std::string& netmask);

		/// A constructor that creates an instance of the class out of a string representing the network prefix and
		/// a prefix length or a netmask
		/// @param addressAndNetmask A string in one of these formats:
		///  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address representing the network prefix and Y is
		///    a number between 0 and 128 representing the network prefix
		///  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address representing the network prefix
		///    and IPV6_NETMASK is a valid IPv6 netmask
		/// @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		IPv6Network(const std::string& addressAndNetmask);

		/// @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16
		uint8_t getPrefixLen() const;

		/// @return The netmask, for example: the netmask of 3546::/16 is ffff::
		std::string getNetmask() const
		{
			return IPv6Address(m_Mask).toString();
		}

		/// @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::
		IPv6Address getNetworkPrefix() const
		{
			return { m_NetworkPrefix };
		}

		/// @return The lowest non-reserved IPv6 address in this network, for example: the lowest address in 3546::/16
		/// is 3546::1
		IPv6Address getLowestAddress() const;

		/// @return The highest IPv6 address in this network, for example: the highest address in 3546::/16 is
		/// 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff
		IPv6Address getHighestAddress() const;

		/// @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256.
		/// If the number of addresses exceeds the size of uint64_t a std::out_of_range exception is thrown
		uint64_t getTotalAddressCount() const;

		/// @param address An IPv6 address
		/// @return True is the address belongs to the network, false otherwise or if the address isn't valid
		bool includes(const IPv6Address& address) const;

		/// @param network An IPv6 network
		/// @return True is the input network is completely included within this network, false otherwise, for example:
		/// 3546::/64 includes 3546::/120 but doesn't include 3546::/16
		bool includes(const IPv6Network& network) const;

		/// @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		/// fda7:9f81:6c23:275::/64
		std::string toString() const;

	private:
		uint8_t m_NetworkPrefix[16]{};
		uint8_t m_Mask[16]{};

		static bool isValidNetmask(const IPv6Address& netmaskAddress);
		void initFromAddressAndPrefixLength(const IPv6Address& address, uint8_t prefixLen);
		void initFromAddressAndNetmask(const IPv6Address& address, const IPv6Address& netmaskAddress);
	};

	/// @class IPNetwork
	/// A class representing version independent IP network definition, both IPv4 and IPv6 are included
	class IPNetwork
	{
	public:
		/// A constructor that creates an instance of the class out of an IP address and a full prefix length,
		/// essentially making a network of consisting of only 1 address.
		/// @param address An address representing the network prefix.
		explicit IPNetwork(const IPAddress& address) : IPNetwork(address, address.isIPv4() ? 32U : 128U)
		{}

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a prefix length
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param prefixLen A number representing the prefix length. Allowed ranges are 0 - 32 for IPv4 networks and 0
		/// - 128 for IPv6 networks.
		/// @throws std::invalid_argument Prefix length is out of acceptable range.
		IPNetwork(const IPAddress& address, uint8_t prefixLen)
		{
			if (address.isIPv4())
			{
				m_IPv4Network = std::make_unique<IPv4Network>(address.getIPv4(), prefixLen);
			}
			else
			{
				m_IPv6Network = std::make_unique<IPv6Network>(address.getIPv6(), prefixLen);
			}
		}

		/// A constructor that creates an instance of the class out of an address representing the network prefix
		/// and a netmask
		/// @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		/// exception is thrown
		/// @param netmask A string representing a netmask in valid format, for example: ffff:ffff:: for IPv6 networks
		/// or 255.255.0.0 for IPv4 networks.
		/// Please notice that netmasks that start with zeros are invalid, for example: 0:ffff:: or 0.255.255.255.
		/// The only netmask starting with zeros that is valid is all zeros (:: or 0.0.0.0).
		/// @throws std::invalid_argument The provided netmask is invalid.
		IPNetwork(const IPAddress& address, const std::string& netmask)
		{
			if (address.isIPv4())
			{
				m_IPv4Network = std::make_unique<IPv4Network>(address.getIPv4(), netmask);
			}
			else
			{
				m_IPv6Network = std::make_unique<IPv6Network>(address.getIPv6(), netmask);
			}
		}

		/// A constructor that creates an instance of the class out of a string representing the network prefix and
		/// a prefix length or a netmask
		/// @param addressAndNetmask A string in one of these formats:
		///  - IP_ADDRESS/Y where IP_ADDRESS is a valid IP address representing the network prefix and Y is
		///    a number representing the network prefix
		///  - IP_ADDRESS/NETMASK where IP_ADDRESS is a valid IP address representing the network prefix and NETMASK
		///    is a valid netmask for this type of network (IPv4 or IPv6 network)
		/// @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		IPNetwork(const std::string& addressAndNetmask)
		{
			try
			{
				m_IPv4Network = std::make_unique<IPv4Network>(addressAndNetmask);
			}
			catch (const std::invalid_argument&)
			{
				m_IPv6Network = std::make_unique<IPv6Network>(addressAndNetmask);
			}
		}

		/// A copy c'tor for this class
		/// @param other The instance to copy from
		IPNetwork(const IPNetwork& other)
		{
			if (other.m_IPv4Network)
			{
				m_IPv4Network = std::make_unique<IPv4Network>(*other.m_IPv4Network);
			}

			if (other.m_IPv6Network)
			{
				m_IPv6Network = std::make_unique<IPv6Network>(*other.m_IPv6Network);
			}
		}

		/// Overload of an assignment operator.
		/// @param[in] other An instance of IPNetwork to assign
		/// @return A reference to the assignee
		IPNetwork& operator=(const IPNetwork& other)
		{
			// NOLINTBEGIN(cppcoreguidelines-c-copy-assignment-signature,misc-unconventional-assign-operator)
			if (other.isIPv4Network())
			{
				return this->operator=(*other.m_IPv4Network);
			}

			return this->operator=(*other.m_IPv6Network);
			// NOLINTEND(cppcoreguidelines-c-copy-assignment-signature,misc-unconventional-assign-operator)
		}

		/// Overload of an assignment operator.
		/// @param[in] other An instance of IPv4Network to assign
		/// @return A reference to the assignee
		IPNetwork& operator=(const IPv4Network& other)
		{
			// Create the new instance first to maintain strong exception guarantee.
			m_IPv4Network = std::make_unique<IPv4Network>(other);
			m_IPv6Network = nullptr;
			return *this;
		}

		/// Overload of an assignment operator.
		/// @param[in] other An instance of IPv6Network to assign
		/// @return A reference to the assignee
		IPNetwork& operator=(const IPv6Network& other)
		{
			// Create the new instance first to maintain strong exception guarantee.
			m_IPv6Network = std::make_unique<IPv6Network>(other);
			m_IPv4Network = nullptr;
			return *this;
		}

		/// @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16, the prefix length of
		/// 10.10.10.10/255.0.0.0 is 8
		uint8_t getPrefixLen() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getPrefixLen() : m_IPv6Network->getPrefixLen());
		}

		/// @return The netmask, for example: the netmask of 3546::/16 is ffff::, the netmask of 10.10.10.10/8 is
		/// 255.0.0.0
		std::string getNetmask() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getNetmask() : m_IPv6Network->getNetmask());
		}

		/// @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::, the network prefix
		/// of 10.10.10.10/16 is 10.10.0.0
		IPAddress getNetworkPrefix() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getNetworkPrefix())
			                                 : IPAddress(m_IPv6Network->getNetworkPrefix()));
		}

		/// @return The lowest non-reserved IP address in this network, for example: the lowest address in 3546::/16 is
		/// 3546::1, the lowest address in 10.10.10.10/16 is 10.10.0.1
		IPAddress getLowestAddress() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getLowestAddress())
			                                 : IPAddress(m_IPv6Network->getLowestAddress()));
		}

		/// @return The highest non-reserved IP address in this network, for example: the highest address in 3546::/16
		/// is 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the highest address in 10.10.10.10/16 is 10.10.255.254
		IPAddress getHighestAddress() const
		{
			return (m_IPv4Network != nullptr ? IPAddress(m_IPv4Network->getHighestAddress())
			                                 : IPAddress(m_IPv6Network->getHighestAddress()));
		}

		/// @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256,
		/// the number of addresses in 10.10.0.0/24 is 256. If the number of addresses exceeds the size of uint64_t
		/// a std::out_of_range exception is thrown
		uint64_t getTotalAddressCount() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->getTotalAddressCount()
			                                 : m_IPv6Network->getTotalAddressCount());
		}

		/// @return True if this is an IPv4 network, false otherwise
		bool isIPv4Network() const
		{
			return m_IPv4Network != nullptr;
		}

		/// @return True if this is an IPv6 network, false otherwise
		bool isIPv6Network() const
		{
			return m_IPv6Network != nullptr;
		}

		/// @param address An IP address
		/// @return True is the address belongs to the network, false otherwise or if the address isn't valid
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

			if (address.isIPv4())
			{
				return false;
			}

			return m_IPv6Network->includes(address.getIPv6());
		}

		/// @param network An IP network
		/// @return True is the input network is completely included within this network, false otherwise
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

			if (network.isIPv4Network())
			{
				return false;
			}

			return m_IPv6Network->includes(*network.m_IPv6Network);
		}

		/// @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		/// fda7:9f81:6c23:275::/64 or 192.168.0.0/16
		std::string toString() const
		{
			return (m_IPv4Network != nullptr ? m_IPv4Network->toString() : m_IPv6Network->toString());
		}

	private:
		std::unique_ptr<IPv4Network> m_IPv4Network;
		std::unique_ptr<IPv6Network> m_IPv6Network;
	};

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPv4Address& ipv4Address)
	{
		oss << ipv4Address.toString();
		return oss;
	}

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPv6Address& ipv6Address)
	{
		oss << ipv6Address.toString();
		return oss;
	}

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPAddress& ipAddress)
	{
		oss << ipAddress.toString();
		return oss;
	}

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPv4Network& network)
	{
		oss << network.toString();
		return oss;
	}

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPv6Network& network)
	{
		oss << network.toString();
		return oss;
	}

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::IPNetwork& network)
	{
		oss << network.toString();
		return oss;
	}
}  // namespace pcpp
