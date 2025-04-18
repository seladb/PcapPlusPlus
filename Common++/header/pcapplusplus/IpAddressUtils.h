#pragma once

/// @file

// Forward declarations
struct in_addr;
struct in6_addr;

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	// Forward declarations
	class IPv4Address;
	class IPv6Address;
	class IPAddress;

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	bool operator==(const IPv4Address& lhs, const in_addr& rhs);

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const IPv4Address& lhs, const in_addr& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	inline bool operator==(const in_addr& lhs, const IPv4Address& rhs)
	{
		return rhs == lhs;
	}

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const in_addr& lhs, const IPv4Address& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	bool operator==(const IPv6Address& lhs, const in6_addr& rhs);

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const IPv6Address& lhs, const in6_addr& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	inline bool operator==(const in6_addr& lhs, const IPv6Address& rhs)
	{
		return rhs == lhs;
	}

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const in6_addr& lhs, const IPv6Address& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	bool operator==(const IPAddress& lhs, const in_addr& rhs);

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const IPAddress& lhs, const in_addr& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	inline bool operator==(const in_addr& lhs, const IPAddress& rhs)
	{
		return rhs == lhs;
	}

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const in_addr& lhs, const IPAddress& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	bool operator==(const IPAddress& lhs, const in6_addr& rhs);

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const IPAddress& lhs, const in6_addr& rhs)
	{
		return !(lhs == rhs);
	}

	/// Overload of the equal-to operator
	/// @return True if the addresses are equal, false otherwise
	inline bool operator==(const in6_addr& lhs, const IPAddress& rhs)
	{
		return rhs == lhs;
	}

	/// Overload of the not-equal-to operator
	/// @return True if the addresses differ, false otherwise
	inline bool operator!=(const in6_addr& lhs, const IPAddress& rhs)
	{
		return !(lhs == rhs);
	}
}  // namespace pcpp
