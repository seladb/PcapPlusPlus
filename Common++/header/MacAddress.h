#pragma once

#include <algorithm>
#include <initializer_list>
#include <iterator>
#include <ostream>
#include <stdint.h>
#include <string.h>
#include <string>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class MacAddress
	 * Represents L2 MAC addresses. Can be constructed from string or a series of 6 byte octets
	 */
	class MacAddress
	{
	public:
		/**
		 * Default constructor for this class.
		 * Initializes the address as 00:00:00:00:00:00.
		 */
		MacAddress() = default;

		/**
		 * A constructor that creates an instance of the class out of a byte array.
		 * The byte array length should be 6 (as MAC address is 6-byte long), and the remaining bytes are ignored.
		 * If the byte array is invalid, the constructor throws an exception.
		 * @param[in] addr A pointer to the byte array containing 6 bytes representing the MAC address
		 */
		explicit MacAddress(const uint8_t* addr)
		{
			memcpy(m_Address, addr, sizeof(m_Address));
		}

		/**
		 * A constructor that creates an instance of the class out of a std::string.
		 * If the string doesn't represent a valid MAC address, the constructor throws an exception.
		 * @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		 */
		explicit MacAddress(const std::string& addr);

		/**
		 * A template constructor that creates an instance of the class out of a string convertible to std::string.
		 * If the string doesn't represent a valid MAC address, the constructor throws an exception.
		 * @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		 */
		template <typename T, typename = typename std::enable_if<std::is_convertible<T, std::string>::value>::type>
		MacAddress(const T& addr) : MacAddress(static_cast<std::string>(addr))
		{}

		/**
		 * A constructor that creates an instance of 6 bytes representing the MAC address
		 * @param[in] firstOctet Represent the first octet in the address
		 * @param[in] secondOctet Represent the second octet in the address
		 * @param[in] thirdOctet Represent the third octet in the address
		 * @param[in] fourthOctet Represent the fourth octet in the address
		 * @param[in] fifthOctet Represent the fifth octet in the address
		 * @param[in] sixthOctet Represent the sixth octet in the address
		 */
		inline MacAddress(uint8_t firstOctet, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet,
		                  uint8_t fifthOctet, uint8_t sixthOctet)
		{
			m_Address[0] = firstOctet;
			m_Address[1] = secondOctet;
			m_Address[2] = thirdOctet;
			m_Address[3] = fourthOctet;
			m_Address[4] = fifthOctet;
			m_Address[5] = sixthOctet;
		}

		/**
		 * A constructor that creates an instance out of the initializer list.
		 * The byte list length should be 6 (as MAC address is 6-byte long).
		 * If the list is invalid, the constructor throws an exception.
		 * @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address
		 */
		MacAddress(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != sizeof(m_Address))
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}
			std::copy(octets.begin(), octets.end(), std::begin(m_Address));
		}

		/**
		 * Overload of the comparison operator.
		 * @param[in] other The object to compare with
		 * @return True if addresses are equal, false otherwise
		 */
		bool operator==(const MacAddress& other) const
		{
			return memcmp(m_Address, other.m_Address, sizeof(m_Address)) == 0;
		}

		/**
		 * Overload of the not-equal operator
		 * @param[in] other The object to compare with
		 * @return True if addresses are not equal, false otherwise
		 */
		bool operator!=(const MacAddress& other) const
		{
			return !operator==(other);
		}

		/**
		 * Overload of the assignment operator.
		 * If the list is invalid, the constructor throws an exception.
		 * @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address, the
		 * length of the list must be equal to 6
		 */
		MacAddress& operator=(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != sizeof(m_Address))
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}

			std::copy(octets.begin(), octets.end(), std::begin(m_Address));
			return *this;
		}

		/**
		 * Returns the pointer to raw data
		 * @return The pointer to raw data
		 */
		const uint8_t* getRawData() const
		{
			return m_Address;
		}

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const;

		/**
		 * Allocates a byte array of length 6 and copies address value into it. Array deallocation is user
		 * responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 */
		void copyTo(uint8_t** arr) const
		{
			*arr = new uint8_t[sizeof(m_Address)];
			memcpy(*arr, m_Address, sizeof(m_Address));
		}

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 6 (the size of a MAC address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copyTo(uint8_t* arr) const
		{
			memcpy(arr, m_Address, sizeof(m_Address));
		}

		/**
		 * A static value representing a zero value of MAC address, meaning address of value "00:00:00:00:00:00"
		 */
		static MacAddress Zero;

	private:
		uint8_t m_Address[6] = { 0 };
	};
}  // namespace pcpp

inline std::ostream& operator<<(std::ostream& os, const pcpp::MacAddress& macAddress)
{
	os << macAddress.toString();
	return os;
}
