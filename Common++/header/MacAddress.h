#pragma once

#include <algorithm>
#include <initializer_list>
#include <iterator>
#include <ostream>
#include <cstdint>
#include <string>
#include <array>
#include <memory>

#include "DeprecationUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @class MacAddress
	/// Represents L2 MAC addresses. Can be constructed from string or a series of 6 byte octets
	class MacAddress
	{
	public:
		/// Default constructor for this class.
		/// Initializes the address as 00:00:00:00:00:00.
		MacAddress() = default;

		/// A constructor that creates an instance of the class out of a byte array.
		/// The byte array length should be 6 (as MAC address is 6-byte long), and the remaining bytes are ignored.
		/// If the byte array is invalid, the constructor throws an exception.
		/// @param[in] addr A pointer to the byte array containing 6 bytes representing the MAC address
		/// @remarks This constructor assumes that the provided array is exactly 6 bytes long.
		/// Prefer using the constructor with size parameter if the array length is not guaranteed to be 6 bytes.
		explicit MacAddress(const uint8_t addr[6]) : MacAddress(addr, 6)
		{}

		/// @brief A constructor that creates an instance of the class out of a byte array of 6 bytes.
		/// @param[in] addr The address as a byte array in network byte order
		/// @param[in] size The size of the array in bytes
		/// @throws std::invalid_argument If the address pointer is null.
		/// @throws std::out_of_range If the provided size is smaller than 6 bytes.
		explicit MacAddress(const uint8_t* addr, size_t size);

		/// A constructor that creates an instance of the class out of a std::array.
		/// The array length should be 6 (as MAC address is 6-byte long).
		/// @param [in] addr A std::array containing 6 bytes representing the MAC address
		explicit MacAddress(const std::array<uint8_t, 6>& addr) : m_Address(addr)
		{}

		/// A constructor that creates an instance of the class out of a std::string.
		/// If the string doesn't represent a valid MAC address, the constructor throws an exception.
		/// @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		explicit MacAddress(const std::string& addr);

		/// A template constructor that creates an instance of the class out of a string convertible to std::string.
		/// If the string doesn't represent a valid MAC address, the constructor throws an exception.
		/// @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		template <typename T, typename = std::enable_if_t<std::is_convertible<T, std::string>::value>>
		MacAddress(const T& addr) : MacAddress(static_cast<std::string>(addr))
		{}

		/// A constructor that creates an instance of 6 bytes representing the MAC address
		/// @param[in] firstOctet Represent the first octet in the address
		/// @param[in] secondOctet Represent the second octet in the address
		/// @param[in] thirdOctet Represent the third octet in the address
		/// @param[in] fourthOctet Represent the fourth octet in the address
		/// @param[in] fifthOctet Represent the fifth octet in the address
		/// @param[in] sixthOctet Represent the sixth octet in the address
		MacAddress(uint8_t firstOctet, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet, uint8_t fifthOctet,
		           uint8_t sixthOctet)
		    : m_Address{ firstOctet, secondOctet, thirdOctet, fourthOctet, fifthOctet, sixthOctet }
		{}

		/// A constructor that creates an instance out of the initializer list.
		/// The byte list length should be 6 (as MAC address is 6-byte long).
		/// If the list is invalid, the constructor throws an exception.
		/// @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address
		MacAddress(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != m_Address.size())
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}
			std::copy(octets.begin(), octets.end(), std::begin(m_Address));
		}

		/// Overload of the comparison operator.
		/// @param[in] other The object to compare with
		/// @return True if addresses are equal, false otherwise
		bool operator==(const MacAddress& other) const
		{
			return m_Address == other.m_Address;
		}

		/// Overload of the not-equal operator
		/// @param[in] other The object to compare with
		/// @return True if addresses are not equal, false otherwise
		bool operator!=(const MacAddress& other) const
		{
			return !operator==(other);
		}

		/// Overload of the assignment operator.
		/// If the list is invalid, the constructor throws an exception.
		/// @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address,
		/// the length of the list must be equal to 6
		MacAddress& operator=(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != sizeof(m_Address))
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}

			std::copy(octets.begin(), octets.end(), m_Address.begin());
			return *this;
		}

		/// Returns the pointer to raw data
		/// @return The pointer to raw data
		const uint8_t* getRawData() const
		{
			return m_Address.data();
		}

		/// Returns a std::string representation of the address
		/// @return A string representation of the address
		std::string toString() const;

		/// @return A 6-byte integer representing the MAC address
		std::array<uint8_t, 6> toByteArray() const
		{
			return m_Address;
		}

		/// Allocates a byte array of length 6 and copies address value into it. Array deallocation is user
		/// responsibility
		/// @param[in] arr A pointer to where array will be allocated
		/// @throws std::invalid_argument If the buffer pointer is null.
		/// @deprecated Use copyToNewBuffer instead.
		PCPP_DEPRECATED("Use copyToNewBuffer instead.")
		void copyTo(uint8_t** arr) const
		{
			size_t unused = 0;
			copyToNewBuffer(arr, unused);
		}

		/// Gets a pointer to an already allocated byte array and copies the address value to it.
		/// This method assumes array allocated size is at least 6 (the size of a MAC address)
		/// @param[in] arr A pointer to the array which address will be copied to
		/// @remarks This method assumes that the provided array is at least 6 bytes long.
		/// Prefer using the copyTo(uint8_t* buffer, size_t size) method if the array length is not guaranteed to be 6
		/// bytes.
		void copyTo(uint8_t arr[6]) const
		{
			copyTo(arr, 6);
		}

		/// @brief Copies the address value to a user-provided buffer.
		///
		/// This function supports querying. If the buffer is null and size is zero, it returns the required size.
		///
		/// @param[in] buffer A pointer to the buffer where the address will be copied
		/// @param[in] size The size of the buffer in bytes
		/// @return The number of bytes copied to the buffer or the required size if the buffer is too small.
		/// @throws std::invalid_argument If the provided buffer is null and size is not zero.
		size_t copyTo(uint8_t* buffer, size_t size) const;

		/// @brief Allocates a new buffer and copies the address value to it.
		/// The user is responsible for deallocating the buffer.
		///
		/// @param buffer A pointer to a pointer where the new buffer will be allocated
		/// @param size A reference to a size_t variable that will be updated with the size of the allocated buffer
		/// @return True if the buffer was successfully allocated and the address was copied, false otherwise.
		/// @throws std::invalid_argument If the buffer pointer is null.
		bool copyToNewBuffer(uint8_t** buffer, size_t& size) const;

		/// A static value representing a zero value of MAC address, meaning address of value "00:00:00:00:00:00"
		static MacAddress Zero;
		/// A static value representing a broadcast MAC address, meaning address of value "ff:ff:ff:ff:ff:ff"
		static MacAddress Broadcast;

	private:
		std::array<uint8_t, 6> m_Address{};
	};

	inline std::ostream& operator<<(std::ostream& oss, const pcpp::MacAddress& macAddress)
	{
		oss << macAddress.toString();
		return oss;
	}
}  // namespace pcpp
