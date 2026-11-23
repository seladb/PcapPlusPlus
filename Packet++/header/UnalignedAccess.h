#pragma once

#include "EndianPortable.h"

#include <cstdint>
#include <cstring>
#include <type_traits>

namespace pcpp
{

	enum class ByteOrder
	{
		Native,
		BigEndian
	};

	/// @struct EndianConverter
	/// A template structure for converting integer values between byte orders
	template <typename T, ByteOrder Order> struct EndianConverter;

	/// @struct EndianConverter
	/// A specialization of EndianConverter for native byte order.
	/// Does not perform any conversion and returns the original value.
	/// @tparam T The integer type
	template <typename T> struct EndianConverter<T, ByteOrder::Native>
	{
		/// Returns the value unchanged
		/// @param[in] value The value to convert
		/// @return The original value
		static T convert(T value)
		{
			return value;
		}
	};

	/// @struct EndianConverter
	/// A specialization of EndianConverter for big-endian byte order.
	/// Converts values between big-endian and native byte order.
	/// Supports unsigned integer types of 2, 4, and 8 bytes.
	/// @tparam T The unsigned integer type
	template <typename T> struct EndianConverter<T, ByteOrder::BigEndian>
	{
		static_assert(std::is_unsigned<T>::value, "T must be unsigned");

		static_assert(sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "Unsupported integer size");

		/// Converts the value between big-endian and native byte order
		/// @param[in] value The value to convert
		/// @return The converted value
		static T convert(T value)
		{
			return convertImpl(value, std::integral_constant<size_t, sizeof(T)>());
		}

	private:
		static T convertImpl(T value, std::integral_constant<size_t, 2>)
		{
			return static_cast<T>(be16toh(static_cast<uint16_t>(value)));
		}

		static T convertImpl(T value, std::integral_constant<size_t, 4>)
		{
			return static_cast<T>(be32toh(static_cast<uint32_t>(value)));
		}

		static T convertImpl(T value, std::integral_constant<size_t, 8>)
		{
			return static_cast<T>(be64toh(static_cast<uint64_t>(value)));
		}
	};

	template <typename T, ByteOrder Order> inline T readUint(const uint8_t* ptr)
	{
		static_assert(std::is_unsigned<T>::value, "T must be unsigned");

		static_assert(sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "Unsupported integer size");

		static_assert(Order == ByteOrder::Native || Order == ByteOrder::BigEndian, "Unsupported byte order");

		T value;

		std::memcpy(&value, ptr, sizeof(T));

		return EndianConverter<T, Order>::convert(value);
	}

	template <typename T, ByteOrder Order> inline void writeUint(uint8_t* ptr, T value)
	{
		static_assert(std::is_unsigned<T>::value, "T must be unsigned");

		static_assert(sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "Unsupported integer size");

		static_assert(Order == ByteOrder::Native || Order == ByteOrder::BigEndian, "Unsupported byte order");

		value = EndianConverter<T, Order>::convert(value);

		std::memcpy(ptr, &value, sizeof(T));
	}

}  // namespace pcpp
