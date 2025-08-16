#pragma once

#include <string>
#include <cstdint>
#include <type_traits>
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Convert a byte array into a string of hex characters. For example: for the array { 0xaa, 0x2b, 0x10 } the string
	/// "aa2b10" will be returned
	/// @param[in] byteArr A byte array
	/// @param[in] byteArrSize The size of the byte array [in bytes]
	/// @param[in] stringSizeLimit An optional parameter that enables to limit the returned string size. If set to a
	/// positive integer value the returned string size will be equal or less than this value. If the string
	/// representation of the whole array is longer than this size then only part of the array will be read. The default
	/// value is -1 which means no string size limitation
	/// @return A string of hex characters representing the byte array
	std::string byteArrayToHexString(const uint8_t* byteArr, size_t byteArrSize, int stringSizeLimit = -1);

	/// Convert a string of hex characters into a byte array. For example: for the string "aa2b10" an array of values
	/// { 0xaa, 0x2b, 0x10 } will be returned
	/// @param[in] hexString A string of hex characters
	/// @param[out] resultByteArr A pre-allocated byte array where the result will be written to
	/// @param[in] resultByteArrSize The size of the pre-allocated byte array
	/// @return The size of the result array. If the string represents an array that is longer than the pre-allocated
	/// size (resultByteArrSize) then the result array will contain only the part of the string that managed to fit into
	/// the array, and the returned size will be resultByteArrSize. However if the string represents an array that is
	/// shorter than the pre-allocated size then some of the cells will remain empty and contain zeros, and the returned
	/// size will be the part of the array that contain data. If the input is an illegal hex string 0 will be returned.
	/// Illegal hex string means odd number of characters or a string that contains non-hex characters
	size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize);

	/// This is a cross platform version of memmem (https://man7.org/linux/man-pages/man3/memmem.3.html) which is not
	/// supported on all platforms.
	/// @param[in] haystack A pointer to the buffer to be searched
	/// @param[in] haystackLen Length of the haystack buffer
	/// @param[in] needle A pointer to a buffer that will be searched for
	/// @param[in] needleLen Length of the needle buffer
	/// @return A pointer to the beginning of the substring, or nullptr if the substring is not found
	char* cross_platform_memmem(const char* haystack, size_t haystackLen, const char* needle, size_t needleLen);

	/// Calculates alignment.
	/// @param[in] number Given number
	/// @return The aligned number
	template <int alignment> static int align(int number)
	{
		// Only works for alignment with power of 2
		constexpr bool isPowerOfTwo = alignment && ((alignment & (alignment - 1)) == 0);
		static_assert(isPowerOfTwo, "Alignment must be a power of 2");
		int mask = alignment - 1;
		return (number + mask) & ~mask;
	}

	/// @class Base64
	/// A class for encoding and decoding strings/data using Base64 algorithm
	/// This implementation is based on the work by Tobias Locker, available at https://github.com/tobiaslocker/base64
	class Base64
	{
	public:
		/// Encode an array of bytes to a Base64 string
		/// @param[in] input The array of bytes to be encoded
		/// @param[in] inputLen The length of the input array [in bytes]
		/// @return The encoded string
		static std::string encode(const uint8_t* input, size_t inputLen);

		/// Encode a string to a Base64 string
		/// @param[in] input The string to be encoded
		/// @return The encoded string
		static std::string encode(const std::string& input);

		/// Encode a hex string to a Base64 string
		/// @param[in] hexStringInput The hex string to be encoded
		/// @return The encoded string
		static std::string encodeHexString(const std::string& hexStringInput);

		/// Encode a vector of bytes to a Base64 string
		/// @param[in] input The vector of bytes to be encoded
		/// @return The encoded string
		static std::string encode(const std::vector<uint8_t>& input);

		/// Decode a Base64 string to a vector of bytes
		/// @param[in] input The Base64 string to be decoded
		/// @return The decoded vector of bytes
		static std::vector<uint8_t> decodeToByteVector(const std::string& input);

		/// Decode a Base64 string to a hex string
		/// @param[in] input The Base64 string to be decoded
		/// @return The decoded hex string
		static std::string decodeToHexString(const std::string& input);

		/// Decode a Base64 string to a regular string
		/// @param[in] input The Base64 string to be decoded
		/// @return The decoded string
		static std::string decodeToString(const std::string& input);

		/// Decode a Base64 string to a byte array
		/// @param[in] input The Base64 string to be decoded
		/// @param[out] resultByteArr A pre-allocated byte array where the result will be written to
		/// @param[in] resultByteArrSize The size of the pre-allocated byte array
		/// @return The size of the decoded data
		static size_t decodeToByteArray(const std::string& input, uint8_t* resultByteArr, size_t resultByteArrSize);

		/// Get the expected decoded size of a Base64 string without actually decoding it
		/// @param[in] input The Base64 string to be decoded
		/// @return The expected size of the decoded data
		static size_t getDecodedSize(const std::string& input);

	private:
		static constexpr uint32_t badChar = 0x01ffffff;
		static constexpr char paddingChar = '=';
	};

	/// A template class to calculate enum class hash
	/// @tparam EnumClass
	template <typename EnumClass, std::enable_if_t<std::is_enum<EnumClass>::value, bool> = false> struct EnumClassHash
	{
		size_t operator()(EnumClass value) const
		{
			return static_cast<std::underlying_type_t<EnumClass>>(value);
		}
	};
}  // namespace pcpp
