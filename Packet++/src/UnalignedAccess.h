#pragma once

#include "EndianPortable.h"

#include <cstdint>
#include <cstring>

// Accessors for multi-byte fields of packets.
//
// The fields of a packet sit at arbitrary byte offsets in the packet buffer, so they are not necessarily aligned for
// their type. Reading or writing one through a cast (for example *(uint16_t*)ptr) is undefined behaviour in C++, and
// UBSan reports it as a misaligned load or store. These accessors copy the bytes with memcpy, which has no alignment
// requirement and is compiled to a plain load on all supported platforms.

namespace pcpp
{

	/// Reads a 16-bit big-endian field (network byte order) at any address.
	inline uint16_t readUint16BigEndian(const uint8_t* ptr)
	{
		uint16_t value;
		std::memcpy(&value, ptr, sizeof(value));
		return be16toh(value);
	}

	/// Reads a 16-bit field in host byte order at any address.
	inline uint16_t readUint16NativeOrder(const uint8_t* ptr)
	{
		uint16_t value;
		std::memcpy(&value, ptr, sizeof(value));
		return value;
	}

	/// Reads a 32-bit big-endian field (network byte order) at any address.
	inline uint32_t readUint32BigEndian(const uint8_t* ptr)
	{
		uint32_t value;
		std::memcpy(&value, ptr, sizeof(value));
		return be32toh(value);
	}

	/// Reads a 32-bit field in host byte order at any address.
	inline uint32_t readUint32NativeOrder(const uint8_t* ptr)
	{
		uint32_t value;
		std::memcpy(&value, ptr, sizeof(value));
		return value;
	}

	/// Reads a 64-bit big-endian field (network byte order) at any address.
	inline uint64_t readUint64BigEndian(const uint8_t* ptr)
	{
		uint64_t value;
		std::memcpy(&value, ptr, sizeof(value));
		return be64toh(value);
	}

	/// Writes a 16-bit value in big-endian (network byte order) at any address.
	inline void writeUint16BigEndian(uint8_t* ptr, uint16_t value)
	{
		const uint16_t bigEndian = htobe16(value);
		std::memcpy(ptr, &bigEndian, sizeof(bigEndian));
	}

	/// Writes a 32-bit value in big-endian (network byte order) at any address.
	inline void writeUint32BigEndian(uint8_t* ptr, uint32_t value)
	{
		const uint32_t bigEndian = htobe32(value);
		std::memcpy(ptr, &bigEndian, sizeof(bigEndian));
	}

}  // namespace pcpp
