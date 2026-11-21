#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"

#include "UnalignedAccess.h"
#include <array>
#include <cstdint>
#include <cstring>

PTF_TEST_CASE(EndianReadWriteBigEndian)
{
	// Test 16-bit, 32-bit and 64-bit BigEndian values at odd offsets.
	std::array<uint8_t, 17> buffer;
	buffer.fill(0xAA);

	// Write values.
	pcpp::writeUint<uint16_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 1, 0x1234);
	pcpp::writeUint<uint32_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 3, 0x12345678);
	pcpp::writeUint<uint64_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 7, 0x0123456789ABCDEFULL);

	// Verify exact byte representation.
	const std::array<uint8_t, 17> expected = { 0xAA, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x01, 0x23,
		                                       0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAA, 0xAA };

	PTF_ASSERT_TRUE(buffer == expected);

	// Read values back.
	PTF_ASSERT_EQUAL((pcpp::readUint<uint16_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 1)),
	                 static_cast<uint16_t>(0x1234));

	PTF_ASSERT_EQUAL((pcpp::readUint<uint32_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 3)), 0x12345678U);

	PTF_ASSERT_EQUAL((pcpp::readUint<uint64_t, pcpp::ByteOrder::BigEndian>(buffer.data() + 7)), 0x0123456789ABCDEFULL);
}  // EndianReadWriteBigEndian

PTF_TEST_CASE(EndianReadWriteNative)
{
	// Test Native byte order at odd offsets.
	std::array<uint8_t, 17> buffer;
	std::array<uint8_t, 17> expected;

	buffer.fill(0xAA);
	expected.fill(0xAA);

	const uint16_t value16 = 0x1234;
	const uint32_t value32 = 0x12345678;
	const uint64_t value64 = 0x0123456789ABCDEFULL;

	// Prepare expected native representation independently.
	std::memcpy(expected.data() + 1, &value16, sizeof(value16));
	std::memcpy(expected.data() + 3, &value32, sizeof(value32));
	std::memcpy(expected.data() + 7, &value64, sizeof(value64));

	// Write values.
	pcpp::writeUint<uint16_t, pcpp::ByteOrder::Native>(buffer.data() + 1, value16);
	pcpp::writeUint<uint32_t, pcpp::ByteOrder::Native>(buffer.data() + 3, value32);
	pcpp::writeUint<uint64_t, pcpp::ByteOrder::Native>(buffer.data() + 7, value64);

	// Verify that Native writes the host representation without conversion.
	PTF_ASSERT_TRUE(buffer == expected);

	// Read values back.
	// Read values back.
	PTF_ASSERT_EQUAL((pcpp::readUint<uint16_t, pcpp::ByteOrder::Native>(buffer.data() + 1)), value16);

	PTF_ASSERT_EQUAL((pcpp::readUint<uint32_t, pcpp::ByteOrder::Native>(buffer.data() + 3)), value32);

	PTF_ASSERT_EQUAL((pcpp::readUint<uint64_t, pcpp::ByteOrder::Native>(buffer.data() + 7)), value64);
}  // EndianReadWriteNative
