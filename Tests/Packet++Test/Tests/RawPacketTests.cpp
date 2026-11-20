#include "../TestDefinition.h"
#include "RawPacket.h"

PTF_TEST_CASE(RawPacketReallocateEmptyTest)
{
	pcpp::RawPacket rawPacket;

	PTF_ASSERT_FALSE(rawPacket.isPacketSet());
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 0);
	PTF_ASSERT_TRUE(rawPacket.reallocateData(16));
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 0);
	PTF_ASSERT_NOT_NULL(rawPacket.getRawData());
}  // RawPacketReallocateEmptyTest

PTF_TEST_CASE(RawPacketSetRawDataExplicitOwnershipTest)
{
	timeval timestamp{};
	auto* ownedBuffer = new uint8_t[4]{ 1, 2, 3, 4 };
	pcpp::RawPacket rawPacket(ownedBuffer, 4, timestamp, true);

	PTF_ASSERT_TRUE(rawPacket.isPacketSet());
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 4);
	PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), ownedBuffer, 4);

	// Replace with a non-owned buffer; clear() must not free the borrowed memory.
	uint8_t borrowedBuffer[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
	PTF_ASSERT_TRUE(rawPacket.setRawData(borrowedBuffer, 8, false, timestamp));
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 8);
	PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), borrowedBuffer, 8);

	// Trigger disposal of the current buffer; with takeOwnership=false this must not
	// delete[] the borrowed stack memory.
	rawPacket.clear();
	PTF_ASSERT_EQUAL(borrowedBuffer[0], 9);
	PTF_ASSERT_EQUAL(borrowedBuffer[7], 2);
}  // RawPacketSetRawDataExplicitOwnershipTest

PTF_TEST_CASE(RawPacketAppendAfterReallocateTest)
{
	timeval timestamp{};
	auto* initialBuffer = new uint8_t[4]{ 1, 2, 3, 4 };
	pcpp::RawPacket rawPacket(initialBuffer, 4, timestamp, true);

	// Documented safe path: grow the buffer first, then append into the spare capacity.
	PTF_ASSERT_TRUE(rawPacket.reallocateData(8));
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 4);
	const uint8_t afterReallocate[] = { 1, 2, 3, 4 };
	PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), afterReallocate, 4);

	const uint8_t extra[] = { 5, 6 };
	rawPacket.appendData(extra, sizeof(extra));
	PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 6);
	const uint8_t afterAppend[] = { 1, 2, 3, 4, 5, 6 };
	PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), afterAppend, 6);
}  // RawPacketAppendAfterReallocateTest
