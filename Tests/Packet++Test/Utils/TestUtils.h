#pragma once

// clang-format off
#ifdef PCPP_TESTS_DEBUG
#include "Packet.h"
#endif
// clang-format on
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "PacketFactory.h"

namespace pcpp_tests
{

	int getFileLength(const char* filename);

	std::vector<std::uint8_t> readFileIntoBuffer(const char* filename);
	uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength);

	void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len);

	void testSetUp();

#ifdef PCPP_TESTS_DEBUG
	void savePacketToPcap(pcpp::Packet& packet, const std::string& fileName);
#endif

}  // namespace pcpp_tests
