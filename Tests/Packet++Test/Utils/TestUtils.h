#pragma once

// clang-format off
#ifdef PCPP_TESTS_DEBUG
#include "Packet.h"
#endif
// clang-format on
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "RawPacket.h"

namespace pcpp_tests
{

	int getFileLength(const char* filename);

	std::vector<std::uint8_t> readFileIntoBuffer(const char* filename);
	uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength);

	void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len);

	void testSetUp();
	
	struct RawPacketFactory
	{
		timeval defaultTime;                 ///< Default time to use when creating RawPackets
		pcpp::LinkLayerType defaultLinkType;  ///< Default link layer type to use when creating RawPackets

		pcpp::RawPacket createRawPacketFromFile(const char* filename) const;
		pcpp::RawPacket createRawPacketFromFile(const char* filename, pcpp::LinkLayerType linkType) const;
	};

#define READ_FILE_INTO_BUFFER(num, filename)                                                                           \
	int bufferLength##num = 0;                                                                                         \
	uint8_t* buffer##num = pcpp_tests::readFileIntoBuffer(filename, bufferLength##num);                                \
	PTF_ASSERT_NOT_NULL(buffer##num)

#define FREE_FILE_INTO_BUFFER(num) delete[] buffer##num;

#define FILE_INTO_BUFFER_LENGTH(num) bufferLength##num

#define FILE_INTO_BUFFER(num) buffer##num

#define READ_FILE_AND_CREATE_PACKET(num, filename)                                                                     \
	READ_FILE_INTO_BUFFER(num, filename);                                                                              \
	pcpp::RawPacket rawPacket##num(static_cast<const uint8_t*>(buffer##num), bufferLength##num, time, true)

#define READ_FILE_AND_CREATE_PACKET_LINKTYPE(num, filename, linktype)                                                  \
	READ_FILE_INTO_BUFFER(num, filename);                                                                              \
	pcpp::RawPacket rawPacket##num(static_cast<const uint8_t*>(buffer##num), bufferLength##num, time, true, linktype)

#ifdef PCPP_TESTS_DEBUG
	void savePacketToPcap(pcpp::Packet& packet, const std::string& fileName);
#endif

}  // namespace pcpp_tests
