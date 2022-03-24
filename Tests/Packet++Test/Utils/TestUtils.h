#pragma once

#ifdef PCPP_TESTS_DEBUG
#include "Packet.h"
#endif
#include <stdint.h>
#include <stdlib.h>

namespace pcpp_tests
{

int getFileLength(const char* filename);

uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength);

void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len);

#define READ_FILE_INTO_BUFFER(num, filename) \
	int bufferLength##num = 0; \
	uint8_t* buffer##num = pcpp_tests::readFileIntoBuffer(filename, bufferLength##num); \
	PTF_ASSERT_NOT_NULL(buffer##num) \

#define READ_FILE_AND_CREATE_PACKET(num, filename) \
  READ_FILE_INTO_BUFFER(num, filename); \
	pcpp::RawPacket rawPacket##num((const uint8_t*)buffer##num, bufferLength##num, time, true)

#define READ_FILE_AND_CREATE_PACKET_LINKTYPE(num, filename, linktype) \
  READ_FILE_INTO_BUFFER(num, filename); \
	pcpp::RawPacket rawPacket##num((const uint8_t*)buffer##num, bufferLength##num, time, true, linktype)

#ifdef PCPP_TESTS_DEBUG
void savePacketToPcap(pcpp::Packet& packet, std::string fileName);
#endif

}
