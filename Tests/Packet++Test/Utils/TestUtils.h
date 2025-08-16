#pragma once

// clang-format off
#ifdef PCPP_TESTS_DEBUG
#include "Packet.h"
#endif
// clang-format on
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "Resources.hpp"
#include "PacketFactory.hpp"

namespace pcpp_tests
{
	void setResourceProvider(utils::ResourceProvider* resourceProvider);
	utils::ResourceProvider* getResourceProvider();

	int getFileLength(const char* filename);

	std::vector<std::uint8_t> readFileIntoBuffer(const char* filename);
	uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength);

	void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len);

	/// @brief Creates a RawPacket from a resource file.
	/// @param resourceName The name of the resource file to read the packet data from.
	/// @param factory The PacketFactory to use for creating the RawPacket.
	/// @param resourceProvider An optional ResourceProvider to use for loading the resource file.
	///   Uses the default resource provider if not provided.
	/// @return A RawPacket object created from the resource file.
	std::unique_ptr<pcpp::RawPacket> createPacketFromHexResource(
	    const std::string& resourceName, const utils::PacketFactory& factory = utils::PacketFactory(),
	    utils::ResourceProvider const* resourceProvider = nullptr);

	void testSetUp();

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
