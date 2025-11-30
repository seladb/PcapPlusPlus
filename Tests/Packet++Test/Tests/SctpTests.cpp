#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "SctpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(SctpLayerParsingTest)
{
	// Parse SCTP INIT packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpInitPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	// Verify it's an SCTP packet
	PTF_ASSERT_TRUE(sctpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(sctpPacket.isPacketOfType(pcpp::SCTP));

	// Get SCTP layer
	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test common header fields
	PTF_ASSERT_EQUAL(sctpLayer->getSrcPort(), 80);
	PTF_ASSERT_EQUAL(sctpLayer->getDstPort(), 81);
	PTF_ASSERT_EQUAL(sctpLayer->getVerificationTag(), 0x12345678);

	// Test checksum validation
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Test chunk count
	PTF_ASSERT_EQUAL(sctpLayer->getChunkCount(), 1);

	// Get INIT chunk
	pcpp::SctpChunk initChunk = sctpLayer->getFirstChunk();
	PTF_ASSERT_TRUE(initChunk.isNotNull());
	PTF_ASSERT_EQUAL(initChunk.getChunkType(), pcpp::SctpChunkType::INIT, enumclass);
	PTF_ASSERT_EQUAL(initChunk.getChunkTypeAsInt(), 1);
	PTF_ASSERT_EQUAL(initChunk.getLength(), 20);

	// Use view for INIT chunk access
	auto initView = pcpp::SctpInitChunkView::fromChunk(initChunk);
	PTF_ASSERT_TRUE(initView.isValid());

	// Test INIT chunk fields
	PTF_ASSERT_EQUAL(initView.getInitiateTag(), 0xaabbccdd);
	PTF_ASSERT_EQUAL(initView.getArwnd(), 65536);
	PTF_ASSERT_EQUAL(initView.getNumOutboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getNumInboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getInitialTsn(), 1);

	// Test toString()
	std::string layerStr = sctpLayer->toString();
	PTF_ASSERT_TRUE(layerStr.find("SCTP Layer") != std::string::npos);
	PTF_ASSERT_TRUE(layerStr.find("Src port: 80") != std::string::npos);
	PTF_ASSERT_TRUE(layerStr.find("Dst port: 81") != std::string::npos);
}

PTF_TEST_CASE(SctpLayerCreationTest)
{
	// Create a new SCTP layer
	pcpp::SctpLayer sctpLayer(12345, 80, 0xDEADBEEF);

	// Test basic fields
	PTF_ASSERT_EQUAL(sctpLayer.getSrcPort(), 12345);
	PTF_ASSERT_EQUAL(sctpLayer.getDstPort(), 80);
	PTF_ASSERT_EQUAL(sctpLayer.getVerificationTag(), 0xDEADBEEF);

	// Test setters
	sctpLayer.setSrcPort(54321);
	sctpLayer.setDstPort(443);
	sctpLayer.setVerificationTag(0x12345678);

	PTF_ASSERT_EQUAL(sctpLayer.getSrcPort(), 54321);
	PTF_ASSERT_EQUAL(sctpLayer.getDstPort(), 443);
	PTF_ASSERT_EQUAL(sctpLayer.getVerificationTag(), 0x12345678);

	// Test header access
	pcpp::sctphdr* sctpHdr = sctpLayer.getSctpHeader();
	PTF_ASSERT_NOT_NULL(sctpHdr);

	// Test header fields in network byte order
	PTF_ASSERT_EQUAL(sctpHdr->portSrc, htobe16(54321));
	PTF_ASSERT_EQUAL(sctpHdr->portDst, htobe16(443));
	PTF_ASSERT_EQUAL(sctpHdr->verificationTag, htobe32(0x12345678));

	// Test OSI layer
	PTF_ASSERT_EQUAL(sctpLayer.getOsiModelLayer(), pcpp::OsiModelTransportLayer, enum);

	// Test header length (should be 12 bytes for common header only)
	PTF_ASSERT_EQUAL(sctpLayer.getHeaderLen(), 12);
}

PTF_TEST_CASE(SctpDataChunkParsingTest)
{
	// Parse SCTP DATA packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpDataPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	PTF_ASSERT_EQUAL(sctpLayer->getSrcPort(), 1234);
	PTF_ASSERT_EQUAL(sctpLayer->getDstPort(), 80);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Get DATA chunk
	pcpp::SctpChunk dataChunk = sctpLayer->getChunk(pcpp::SctpChunkType::DATA);
	PTF_ASSERT_TRUE(dataChunk.isNotNull());
	PTF_ASSERT_EQUAL(dataChunk.getChunkType(), pcpp::SctpChunkType::DATA, enumclass);

	// Use view for DATA chunk access
	auto dataView = pcpp::SctpDataChunkView::fromChunk(dataChunk);
	PTF_ASSERT_TRUE(dataView.isValid());

	// Test DATA chunk fields
	PTF_ASSERT_EQUAL(dataView.getTsn(), 10);
	PTF_ASSERT_EQUAL(dataView.getStreamId(), 1);
	PTF_ASSERT_EQUAL(dataView.getSequenceNumber(), 5);
	PTF_ASSERT_EQUAL(dataView.getPpid(), 46);

	// Test flags
	PTF_ASSERT_TRUE(dataView.isBeginFragment());
	PTF_ASSERT_TRUE(dataView.isEndFragment());
	PTF_ASSERT_FALSE(dataView.isUnordered());
	PTF_ASSERT_FALSE(dataView.isImmediate());

	// Test user data
	PTF_ASSERT_EQUAL(dataView.getUserDataLength(), 12);
	uint8_t* userData = dataView.getUserData();
	PTF_ASSERT_NOT_NULL(userData);
	PTF_ASSERT_BUF_COMPARE(userData, "Hello World!", 12);

	// Test chunk type name
	PTF_ASSERT_EQUAL(dataChunk.getChunkTypeName(), "DATA");
}

PTF_TEST_CASE(SctpSackChunkParsingTest)
{
	// Parse SCTP SACK packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpSackPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Get SACK chunk
	pcpp::SctpChunk sackChunk = sctpLayer->getChunk(pcpp::SctpChunkType::SACK);
	PTF_ASSERT_TRUE(sackChunk.isNotNull());
	PTF_ASSERT_EQUAL(sackChunk.getChunkType(), pcpp::SctpChunkType::SACK, enumclass);

	// Use view for SACK chunk access
	auto sackView = pcpp::SctpSackChunkView::fromChunk(sackChunk);
	PTF_ASSERT_TRUE(sackView.isValid());

	// Test SACK chunk fields
	PTF_ASSERT_EQUAL(sackView.getCumulativeTsnAck(), 20);
	PTF_ASSERT_EQUAL(sackView.getArwnd(), 32768);
	PTF_ASSERT_EQUAL(sackView.getNumGapBlocks(), 1);
	PTF_ASSERT_EQUAL(sackView.getNumDupTsns(), 1);

	// Test gap blocks
	std::vector<pcpp::sctp_gap_ack_block> gapBlocks = sackView.getGapBlocks();
	PTF_ASSERT_EQUAL(gapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(gapBlocks[0].start, 5);
	PTF_ASSERT_EQUAL(gapBlocks[0].end, 8);

	// Test duplicate TSNs
	std::vector<uint32_t> dupTsns = sackView.getDupTsns();
	PTF_ASSERT_EQUAL(dupTsns.size(), 1);
	PTF_ASSERT_EQUAL(dupTsns[0], 15);

	// Test chunk type name
	PTF_ASSERT_EQUAL(sackChunk.getChunkTypeName(), "SACK");
}

PTF_TEST_CASE(SctpMultipleChunksTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with multiple chunks (COOKIE-ACK + DATA)
	// This test uses inline bytes since we need to test bundled chunks
	uint8_t sctpMultiPacket[] = {
		// Ethernet header (14 bytes)
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header (20 bytes)
		0x45, 0x00, 0x00, 0x40,  // Total Length: 64
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP common header (12 bytes)
		0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		// COOKIE-ACK chunk (4 bytes)
		0x0b,        // Type: COOKIE-ACK
		0x00,        // Flags
		0x00, 0x04,  // Length: 4

		// DATA chunk (20 bytes: 16 header + 4 data)
		0x00,                    // Type: DATA
		0x03,                    // Flags: B=1, E=1
		0x00, 0x14,              // Length: 20
		0x00, 0x00, 0x00, 0x01,  // TSN: 1
		0x00, 0x00,              // Stream ID: 0
		0x00, 0x00,              // Stream Seq: 0
		0x00, 0x00, 0x00, 0x00,  // PPID: 0
		0x54, 0x45, 0x53, 0x54   // User data: "TEST"
	};

	// Calculate CRC32c checksum
	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpMultiPacket) - sctpOffset;

	sctpMultiPacket[sctpOffset + 8] = 0;
	sctpMultiPacket[sctpOffset + 9] = 0;
	sctpMultiPacket[sctpOffset + 10] = 0;
	sctpMultiPacket[sctpOffset + 11] = 0;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpMultiPacket + sctpOffset, sctpLen);
	// Store checksum in network byte order (big-endian) per RFC 3309/9260
	sctpMultiPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpMultiPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpMultiPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpMultiPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpMultiPacket, sizeof(sctpMultiPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test chunk count
	PTF_ASSERT_EQUAL(sctpLayer->getChunkCount(), 2);

	// Test first chunk (COOKIE-ACK)
	pcpp::SctpChunk firstChunk = sctpLayer->getFirstChunk();
	PTF_ASSERT_TRUE(firstChunk.isNotNull());
	PTF_ASSERT_EQUAL(firstChunk.getChunkType(), pcpp::SctpChunkType::COOKIE_ACK, enumclass);
	PTF_ASSERT_EQUAL(firstChunk.getLength(), 4);

	// Test second chunk (DATA)
	pcpp::SctpChunk secondChunk = sctpLayer->getNextChunk(firstChunk);
	PTF_ASSERT_TRUE(secondChunk.isNotNull());
	PTF_ASSERT_EQUAL(secondChunk.getChunkType(), pcpp::SctpChunkType::DATA, enumclass);
	auto secondDataView = pcpp::SctpDataChunkView::fromChunk(secondChunk);
	PTF_ASSERT_EQUAL(secondDataView.getTsn(), 1);

	// Test getting chunk by type
	pcpp::SctpChunk cookieAckChunk = sctpLayer->getChunk(pcpp::SctpChunkType::COOKIE_ACK);
	PTF_ASSERT_TRUE(cookieAckChunk.isNotNull());

	pcpp::SctpChunk dataChunk = sctpLayer->getChunk(pcpp::SctpChunkType::DATA);
	PTF_ASSERT_TRUE(dataChunk.isNotNull());

	// Test non-existent chunk
	pcpp::SctpChunk initChunk = sctpLayer->getChunk(pcpp::SctpChunkType::INIT);
	PTF_ASSERT_TRUE(initChunk.isNull());

	// Test no more chunks
	pcpp::SctpChunk thirdChunk = sctpLayer->getNextChunk(secondChunk);
	PTF_ASSERT_TRUE(thirdChunk.isNull());
}

PTF_TEST_CASE(SctpChecksumTest)
{
	// Parse SCTP INIT packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpInitPacket.dat");

	pcpp::Packet packet(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = packet.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Verify checksum is valid
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Calculate checksum and verify it matches
	uint32_t calculatedCrc = sctpLayer->calculateChecksum(false);
	// The stored checksum should match what we calculate
	uint32_t storedCrc = be32toh(sctpLayer->getSctpHeader()->checksum);
	PTF_ASSERT_EQUAL(calculatedCrc, storedCrc);

	// Test recalculating checksum
	sctpLayer->getSctpHeader()->checksum = 0;  // Clear checksum
	sctpLayer->calculateChecksum(true);        // Recalculate and write
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());
}

PTF_TEST_CASE(SctpValidationTest)
{
	// Test isDataValid with various inputs

	// Valid SCTP header only (12 bytes)
	uint8_t validHeader[] = {
		0x00, 0x50, 0x00, 0x51,  // Ports
		0x12, 0x34, 0x56, 0x78,  // Tag
		0x00, 0x00, 0x00, 0x00   // Checksum
	};
	PTF_ASSERT_TRUE(pcpp::SctpLayer::isDataValid(validHeader, sizeof(validHeader)));

	// Too short (less than 12 bytes)
	uint8_t tooShort[] = { 0x00, 0x50, 0x00, 0x51, 0x12, 0x34 };
	PTF_ASSERT_FALSE(pcpp::SctpLayer::isDataValid(tooShort, sizeof(tooShort)));

	// Null pointer
	PTF_ASSERT_FALSE(pcpp::SctpLayer::isDataValid(nullptr, 12));

	// Zero source port (invalid)
	uint8_t zeroSrcPort[] = { 0x00, 0x00, 0x00, 0x51, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_FALSE(pcpp::SctpLayer::isDataValid(zeroSrcPort, sizeof(zeroSrcPort)));

	// Zero destination port (invalid)
	uint8_t zeroDstPort[] = { 0x00, 0x50, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00 };
	PTF_ASSERT_FALSE(pcpp::SctpLayer::isDataValid(zeroDstPort, sizeof(zeroDstPort)));

	// Valid header with valid chunk
	uint8_t validWithChunk[] = { 0x00, 0x50, 0x00, 0x51, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
		                         // SHUTDOWN-ACK chunk
		                         0x08, 0x00, 0x00, 0x04 };
	PTF_ASSERT_TRUE(pcpp::SctpLayer::isDataValid(validWithChunk, sizeof(validWithChunk)));

	// Valid header with chunk that has length too small
	uint8_t invalidChunkLen[] = { 0x00, 0x50, 0x00, 0x51, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
		                          // Invalid chunk (length < 4)
		                          0x08, 0x00, 0x00, 0x02 };
	PTF_ASSERT_FALSE(pcpp::SctpLayer::isDataValid(invalidChunkLen, sizeof(invalidChunkLen)));
}

PTF_TEST_CASE(SctpChunkTypesTest)
{
	// Test chunk type name conversion for all known chunk types
	pcpp::sctp_chunk_hdr chunkHdr;

	// Test each chunk type
	struct ChunkTypeTest
	{
		uint8_t type;
		pcpp::SctpChunkType expectedType;
		const char* expectedName;
	};

	constexpr ChunkTypeTest tests[] = {
		{ 0,   pcpp::SctpChunkType::DATA,              "DATA"              },
		{ 1,   pcpp::SctpChunkType::INIT,              "INIT"              },
		{ 2,   pcpp::SctpChunkType::INIT_ACK,          "INIT-ACK"          },
		{ 3,   pcpp::SctpChunkType::SACK,              "SACK"              },
		{ 4,   pcpp::SctpChunkType::HEARTBEAT,         "HEARTBEAT"         },
		{ 5,   pcpp::SctpChunkType::HEARTBEAT_ACK,     "HEARTBEAT-ACK"     },
		{ 6,   pcpp::SctpChunkType::ABORT,             "ABORT"             },
		{ 7,   pcpp::SctpChunkType::SHUTDOWN,          "SHUTDOWN"          },
		{ 8,   pcpp::SctpChunkType::SHUTDOWN_ACK,      "SHUTDOWN-ACK"      },
		{ 9,   pcpp::SctpChunkType::SCTP_ERROR,        "ERROR"             },
		{ 10,  pcpp::SctpChunkType::COOKIE_ECHO,       "COOKIE-ECHO"       },
		{ 11,  pcpp::SctpChunkType::COOKIE_ACK,        "COOKIE-ACK"        },
		{ 12,  pcpp::SctpChunkType::ECNE,              "ECNE"              },
		{ 13,  pcpp::SctpChunkType::CWR,               "CWR"               },
		{ 14,  pcpp::SctpChunkType::SHUTDOWN_COMPLETE, "SHUTDOWN-COMPLETE" },
		{ 15,  pcpp::SctpChunkType::AUTH,              "AUTH"              },
		{ 64,  pcpp::SctpChunkType::I_DATA,            "I-DATA"            },
		{ 128, pcpp::SctpChunkType::ASCONF_ACK,        "ASCONF-ACK"        },
		{ 130, pcpp::SctpChunkType::RE_CONFIG,         "RE-CONFIG"         },
		{ 132, pcpp::SctpChunkType::PAD,               "PAD"               },
		{ 192, pcpp::SctpChunkType::FORWARD_TSN,       "FORWARD-TSN"       },
		{ 193, pcpp::SctpChunkType::ASCONF,            "ASCONF"            },
		{ 194, pcpp::SctpChunkType::I_FORWARD_TSN,     "I-FORWARD-TSN"     },
		{ 200, pcpp::SctpChunkType::UNKNOWN,           "UNKNOWN"           }  // Unknown type
	};

	for (const auto& test : tests)
	{
		chunkHdr.type = test.type;
		chunkHdr.flags = 0;
		chunkHdr.length = htobe16(4);

		pcpp::SctpChunk chunk(reinterpret_cast<uint8_t*>(&chunkHdr));
		PTF_ASSERT_EQUAL(chunk.getChunkType(), test.expectedType, enumclass);
		PTF_ASSERT_EQUAL(chunk.getChunkTypeName(), test.expectedName);
	}
}

PTF_TEST_CASE(SctpShutdownChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with SHUTDOWN chunk
	uint8_t sctpShutdownPacket[] = {
		// Ethernet header
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header
		0x45, 0x00, 0x00, 0x28,  // Total Length: 40
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP header + SHUTDOWN chunk
		0x00, 0x50, 0x00, 0x51, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,

		// SHUTDOWN chunk (8 bytes)
		0x07,                   // Type: SHUTDOWN
		0x00,                   // Flags
		0x00, 0x08,             // Length: 8
		0x00, 0x00, 0x00, 0x64  // Cumulative TSN Ack: 100
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpShutdownPacket) - sctpOffset;

	sctpShutdownPacket[sctpOffset + 8] = 0;
	sctpShutdownPacket[sctpOffset + 9] = 0;
	sctpShutdownPacket[sctpOffset + 10] = 0;
	sctpShutdownPacket[sctpOffset + 11] = 0;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpShutdownPacket + sctpOffset, sctpLen);
	// Store checksum in network byte order (big-endian) per RFC 3309/9260
	sctpShutdownPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpShutdownPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpShutdownPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpShutdownPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpShutdownPacket, sizeof(sctpShutdownPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk shutdownChunk = sctpLayer->getChunk(pcpp::SctpChunkType::SHUTDOWN);
	PTF_ASSERT_TRUE(shutdownChunk.isNotNull());
	auto shutdownView = pcpp::SctpShutdownChunkView::fromChunk(shutdownChunk);
	PTF_ASSERT_TRUE(shutdownView.isValid());
	PTF_ASSERT_EQUAL(shutdownView.getCumulativeTsnAck(), 100);
}

PTF_TEST_CASE(SctpForwardTsnChunkTest)
{
	// Parse FORWARD-TSN packet from hex resource file (RFC 3758)
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpForwardTsnPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk fwdTsnChunk = sctpLayer->getChunk(pcpp::SctpChunkType::FORWARD_TSN);
	PTF_ASSERT_TRUE(fwdTsnChunk.isNotNull());
	PTF_ASSERT_EQUAL(fwdTsnChunk.getChunkType(), pcpp::SctpChunkType::FORWARD_TSN, enumclass);
	PTF_ASSERT_EQUAL(fwdTsnChunk.getChunkTypeName(), "FORWARD-TSN");

	// Use view for FORWARD-TSN chunk access
	auto fwdTsnView = pcpp::SctpForwardTsnChunkView::fromChunk(fwdTsnChunk);
	PTF_ASSERT_TRUE(fwdTsnView.isValid());

	// Test FORWARD-TSN fields
	PTF_ASSERT_EQUAL(fwdTsnView.getNewCumulativeTsn(), 256);
	PTF_ASSERT_EQUAL(fwdTsnView.getStreamCount(), 2);

	// Test stream entries - values are returned in host byte order
	std::vector<pcpp::sctp_forward_tsn_stream> streams = fwdTsnView.getStreams();
	PTF_ASSERT_EQUAL(streams.size(), 2);
	PTF_ASSERT_EQUAL(streams[0].streamId, 1);
	PTF_ASSERT_EQUAL(streams[0].streamSeq, 10);
	PTF_ASSERT_EQUAL(streams[1].streamId, 5);
	PTF_ASSERT_EQUAL(streams[1].streamSeq, 20);
}

PTF_TEST_CASE(SctpIForwardTsnChunkTest)
{
	// Parse I-FORWARD-TSN packet from hex resource file (RFC 8260)
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpIForwardTsnPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk iFwdTsnChunk = sctpLayer->getChunk(pcpp::SctpChunkType::I_FORWARD_TSN);
	PTF_ASSERT_TRUE(iFwdTsnChunk.isNotNull());
	PTF_ASSERT_EQUAL(iFwdTsnChunk.getChunkType(), pcpp::SctpChunkType::I_FORWARD_TSN, enumclass);
	PTF_ASSERT_EQUAL(iFwdTsnChunk.getChunkTypeName(), "I-FORWARD-TSN");

	// Use view for I-FORWARD-TSN chunk access
	auto iFwdTsnView = pcpp::SctpIForwardTsnChunkView::fromChunk(iFwdTsnChunk);
	PTF_ASSERT_TRUE(iFwdTsnView.isValid());

	// Test I-FORWARD-TSN fields
	PTF_ASSERT_EQUAL(iFwdTsnView.getNewCumulativeTsn(), 512);
	PTF_ASSERT_EQUAL(iFwdTsnView.getStreamCount(), 2);

	// Test stream entries - values returned in host byte order
	std::vector<pcpp::sctp_iforward_tsn_stream> streams = iFwdTsnView.getStreams();
	PTF_ASSERT_EQUAL(streams.size(), 2);
	PTF_ASSERT_EQUAL(streams[0].streamId, 2);
	PTF_ASSERT_TRUE(pcpp::sctp_iforward_tsn_stream::isUnordered(streams[0].reserved));  // U flag = 1
	PTF_ASSERT_EQUAL(streams[0].mid, 100);
	PTF_ASSERT_EQUAL(streams[1].streamId, 7);
	PTF_ASSERT_FALSE(pcpp::sctp_iforward_tsn_stream::isUnordered(streams[1].reserved));  // U flag = 0
	PTF_ASSERT_EQUAL(streams[1].mid, 200);
}

PTF_TEST_CASE(SctpHeartbeatChunkTest)
{
	// Parse HEARTBEAT packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpHeartbeatPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk hbChunk = sctpLayer->getChunk(pcpp::SctpChunkType::HEARTBEAT);
	PTF_ASSERT_TRUE(hbChunk.isNotNull());
	PTF_ASSERT_EQUAL(hbChunk.getChunkType(), pcpp::SctpChunkType::HEARTBEAT, enumclass);
	PTF_ASSERT_EQUAL(hbChunk.getChunkTypeName(), "HEARTBEAT");

	// Use view for HEARTBEAT chunk access
	auto hbView = pcpp::SctpHeartbeatChunkView::fromChunk(hbChunk);
	PTF_ASSERT_TRUE(hbView.isValid());

	// Test HEARTBEAT info (returns the full TLV parameter: type + length + value)
	PTF_ASSERT_EQUAL(hbView.getInfoLength(), 12);
	uint8_t* hbInfo = hbView.getInfo();
	PTF_ASSERT_NOT_NULL(hbInfo);
	// TLV: type=0x0001, length=0x000c, value="HBINFO!!"
	uint8_t expectedTlv[] = { 0x00, 0x01, 0x00, 0x0c, 'H', 'B', 'I', 'N', 'F', 'O', '!', '!' };
	PTF_ASSERT_BUF_COMPARE(hbInfo, expectedTlv, 12);
}

PTF_TEST_CASE(SctpCookieEchoChunkTest)
{
	// Parse COOKIE-ECHO packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpCookieEchoPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk cookieChunk = sctpLayer->getChunk(pcpp::SctpChunkType::COOKIE_ECHO);
	PTF_ASSERT_TRUE(cookieChunk.isNotNull());
	PTF_ASSERT_EQUAL(cookieChunk.getChunkType(), pcpp::SctpChunkType::COOKIE_ECHO, enumclass);
	PTF_ASSERT_EQUAL(cookieChunk.getChunkTypeName(), "COOKIE-ECHO");

	// Use view for COOKIE-ECHO chunk access
	auto cookieView = pcpp::SctpCookieEchoChunkView::fromChunk(cookieChunk);
	PTF_ASSERT_TRUE(cookieView.isValid());

	// Test COOKIE-ECHO data
	PTF_ASSERT_EQUAL(cookieView.getCookieLength(), 12);
	uint8_t* cookieData = cookieView.getCookie();
	PTF_ASSERT_NOT_NULL(cookieData);
	PTF_ASSERT_BUF_COMPARE(cookieData, "SECRETCOOKIE", 12);
}

PTF_TEST_CASE(SctpAuthChunkTest)
{
	// Parse AUTH packet from hex resource file (RFC 4895)
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpAuthPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk authChunk = sctpLayer->getChunk(pcpp::SctpChunkType::AUTH);
	PTF_ASSERT_TRUE(authChunk.isNotNull());
	PTF_ASSERT_EQUAL(authChunk.getChunkType(), pcpp::SctpChunkType::AUTH, enumclass);
	PTF_ASSERT_EQUAL(authChunk.getChunkTypeName(), "AUTH");

	// Use view for AUTH chunk access
	auto authView = pcpp::SctpAuthChunkView::fromChunk(authChunk);
	PTF_ASSERT_TRUE(authView.isValid());

	// Test AUTH chunk fields
	PTF_ASSERT_EQUAL(authView.getSharedKeyId(), 1);
	PTF_ASSERT_EQUAL(authView.getHmacId(), 3);  // SHA-256

	// Test HMAC data
	PTF_ASSERT_EQUAL(authView.getHmacLength(), 16);
	uint8_t* hmacData = authView.getHmacData();
	PTF_ASSERT_NOT_NULL(hmacData);

	uint8_t expectedHmac[] = { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		                       0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	PTF_ASSERT_BUF_COMPARE(hmacData, expectedHmac, 16);
}

PTF_TEST_CASE(SctpIDataChunkTest)
{
	// Parse I-DATA packet from hex resource file (RFC 8260)
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpIDataPacket.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk idataChunk = sctpLayer->getChunk(pcpp::SctpChunkType::I_DATA);
	PTF_ASSERT_TRUE(idataChunk.isNotNull());
	PTF_ASSERT_EQUAL(idataChunk.getChunkType(), pcpp::SctpChunkType::I_DATA, enumclass);
	PTF_ASSERT_EQUAL(idataChunk.getChunkTypeName(), "I-DATA");

	// Use view for I-DATA chunk access
	auto idataView = pcpp::SctpIDataChunkView::fromChunk(idataChunk);
	PTF_ASSERT_TRUE(idataView.isValid());

	// Test I-DATA chunk fields
	PTF_ASSERT_EQUAL(idataView.getTsn(), 10);
	PTF_ASSERT_EQUAL(idataView.getStreamId(), 3);
	PTF_ASSERT_EQUAL(idataView.getMessageId(), 5);
	PTF_ASSERT_EQUAL(idataView.getPpidOrFsn(), 51);  // PPID when B=1

	// Test flags
	PTF_ASSERT_TRUE(idataView.isBeginFragment());
	PTF_ASSERT_TRUE(idataView.isEndFragment());

	// Test user data (I-DATA header is 20 bytes vs DATA's 16)
	PTF_ASSERT_EQUAL(idataView.getUserDataLength(), 8);
	uint8_t* userData = idataView.getUserData();
	PTF_ASSERT_NOT_NULL(userData);
	PTF_ASSERT_BUF_COMPARE(userData, "IDATA!!!", 8);
}

PTF_TEST_CASE(SctpEcneCwrChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with ECNE chunk
	uint8_t sctpEcnePacket[] = {
		// Ethernet header
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header
		0x45, 0x00, 0x00, 0x28,  // Total Length: 40
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP common header (12 bytes)
		0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		// ECNE chunk (8 bytes)
		0x0c,                   // Type: ECNE (12)
		0x00,                   // Flags
		0x00, 0x08,             // Length: 8
		0x00, 0x00, 0x01, 0x00  // Lowest TSN: 256
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpEcnePacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpEcnePacket + sctpOffset, sctpLen);
	sctpEcnePacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpEcnePacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpEcnePacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpEcnePacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpEcnePacket, sizeof(sctpEcnePacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk ecneChunk = sctpLayer->getChunk(pcpp::SctpChunkType::ECNE);
	PTF_ASSERT_TRUE(ecneChunk.isNotNull());
	PTF_ASSERT_EQUAL(ecneChunk.getChunkType(), pcpp::SctpChunkType::ECNE, enumclass);
	PTF_ASSERT_EQUAL(ecneChunk.getChunkTypeName(), "ECNE");

	auto ecneView = pcpp::SctpEcneChunkView::fromChunk(ecneChunk);
	PTF_ASSERT_TRUE(ecneView.isValid());
	PTF_ASSERT_EQUAL(ecneView.getLowestTsn(), 256);
}

PTF_TEST_CASE(SctpOverIPv6Test)
{
	// Parse SCTP over IPv6 packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpIPv6Packet.dat");
	pcpp::Packet sctpPacket(rawPacket.get());

	// Verify IPv6 layer
	PTF_ASSERT_TRUE(sctpPacket.isPacketOfType(pcpp::IPv6));
	pcpp::IPv6Layer* ipv6Layer = sctpPacket.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_NOT_NULL(ipv6Layer);
	PTF_ASSERT_EQUAL(ipv6Layer->getSrcIPAddress().toString(), "2001:db8::1");
	PTF_ASSERT_EQUAL(ipv6Layer->getDstIPAddress().toString(), "2001:db8::2");

	// Verify SCTP layer
	PTF_ASSERT_TRUE(sctpPacket.isPacketOfType(pcpp::SCTP));
	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test SCTP header fields
	PTF_ASSERT_EQUAL(sctpLayer->getSrcPort(), 5000);
	PTF_ASSERT_EQUAL(sctpLayer->getDstPort(), 5001);
	PTF_ASSERT_EQUAL(sctpLayer->getVerificationTag(), 0xdeadbeef);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Test DATA chunk
	pcpp::SctpChunk dataChunk = sctpLayer->getChunk(pcpp::SctpChunkType::DATA);
	PTF_ASSERT_TRUE(dataChunk.isNotNull());
	auto dataView = pcpp::SctpDataChunkView::fromChunk(dataChunk);
	PTF_ASSERT_TRUE(dataView.isValid());
	PTF_ASSERT_EQUAL(dataView.getTsn(), 1);
	PTF_ASSERT_EQUAL(dataView.getUserDataLength(), 12);
	PTF_ASSERT_BUF_COMPARE(dataView.getUserData(), "Hello IPv6!!", 12);
}

PTF_TEST_CASE(SctpCwrChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with CWR chunk (RFC 9260 Section 3.3.14)
	uint8_t sctpCwrPacket[] = {
		// Ethernet header
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header
		0x45, 0x00, 0x00, 0x28,  // Total Length: 40
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP common header (12 bytes)
		0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		// CWR chunk (8 bytes)
		0x0d,                   // Type: CWR (13)
		0x00,                   // Flags
		0x00, 0x08,             // Length: 8
		0x00, 0x00, 0x02, 0x00  // Lowest TSN: 512
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpCwrPacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpCwrPacket + sctpOffset, sctpLen);
	sctpCwrPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpCwrPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpCwrPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpCwrPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpCwrPacket, sizeof(sctpCwrPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk cwrChunk = sctpLayer->getChunk(pcpp::SctpChunkType::CWR);
	PTF_ASSERT_TRUE(cwrChunk.isNotNull());
	PTF_ASSERT_EQUAL(cwrChunk.getChunkType(), pcpp::SctpChunkType::CWR, enumclass);
	PTF_ASSERT_EQUAL(cwrChunk.getChunkTypeName(), "CWR");

	auto cwrView = pcpp::SctpCwrChunkView::fromChunk(cwrChunk);
	PTF_ASSERT_TRUE(cwrView.isValid());
	PTF_ASSERT_EQUAL(cwrView.getLowestTsn(), 512);
}

PTF_TEST_CASE(SctpAbortChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with ABORT chunk with T bit and error cause
	uint8_t sctpAbortPacket[] = {
		// Ethernet header
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header
		0x45, 0x00, 0x00, 0x2c,  // Total Length: 44
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP common header (12 bytes)
		0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		// ABORT chunk (12 bytes: 4 header + 8 error cause)
		0x06,        // Type: ABORT (6)
		0x01,        // Flags: T bit set
		0x00, 0x0c,  // Length: 12
		// Error cause: User Initiated Abort (code=12, length=8)
		0x00, 0x0c,             // Cause Code: 12
		0x00, 0x08,             // Cause Length: 8
		0x41, 0x42, 0x43, 0x44  // Cause data: "ABCD"
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpAbortPacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpAbortPacket + sctpOffset, sctpLen);
	sctpAbortPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpAbortPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpAbortPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpAbortPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpAbortPacket, sizeof(sctpAbortPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk abortChunk = sctpLayer->getChunk(pcpp::SctpChunkType::ABORT);
	PTF_ASSERT_TRUE(abortChunk.isNotNull());
	PTF_ASSERT_EQUAL(abortChunk.getChunkType(), pcpp::SctpChunkType::ABORT, enumclass);
	PTF_ASSERT_EQUAL(abortChunk.getChunkTypeName(), "ABORT");

	auto abortView = pcpp::SctpAbortChunkView::fromChunk(abortChunk);
	PTF_ASSERT_TRUE(abortView.isValid());

	// Test T bit
	PTF_ASSERT_TRUE(abortView.isTBitSet());

	// Test error causes
	PTF_ASSERT_EQUAL(abortView.getErrorCausesLength(), 8);
	uint8_t* errorCause = abortView.getFirstErrorCause();
	PTF_ASSERT_NOT_NULL(errorCause);

	// Verify error cause header (code and length in network byte order)
	auto* causeHdr = reinterpret_cast<const pcpp::sctp_error_cause*>(errorCause);
	PTF_ASSERT_EQUAL(be16toh(causeHdr->code), 12);  // User Initiated Abort
	PTF_ASSERT_EQUAL(be16toh(causeHdr->length), 8);
}

PTF_TEST_CASE(SctpErrorChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with ERROR chunk
	uint8_t sctpErrorPacket[] = {
		// Ethernet header
		0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		// IPv4 header
		0x45, 0x00, 0x00, 0x2c,  // Total Length: 44
		0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65,

		// SCTP common header (12 bytes)
		0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		// ERROR chunk (12 bytes: 4 header + 8 error cause)
		0x09,        // Type: ERROR (9)
		0x00,        // Flags
		0x00, 0x0c,  // Length: 12
		// Error cause: Invalid Stream Identifier (code=1, length=8)
		0x00, 0x01,  // Cause Code: 1 (Invalid Stream ID)
		0x00, 0x08,  // Cause Length: 8
		0x00, 0x05,  // Stream Identifier: 5
		0x00, 0x00   // Reserved
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpErrorPacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpErrorPacket + sctpOffset, sctpLen);
	sctpErrorPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpErrorPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpErrorPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpErrorPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpErrorPacket, sizeof(sctpErrorPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk errorChunk = sctpLayer->getChunk(pcpp::SctpChunkType::SCTP_ERROR);
	PTF_ASSERT_TRUE(errorChunk.isNotNull());
	PTF_ASSERT_EQUAL(errorChunk.getChunkType(), pcpp::SctpChunkType::SCTP_ERROR, enumclass);
	PTF_ASSERT_EQUAL(errorChunk.getChunkTypeName(), "ERROR");

	auto errorView = pcpp::SctpErrorChunkView::fromChunk(errorChunk);
	PTF_ASSERT_TRUE(errorView.isValid());

	// Test error causes
	PTF_ASSERT_EQUAL(errorView.getCausesLength(), 8);
	uint8_t* errorCause = errorView.getFirstCause();
	PTF_ASSERT_NOT_NULL(errorCause);

	// Verify error cause header
	auto* causeHdr = reinterpret_cast<const pcpp::sctp_error_cause*>(errorCause);
	PTF_ASSERT_EQUAL(be16toh(causeHdr->code), 1);  // Invalid Stream Identifier
	PTF_ASSERT_EQUAL(be16toh(causeHdr->length), 8);
}

PTF_TEST_CASE(SctpAsconfChunkTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with ASCONF chunk (RFC 5061)
	uint8_t sctpAsconfPacket[] = { // Ethernet header
		                           0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		                           // IPv4 header
		                           0x45, 0x00, 0x00, 0x30,  // Total Length: 48
		                           0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8,
		                           0x01, 0x65,

		                           // SCTP common header (12 bytes)
		                           0x04, 0xd2, 0x00, 0x50, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00,

		                           // ASCONF chunk (12 bytes: 8 header + 4 placeholder data)
		                           0xc1,                    // Type: ASCONF (193)
		                           0x00,                    // Flags
		                           0x00, 0x0c,              // Length: 12
		                           0x00, 0x00, 0x12, 0x34,  // Serial Number: 0x1234
		                                                    // Address Parameter placeholder (4 bytes)
		                           0x00, 0x00, 0x00, 0x00
	};

	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpAsconfPacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpAsconfPacket + sctpOffset, sctpLen);
	sctpAsconfPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpAsconfPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpAsconfPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpAsconfPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpAsconfPacket, sizeof(sctpAsconfPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	pcpp::SctpChunk asconfChunk = sctpLayer->getChunk(pcpp::SctpChunkType::ASCONF);
	PTF_ASSERT_TRUE(asconfChunk.isNotNull());
	PTF_ASSERT_EQUAL(asconfChunk.getChunkType(), pcpp::SctpChunkType::ASCONF, enumclass);
	PTF_ASSERT_EQUAL(asconfChunk.getChunkTypeName(), "ASCONF");

	auto asconfView = pcpp::SctpAsconfChunkView::fromChunk(asconfChunk);
	PTF_ASSERT_TRUE(asconfView.isValid());
	PTF_ASSERT_EQUAL(asconfView.getSerialNumber(), 0x1234);
}

// ==================== Chunk Creation Tests ====================

PTF_TEST_CASE(SctpAddDataChunkTest)
{
	// Create a new SCTP layer and add a DATA chunk
	pcpp::SctpLayer sctpLayer(1234, 80, 0xDEADBEEF);

	const char* userData = "Hello SCTP!";
	size_t userDataLen = strlen(userData);

	// Add DATA chunk with all flags
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(100,  // TSN
	                                       5,    // Stream ID
	                                       10,   // Stream Sequence Number
	                                       47,   // PPID
	                                       reinterpret_cast<const uint8_t*>(userData), userDataLen,
	                                       true,   // Begin fragment
	                                       true,   // End fragment
	                                       false,  // Unordered
	                                       true    // Immediate
	                                       ));

	// Verify chunk was added
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 1);

	pcpp::SctpChunk dataChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(dataChunk.isNotNull());
	PTF_ASSERT_EQUAL(dataChunk.getChunkType(), pcpp::SctpChunkType::DATA, enumclass);

	auto dataView = pcpp::SctpDataChunkView::fromChunk(dataChunk);
	PTF_ASSERT_TRUE(dataView.isValid());

	// Verify DATA chunk fields
	PTF_ASSERT_EQUAL(dataView.getTsn(), 100);
	PTF_ASSERT_EQUAL(dataView.getStreamId(), 5);
	PTF_ASSERT_EQUAL(dataView.getSequenceNumber(), 10);
	PTF_ASSERT_EQUAL(dataView.getPpid(), 47);

	// Verify flags
	PTF_ASSERT_TRUE(dataView.isBeginFragment());
	PTF_ASSERT_TRUE(dataView.isEndFragment());
	PTF_ASSERT_FALSE(dataView.isUnordered());
	PTF_ASSERT_TRUE(dataView.isImmediate());

	// Verify user data
	PTF_ASSERT_EQUAL(dataView.getUserDataLength(), userDataLen);
	PTF_ASSERT_BUF_COMPARE(dataView.getUserData(), userData, userDataLen);
}

PTF_TEST_CASE(SctpAddInitChunkTest)
{
	// Create a new SCTP layer and add an INIT chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0);

	PTF_ASSERT_TRUE(sctpLayer.addInitChunk(0xAABBCCDD,  // Initiate Tag
	                                       65536,       // A-RWND
	                                       10,          // Outbound Streams
	                                       10,          // Inbound Streams
	                                       1000         // Initial TSN
	                                       ));

	// Verify chunk was added
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 1);

	pcpp::SctpChunk initChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(initChunk.isNotNull());
	PTF_ASSERT_EQUAL(initChunk.getChunkType(), pcpp::SctpChunkType::INIT, enumclass);

	auto initView = pcpp::SctpInitChunkView::fromChunk(initChunk);
	PTF_ASSERT_TRUE(initView.isValid());

	// Verify INIT chunk fields
	PTF_ASSERT_EQUAL(initView.getInitiateTag(), 0xAABBCCDD);
	PTF_ASSERT_EQUAL(initView.getArwnd(), 65536);
	PTF_ASSERT_EQUAL(initView.getNumOutboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getNumInboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getInitialTsn(), 1000);
}

PTF_TEST_CASE(SctpAddInitAckChunkTest)
{
	// Create a new SCTP layer and add an INIT-ACK chunk with parameters
	pcpp::SctpLayer sctpLayer(5001, 5000, 0xAABBCCDD);

	// Create a simple State Cookie parameter (Type=7, Length=12, 8 bytes of cookie data)
	uint8_t params[] = {
		0x00, 0x07,              // Type: State Cookie (7)
		0x00, 0x0C,              // Length: 12 (4 header + 8 data)
		0x43, 0x4F, 0x4F, 0x4B,  // "COOK"
		0x49, 0x45, 0x21, 0x21   // "IE!!"
	};

	PTF_ASSERT_TRUE(sctpLayer.addInitAckChunk(0x11223344,  // Initiate Tag
	                                          32768,       // A-RWND
	                                          5,           // Outbound Streams
	                                          5,           // Inbound Streams
	                                          2000,        // Initial TSN
	                                          params, sizeof(params)));

	// Verify chunk was added
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 1);

	pcpp::SctpChunk initAckChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(initAckChunk.isNotNull());
	PTF_ASSERT_EQUAL(initAckChunk.getChunkType(), pcpp::SctpChunkType::INIT_ACK, enumclass);

	auto initAckView = pcpp::SctpInitAckChunkView::fromChunk(initAckChunk);
	PTF_ASSERT_TRUE(initAckView.isValid());

	// Verify INIT-ACK chunk fields
	PTF_ASSERT_EQUAL(initAckView.getInitiateTag(), 0x11223344);
	PTF_ASSERT_EQUAL(initAckView.getArwnd(), 32768);
	PTF_ASSERT_EQUAL(initAckView.getNumOutboundStreams(), 5);
	PTF_ASSERT_EQUAL(initAckView.getNumInboundStreams(), 5);
	PTF_ASSERT_EQUAL(initAckView.getInitialTsn(), 2000);

	// Verify parameters were included
	PTF_ASSERT_EQUAL(initAckView.getParametersLength(), sizeof(params));
}

PTF_TEST_CASE(SctpAddSackChunkTest)
{
	// Create a new SCTP layer and add a SACK chunk
	pcpp::SctpLayer sctpLayer(80, 1234, 0x12345678);

	std::vector<pcpp::sctp_gap_ack_block> gapBlocks;
	gapBlocks.push_back({ 3, 5 });
	gapBlocks.push_back({ 10, 15 });

	std::vector<uint32_t> dupTsns;
	dupTsns.push_back(100);
	dupTsns.push_back(200);

	PTF_ASSERT_TRUE(sctpLayer.addSackChunk(50,     // Cumulative TSN Ack
	                                       65535,  // A-RWND
	                                       gapBlocks, dupTsns));

	// Verify chunk was added
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 1);

	pcpp::SctpChunk sackChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(sackChunk.isNotNull());
	PTF_ASSERT_EQUAL(sackChunk.getChunkType(), pcpp::SctpChunkType::SACK, enumclass);

	auto sackView = pcpp::SctpSackChunkView::fromChunk(sackChunk);
	PTF_ASSERT_TRUE(sackView.isValid());

	// Verify SACK chunk fields
	PTF_ASSERT_EQUAL(sackView.getCumulativeTsnAck(), 50);
	PTF_ASSERT_EQUAL(sackView.getArwnd(), 65535);
	PTF_ASSERT_EQUAL(sackView.getNumGapBlocks(), 2);
	PTF_ASSERT_EQUAL(sackView.getNumDupTsns(), 2);

	// Verify gap blocks
	std::vector<pcpp::sctp_gap_ack_block> readGapBlocks = sackView.getGapBlocks();
	PTF_ASSERT_EQUAL(readGapBlocks.size(), 2);
	PTF_ASSERT_EQUAL(readGapBlocks[0].start, 3);
	PTF_ASSERT_EQUAL(readGapBlocks[0].end, 5);
	PTF_ASSERT_EQUAL(readGapBlocks[1].start, 10);
	PTF_ASSERT_EQUAL(readGapBlocks[1].end, 15);

	// Verify duplicate TSNs
	std::vector<uint32_t> readDupTsns = sackView.getDupTsns();
	PTF_ASSERT_EQUAL(readDupTsns.size(), 2);
	PTF_ASSERT_EQUAL(readDupTsns[0], 100);
	PTF_ASSERT_EQUAL(readDupTsns[1], 200);
}

PTF_TEST_CASE(SctpAddHeartbeatChunkTest)
{
	// Create a new SCTP layer and add HEARTBEAT and HEARTBEAT-ACK chunks
	pcpp::SctpLayer sctpLayer(1234, 5678, 0xABCDEF00);

	const char* hbInfo = "HB-INFO!";
	size_t hbInfoLen = strlen(hbInfo);

	PTF_ASSERT_TRUE(sctpLayer.addHeartbeatChunk(reinterpret_cast<const uint8_t*>(hbInfo), hbInfoLen));

	// Verify chunk was added
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 1);

	pcpp::SctpChunk hbChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(hbChunk.isNotNull());
	PTF_ASSERT_EQUAL(hbChunk.getChunkType(), pcpp::SctpChunkType::HEARTBEAT, enumclass);

	// Verify heartbeat info using view
	auto hbView = pcpp::SctpHeartbeatChunkView::fromChunk(hbChunk);
	PTF_ASSERT_TRUE(hbView.isValid());
	PTF_ASSERT_EQUAL(hbView.getInfoLength(), hbInfoLen);
	PTF_ASSERT_BUF_COMPARE(hbView.getInfo(), hbInfo, hbInfoLen);
}

PTF_TEST_CASE(SctpAddShutdownChunksTest)
{
	// Test SHUTDOWN, SHUTDOWN-ACK, and SHUTDOWN-COMPLETE chunks
	pcpp::SctpLayer sctpLayer(1234, 5678, 0x11111111);

	// Add SHUTDOWN chunk
	PTF_ASSERT_TRUE(sctpLayer.addShutdownChunk(500));

	pcpp::SctpChunk shutdownChunk = sctpLayer.getChunk(pcpp::SctpChunkType::SHUTDOWN);
	PTF_ASSERT_TRUE(shutdownChunk.isNotNull());
	auto shutdownView = pcpp::SctpShutdownChunkView::fromChunk(shutdownChunk);
	PTF_ASSERT_TRUE(shutdownView.isValid());
	PTF_ASSERT_EQUAL(shutdownView.getCumulativeTsnAck(), 500);

	// Create another layer for SHUTDOWN-ACK
	pcpp::SctpLayer sctpLayer2(5678, 1234, 0x22222222);
	PTF_ASSERT_TRUE(sctpLayer2.addShutdownAckChunk());

	pcpp::SctpChunk shutdownAckChunk = sctpLayer2.getChunk(pcpp::SctpChunkType::SHUTDOWN_ACK);
	PTF_ASSERT_TRUE(shutdownAckChunk.isNotNull());
	PTF_ASSERT_EQUAL(shutdownAckChunk.getChunkType(), pcpp::SctpChunkType::SHUTDOWN_ACK, enumclass);

	// Create another layer for SHUTDOWN-COMPLETE with T bit
	pcpp::SctpLayer sctpLayer3(1234, 5678, 0x33333333);
	PTF_ASSERT_TRUE(sctpLayer3.addShutdownCompleteChunk(true));

	pcpp::SctpChunk shutdownCompleteChunk = sctpLayer3.getChunk(pcpp::SctpChunkType::SHUTDOWN_COMPLETE);
	PTF_ASSERT_TRUE(shutdownCompleteChunk.isNotNull());
	// T bit is in the flags field - bit 0 indicates no TCB destroyed
	PTF_ASSERT_EQUAL((shutdownCompleteChunk.getFlags() & 0x01), 0x01);
}

PTF_TEST_CASE(SctpAddAbortChunkTest)
{
	// Create a new SCTP layer and add an ABORT chunk with error cause
	pcpp::SctpLayer sctpLayer(1234, 5678, 0xDEADBEEF);

	// Error cause: User Initiated Abort (code=12)
	uint8_t errorCause[] = {
		0x00, 0x0C,             // Cause Code: 12
		0x00, 0x08,             // Cause Length: 8
		0x42, 0x59, 0x45, 0x21  // "BYE!"
	};

	PTF_ASSERT_TRUE(sctpLayer.addAbortChunk(true, errorCause, sizeof(errorCause)));

	pcpp::SctpChunk abortChunk = sctpLayer.getChunk(pcpp::SctpChunkType::ABORT);
	PTF_ASSERT_TRUE(abortChunk.isNotNull());
	auto abortView = pcpp::SctpAbortChunkView::fromChunk(abortChunk);
	PTF_ASSERT_TRUE(abortView.isValid());
	PTF_ASSERT_TRUE(abortView.isTBitSet());
	PTF_ASSERT_EQUAL(abortView.getErrorCausesLength(), sizeof(errorCause));
}

PTF_TEST_CASE(SctpAddCookieChunksTest)
{
	// Test COOKIE-ECHO and COOKIE-ACK chunks
	pcpp::SctpLayer sctpLayer(1234, 5678, 0xAABBCCDD);

	const char* cookie = "STATE_COOKIE_DATA";
	size_t cookieLen = strlen(cookie);

	PTF_ASSERT_TRUE(sctpLayer.addCookieEchoChunk(reinterpret_cast<const uint8_t*>(cookie), cookieLen));

	pcpp::SctpChunk cookieEchoChunk = sctpLayer.getChunk(pcpp::SctpChunkType::COOKIE_ECHO);
	PTF_ASSERT_TRUE(cookieEchoChunk.isNotNull());
	auto cookieView = pcpp::SctpCookieEchoChunkView::fromChunk(cookieEchoChunk);
	PTF_ASSERT_TRUE(cookieView.isValid());
	PTF_ASSERT_EQUAL(cookieView.getCookieLength(), cookieLen);
	PTF_ASSERT_BUF_COMPARE(cookieView.getCookie(), cookie, cookieLen);

	// Create another layer for COOKIE-ACK
	pcpp::SctpLayer sctpLayer2(5678, 1234, 0x11223344);
	PTF_ASSERT_TRUE(sctpLayer2.addCookieAckChunk());

	pcpp::SctpChunk cookieAckChunk = sctpLayer2.getChunk(pcpp::SctpChunkType::COOKIE_ACK);
	PTF_ASSERT_TRUE(cookieAckChunk.isNotNull());
	PTF_ASSERT_EQUAL(cookieAckChunk.getChunkType(), pcpp::SctpChunkType::COOKIE_ACK, enumclass);
}

PTF_TEST_CASE(SctpAddErrorChunkTest)
{
	// Create a new SCTP layer and add an ERROR chunk
	pcpp::SctpLayer sctpLayer(1234, 5678, 0x12345678);

	// Error cause: Invalid Stream Identifier (code=1)
	uint8_t errorCause[] = {
		0x00, 0x01,  // Cause Code: 1
		0x00, 0x08,  // Cause Length: 8
		0x00, 0x10,  // Stream Identifier: 16
		0x00, 0x00   // Reserved
	};

	PTF_ASSERT_TRUE(sctpLayer.addErrorChunk(errorCause, sizeof(errorCause)));

	pcpp::SctpChunk errorChunk = sctpLayer.getChunk(pcpp::SctpChunkType::SCTP_ERROR);
	PTF_ASSERT_TRUE(errorChunk.isNotNull());
	auto errorView = pcpp::SctpErrorChunkView::fromChunk(errorChunk);
	PTF_ASSERT_TRUE(errorView.isValid());
	PTF_ASSERT_EQUAL(errorView.getCausesLength(), sizeof(errorCause));
}

PTF_TEST_CASE(SctpMultipleChunkCreationTest)
{
	// Create a layer with multiple chunks (bundling)
	pcpp::SctpLayer sctpLayer(1234, 5678, 0xFEDCBA98);

	// Add COOKIE-ACK followed by DATA
	PTF_ASSERT_TRUE(sctpLayer.addCookieAckChunk());

	const char* data = "First message";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(1, 0, 0, 0, reinterpret_cast<const uint8_t*>(data), strlen(data)));

	// Verify both chunks exist
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 2);

	pcpp::SctpChunk firstChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_EQUAL(firstChunk.getChunkType(), pcpp::SctpChunkType::COOKIE_ACK, enumclass);

	pcpp::SctpChunk secondChunk = sctpLayer.getNextChunk(firstChunk);
	PTF_ASSERT_TRUE(secondChunk.isNotNull());
	PTF_ASSERT_EQUAL(secondChunk.getChunkType(), pcpp::SctpChunkType::DATA, enumclass);
	auto dataView = pcpp::SctpDataChunkView::fromChunk(secondChunk);
	PTF_ASSERT_TRUE(dataView.isValid());
	PTF_ASSERT_EQUAL(dataView.getTsn(), 1);
}

// ==================== INIT Parameter Iterator Tests ====================

PTF_TEST_CASE(SctpInitParameterIteratorTest)
{
	// Create INIT chunk with multiple parameters
	pcpp::SctpLayer sctpLayer(5000, 5001, 0);

	// Build parameters:
	// 1. IPv4 Address (Type=5, Length=8, 4 bytes of IP)
	// 2. Supported Address Types (Type=12, Length=8, 2 address types)
	uint8_t params[] = {
		// IPv4 Address Parameter
		0x00, 0x05,              // Type: IPv4 Address (5)
		0x00, 0x08,              // Length: 8
		0xC0, 0xA8, 0x01, 0x01,  // IP: 192.168.1.1

		// Supported Address Types Parameter
		0x00, 0x0C,  // Type: Supported Address Types (12)
		0x00, 0x08,  // Length: 8
		0x00, 0x05,  // IPv4 (5)
		0x00, 0x06   // IPv6 (6)
	};

	PTF_ASSERT_TRUE(sctpLayer.addInitChunk(0xAABBCCDD, 65536, 10, 10, 1, params, sizeof(params)));

	pcpp::SctpChunk initChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(initChunk.isNotNull());

	// Create iterator
	pcpp::SctpInitParameterIterator iter(initChunk);
	PTF_ASSERT_TRUE(iter.isValid());

	// First parameter: IPv4 Address
	pcpp::SctpInitParameter param1 = iter.getParameter();
	PTF_ASSERT_TRUE(param1.isNotNull());
	PTF_ASSERT_EQUAL(param1.getType(), pcpp::SctpParameterType::IPV4_ADDRESS, enumclass);
	PTF_ASSERT_EQUAL(param1.getLength(), 8);
	PTF_ASSERT_EQUAL(param1.getTypeName(), "IPv4 Address");

	pcpp::IPv4Address ipv4 = param1.getIPv4Address();
	PTF_ASSERT_EQUAL(ipv4.toString(), "192.168.1.1");

	// Move to next parameter
	iter.next();
	PTF_ASSERT_TRUE(iter.isValid());

	// Second parameter: Supported Address Types
	pcpp::SctpInitParameter param2 = iter.getParameter();
	PTF_ASSERT_TRUE(param2.isNotNull());
	PTF_ASSERT_EQUAL(param2.getType(), pcpp::SctpParameterType::SUPPORTED_ADDRESS_TYPES, enumclass);
	PTF_ASSERT_EQUAL(param2.getTypeName(), "Supported Address Types");

	std::vector<uint16_t> addrTypes = param2.getSupportedAddressTypes();
	PTF_ASSERT_EQUAL(addrTypes.size(), 2);
	PTF_ASSERT_EQUAL(addrTypes[0], 5);  // IPv4
	PTF_ASSERT_EQUAL(addrTypes[1], 6);  // IPv6

	// No more parameters
	iter.next();
	PTF_ASSERT_FALSE(iter.isValid());
}

PTF_TEST_CASE(SctpInitParameterIPv6Test)
{
	// Create INIT chunk with IPv6 address parameter
	pcpp::SctpLayer sctpLayer(5000, 5001, 0);

	// IPv6 Address Parameter (Type=6, Length=20, 16 bytes of IP)
	uint8_t params[] = { 0x00, 0x06,              // Type: IPv6 Address (6)
		                 0x00, 0x14,              // Length: 20
		                 0x20, 0x01, 0x0d, 0xb8,  // 2001:db8::1
		                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	PTF_ASSERT_TRUE(sctpLayer.addInitChunk(0x11111111, 65536, 10, 10, 1, params, sizeof(params)));

	pcpp::SctpChunk initChunk = sctpLayer.getFirstChunk();
	pcpp::SctpInitParameterIterator iter(initChunk);
	PTF_ASSERT_TRUE(iter.isValid());

	pcpp::SctpInitParameter param = iter.getParameter();
	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::IPV6_ADDRESS, enumclass);
	PTF_ASSERT_EQUAL(param.getTypeName(), "IPv6 Address");

	pcpp::IPv6Address ipv6 = param.getIPv6Address();
	PTF_ASSERT_EQUAL(ipv6.toString(), "2001:db8::1");
}

PTF_TEST_CASE(SctpChunkPaddingTest)
{
	// Test that chunks are properly padded to 4-byte boundaries
	pcpp::SctpLayer sctpLayer(1234, 5678, 0x12345678);

	// Add DATA chunk with 5 bytes of data (needs 3 bytes padding)
	const char* data5 = "ABCDE";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(1, 0, 0, 0, reinterpret_cast<const uint8_t*>(data5), 5));

	// Add another DATA chunk after it to verify padding worked
	const char* data4 = "WXYZ";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(2, 0, 1, 0, reinterpret_cast<const uint8_t*>(data4), 4));

	// Verify both chunks can be read correctly
	PTF_ASSERT_EQUAL(sctpLayer.getChunkCount(), 2);

	pcpp::SctpChunk chunk1 = sctpLayer.getFirstChunk();
	auto dataView1 = pcpp::SctpDataChunkView::fromChunk(chunk1);
	PTF_ASSERT_TRUE(dataView1.isValid());
	PTF_ASSERT_EQUAL(dataView1.getTsn(), 1);
	PTF_ASSERT_EQUAL(dataView1.getUserDataLength(), 5);

	pcpp::SctpChunk chunk2 = sctpLayer.getNextChunk(chunk1);
	PTF_ASSERT_TRUE(chunk2.isNotNull());
	auto dataView2 = pcpp::SctpDataChunkView::fromChunk(chunk2);
	PTF_ASSERT_TRUE(dataView2.isValid());
	PTF_ASSERT_EQUAL(dataView2.getTsn(), 2);
	PTF_ASSERT_EQUAL(dataView2.getUserDataLength(), 4);
}

// ==================== RFC 9260 Validation Tests ====================

PTF_TEST_CASE(SctpBundlingValidationTest)
{
	// Test bundling validation for INIT
	pcpp::SctpLayer initLayer(5000, 5001, 0);
	PTF_ASSERT_TRUE(initLayer.addInitChunk(0x12345678, 65536, 10, 10, 1));
	PTF_ASSERT_EQUAL(initLayer.validateBundling(), pcpp::SctpBundlingStatus::VALID, enumclass);

	// Test INIT with non-zero verification tag
	pcpp::SctpLayer initLayerBadTag(5000, 5001, 0x12345678);
	PTF_ASSERT_TRUE(initLayerBadTag.addInitChunk(0x12345678, 65536, 10, 10, 1));
	PTF_ASSERT_EQUAL(initLayerBadTag.validateBundling(), pcpp::SctpBundlingStatus::INIT_NONZERO_TAG, enumclass);

	// Test canAddChunk prevents bundling with INIT
	PTF_ASSERT_FALSE(initLayer.canAddChunk(pcpp::SctpChunkType::DATA));
	PTF_ASSERT_FALSE(initLayer.canAddChunk(pcpp::SctpChunkType::SACK));

	// Test DATA bundling is allowed
	pcpp::SctpLayer dataLayer(1234, 80, 0xDEADBEEF);
	const char* data = "test";
	PTF_ASSERT_TRUE(dataLayer.addDataChunk(1, 0, 0, 0, reinterpret_cast<const uint8_t*>(data), 4));
	PTF_ASSERT_EQUAL(dataLayer.validateBundling(), pcpp::SctpBundlingStatus::VALID, enumclass);
	PTF_ASSERT_TRUE(dataLayer.canAddChunk(pcpp::SctpChunkType::DATA));
	PTF_ASSERT_TRUE(dataLayer.canAddChunk(pcpp::SctpChunkType::SACK));
	PTF_ASSERT_FALSE(dataLayer.canAddChunk(pcpp::SctpChunkType::INIT));
}

PTF_TEST_CASE(SctpAddEcneCwrChunkTest)
{
	// Test ECNE chunk creation
	pcpp::SctpLayer ecneLayer(1234, 5678, 0x12345678);
	PTF_ASSERT_TRUE(ecneLayer.addEcneChunk(1000));

	pcpp::SctpChunk ecneChunk = ecneLayer.getFirstChunk();
	PTF_ASSERT_TRUE(ecneChunk.isNotNull());
	PTF_ASSERT_EQUAL(ecneChunk.getChunkType(), pcpp::SctpChunkType::ECNE, enumclass);
	auto ecneView = pcpp::SctpEcneChunkView::fromChunk(ecneChunk);
	PTF_ASSERT_TRUE(ecneView.isValid());
	PTF_ASSERT_EQUAL(ecneView.getLowestTsn(), 1000);

	// Test CWR chunk creation
	pcpp::SctpLayer cwrLayer(5678, 1234, 0x87654321);
	PTF_ASSERT_TRUE(cwrLayer.addCwrChunk(1000));

	pcpp::SctpChunk cwrChunk = cwrLayer.getFirstChunk();
	PTF_ASSERT_TRUE(cwrChunk.isNotNull());
	PTF_ASSERT_EQUAL(cwrChunk.getChunkType(), pcpp::SctpChunkType::CWR, enumclass);
	auto cwrView = pcpp::SctpCwrChunkView::fromChunk(cwrChunk);
	PTF_ASSERT_TRUE(cwrView.isValid());
	PTF_ASSERT_EQUAL(cwrView.getLowestTsn(), 1000);
}

PTF_TEST_CASE(SctpAddForwardTsnChunkTest)
{
	// Test FORWARD-TSN chunk creation
	pcpp::SctpLayer fwdLayer(1234, 5678, 0x12345678);

	std::vector<pcpp::sctp_forward_tsn_stream> streams;
	streams.push_back({ 0, 5 });
	streams.push_back({ 1, 10 });

	PTF_ASSERT_TRUE(fwdLayer.addForwardTsnChunk(100, streams));

	pcpp::SctpChunk fwdChunk = fwdLayer.getFirstChunk();
	PTF_ASSERT_TRUE(fwdChunk.isNotNull());
	PTF_ASSERT_EQUAL(fwdChunk.getChunkType(), pcpp::SctpChunkType::FORWARD_TSN, enumclass);

	auto fwdView = pcpp::SctpForwardTsnChunkView::fromChunk(fwdChunk);
	PTF_ASSERT_TRUE(fwdView.isValid());
	PTF_ASSERT_EQUAL(fwdView.getNewCumulativeTsn(), 100);
	PTF_ASSERT_EQUAL(fwdView.getStreamCount(), 2);

	std::vector<pcpp::sctp_forward_tsn_stream> readStreams = fwdView.getStreams();
	PTF_ASSERT_EQUAL(readStreams.size(), 2);
	PTF_ASSERT_EQUAL(readStreams[0].streamId, 0);
	PTF_ASSERT_EQUAL(readStreams[0].streamSeq, 5);
	PTF_ASSERT_EQUAL(readStreams[1].streamId, 1);
	PTF_ASSERT_EQUAL(readStreams[1].streamSeq, 10);
}

PTF_TEST_CASE(SctpAddIDataChunkTest)
{
	// Test I-DATA chunk creation (RFC 8260)
	pcpp::SctpLayer idataLayer(1234, 5678, 0x12345678);

	const char* userData = "WebRTC data";
	PTF_ASSERT_TRUE(idataLayer.addIDataChunk(1,    // TSN
	                                         0,    // Stream ID
	                                         100,  // Message ID
	                                         51,   // PPID (WebRTC String)
	                                         reinterpret_cast<const uint8_t*>(userData), strlen(userData), true, true,
	                                         false, false));

	pcpp::SctpChunk idataChunk = idataLayer.getFirstChunk();
	PTF_ASSERT_TRUE(idataChunk.isNotNull());
	PTF_ASSERT_EQUAL(idataChunk.getChunkType(), pcpp::SctpChunkType::I_DATA, enumclass);

	auto idataView = pcpp::SctpIDataChunkView::fromChunk(idataChunk);
	PTF_ASSERT_TRUE(idataView.isValid());
	PTF_ASSERT_EQUAL(idataView.getTsn(), 1);
	PTF_ASSERT_EQUAL(idataView.getStreamId(), 0);
	PTF_ASSERT_EQUAL(idataView.getMessageId(), 100);
	PTF_ASSERT_EQUAL(idataView.getPpidOrFsn(), 51);
	PTF_ASSERT_TRUE(idataView.isBeginFragment());
	PTF_ASSERT_TRUE(idataView.isEndFragment());
}

PTF_TEST_CASE(SctpAddIForwardTsnChunkTest)
{
	// Test I-FORWARD-TSN chunk creation (RFC 8260)
	pcpp::SctpLayer ifwdLayer(1234, 5678, 0x12345678);

	std::vector<pcpp::sctp_iforward_tsn_stream> streams;
	pcpp::sctp_iforward_tsn_stream s1 = { 0, 0, 50 };  // Stream 0, MID 50
	pcpp::sctp_iforward_tsn_stream s2 = { 1, 1, 25 };  // Stream 1, unordered, MID 25
	streams.push_back(s1);
	streams.push_back(s2);

	PTF_ASSERT_TRUE(ifwdLayer.addIForwardTsnChunk(200, streams));

	pcpp::SctpChunk ifwdChunk = ifwdLayer.getFirstChunk();
	PTF_ASSERT_TRUE(ifwdChunk.isNotNull());
	PTF_ASSERT_EQUAL(ifwdChunk.getChunkType(), pcpp::SctpChunkType::I_FORWARD_TSN, enumclass);

	auto ifwdView = pcpp::SctpIForwardTsnChunkView::fromChunk(ifwdChunk);
	PTF_ASSERT_TRUE(ifwdView.isValid());
	PTF_ASSERT_EQUAL(ifwdView.getNewCumulativeTsn(), 200);
	PTF_ASSERT_EQUAL(ifwdView.getStreamCount(), 2);
}

PTF_TEST_CASE(SctpAddPadChunkTest)
{
	// Test PAD chunk creation (RFC 4820)
	pcpp::SctpLayer padLayer(1234, 5678, 0x12345678);

	PTF_ASSERT_TRUE(padLayer.addPadChunk(100));

	pcpp::SctpChunk padChunk = padLayer.getFirstChunk();
	PTF_ASSERT_TRUE(padChunk.isNotNull());
	PTF_ASSERT_EQUAL(padChunk.getChunkType(), pcpp::SctpChunkType::PAD, enumclass);
	PTF_ASSERT_EQUAL(padChunk.getLength(), 104);  // 4 header + 100 padding
}

PTF_TEST_CASE(SctpErrorCauseIteratorTest)
{
	// Create ABORT chunk with multiple error causes
	pcpp::SctpLayer abortLayer(1234, 5678, 0x12345678);

	// Build error causes:
	// 1. Invalid Stream Identifier (code=1)
	// 2. User Initiated Abort (code=12)
	uint8_t errorCauses[] = {
		// Invalid Stream Identifier
		0x00, 0x01,  // Code: 1
		0x00, 0x08,  // Length: 8
		0x00, 0x10,  // Stream ID: 16
		0x00, 0x00,  // Reserved

		// User Initiated Abort
		0x00, 0x0C,             // Code: 12
		0x00, 0x08,             // Length: 8
		0x42, 0x59, 0x45, 0x21  // "BYE!"
	};

	PTF_ASSERT_TRUE(abortLayer.addAbortChunk(false, errorCauses, sizeof(errorCauses)));

	pcpp::SctpChunk abortChunk = abortLayer.getFirstChunk();
	pcpp::SctpErrorCauseIterator iter(abortChunk);
	PTF_ASSERT_TRUE(iter.isValid());

	// First cause: Invalid Stream Identifier
	pcpp::SctpErrorCause cause1 = iter.getErrorCause();
	PTF_ASSERT_TRUE(cause1.isNotNull());
	PTF_ASSERT_EQUAL(cause1.getCode(), pcpp::SctpErrorCauseCode::INVALID_STREAM_ID, enumclass);
	PTF_ASSERT_EQUAL(cause1.getCodeName(), "Invalid Stream Identifier");
	PTF_ASSERT_EQUAL(cause1.getInvalidStreamId(), 16);

	// Second cause: User Initiated Abort
	iter.next();
	PTF_ASSERT_TRUE(iter.isValid());

	pcpp::SctpErrorCause cause2 = iter.getErrorCause();
	PTF_ASSERT_EQUAL(cause2.getCode(), pcpp::SctpErrorCauseCode::USER_INITIATED_ABORT, enumclass);

	// No more causes
	iter.next();
	PTF_ASSERT_FALSE(iter.isValid());
}

PTF_TEST_CASE(SctpStateCookieParameterTest)
{
	// Create INIT-ACK chunk with State Cookie parameter
	pcpp::SctpLayer initAckLayer(5001, 5000, 0x12345678);

	// Build State Cookie parameter (Type=7)
	uint8_t params[] = {
		0x00, 0x07,              // Type: State Cookie (7)
		0x00, 0x10,              // Length: 16 (4 header + 12 cookie)
		0x53, 0x54, 0x41, 0x54,  // "STAT"
		0x45, 0x43, 0x4F, 0x4F,  // "ECOO"
		0x4B, 0x49, 0x45, 0x21   // "KIE!"
	};

	PTF_ASSERT_TRUE(initAckLayer.addInitAckChunk(0xAABBCCDD, 65536, 10, 10, 1, params, sizeof(params)));

	pcpp::SctpChunk initAckChunk = initAckLayer.getFirstChunk();
	pcpp::SctpInitParameterIterator iter(initAckChunk);
	PTF_ASSERT_TRUE(iter.isValid());

	pcpp::SctpInitParameter param = iter.getParameter();
	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::STATE_COOKIE, enumclass);
	PTF_ASSERT_EQUAL(param.getTypeName(), "State Cookie");
	PTF_ASSERT_NOT_NULL(param.getStateCookie());
	PTF_ASSERT_EQUAL(param.getStateCookieLength(), 12);
}

PTF_TEST_CASE(SctpHostNameAddressDetectionTest)
{
	// Create INIT chunk with deprecated Host Name Address parameter
	pcpp::SctpLayer initLayer(5000, 5001, 0);

	// Host Name Address parameter (Type=11, deprecated per RFC 9260)
	uint8_t params[] = {
		0x00, 0x0B,              // Type: Host Name Address (11)
		0x00, 0x10,              // Length: 16
		0x74, 0x65, 0x73, 0x74,  // "test"
		0x2E, 0x6C, 0x6F, 0x63,  // ".loc"
		0x61, 0x6C, 0x00, 0x00   // "al\0\0" (null-terminated + padding)
	};

	PTF_ASSERT_TRUE(initLayer.addInitChunk(0x12345678, 65536, 10, 10, 1, params, sizeof(params)));

	// Verify containsHostNameAddress detects it
	PTF_ASSERT_TRUE(initLayer.containsHostNameAddress());

	// Verify parameter iterator identifies it as deprecated
	pcpp::SctpChunk initChunk = initLayer.getFirstChunk();
	pcpp::SctpInitParameterIterator iter(initChunk);
	PTF_ASSERT_TRUE(iter.isValid());

	pcpp::SctpInitParameter param = iter.getParameter();
	PTF_ASSERT_TRUE(param.isHostNameAddress());
	PTF_ASSERT_EQUAL(param.getTypeName(), "Host Name Address (DEPRECATED)");
}

PTF_TEST_CASE(SctpAuthParametersTest)
{
	// Create INIT chunk with AUTH parameters (RFC 4895)
	pcpp::SctpLayer initLayer(5000, 5001, 0);

	// Build parameters:
	// 1. Random (32 bytes)
	// 2. Chunk List
	// 3. Requested HMAC Algorithm
	uint8_t params[] = {
		// Random parameter (Type=0x8002)
		0x80, 0x02,  // Type: Random
		0x00, 0x24,  // Length: 36 (4 + 32 bytes of random)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,

		// Chunk List parameter (Type=0x8003)
		0x80, 0x03,  // Type: Chunk List
		0x00, 0x06,  // Length: 6
		0x00, 0x0F,  // DATA, AUTH chunks
		0x00, 0x00,  // Padding

		// HMAC Algorithm parameter (Type=0x8004)
		0x80, 0x04,  // Type: Requested HMAC Algorithm
		0x00, 0x06,  // Length: 6
		0x00, 0x01,  // SHA-1 (1)
		0x00, 0x00   // Padding
	};

	PTF_ASSERT_TRUE(initLayer.addInitChunk(0x12345678, 65536, 10, 10, 1, params, sizeof(params)));

	pcpp::SctpChunk initChunk = initLayer.getFirstChunk();
	pcpp::SctpInitParameterIterator iter(initChunk);

	// First: Random
	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpInitParameter randomParam = iter.getParameter();
	PTF_ASSERT_EQUAL(randomParam.getType(), pcpp::SctpParameterType::RANDOM, enumclass);
	PTF_ASSERT_NOT_NULL(randomParam.getRandomData());
	PTF_ASSERT_EQUAL(randomParam.getRandomDataLength(), 32);

	// Second: Chunk List
	iter.next();
	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpInitParameter chunkListParam = iter.getParameter();
	PTF_ASSERT_EQUAL(chunkListParam.getType(), pcpp::SctpParameterType::CHUNK_LIST, enumclass);
	std::vector<uint8_t> chunkList = chunkListParam.getChunkList();
	PTF_ASSERT_EQUAL(chunkList.size(), 2);
	PTF_ASSERT_EQUAL(chunkList[0], 0);   // DATA
	PTF_ASSERT_EQUAL(chunkList[1], 15);  // AUTH

	// Third: HMAC Algorithm
	iter.next();
	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpInitParameter hmacParam = iter.getParameter();
	PTF_ASSERT_EQUAL(hmacParam.getType(), pcpp::SctpParameterType::REQUESTED_HMAC_ALGO, enumclass);
	std::vector<uint16_t> hmacAlgos = hmacParam.getRequestedHmacAlgorithms();
	PTF_ASSERT_EQUAL(hmacAlgos.size(), 1);
	PTF_ASSERT_EQUAL(hmacAlgos[0], 1);  // SHA-1
}

PTF_TEST_CASE(SctpAddAuthChunkTest)
{
	// Test AUTH chunk creation (RFC 4895)
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Create a dummy HMAC (20 bytes for SHA-1)
	uint8_t hmac[20] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
		                 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14 };

	PTF_ASSERT_TRUE(sctpLayer.addAuthChunk(1, 1, hmac, sizeof(hmac)));

	// Verify chunk
	pcpp::SctpChunk authChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(authChunk.isNotNull());
	PTF_ASSERT_EQUAL(authChunk.getChunkType(), pcpp::SctpChunkType::AUTH, enumclass);
	PTF_ASSERT_EQUAL(authChunk.getLength(), 28);  // 8 byte header + 20 byte HMAC

	// Use view for AUTH chunk access
	auto authView = pcpp::SctpAuthChunkView::fromChunk(authChunk);
	PTF_ASSERT_TRUE(authView.isValid());

	// Verify AUTH chunk fields
	PTF_ASSERT_EQUAL(authView.getSharedKeyId(), 1);
	PTF_ASSERT_EQUAL(authView.getHmacId(), 1);  // SHA-1
	PTF_ASSERT_NOT_NULL(authView.getHmacData());
	PTF_ASSERT_EQUAL(authView.getHmacLength(), 20);

	// Verify HMAC content
	const uint8_t* hmacData = authView.getHmacData();
	PTF_ASSERT_BUF_COMPARE(hmacData, hmac, 20);
}

PTF_TEST_CASE(SctpAddAsconfChunkTest)
{
	// Test ASCONF chunk creation (RFC 5061)
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build mandatory Address Parameter (IPv4)
	uint8_t addressParam[] = {
		0x00, 0x05,             // Type: IPv4 Address
		0x00, 0x08,             // Length: 8
		0xC0, 0xA8, 0x01, 0x01  // 192.168.1.1
	};

	// Build ASCONF parameter (Add IP)
	uint8_t asconfParam[] = {
		0xC0, 0x01,              // Type: Add IP Address (0xC001)
		0x00, 0x10,              // Length: 16
		0x00, 0x00, 0x00, 0x01,  // Correlation ID: 1
		0x00, 0x05,              // Type: IPv4 Address
		0x00, 0x08,              // Length: 8
		0xC0, 0xA8, 0x02, 0x01   // 192.168.2.1
	};

	PTF_ASSERT_TRUE(
	    sctpLayer.addAsconfChunk(12345, addressParam, sizeof(addressParam), asconfParam, sizeof(asconfParam)));

	// Verify chunk
	pcpp::SctpChunk asconfChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(asconfChunk.isNotNull());
	PTF_ASSERT_EQUAL(asconfChunk.getChunkType(), pcpp::SctpChunkType::ASCONF, enumclass);

	// Use view for ASCONF chunk access
	auto asconfView = pcpp::SctpAsconfChunkView::fromChunk(asconfChunk);
	PTF_ASSERT_TRUE(asconfView.isValid());
	PTF_ASSERT_EQUAL(asconfView.getSerialNumber(), 12345);
}

PTF_TEST_CASE(SctpAddAsconfAckChunkTest)
{
	// Test ASCONF-ACK chunk creation (RFC 5061)
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Success Indication response
	uint8_t responseParam[] = {
		0xC0, 0x05,             // Type: Success Indication (0xC005)
		0x00, 0x08,             // Length: 8
		0x00, 0x00, 0x00, 0x01  // Correlation ID: 1
	};

	PTF_ASSERT_TRUE(sctpLayer.addAsconfAckChunk(12345, responseParam, sizeof(responseParam)));

	// Verify chunk
	pcpp::SctpChunk asconfAckChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(asconfAckChunk.isNotNull());
	PTF_ASSERT_EQUAL(asconfAckChunk.getChunkType(), pcpp::SctpChunkType::ASCONF_ACK, enumclass);

	// Use view for ASCONF-ACK chunk access
	auto asconfAckView = pcpp::SctpAsconfAckChunkView::fromChunk(asconfAckChunk);
	PTF_ASSERT_TRUE(asconfAckView.isValid());
	PTF_ASSERT_EQUAL(asconfAckView.getSerialNumber(), 12345);
}

PTF_TEST_CASE(SctpAddReconfigChunkTest)
{
	// Test RE-CONFIG chunk creation (RFC 6525)
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Outgoing SSN Reset Request parameter
	uint8_t reconfigParam[] = {
		0x00, 0x0D,              // Type: Outgoing SSN Reset Request (13)
		0x00, 0x14,              // Length: 20
		0x00, 0x00, 0x00, 0x01,  // Request Sequence Number: 1
		0x00, 0x00, 0x00, 0x00,  // Response Sequence Number: 0
		0x00, 0x00, 0x00, 0x64,  // Last TSN: 100
		0x00, 0x00,              // Stream 0
		0x00, 0x01               // Stream 1
	};

	PTF_ASSERT_TRUE(sctpLayer.addReconfigChunk(reconfigParam, sizeof(reconfigParam)));

	// Verify chunk
	pcpp::SctpChunk reconfigChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(reconfigChunk.isNotNull());
	PTF_ASSERT_EQUAL(reconfigChunk.getChunkType(), pcpp::SctpChunkType::RE_CONFIG, enumclass);
}

PTF_TEST_CASE(SctpReconfigParameterIteratorTest)
{
	// Create RE-CONFIG chunk with parameters
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Outgoing SSN Reset Request with 2 streams
	uint8_t reconfigParam[] = {
		0x00, 0x0D,              // Type: Outgoing SSN Reset Request (13)
		0x00, 0x14,              // Length: 20
		0x00, 0x00, 0x00, 0x0A,  // Request Sequence Number: 10
		0x00, 0x00, 0x00, 0x05,  // Response Sequence Number: 5
		0x00, 0x00, 0x01, 0x00,  // Last TSN: 256
		0x00, 0x00,              // Stream 0
		0x00, 0x01               // Stream 1
	};

	PTF_ASSERT_TRUE(sctpLayer.addReconfigChunk(reconfigParam, sizeof(reconfigParam)));

	// Test iterator
	pcpp::SctpChunk reconfigChunk = sctpLayer.getFirstChunk();
	pcpp::SctpReconfigParameterIterator iter(reconfigChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpReconfigParameter param = iter.getParameter();

	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::OUTGOING_SSN_RESET_REQ, enumclass);
	PTF_ASSERT_EQUAL(param.getOutgoingReqSeqNum(), 10);
	PTF_ASSERT_EQUAL(param.getOutgoingRespSeqNum(), 5);
	PTF_ASSERT_EQUAL(param.getOutgoingLastTsn(), 256);

	std::vector<uint16_t> streams = param.getResetStreamNumbers();
	PTF_ASSERT_EQUAL(streams.size(), 2);
	PTF_ASSERT_EQUAL(streams[0], 0);
	PTF_ASSERT_EQUAL(streams[1], 1);

	// No more parameters
	iter.next();
	PTF_ASSERT_FALSE(iter.isValid());
}

PTF_TEST_CASE(SctpReconfigResponseTest)
{
	// Test RE-CONFIG Response parameter with optional TSN fields
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Re-configuration Response with optional TSNs
	uint8_t reconfigParam[] = {
		0x00, 0x10,              // Type: Re-configuration Response (16)
		0x00, 0x14,              // Length: 20 (with optional fields)
		0x00, 0x00, 0x00, 0x0A,  // Response Sequence Number: 10
		0x00, 0x00, 0x00, 0x01,  // Result: Success - Performed
		0x00, 0x00, 0x02, 0x00,  // Sender's Next TSN: 512
		0x00, 0x00, 0x03, 0x00   // Receiver's Next TSN: 768
	};

	PTF_ASSERT_TRUE(sctpLayer.addReconfigChunk(reconfigParam, sizeof(reconfigParam)));

	pcpp::SctpChunk reconfigChunk = sctpLayer.getFirstChunk();
	pcpp::SctpReconfigParameterIterator iter(reconfigChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpReconfigParameter param = iter.getParameter();

	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::RECONFIG_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(param.getReconfigRespSeqNum(), 10);
	PTF_ASSERT_EQUAL(param.getReconfigResult(), pcpp::SctpReconfigResult::SUCCESS_PERFORMED, enumclass);
	PTF_ASSERT_TRUE(param.hasReconfigOptionalTsn());
	PTF_ASSERT_EQUAL(param.getReconfigSenderNextTsn(), 512);
	PTF_ASSERT_EQUAL(param.getReconfigReceiverNextTsn(), 768);
}

PTF_TEST_CASE(SctpAsconfParameterIteratorTest)
{
	// Create ASCONF chunk with parameters
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build mandatory Address Parameter + Add IP parameter
	uint8_t addressParam[] = {
		0x00, 0x05,             // Type: IPv4 Address
		0x00, 0x08,             // Length: 8
		0xC0, 0xA8, 0x01, 0x01  // 192.168.1.1
	};

	uint8_t asconfParam[] = {
		0xC0, 0x01,              // Type: Add IP Address (0xC001)
		0x00, 0x10,              // Length: 16
		0x00, 0x00, 0x00, 0x42,  // Correlation ID: 66
		0x00, 0x05,              // Type: IPv4 Address
		0x00, 0x08,              // Length: 8
		0xAC, 0x10, 0x00, 0x01   // 172.16.0.1
	};

	PTF_ASSERT_TRUE(
	    sctpLayer.addAsconfChunk(999, addressParam, sizeof(addressParam), asconfParam, sizeof(asconfParam)));

	// Test iterator (skips Address Parameter by default)
	pcpp::SctpChunk asconfChunk = sctpLayer.getFirstChunk();
	pcpp::SctpAsconfParameterIterator iter(asconfChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpAsconfParameter param = iter.getParameter();

	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::ADD_IP_ADDRESS, enumclass);
	PTF_ASSERT_EQUAL(param.getCorrelationId(), 66);
	PTF_ASSERT_NOT_NULL(param.getAddressParameter());

	// Test address extraction
	pcpp::IPv4Address ipv4 = param.getIPv4Address();
	PTF_ASSERT_EQUAL(ipv4.toString(), "172.16.0.1");

	// No more parameters
	iter.next();
	PTF_ASSERT_FALSE(iter.isValid());
}

PTF_TEST_CASE(SctpZeroChecksumParameterTest)
{
	// Test Zero Checksum Acceptable parameter (RFC 9653)
	pcpp::SctpLayer initLayer(5000, 5001, 0);

	// Build Zero Checksum Acceptable parameter
	uint8_t params[] = {
		0x80, 0x01,             // Type: Zero Checksum Acceptable (0x8001)
		0x00, 0x08,             // Length: 8
		0x00, 0x00, 0x00, 0x01  // EDMID: 1 (DTLS)
	};

	PTF_ASSERT_TRUE(initLayer.addInitChunk(0x12345678, 65536, 10, 10, 1, params, sizeof(params)));

	pcpp::SctpChunk initChunk = initLayer.getFirstChunk();
	pcpp::SctpInitParameterIterator iter(initChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpInitParameter param = iter.getParameter();

	PTF_ASSERT_EQUAL(param.getType(), pcpp::SctpParameterType::ZERO_CHECKSUM_ACCEPTABLE, enumclass);
	PTF_ASSERT_EQUAL(param.getZeroChecksumEdmid(), 1);  // DTLS
}

PTF_TEST_CASE(SctpAdditionalErrorCauseAccessorsTest)
{
	// Test additional error cause accessors
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Missing Mandatory Parameter error cause
	uint8_t missingParamCause[] = {
		0x00, 0x02,              // Cause Code: Missing Mandatory Parameter
		0x00, 0x0C,              // Length: 12
		0x00, 0x00, 0x00, 0x02,  // Number of missing params: 2
		0x00, 0x05,              // Type: IPv4 Address
		0x00, 0x07               // Type: State Cookie
	};

	PTF_ASSERT_TRUE(sctpLayer.addErrorChunk(missingParamCause, sizeof(missingParamCause)));

	pcpp::SctpChunk errorChunk = sctpLayer.getFirstChunk();
	pcpp::SctpErrorCauseIterator iter(errorChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpErrorCause cause = iter.getErrorCause();

	PTF_ASSERT_EQUAL(cause.getCode(), pcpp::SctpErrorCauseCode::MISSING_MANDATORY_PARAM, enumclass);

	std::vector<uint16_t> missingParams = cause.getMissingMandatoryParams();
	PTF_ASSERT_EQUAL(missingParams.size(), 2);
	PTF_ASSERT_EQUAL(missingParams[0], 5);  // IPv4 Address
	PTF_ASSERT_EQUAL(missingParams[1], 7);  // State Cookie
}

PTF_TEST_CASE(SctpUnrecognizedChunkErrorTest)
{
	// Test Unrecognized Chunk Type error cause
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Build Unrecognized Chunk Type error cause with embedded chunk
	uint8_t unrecognizedChunkCause[] = {
		0x00, 0x06,  // Cause Code: Unrecognized Chunk Type
		0x00, 0x0C,  // Length: 12
		// Embedded unrecognized chunk
		0xFF,                   // Unknown chunk type
		0x00,                   // Flags
		0x00, 0x08,             // Length
		0xDE, 0xAD, 0xBE, 0xEF  // Data
	};

	PTF_ASSERT_TRUE(sctpLayer.addErrorChunk(unrecognizedChunkCause, sizeof(unrecognizedChunkCause)));

	pcpp::SctpChunk errorChunk = sctpLayer.getFirstChunk();
	pcpp::SctpErrorCauseIterator iter(errorChunk);

	PTF_ASSERT_TRUE(iter.isValid());
	pcpp::SctpErrorCause cause = iter.getErrorCause();

	PTF_ASSERT_EQUAL(cause.getCode(), pcpp::SctpErrorCauseCode::UNRECOGNIZED_CHUNK_TYPE, enumclass);
	PTF_ASSERT_NOT_NULL(cause.getUnrecognizedChunk());
	PTF_ASSERT_EQUAL(cause.getUnrecognizedChunkLength(), 8);

	// Verify the unrecognized chunk content
	const uint8_t* chunk = cause.getUnrecognizedChunk();
	PTF_ASSERT_EQUAL(chunk[0], 0xFF);  // Unknown type
}

PTF_TEST_CASE(SctpExtendedPpidEnumsTest)
{
	// Test extended PPID definitions
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::H248), 7);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::S1AP), 18);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::X2AP), 27);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::XNAP), 61);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::F1AP), 62);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::E1AP), 64);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::W1AP), 72);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::WEBRTC_BINARY_PARTIAL), 52);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::WEBRTC_STRING_PARTIAL), 54);
}

PTF_TEST_CASE(SctpReconfigResultEnumsTest)
{
	// Test RE-CONFIG result code definitions (RFC 6525)
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::SUCCESS_NOTHING_TO_DO), 0);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::SUCCESS_PERFORMED), 1);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::DENIED), 2);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::ERROR_WRONG_SSN), 3);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::ERROR_REQUEST_IN_PROGRESS), 4);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::ERROR_BAD_SEQUENCE_NUMBER), 5);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpReconfigResult::IN_PROGRESS), 6);
}

PTF_TEST_CASE(SctpEdmidEnumsTest)
{
	// Test EDMID definitions (RFC 9653)
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpEdmid::RESERVED), 0);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpEdmid::DTLS), 1);
}

PTF_TEST_CASE(SctpNrSackChunkParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// Create SCTP packet with NR-SACK chunk (Type 16)
	// NR-SACK format: 20-byte header + gap blocks + NR gap blocks + dup TSNs
	uint8_t sctpNrSackPacket[] = { // Ethernet header (14 bytes)
		                           0x00, 0x0c, 0x29, 0x3e, 0x50, 0x4f, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,

		                           // IPv4 header (20 bytes)
		                           0x45, 0x00, 0x00, 0x48,  // Total Length: 72
		                           0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8,
		                           0x01, 0x65,

		                           // SCTP common header (12 bytes)
		                           0x13, 0x88, 0x13, 0x89,  // Ports: 5000 -> 5001
		                           0xab, 0xcd, 0xef, 0x01,  // Verification tag
		                           0x00, 0x00, 0x00, 0x00,  // Checksum placeholder

		                           // NR-SACK chunk (32 bytes: 20 header + 4 gap + 4 nr-gap + 4 dup)
		                           0x10,                    // Type: NR-SACK (16)
		                           0x01,                    // Flags: A=1 (all non-renegable)
		                           0x00, 0x20,              // Length: 32
		                           0x00, 0x00, 0x00, 0x64,  // Cumulative TSN Ack: 100
		                           0x00, 0x01, 0x00, 0x00,  // ARWND: 65536
		                           0x00, 0x01,              // Num Gap Blocks: 1
		                           0x00, 0x01,              // Num NR Gap Blocks: 1
		                           0x00, 0x01,              // Num Dup TSNs: 1
		                           0x00, 0x00,              // Reserved
		                                                    // Gap Ack Block: start=5, end=8
		                           0x00, 0x05,              // Start: 5
		                           0x00, 0x08,              // End: 8
		                                                    // NR Gap Ack Block: start=10, end=12
		                           0x00, 0x0A,              // Start: 10
		                           0x00, 0x0C,              // End: 12
		                                                    // Duplicate TSN: 50
		                           0x00, 0x00, 0x00, 0x32
	};

	// Calculate CRC32c checksum
	size_t sctpOffset = 14 + 20;
	size_t sctpLen = sizeof(sctpNrSackPacket) - sctpOffset;

	uint32_t crc = pcpp::calculateSctpCrc32c(sctpNrSackPacket + sctpOffset, sctpLen);
	sctpNrSackPacket[sctpOffset + 8] = (crc >> 24) & 0xFF;
	sctpNrSackPacket[sctpOffset + 9] = (crc >> 16) & 0xFF;
	sctpNrSackPacket[sctpOffset + 10] = (crc >> 8) & 0xFF;
	sctpNrSackPacket[sctpOffset + 11] = (crc >> 0) & 0xFF;

	pcpp::RawPacket rawPacket(sctpNrSackPacket, sizeof(sctpNrSackPacket), time, false);
	pcpp::Packet sctpPacket(&rawPacket);

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);
	PTF_ASSERT_TRUE(sctpLayer->isChecksumValid());

	// Get NR-SACK chunk
	pcpp::SctpChunk nrSackChunk = sctpLayer->getChunk(pcpp::SctpChunkType::NR_SACK);
	PTF_ASSERT_TRUE(nrSackChunk.isNotNull());
	PTF_ASSERT_EQUAL(nrSackChunk.getChunkType(), pcpp::SctpChunkType::NR_SACK, enumclass);
	PTF_ASSERT_EQUAL(nrSackChunk.getChunkTypeAsInt(), 16);

	// Use view for NR-SACK access
	auto nrSackView = pcpp::SctpNrSackChunkView::fromChunk(nrSackChunk);
	PTF_ASSERT_TRUE(nrSackView.isValid());

	// Test NR-SACK fields
	PTF_ASSERT_EQUAL(nrSackView.getCumulativeTsnAck(), 100);
	PTF_ASSERT_EQUAL(nrSackView.getArwnd(), 65536);
	PTF_ASSERT_EQUAL(nrSackView.getNumGapBlocks(), 1);
	PTF_ASSERT_EQUAL(nrSackView.getNumNrGapBlocks(), 1);
	PTF_ASSERT_EQUAL(nrSackView.getNumDupTsns(), 1);
	PTF_ASSERT_TRUE(nrSackView.isAllNonRenegable());

	// Test gap blocks
	std::vector<pcpp::sctp_gap_ack_block> gapBlocks = nrSackView.getGapBlocks();
	PTF_ASSERT_EQUAL(gapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(gapBlocks[0].start, 5);
	PTF_ASSERT_EQUAL(gapBlocks[0].end, 8);

	// Test NR gap blocks
	std::vector<pcpp::sctp_gap_ack_block> nrGapBlocks = nrSackView.getNrGapBlocks();
	PTF_ASSERT_EQUAL(nrGapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(nrGapBlocks[0].start, 10);
	PTF_ASSERT_EQUAL(nrGapBlocks[0].end, 12);

	// Test duplicate TSNs
	std::vector<uint32_t> dupTsns = nrSackView.getDupTsns();
	PTF_ASSERT_EQUAL(dupTsns.size(), 1);
	PTF_ASSERT_EQUAL(dupTsns[0], 50);
}

PTF_TEST_CASE(SctpAddNrSackChunkTest)
{
	// Test NR-SACK chunk creation
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Create gap blocks
	std::vector<pcpp::sctp_gap_ack_block> gapBlocks;
	pcpp::sctp_gap_ack_block gap1 = { 3, 5 };
	pcpp::sctp_gap_ack_block gap2 = { 10, 15 };
	gapBlocks.push_back(gap1);
	gapBlocks.push_back(gap2);

	// Create NR gap blocks
	std::vector<pcpp::sctp_gap_ack_block> nrGapBlocks;
	pcpp::sctp_gap_ack_block nrGap1 = { 20, 25 };
	nrGapBlocks.push_back(nrGap1);

	// Create duplicate TSNs
	std::vector<uint32_t> dupTsns;
	dupTsns.push_back(1000);
	dupTsns.push_back(2000);

	// Add NR-SACK chunk with all non-renegable flag
	PTF_ASSERT_TRUE(sctpLayer.addNrSackChunk(500, 131072, gapBlocks, nrGapBlocks, dupTsns, true));

	// Verify chunk
	pcpp::SctpChunk nrSackChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(nrSackChunk.isNotNull());
	PTF_ASSERT_EQUAL(nrSackChunk.getChunkType(), pcpp::SctpChunkType::NR_SACK, enumclass);

	// Use view for NR-SACK access
	auto nrSackView = pcpp::SctpNrSackChunkView::fromChunk(nrSackChunk);
	PTF_ASSERT_TRUE(nrSackView.isValid());

	// Verify fields
	PTF_ASSERT_EQUAL(nrSackView.getCumulativeTsnAck(), 500);
	PTF_ASSERT_EQUAL(nrSackView.getArwnd(), 131072);
	PTF_ASSERT_EQUAL(nrSackView.getNumGapBlocks(), 2);
	PTF_ASSERT_EQUAL(nrSackView.getNumNrGapBlocks(), 1);
	PTF_ASSERT_EQUAL(nrSackView.getNumDupTsns(), 2);
	PTF_ASSERT_TRUE(nrSackView.isAllNonRenegable());

	// Verify gap blocks
	std::vector<pcpp::sctp_gap_ack_block> retrievedGaps = nrSackView.getGapBlocks();
	PTF_ASSERT_EQUAL(retrievedGaps.size(), 2);
	PTF_ASSERT_EQUAL(retrievedGaps[0].start, 3);
	PTF_ASSERT_EQUAL(retrievedGaps[0].end, 5);
	PTF_ASSERT_EQUAL(retrievedGaps[1].start, 10);
	PTF_ASSERT_EQUAL(retrievedGaps[1].end, 15);

	// Verify NR gap blocks
	std::vector<pcpp::sctp_gap_ack_block> retrievedNrGaps = nrSackView.getNrGapBlocks();
	PTF_ASSERT_EQUAL(retrievedNrGaps.size(), 1);
	PTF_ASSERT_EQUAL(retrievedNrGaps[0].start, 20);
	PTF_ASSERT_EQUAL(retrievedNrGaps[0].end, 25);

	// Verify duplicate TSNs
	std::vector<uint32_t> retrievedDups = nrSackView.getDupTsns();
	PTF_ASSERT_EQUAL(retrievedDups.size(), 2);
	PTF_ASSERT_EQUAL(retrievedDups[0], 1000);
	PTF_ASSERT_EQUAL(retrievedDups[1], 2000);
}

PTF_TEST_CASE(SctpAddNrSackChunkMinimalTest)
{
	// Test NR-SACK chunk creation with no optional fields
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Add minimal NR-SACK chunk
	PTF_ASSERT_TRUE(sctpLayer.addNrSackChunk(100, 65536));

	// Verify chunk
	pcpp::SctpChunk nrSackChunk = sctpLayer.getFirstChunk();
	PTF_ASSERT_TRUE(nrSackChunk.isNotNull());
	PTF_ASSERT_EQUAL(nrSackChunk.getChunkType(), pcpp::SctpChunkType::NR_SACK, enumclass);
	PTF_ASSERT_EQUAL(nrSackChunk.getLength(), 20);  // Just header, no blocks

	// Use view for NR-SACK access
	auto nrSackView = pcpp::SctpNrSackChunkView::fromChunk(nrSackChunk);
	PTF_ASSERT_TRUE(nrSackView.isValid());

	// Verify fields
	PTF_ASSERT_EQUAL(nrSackView.getCumulativeTsnAck(), 100);
	PTF_ASSERT_EQUAL(nrSackView.getArwnd(), 65536);
	PTF_ASSERT_EQUAL(nrSackView.getNumGapBlocks(), 0);
	PTF_ASSERT_EQUAL(nrSackView.getNumNrGapBlocks(), 0);
	PTF_ASSERT_EQUAL(nrSackView.getNumDupTsns(), 0);
	PTF_ASSERT_FALSE(nrSackView.isAllNonRenegable());
}

PTF_TEST_CASE(SctpHmacSha1ComputationTest)
{
	// Test HMAC-SHA1 computation with RFC 2202 test vectors
	// Test Case 1: key = 0x0b repeated 20 times, data = "Hi There"
	uint8_t key1[20];
	memset(key1, 0x0B, 20);
	const uint8_t data1[] = "Hi There";
	uint8_t hmac1[20];

	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha1(key1, 20, data1, 8, hmac1));

	// Expected HMAC-SHA1 from RFC 2202: 0xb617318655057264e28bc0b6fb378c8ef146be00
	uint8_t expected1[] = { 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
		                    0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00 };
	PTF_ASSERT_BUF_COMPARE(hmac1, expected1, 20);

	// Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
	const uint8_t key2[] = "Jefe";
	const uint8_t data2[] = "what do ya want for nothing?";
	uint8_t hmac2[20];

	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha1(key2, 4, data2, 28, hmac2));

	// Expected HMAC-SHA1: 0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
	uint8_t expected2[] = { 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
		                    0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79 };
	PTF_ASSERT_BUF_COMPARE(hmac2, expected2, 20);
}

PTF_TEST_CASE(SctpHmacSha256ComputationTest)
{
	// Test HMAC-SHA256 computation with RFC 4231 test vectors
	// Test Case 1: key = 0x0b repeated 20 times, data = "Hi There"
	uint8_t key1[20];
	memset(key1, 0x0B, 20);
	const uint8_t data1[] = "Hi There";
	uint8_t hmac1[32];

	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha256(key1, 20, data1, 8, hmac1));

	// Expected HMAC-SHA256 from RFC 4231
	uint8_t expected1[] = { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
		                    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
		                    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };
	PTF_ASSERT_BUF_COMPARE(hmac1, expected1, 32);

	// Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
	const uint8_t key2[] = "Jefe";
	const uint8_t data2[] = "what do ya want for nothing?";
	uint8_t hmac2[32];

	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha256(key2, 4, data2, 28, hmac2));

	// Expected HMAC-SHA256 from RFC 4231
	uint8_t expected2[] = { 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
		                    0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
		                    0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 };
	PTF_ASSERT_BUF_COMPARE(hmac2, expected2, 32);
}

PTF_TEST_CASE(SctpHmacVerificationTest)
{
	// Test HMAC verification for both SHA-1 and SHA-256
	const uint8_t key[] = "TestKey123";
	const uint8_t data[] = "Test data for SCTP AUTH chunk verification";

	// Calculate and verify SHA-1 HMAC
	uint8_t hmacSha1[20] = { 0 };
	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha1(key, 10, data, 44, hmacSha1));

	// Verify with correct HMAC (HMAC ID 1 = SHA-1)
	PTF_ASSERT_TRUE(pcpp::verifySctpHmac(1, key, 10, data, 44, hmacSha1, 20));

	// Verify with wrong HMAC
	uint8_t wrongHmac[20] = { 0 };
	PTF_ASSERT_FALSE(pcpp::verifySctpHmac(1, key, 10, data, 44, wrongHmac, 20));

	// Calculate and verify SHA-256 HMAC
	uint8_t hmacSha256[32] = { 0 };
	PTF_ASSERT_TRUE(pcpp::calculateSctpHmacSha256(key, 10, data, 44, hmacSha256));

	// Verify with correct HMAC (HMAC ID 3 = SHA-256)
	PTF_ASSERT_TRUE(pcpp::verifySctpHmac(3, key, 10, data, 44, hmacSha256, 32));

	// Verify with wrong HMAC (filled with 0xFF)
	uint8_t wrongHmac256[32];
	memset(wrongHmac256, 0xFF, sizeof(wrongHmac256));
	PTF_ASSERT_FALSE(pcpp::verifySctpHmac(3, key, 10, data, 44, wrongHmac256, 32));

	// Verify with unknown HMAC ID returns false
	PTF_ASSERT_FALSE(pcpp::verifySctpHmac(99, key, 10, data, 44, hmacSha1, 20));
}

PTF_TEST_CASE(SctpHmacSizeConstantsTest)
{
	// Test HMAC size constants
	PTF_ASSERT_EQUAL(pcpp::SctpHmacSize::SHA1, 20);
	PTF_ASSERT_EQUAL(pcpp::SctpHmacSize::SHA256, 32);
}

PTF_TEST_CASE(SctpExtendedPpidEnumsNewTest)
{
	// Test newly added PPID definitions from IANA registry
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::IRCP), 28);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::MPICH2), 31);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::FGP), 32);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::PPP), 33);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::CALCAPP), 34);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::SSP), 35);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::NPMP_CONTROL), 36);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::NPMP_DATA), 37);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::ECHO), 38);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::DISCARD), 39);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::DAYTIME), 40);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::CHARGEN), 41);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::RNA), 42);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::SSH), 45);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::DIAMETER_DTLS), 47);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::R14P_BER), 48);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::R14P_GPB), 49);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::WEBRTC_STRING_EMPTY), 56);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::WEBRTC_BINARY_EMPTY), 57);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::NRPPA), 68);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::NGAP_DTLS), 73);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::XNAP_DTLS), 74);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::DTLS_KEY_MGMT), 4242);
}

PTF_TEST_CASE(SctpNrSackChunkTypeNameTest)
{
	// Test NR-SACK chunk type name
	pcpp::sctp_chunk_hdr chunkHdr;
	chunkHdr.type = 16;  // NR-SACK
	chunkHdr.flags = 0;
	chunkHdr.length = htobe16(20);

	pcpp::SctpChunk chunk(reinterpret_cast<uint8_t*>(&chunkHdr));
	PTF_ASSERT_EQUAL(chunk.getChunkType(), pcpp::SctpChunkType::NR_SACK, enumclass);
	PTF_ASSERT_EQUAL(chunk.getChunkTypeName(), "NR-SACK");
}

PTF_TEST_CASE(SctpChunkActionBitsTest)
{
	// Test chunk action bits (RFC 9260 Section 3.2)

	// Test action bit extraction
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0x00), pcpp::SctpChunkActionBits::STOP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0x0F), pcpp::SctpChunkActionBits::STOP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0x40), pcpp::SctpChunkActionBits::STOP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0x7F), pcpp::SctpChunkActionBits::STOP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0x80), pcpp::SctpChunkActionBits::SKIP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0xBF), pcpp::SctpChunkActionBits::SKIP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0xC0), pcpp::SctpChunkActionBits::SKIP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0xFF), pcpp::SctpChunkActionBits::SKIP_NO_REPORT);

	// Test known chunk types (should all be 00 - stop and report)
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(0), pcpp::SctpChunkActionBits::STOP_AND_REPORT);   // DATA
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(1), pcpp::SctpChunkActionBits::STOP_AND_REPORT);   // INIT
	PTF_ASSERT_EQUAL(pcpp::getSctpChunkActionBits(15), pcpp::SctpChunkActionBits::STOP_AND_REPORT);  // AUTH

	// Test shouldStopOnUnrecognizedChunk
	PTF_ASSERT_TRUE(pcpp::shouldStopOnUnrecognizedChunk(0x00));   // 00 - stop
	PTF_ASSERT_TRUE(pcpp::shouldStopOnUnrecognizedChunk(0x40));   // 01 - stop
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedChunk(0x80));  // 10 - skip
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedChunk(0xC0));  // 11 - skip

	// Test shouldReportUnrecognizedChunk
	PTF_ASSERT_TRUE(pcpp::shouldReportUnrecognizedChunk(0x00));   // 00 - report
	PTF_ASSERT_FALSE(pcpp::shouldReportUnrecognizedChunk(0x40));  // 01 - no report
	PTF_ASSERT_TRUE(pcpp::shouldReportUnrecognizedChunk(0x80));   // 10 - report
	PTF_ASSERT_FALSE(pcpp::shouldReportUnrecognizedChunk(0xC0));  // 11 - no report

	// Test with actual SCTP chunk types that use high bits
	// I-DATA (64 = 0x40) has bits 01 - stop, no report
	PTF_ASSERT_TRUE(pcpp::shouldStopOnUnrecognizedChunk(64));
	PTF_ASSERT_FALSE(pcpp::shouldReportUnrecognizedChunk(64));

	// ASCONF-ACK (128 = 0x80) has bits 10 - skip, report
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedChunk(128));
	PTF_ASSERT_TRUE(pcpp::shouldReportUnrecognizedChunk(128));

	// FORWARD-TSN (192 = 0xC0) has bits 11 - skip, no report
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedChunk(192));
	PTF_ASSERT_FALSE(pcpp::shouldReportUnrecognizedChunk(192));
}

PTF_TEST_CASE(SctpParamActionBitsTest)
{
	// Test parameter action bits (RFC 9260 Section 3.2.1)

	// Test action bit extraction
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0x0000), pcpp::SctpParamActionBits::STOP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0x0FFF), pcpp::SctpParamActionBits::STOP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0x4000), pcpp::SctpParamActionBits::STOP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0x7FFF), pcpp::SctpParamActionBits::STOP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0x8000), pcpp::SctpParamActionBits::SKIP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0xBFFF), pcpp::SctpParamActionBits::SKIP_AND_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0xC000), pcpp::SctpParamActionBits::SKIP_NO_REPORT);
	PTF_ASSERT_EQUAL(pcpp::getSctpParamActionBits(0xFFFF), pcpp::SctpParamActionBits::SKIP_NO_REPORT);

	// Test known parameter types
	// IPv4 Address (5) - bits 00
	PTF_ASSERT_TRUE(pcpp::shouldStopOnUnrecognizedParam(5));
	PTF_ASSERT_TRUE(pcpp::shouldReportUnrecognizedParam(5));

	// ECN Capable (0x8000) - bits 10
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedParam(0x8000));
	PTF_ASSERT_TRUE(pcpp::shouldReportUnrecognizedParam(0x8000));

	// Forward TSN Supported (0xC000) - bits 11
	PTF_ASSERT_FALSE(pcpp::shouldStopOnUnrecognizedParam(0xC000));
	PTF_ASSERT_FALSE(pcpp::shouldReportUnrecognizedParam(0xC000));
}

PTF_TEST_CASE(SctpComputeAuthHmacTest)
{
	// Create SCTP packet with AUTH chunk followed by DATA chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Add AUTH chunk with SHA-1 HMAC (ID 1)
	uint8_t dummyHmac[20] = { 0 };  // Will be replaced
	PTF_ASSERT_TRUE(sctpLayer.addAuthChunk(0, 1, dummyHmac, 20));

	// Add DATA chunk after AUTH
	uint8_t userData[] = "Test data for AUTH";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(1, 0, 0, 0, userData, sizeof(userData) - 1, true, true, false, false));

	// Compute HMAC
	const uint8_t key[] = "SharedSecretKey";
	uint8_t hmacOut[32];
	size_t hmacOutLen = 0;

	PTF_ASSERT_TRUE(pcpp::computeSctpAuthHmac(sctpLayer, key, 15, hmacOut, &hmacOutLen));
	PTF_ASSERT_EQUAL(hmacOutLen, 20);  // SHA-1 produces 20 bytes

	// Verify HMAC is not all zeros (it was computed)
	bool allZeros = true;
	for (size_t i = 0; i < hmacOutLen; ++i)
	{
		if (hmacOut[i] != 0)
		{
			allZeros = false;
			break;
		}
	}
	PTF_ASSERT_FALSE(allZeros);
}

PTF_TEST_CASE(SctpComputeAuthHmacSha256Test)
{
	// Create SCTP packet with AUTH chunk using SHA-256
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	// Add AUTH chunk with SHA-256 HMAC (ID 3)
	uint8_t dummyHmac[32] = { 0 };
	PTF_ASSERT_TRUE(sctpLayer.addAuthChunk(0, 3, dummyHmac, 32));

	// Add DATA chunk after AUTH
	uint8_t userData[] = "Test data";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(1, 0, 0, 0, userData, sizeof(userData) - 1, true, true, false, false));

	// Compute HMAC
	const uint8_t key[] = "AnotherKey";
	uint8_t hmacOut[32];
	size_t hmacOutLen = 0;

	PTF_ASSERT_TRUE(pcpp::computeSctpAuthHmac(sctpLayer, key, 10, hmacOut, &hmacOutLen));
	PTF_ASSERT_EQUAL(hmacOutLen, 32);  // SHA-256 produces 32 bytes
}

PTF_TEST_CASE(SctpComputeAuthHmacNoAuthChunkTest)
{
	// Create SCTP packet without AUTH chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	uint8_t userData[] = "Test data";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(1, 0, 0, 0, userData, sizeof(userData) - 1, true, true, false, false));

	// Should fail - no AUTH chunk
	const uint8_t key[] = "Key";
	uint8_t hmacOut[32];
	size_t hmacOutLen = 0;

	PTF_ASSERT_FALSE(pcpp::computeSctpAuthHmac(sctpLayer, key, 3, hmacOut, &hmacOutLen));
}

PTF_TEST_CASE(SctpExtendedPpidEnumsNewTelecomTest)
{
	// Test newly added telecom PPID definitions
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::HTTP_SCTP), 63);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::E2AP), 65);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::E2AP_DTLS), 66);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::W1AP_NON_DTLS), 67);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::NRPPA_DTLS), 69);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::F1AP_DTLS), 70);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(pcpp::SctpPayloadProtocolId::E1AP_DTLS), 71);
}

// ==================== Typed View API Tests ====================

PTF_TEST_CASE(SctpDataChunkViewTest)
{
	// Parse SCTP DATA packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpDataPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpDataChunkView dataView = sctpLayer->getDataChunk();
	PTF_ASSERT_TRUE(dataView.isValid());

	// Test DATA chunk fields via view
	PTF_ASSERT_EQUAL(dataView.getTsn(), 10);
	PTF_ASSERT_EQUAL(dataView.getStreamId(), 1);
	PTF_ASSERT_EQUAL(dataView.getSequenceNumber(), 5);
	PTF_ASSERT_EQUAL(dataView.getPpid(), 46);

	// Test flags via view
	PTF_ASSERT_TRUE(dataView.isBeginFragment());
	PTF_ASSERT_TRUE(dataView.isEndFragment());
	PTF_ASSERT_FALSE(dataView.isUnordered());
	PTF_ASSERT_FALSE(dataView.isImmediate());

	// Test user data via view
	PTF_ASSERT_EQUAL(dataView.getUserDataLength(), 12);
	uint8_t* userData = dataView.getUserData();
	PTF_ASSERT_NOT_NULL(userData);
	PTF_ASSERT_BUF_COMPARE(userData, "Hello World!", 12);

	// Test fromChunk factory method
	pcpp::SctpChunk genericChunk = sctpLayer->getChunk(pcpp::SctpChunkType::DATA);
	pcpp::SctpDataChunkView dataView2 = pcpp::SctpDataChunkView::fromChunk(genericChunk);
	PTF_ASSERT_TRUE(dataView2.isValid());
	PTF_ASSERT_EQUAL(dataView2.getTsn(), 10);

	// Test invalid view (wrong chunk type)
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpDataChunkView invalidView = pcpp::SctpDataChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getTsn(), 0);
	PTF_ASSERT_NULL(invalidView.getUserData());
}

PTF_TEST_CASE(SctpInitChunkViewTest)
{
	// Parse SCTP INIT packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpInitPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpInitChunkView initView = sctpLayer->getInitChunk();
	PTF_ASSERT_TRUE(initView.isValid());

	// Test INIT chunk fields via view
	PTF_ASSERT_EQUAL(initView.getInitiateTag(), 0xaabbccdd);
	PTF_ASSERT_EQUAL(initView.getArwnd(), 65536);
	PTF_ASSERT_EQUAL(initView.getNumOutboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getNumInboundStreams(), 10);
	PTF_ASSERT_EQUAL(initView.getInitialTsn(), 1);

	// Test common methods via view
	PTF_ASSERT_EQUAL(initView.getLength(), 20);
	PTF_ASSERT_EQUAL(initView.getFlags(), 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = initView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::INIT, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpInitChunkView invalidView = pcpp::SctpInitChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getInitiateTag(), 0);
}

PTF_TEST_CASE(SctpInitAckChunkViewTest)
{
	// Create SCTP packet with INIT-ACK chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	uint8_t params[] = { 0x00, 0x05, 0x00, 0x08, 0xc0, 0xa8, 0x01, 0x01 };  // IPv4 address parameter
	PTF_ASSERT_TRUE(sctpLayer.addInitAckChunk(0x11223344, 131072, 20, 15, 1000, params, sizeof(params)));

	// Test using typed getter
	pcpp::SctpInitAckChunkView initAckView = sctpLayer.getInitAckChunk();
	PTF_ASSERT_TRUE(initAckView.isValid());

	// Test INIT-ACK chunk fields via view
	PTF_ASSERT_EQUAL(initAckView.getInitiateTag(), 0x11223344);
	PTF_ASSERT_EQUAL(initAckView.getArwnd(), 131072);
	PTF_ASSERT_EQUAL(initAckView.getNumOutboundStreams(), 20);
	PTF_ASSERT_EQUAL(initAckView.getNumInboundStreams(), 15);
	PTF_ASSERT_EQUAL(initAckView.getInitialTsn(), 1000);

	// Test parameters access
	PTF_ASSERT_EQUAL(initAckView.getParametersLength(), sizeof(params));
	PTF_ASSERT_NOT_NULL(initAckView.getFirstParameter());

	// Test that INIT view is invalid for INIT-ACK chunk
	pcpp::SctpInitChunkView wrongView = sctpLayer.getInitChunk();
	PTF_ASSERT_FALSE(wrongView.isValid());
}

PTF_TEST_CASE(SctpSackChunkViewTest)
{
	// Parse SCTP SACK packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpSackPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpSackChunkView sackView = sctpLayer->getSackChunk();
	PTF_ASSERT_TRUE(sackView.isValid());

	// Test SACK chunk fields via view
	PTF_ASSERT_EQUAL(sackView.getCumulativeTsnAck(), 20);
	PTF_ASSERT_EQUAL(sackView.getArwnd(), 32768);
	PTF_ASSERT_EQUAL(sackView.getNumGapBlocks(), 1);
	PTF_ASSERT_EQUAL(sackView.getNumDupTsns(), 1);

	// Test gap blocks via view
	std::vector<pcpp::sctp_gap_ack_block> gapBlocks = sackView.getGapBlocks();
	PTF_ASSERT_EQUAL(gapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(gapBlocks[0].start, 5);
	PTF_ASSERT_EQUAL(gapBlocks[0].end, 8);

	// Test duplicate TSNs via view
	std::vector<uint32_t> dupTsns = sackView.getDupTsns();
	PTF_ASSERT_EQUAL(dupTsns.size(), 1);
	PTF_ASSERT_EQUAL(dupTsns[0], 15);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpSackChunkView invalidView = pcpp::SctpSackChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getCumulativeTsnAck(), 0);
	PTF_ASSERT_TRUE(invalidView.getGapBlocks().empty());
	PTF_ASSERT_TRUE(invalidView.getDupTsns().empty());
}

PTF_TEST_CASE(SctpChunkViewTypeSafetyTest)
{
	// Create SCTP packet with DATA chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	uint8_t userData[] = "Test";
	PTF_ASSERT_TRUE(sctpLayer.addDataChunk(100, 1, 0, 46, userData, sizeof(userData) - 1, true, true, false, false));

	// Get the DATA chunk
	pcpp::SctpChunk dataChunk = sctpLayer.getChunk(pcpp::SctpChunkType::DATA);
	PTF_ASSERT_TRUE(dataChunk.isNotNull());

	// DATA view should be valid
	pcpp::SctpDataChunkView dataView = pcpp::SctpDataChunkView::fromChunk(dataChunk);
	PTF_ASSERT_TRUE(dataView.isValid());

	// INIT view should be invalid for DATA chunk
	pcpp::SctpInitChunkView initView = pcpp::SctpInitChunkView::fromChunk(dataChunk);
	PTF_ASSERT_FALSE(initView.isValid());

	// SACK view should be invalid for DATA chunk
	pcpp::SctpSackChunkView sackView = pcpp::SctpSackChunkView::fromChunk(dataChunk);
	PTF_ASSERT_FALSE(sackView.isValid());

	// Typed getters should return invalid views for missing chunk types
	PTF_ASSERT_FALSE(sctpLayer.getInitChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getInitAckChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getSackChunk().isValid());
}

PTF_TEST_CASE(SctpHeartbeatChunkViewTest)
{
	// Parse SCTP HEARTBEAT packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpHeartbeatPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpHeartbeatChunkView hbView = sctpLayer->getHeartbeatChunk();
	PTF_ASSERT_TRUE(hbView.isValid());

	// Test common methods via view
	PTF_ASSERT_EQUAL(hbView.getLength(), 16);
	PTF_ASSERT_EQUAL(hbView.getFlags(), 0);

	// Test heartbeat info access
	PTF_ASSERT_TRUE(hbView.getInfoLength() > 0);
	PTF_ASSERT_NOT_NULL(hbView.getInfo());

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = hbView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::HEARTBEAT, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpHeartbeatChunkView invalidView = pcpp::SctpHeartbeatChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getInfoLength(), 0);
	PTF_ASSERT_NULL(invalidView.getInfo());
}

PTF_TEST_CASE(SctpCookieEchoChunkViewTest)
{
	// Parse SCTP COOKIE-ECHO packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpCookieEchoPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpCookieEchoChunkView cookieView = sctpLayer->getCookieEchoChunk();
	PTF_ASSERT_TRUE(cookieView.isValid());

	// Test cookie access
	PTF_ASSERT_TRUE(cookieView.getCookieLength() > 0);
	PTF_ASSERT_NOT_NULL(cookieView.getCookie());

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = cookieView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::COOKIE_ECHO, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpCookieEchoChunkView invalidView = pcpp::SctpCookieEchoChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getCookieLength(), 0);
	PTF_ASSERT_NULL(invalidView.getCookie());
}

PTF_TEST_CASE(SctpAbortChunkViewTest)
{
	// Create SCTP packet with ABORT chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addAbortChunk(false));

	// Test using typed getter from SctpLayer
	pcpp::SctpAbortChunkView abortView = sctpLayer.getAbortChunk();
	PTF_ASSERT_TRUE(abortView.isValid());

	// Test ABORT chunk fields via view
	PTF_ASSERT_FALSE(abortView.isTBitSet());
	PTF_ASSERT_EQUAL(abortView.getErrorCausesLength(), 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = abortView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::ABORT, enumclass);

	// Test with T bit set
	pcpp::SctpLayer sctpLayer2(5000, 5001, 0xDEADBEEF);
	PTF_ASSERT_TRUE(sctpLayer2.addAbortChunk(true));
	pcpp::SctpAbortChunkView abortView2 = sctpLayer2.getAbortChunk();
	PTF_ASSERT_TRUE(abortView2.isValid());
	PTF_ASSERT_TRUE(abortView2.isTBitSet());

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpAbortChunkView invalidView = pcpp::SctpAbortChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_FALSE(invalidView.isTBitSet());
}

PTF_TEST_CASE(SctpShutdownChunkViewTest)
{
	// Create SCTP packet with SHUTDOWN chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addShutdownChunk(12345678));

	// Test using typed getter from SctpLayer
	pcpp::SctpShutdownChunkView shutdownView = sctpLayer.getShutdownChunk();
	PTF_ASSERT_TRUE(shutdownView.isValid());

	// Test SHUTDOWN chunk fields via view
	PTF_ASSERT_EQUAL(shutdownView.getCumulativeTsnAck(), 12345678);

	// Test common methods via view
	PTF_ASSERT_EQUAL(shutdownView.getLength(), 8);
	PTF_ASSERT_EQUAL(shutdownView.getFlags(), 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = shutdownView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::SHUTDOWN, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpShutdownChunkView invalidView = pcpp::SctpShutdownChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getCumulativeTsnAck(), 0);
}

PTF_TEST_CASE(SctpShutdownAckChunkViewTest)
{
	// Create SCTP packet with SHUTDOWN-ACK chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addShutdownAckChunk());

	// Test using typed getter from SctpLayer
	pcpp::SctpShutdownAckChunkView shutdownAckView = sctpLayer.getShutdownAckChunk();
	PTF_ASSERT_TRUE(shutdownAckView.isValid());

	// Test common methods via view
	PTF_ASSERT_EQUAL(shutdownAckView.getLength(), 4);
	PTF_ASSERT_EQUAL(shutdownAckView.getFlags(), 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = shutdownAckView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::SHUTDOWN_ACK, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpShutdownAckChunkView invalidView = pcpp::SctpShutdownAckChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
}

PTF_TEST_CASE(SctpShutdownCompleteChunkViewTest)
{
	// Create SCTP packet with SHUTDOWN-COMPLETE chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addShutdownCompleteChunk(false));

	// Test using typed getter from SctpLayer
	pcpp::SctpShutdownCompleteChunkView shutdownCompleteView = sctpLayer.getShutdownCompleteChunk();
	PTF_ASSERT_TRUE(shutdownCompleteView.isValid());

	// Test SHUTDOWN-COMPLETE chunk fields via view
	PTF_ASSERT_FALSE(shutdownCompleteView.isTBitSet());

	// Test common methods via view
	PTF_ASSERT_EQUAL(shutdownCompleteView.getLength(), 4);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = shutdownCompleteView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::SHUTDOWN_COMPLETE, enumclass);

	// Test with T bit set
	pcpp::SctpLayer sctpLayer2(5000, 5001, 0xDEADBEEF);
	PTF_ASSERT_TRUE(sctpLayer2.addShutdownCompleteChunk(true));
	pcpp::SctpShutdownCompleteChunkView shutdownCompleteView2 = sctpLayer2.getShutdownCompleteChunk();
	PTF_ASSERT_TRUE(shutdownCompleteView2.isValid());
	PTF_ASSERT_TRUE(shutdownCompleteView2.isTBitSet());

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpShutdownCompleteChunkView invalidView = pcpp::SctpShutdownCompleteChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_FALSE(invalidView.isTBitSet());
}

PTF_TEST_CASE(SctpControlChunkViewTypeSafetyTest)
{
	// Create SCTP packet with HEARTBEAT chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addHeartbeatChunk(nullptr, 0));

	// Get the HEARTBEAT chunk
	pcpp::SctpChunk hbChunk = sctpLayer.getChunk(pcpp::SctpChunkType::HEARTBEAT);
	PTF_ASSERT_TRUE(hbChunk.isNotNull());

	// HEARTBEAT view should be valid
	pcpp::SctpHeartbeatChunkView hbView = pcpp::SctpHeartbeatChunkView::fromChunk(hbChunk);
	PTF_ASSERT_TRUE(hbView.isValid());

	// Other control chunk views should be invalid for HEARTBEAT chunk
	PTF_ASSERT_FALSE(pcpp::SctpHeartbeatAckChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpAbortChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpShutdownChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpShutdownAckChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpShutdownCompleteChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpErrorChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpCookieEchoChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpCookieAckChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpEcneChunkView::fromChunk(hbChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpCwrChunkView::fromChunk(hbChunk).isValid());

	// Typed getters should return invalid views for missing chunk types
	PTF_ASSERT_FALSE(sctpLayer.getHeartbeatAckChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getAbortChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getShutdownChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getShutdownAckChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getShutdownCompleteChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getErrorChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getCookieEchoChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getCookieAckChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getEcneChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getCwrChunk().isValid());
}

PTF_TEST_CASE(SctpAuthChunkViewTest)
{
	// Parse SCTP AUTH packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpAuthPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpAuthChunkView authView = sctpLayer->getAuthChunk();
	PTF_ASSERT_TRUE(authView.isValid());

	// Test AUTH chunk fields via view
	PTF_ASSERT_TRUE(authView.getSharedKeyId() == 0 || authView.getSharedKeyId() > 0);
	PTF_ASSERT_TRUE(authView.getHmacId() == 1 || authView.getHmacId() == 3);  // SHA-1 or SHA-256
	PTF_ASSERT_TRUE(authView.getHmacLength() > 0);
	PTF_ASSERT_NOT_NULL(authView.getHmacData());

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = authView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::AUTH, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpAuthChunkView invalidView = pcpp::SctpAuthChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getSharedKeyId(), 0);
	PTF_ASSERT_EQUAL(invalidView.getHmacLength(), 0);
	PTF_ASSERT_NULL(invalidView.getHmacData());
}

PTF_TEST_CASE(SctpForwardTsnChunkViewTest)
{
	// Parse SCTP FORWARD-TSN packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpForwardTsnPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpForwardTsnChunkView fwdView = sctpLayer->getForwardTsnChunk();
	PTF_ASSERT_TRUE(fwdView.isValid());

	// Test FORWARD-TSN chunk fields via view
	PTF_ASSERT_TRUE(fwdView.getNewCumulativeTsn() > 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = fwdView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::FORWARD_TSN, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpForwardTsnChunkView invalidView = pcpp::SctpForwardTsnChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getNewCumulativeTsn(), 0);
	PTF_ASSERT_EQUAL(invalidView.getStreamCount(), 0);
	PTF_ASSERT_TRUE(invalidView.getStreams().empty());
}

PTF_TEST_CASE(SctpIDataChunkViewTest)
{
	// Parse SCTP I-DATA packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpIDataPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpIDataChunkView idataView = sctpLayer->getIDataChunk();
	PTF_ASSERT_TRUE(idataView.isValid());

	// Test I-DATA chunk fields via view
	PTF_ASSERT_TRUE(idataView.getTsn() > 0);
	PTF_ASSERT_TRUE(idataView.getUserDataLength() > 0);
	PTF_ASSERT_NOT_NULL(idataView.getUserData());

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = idataView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::I_DATA, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpIDataChunkView invalidView = pcpp::SctpIDataChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getTsn(), 0);
	PTF_ASSERT_EQUAL(invalidView.getMessageId(), 0);
	PTF_ASSERT_NULL(invalidView.getUserData());
}

PTF_TEST_CASE(SctpIForwardTsnChunkViewTest)
{
	// Parse SCTP I-FORWARD-TSN packet from hex resource file
	auto rawPacket = createPacketFromHexResource("PacketExamples/SctpIForwardTsnPacket.dat");

	pcpp::Packet sctpPacket(rawPacket.get());

	pcpp::SctpLayer* sctpLayer = sctpPacket.getLayerOfType<pcpp::SctpLayer>();
	PTF_ASSERT_NOT_NULL(sctpLayer);

	// Test using typed getter from SctpLayer
	pcpp::SctpIForwardTsnChunkView ifwdView = sctpLayer->getIForwardTsnChunk();
	PTF_ASSERT_TRUE(ifwdView.isValid());

	// Test I-FORWARD-TSN chunk fields via view
	PTF_ASSERT_TRUE(ifwdView.getNewCumulativeTsn() > 0);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = ifwdView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::I_FORWARD_TSN, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpIForwardTsnChunkView invalidView = pcpp::SctpIForwardTsnChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getNewCumulativeTsn(), 0);
	PTF_ASSERT_EQUAL(invalidView.getStreamCount(), 0);
	PTF_ASSERT_TRUE(invalidView.getStreams().empty());
}

PTF_TEST_CASE(SctpNrSackChunkViewTest)
{
	// Create SCTP packet with NR-SACK chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	std::vector<pcpp::sctp_gap_ack_block> gapBlocks = {
		{ 3, 5 }
	};
	std::vector<pcpp::sctp_gap_ack_block> nrGapBlocks = {
		{ 10, 12 }
	};
	std::vector<uint32_t> dupTsns = { 100 };

	PTF_ASSERT_TRUE(sctpLayer.addNrSackChunk(1000, 65535, gapBlocks, nrGapBlocks, dupTsns));

	// Test using typed getter from SctpLayer
	pcpp::SctpNrSackChunkView nrsackView = sctpLayer.getNrSackChunk();
	PTF_ASSERT_TRUE(nrsackView.isValid());

	// Test NR-SACK chunk fields via view
	PTF_ASSERT_EQUAL(nrsackView.getCumulativeTsnAck(), 1000);
	PTF_ASSERT_EQUAL(nrsackView.getArwnd(), 65535);
	PTF_ASSERT_EQUAL(nrsackView.getNumGapBlocks(), 1);
	PTF_ASSERT_EQUAL(nrsackView.getNumNrGapBlocks(), 1);
	PTF_ASSERT_EQUAL(nrsackView.getNumDupTsns(), 1);

	// Test gap blocks via view
	std::vector<pcpp::sctp_gap_ack_block> retrievedGapBlocks = nrsackView.getGapBlocks();
	PTF_ASSERT_EQUAL(retrievedGapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(retrievedGapBlocks[0].start, 3);
	PTF_ASSERT_EQUAL(retrievedGapBlocks[0].end, 5);

	// Test NR gap blocks via view
	std::vector<pcpp::sctp_gap_ack_block> retrievedNrGapBlocks = nrsackView.getNrGapBlocks();
	PTF_ASSERT_EQUAL(retrievedNrGapBlocks.size(), 1);
	PTF_ASSERT_EQUAL(retrievedNrGapBlocks[0].start, 10);
	PTF_ASSERT_EQUAL(retrievedNrGapBlocks[0].end, 12);

	// Test duplicate TSNs via view
	std::vector<uint32_t> retrievedDupTsns = nrsackView.getDupTsns();
	PTF_ASSERT_EQUAL(retrievedDupTsns.size(), 1);
	PTF_ASSERT_EQUAL(retrievedDupTsns[0], 100);

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = nrsackView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::NR_SACK, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpNrSackChunkView invalidView = pcpp::SctpNrSackChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getCumulativeTsnAck(), 0);
	PTF_ASSERT_TRUE(invalidView.getGapBlocks().empty());
	PTF_ASSERT_TRUE(invalidView.getNrGapBlocks().empty());
	PTF_ASSERT_TRUE(invalidView.getDupTsns().empty());
}

PTF_TEST_CASE(SctpPadChunkViewTest)
{
	// Create SCTP packet with PAD chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	PTF_ASSERT_TRUE(sctpLayer.addPadChunk(16));

	// Test using typed getter from SctpLayer
	pcpp::SctpPadChunkView padView = sctpLayer.getPadChunk();
	PTF_ASSERT_TRUE(padView.isValid());

	// Test PAD chunk fields via view
	PTF_ASSERT_EQUAL(padView.getPaddingLength(), 16);
	PTF_ASSERT_NOT_NULL(padView.getPaddingData());

	// Test getChunk() returns underlying chunk
	pcpp::SctpChunk underlyingChunk = padView.getChunk();
	PTF_ASSERT_TRUE(underlyingChunk.isNotNull());
	PTF_ASSERT_EQUAL(underlyingChunk.getChunkType(), pcpp::SctpChunkType::PAD, enumclass);

	// Test invalid view
	pcpp::SctpChunk nullChunk(nullptr);
	pcpp::SctpPadChunkView invalidView = pcpp::SctpPadChunkView::fromChunk(nullChunk);
	PTF_ASSERT_FALSE(invalidView.isValid());
	PTF_ASSERT_EQUAL(invalidView.getPaddingLength(), 0);
	PTF_ASSERT_NULL(invalidView.getPaddingData());
}

PTF_TEST_CASE(SctpExtensionChunkViewTypeSafetyTest)
{
	// Create SCTP packet with FORWARD-TSN chunk
	pcpp::SctpLayer sctpLayer(5000, 5001, 0xDEADBEEF);

	std::vector<pcpp::sctp_forward_tsn_stream> streams;
	PTF_ASSERT_TRUE(sctpLayer.addForwardTsnChunk(1000, streams));

	// Get the FORWARD-TSN chunk
	pcpp::SctpChunk fwdChunk = sctpLayer.getChunk(pcpp::SctpChunkType::FORWARD_TSN);
	PTF_ASSERT_TRUE(fwdChunk.isNotNull());

	// FORWARD-TSN view should be valid
	pcpp::SctpForwardTsnChunkView fwdView = pcpp::SctpForwardTsnChunkView::fromChunk(fwdChunk);
	PTF_ASSERT_TRUE(fwdView.isValid());

	// Other extension chunk views should be invalid for FORWARD-TSN chunk
	PTF_ASSERT_FALSE(pcpp::SctpAuthChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpIDataChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpIForwardTsnChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpAsconfChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpAsconfAckChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpReconfigChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpPadChunkView::fromChunk(fwdChunk).isValid());
	PTF_ASSERT_FALSE(pcpp::SctpNrSackChunkView::fromChunk(fwdChunk).isValid());

	// Typed getters should return invalid views for missing chunk types
	PTF_ASSERT_FALSE(sctpLayer.getAuthChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getIDataChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getIForwardTsnChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getAsconfChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getAsconfAckChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getReconfigChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getPadChunk().isValid());
	PTF_ASSERT_FALSE(sctpLayer.getNrSackChunk().isValid());
}
