#include "PcapFileDevice.h"
#include "IoUringPcapDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"

#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>
#include <memory>

#define TEST_CHECK(condition, msg)                                                                                     \
	do                                                                                                                 \
	{                                                                                                                  \
		if (!(condition))                                                                                              \
		{                                                                                                              \
			std::cerr << "\n[TEST FAILED] " << __FILE__ << ":" << __LINE__ << ": " << (msg) << " (" #condition ")\n";  \
			return false;                                                                                              \
		}                                                                                                              \
	} while (false)

struct ReaderScopeGuard
{
	pcpp::IDevice* dev = nullptr;
	explicit ReaderScopeGuard(pcpp::IDevice* d) : dev(d)
	{}
	~ReaderScopeGuard()
	{
		if (dev != nullptr && dev->isOpened())
		{
			dev->close();
		}
	}
};

static inline void write16(uint8_t* dst, uint16_t v, bool bigEndian)
{
	if (bigEndian)
	{
		dst[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
		dst[1] = static_cast<uint8_t>(v & 0xFF);
	}
	else
	{
		dst[0] = static_cast<uint8_t>(v & 0xFF);
		dst[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
	}
}

static inline void write32(uint8_t* dst, uint32_t v, bool bigEndian)
{
	if (bigEndian)
	{
		dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
		dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
		dst[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
		dst[3] = static_cast<uint8_t>(v & 0xFF);
	}
	else
	{
		dst[0] = static_cast<uint8_t>(v & 0xFF);
		dst[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
		dst[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
		dst[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
	}
}

static bool comparePackets(const pcpp::RawPacket& p1, const pcpp::RawPacket& p2, size_t idx)
{
	if (p1.getRawDataLen() != p2.getRawDataLen())
	{
		std::cerr << "Mismatch at packet " << idx << ": length " << p1.getRawDataLen() << " vs " << p2.getRawDataLen()
		          << "\n";
		return false;
	}
	if (p1.getFrameLength() != p2.getFrameLength())
	{
		std::cerr << "Mismatch at packet " << idx << ": frame length " << p1.getFrameLength() << " vs "
		          << p2.getFrameLength() << "\n";
		return false;
	}
	if (p1.getPacketTimeStamp().tv_sec != p2.getPacketTimeStamp().tv_sec ||
	    p1.getPacketTimeStamp().tv_nsec != p2.getPacketTimeStamp().tv_nsec)
	{
		std::cerr << "Mismatch at packet " << idx << ": timestamp (" << p1.getPacketTimeStamp().tv_sec << "."
		          << p1.getPacketTimeStamp().tv_nsec << " vs " << p2.getPacketTimeStamp().tv_sec << "."
		          << p2.getPacketTimeStamp().tv_nsec << ")\n";
		return false;
	}
	if (p1.getLinkLayerType() != p2.getLinkLayerType())
	{
		std::cerr << "Mismatch at packet " << idx << ": link layer " << p1.getLinkLayerType() << " vs "
		          << p2.getLinkLayerType() << "\n";
		return false;
	}
	if (p1.getRawDataLen() > 0 && std::memcmp(p1.getRawData(), p2.getRawData(), p1.getRawDataLen()) != 0)
	{
		std::cerr << "Mismatch at packet " << idx << ": raw data mismatch!\n";
		return false;
	}
	return true;
}

static bool testDifferential(const std::string& pcapPath, size_t bufferSize, size_t numBuffers, bool useView)
{
	std::cout << "Differential test: " << pcapPath << " (buf=" << bufferSize << ", count=" << numBuffers
	          << ", view=" << useView << ")... ";

	pcpp::PcapFileReaderDevice baseline(pcapPath);
	ReaderScopeGuard guardBaseline(&baseline);
	TEST_CHECK(baseline.open(), "Could not open baseline reader");

	pcpp::IoUringReaderOptions opts;
	opts.bufferSize = bufferSize;
	opts.numBuffers = numBuffers;

	pcpp::IoUringPcapReaderDevice contender(pcapPath, opts);
	ReaderScopeGuard guardContender(&contender);
	TEST_CHECK(contender.open(), "Could not open io_uring reader");
	TEST_CHECK(contender.getStatus() == pcpp::IoUringReaderStatus::Ok, "Initial status after open must be Ok");

	pcpp::RawPacket pktBase;
	pcpp::RawPacket pktRing;
	size_t count = 0;

	while (true)
	{
		bool bBase = baseline.getNextPacket(pktBase);
		bool bRing = useView ? contender.getNextPacketView(pktRing) : contender.getNextPacket(pktRing);

		TEST_CHECK(bBase == bRing, "EOF or packet availability mismatch between baseline and contender");
		if (!bBase)
		{
			break;
		}

		TEST_CHECK(comparePackets(pktBase, pktRing, count), "Packet equivalence failed");

		if (pktRing.getLinkLayerType() == pcpp::LINKTYPE_ETHERNET)
		{
			pcpp::Packet parsed(&pktRing);
			TEST_CHECK(parsed.isPacketOfType(pcpp::Ethernet), "Packet link layer is Ethernet but parsing failed");
		}

		count++;
	}

	TEST_CHECK(contender.getStatus() == pcpp::IoUringReaderStatus::EndOfFile,
	           "Expected EndOfFile status at end of file");

	std::cout << "PASSED (" << count << " pkts verified)\n";
	return true;
}

static bool testOwningVectorSafety(const std::string& pcapPath)
{
	std::cout << "Testing owning vector persistence... ";

	std::vector<pcpp::RawPacket> storedPackets;
	{
		pcpp::IoUringReaderOptions opts;
		opts.bufferSize = 4096;
		opts.numBuffers = 2;

		pcpp::IoUringPcapReaderDevice reader(pcapPath, opts);
		ReaderScopeGuard guardReader(&reader);
		TEST_CHECK(reader.open(), "Could not open reader for vector test");

		pcpp::RawPacket tempPkt;
		while (reader.getNextPacket(tempPkt))
		{
			storedPackets.push_back(tempPkt);
		}
	}

	pcpp::PcapFileReaderDevice baseline(pcapPath);
	ReaderScopeGuard guardBaseline(&baseline);
	TEST_CHECK(baseline.open(), "Could not open baseline reader for vector test");

	pcpp::RawPacket basePkt;
	size_t checkIdx = 0;
	while (baseline.getNextPacket(basePkt))
	{
		TEST_CHECK(checkIdx < storedPackets.size(), "Baseline returned more packets than io_uring reader");
		TEST_CHECK(comparePackets(basePkt, storedPackets[checkIdx], checkIdx),
		           "Vector element corrupted after buffer reuse");
		checkIdx++;
	}

	TEST_CHECK(checkIdx == storedPackets.size(), "Packet count mismatch between baseline and stored vector");

	std::cout << "PASSED (" << storedPackets.size() << " pkts safely retained in vector)\n";
	return true;
}

static bool testZeroCopyViewLifetime(const std::string& pcapPath)
{
	std::cout << "Testing zero-copy view lifetime and memory stability... ";

	pcpp::IoUringReaderOptions opts;
	opts.bufferSize = 4096;
	opts.numBuffers = 2;

	pcpp::IoUringPcapReaderDevice reader(pcapPath, opts);
	ReaderScopeGuard guardReader(&reader);
	TEST_CHECK(reader.open(), "Could not open reader for zero-copy lifetime test");

	pcpp::RawPacket viewPkt;
	TEST_CHECK(reader.getNextPacketView(viewPkt), "Failed to read first packet as view");
	const uint8_t* viewDataPtr = viewPkt.getRawData();
	size_t viewLen = viewPkt.getRawDataLen();
	TEST_CHECK(viewDataPtr != nullptr, "View packet raw data pointer must not be null");
	TEST_CHECK(viewLen > 0, "View packet length must be greater than zero");

	pcpp::RawPacket ownedPkt;
	TEST_CHECK(reader.getNextPacket(ownedPkt), "Failed to read second packet as owned");
	const uint8_t* ownedDataPtr = ownedPkt.getRawData();
	size_t ownedLen = ownedPkt.getRawDataLen();
	TEST_CHECK(ownedDataPtr != nullptr, "Owned packet raw data pointer must not be null");

	std::vector<uint8_t> ownedExpectedBytes(ownedDataPtr, ownedDataPtr + ownedLen);

	// Advance through many packets to trigger circular buffer reuse
	size_t advanced = 0;
	pcpp::RawPacket scrollPkt;
	while (advanced < 500 && reader.getNextPacketView(scrollPkt))
	{
		advanced++;
	}

	TEST_CHECK(ownedPkt.getRawData() == ownedDataPtr, "Owned packet data pointer changed unexpectedly");
	TEST_CHECK(ownedPkt.getRawDataLen() == static_cast<int>(ownedLen), "Owned packet length changed");
	TEST_CHECK(std::memcmp(ownedPkt.getRawData(), ownedExpectedBytes.data(), ownedLen) == 0,
	           "Owned packet memory corrupted after circular buffer recycling");

	std::cout << "PASSED (" << advanced << " pkts advanced, owned buffer uncorrupted)\n";
	return true;
}

static bool testReopenLifecycle(const std::string& pcapPath)
{
	std::cout << "Testing open/close/re-open lifecycle (partial, EOF, error recovery)...\n";

	// 1. Partial-read early close and reopen
	{
		pcpp::IoUringPcapReaderDevice reader(pcapPath);
		for (int cycle = 0; cycle < 3; ++cycle)
		{
			TEST_CHECK(reader.open(), "Failed to open reader during partial read cycle");
			TEST_CHECK(reader.isOpened(), "Reader must report isOpened() == true");
			pcpp::RawPacket pkt;
			size_t pkts = 0;
			while (pkts < 50 && reader.getNextPacket(pkt))
			{
				pkts++;
			}
			reader.close();
			TEST_CHECK(!reader.isOpened(), "Reader must report isOpened() == false after close()");
		}
		std::cout << "  - Partial read early-close cycles: PASSED\n";
	}

	// 2. Full read to EOF, close, reopen, and re-read to EOF
	{
		pcpp::IoUringPcapReaderDevice reader(pcapPath);
		TEST_CHECK(reader.open(), "Failed to open reader for full-read cycle 1");
		size_t count1 = 0;
		pcpp::RawPacket pkt;
		while (reader.getNextPacket(pkt))
		{
			count1++;
		}
		TEST_CHECK(reader.getStatus() == pcpp::IoUringReaderStatus::EndOfFile, "Expected EOF status after full read 1");
		reader.close();
		TEST_CHECK(!reader.isOpened(), "Reader must report closed after EOF");

		TEST_CHECK(reader.open(), "Failed to reopen reader for full-read cycle 2");
		size_t count2 = 0;
		while (reader.getNextPacket(pkt))
		{
			count2++;
		}
		TEST_CHECK(reader.getStatus() == pcpp::IoUringReaderStatus::EndOfFile, "Expected EOF status after full read 2");
		TEST_CHECK(count1 == count2, "Packet count mismatch between consecutive full-read runs");
		reader.close();
		std::cout << "  - Full read to EOF and reopen (" << count1 << " pkts): PASSED\n";
	}

	// 3. Failed open handling and clean state
	{
		pcpp::IoUringPcapReaderDevice reader("/tmp/non_existent_file_definitely_missing.pcap");
		TEST_CHECK(!reader.open(), "open() should fail on non-existent file");
		TEST_CHECK(!reader.isOpened(), "Device must not be open after failed open");
		TEST_CHECK(reader.getStatus() == pcpp::IoUringReaderStatus::IoError, "Status must be IoError on missing file");
		reader.close();
		std::cout << "  - Reopen after failed open recovery: PASSED\n";
	}

	return true;
}

static bool testDeterministicChunkBoundaries()
{
	std::cout << "Testing deterministic chunk-boundary splits (offsets 1, 7, 15, multi-chunk gathering)...\n";

	const std::string path = "/tmp/test_boundary_splits.pcap";
	constexpr size_t BUF_SIZE = 65536;

	// Write handcrafted fixture tailored for 64 KiB chunks
	{
		std::ofstream out(path, std::ios::binary);
		TEST_CHECK(out.is_open(), "Failed to open fixture output file");

		// Global header (24 bytes)
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);  // TCPDUMP magic
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 1048576, false);  // 1 MiB snaplen
		write32(gh + 20, 1, false);        // LINKTYPE_ETHERNET
		out.write(reinterpret_cast<const char*>(gh), 24);
		size_t currentOffset = 24;

		auto writePacket = [&](uint32_t sec, uint32_t usec, uint32_t payloadLen, uint8_t fillByte) {
			uint8_t ph[16];
			write32(ph + 0, sec, false);
			write32(ph + 4, usec, false);
			write32(ph + 8, payloadLen, false);
			write32(ph + 12, payloadLen, false);
			out.write(reinterpret_cast<const char*>(ph), 16);
			currentOffset += 16;

			std::vector<uint8_t> pld(payloadLen);
			for (size_t i = 0; i < payloadLen; ++i)
			{
				pld[i] = static_cast<uint8_t>((fillByte + i) & 0xFF);
			}
			out.write(reinterpret_cast<const char*>(pld.data()), payloadLen);
			currentOffset += payloadLen;
		};

		// 1. Packet 0: Fills chunk 0 up to byte 65534 so Packet 1 starts at 65535 (1 byte before chunk boundary)
		// Header = 16 bytes. Desired currentOffset after pkt0 = 65535.
		// payloadLen = 65535 - 24 - 16 = 65495 bytes.
		writePacket(1, 100, 65495, 0x10);
		TEST_CHECK(currentOffset == 65535, "Packet 0 must end at offset 65535");

		// 2. Packet 1: Boundary Split 1 (1 byte of header in chunk 0, 15 bytes in chunk 1)
		// Starts at offset 65535.
		writePacket(2, 200, 100, 0x20);
		TEST_CHECK(currentOffset == 65651, "Packet 1 must end at offset 65651");

		// 3. Packet 1.5 pad: Fills chunk 1 so Packet 2 starts at 131072 - 7 = 131065 (7 bytes before chunk 2 boundary)
		// Desired start = 131065. currentOffset = 65651.
		// payloadLen = 131065 - 65651 - 16 = 65398 bytes.
		writePacket(3, 300, 65398, 0x30);
		TEST_CHECK(currentOffset == 131065, "Pad packet must end at offset 131065");

		// 4. Packet 2: Boundary Split 2 (7 bytes of header in chunk 1, 9 bytes in chunk 2)
		// Starts at offset 131065.
		writePacket(4, 400, 100, 0x40);
		TEST_CHECK(currentOffset == 131181, "Packet 2 must end at offset 131181");

		// 5. Packet 2.5 pad: Fills chunk 2 so Packet 3 starts at 196608 - 15 = 196593 (15 bytes before chunk 3
		// boundary) Desired start = 196593. currentOffset = 131181. payloadLen = 196593 - 131181 - 16 = 65396 bytes.
		writePacket(5, 500, 65396, 0x50);
		TEST_CHECK(currentOffset == 196593, "Pad packet must end at offset 196593");

		// 6. Packet 3: Boundary Split 3 (15 bytes of header in chunk 2, 1 byte in chunk 3)
		// Starts at offset 196593.
		writePacket(6, 600, 100, 0x60);
		TEST_CHECK(currentOffset == 196709, "Packet 3 must end at offset 196709");

		// 7. Packet 4: Payload crosses 2 chunks (Header fully in chunk 3, payload crosses into chunk 4)
		// Chunk 3 ends at 262143. Place header at 262144 - 60 = 262084.
		// Pad to 262084: payloadLen = 262084 - 196709 - 16 = 65359.
		writePacket(7, 700, 65359, 0x70);
		TEST_CHECK(currentOffset == 262084, "Pad packet must end at offset 262084");
		// Header at 262084..262099 (chunk 3). Payload 200 bytes crosses 262144 into chunk 4.
		writePacket(8, 800, 200, 0x80);
		TEST_CHECK(currentOffset == 262300, "Packet 4 must end at offset 262300");

		// 8. Packet 5: Multi-chunk gathering across THREE chunks (Chunk 4, Chunk 5, and Chunk 6)
		// Payload = 140,000 bytes. Header 16 bytes.
		// Spans chunk 4 (ends at 327679), all of chunk 5 (327680..393215), into chunk 6.
		writePacket(9, 900, 140000, 0x90);

		out.flush();
		out.close();
	}

	// Verify using differential testing against baseline PcapFileReaderDevice
	pcpp::IoUringReaderOptions opts;
	opts.bufferSize = BUF_SIZE;
	opts.numBuffers = 4;

	pcpp::IoUringPcapReaderDevice contender(path, opts);
	ReaderScopeGuard guardContender(&contender);
	TEST_CHECK(contender.open(), "Could not open contender for boundary test");

	pcpp::PcapFileReaderDevice baseline(path);
	ReaderScopeGuard guardBaseline(&baseline);
	TEST_CHECK(baseline.open(), "Could not open baseline for boundary test");

	pcpp::RawPacket pktBase;
	pcpp::RawPacket pktRing;
	size_t count = 0;

	while (true)
	{
		bool bBase = baseline.getNextPacket(pktBase);
		bool bRing = contender.getNextPacket(pktRing);
		TEST_CHECK(bBase == bRing, "EOF mismatch in boundary split test");
		if (!bBase)
		{
			break;
		}
		TEST_CHECK(comparePackets(pktBase, pktRing, count), "Mismatch in split boundary packet");
		count++;
	}

	TEST_CHECK(count == 9, "Expected exactly 9 packets in handcrafted boundary split fixture");
	TEST_CHECK(contender.getStatus() == pcpp::IoUringReaderStatus::EndOfFile, "Status must be EndOfFile");

	std::cout << "  - All 9 split boundary packets verified with byte-level precision: PASSED\n";
	return true;
}

static bool testMalformedCases()
{
	std::cout << "Testing malformed input error handling...\n";

	// 1. Clean empty PCAP (24 bytes)
	{
		const std::string path = "/tmp/test_clean_empty.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "Clean empty PCAP should open successfully");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::Ok, "Status immediately after open must be Ok");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket on empty PCAP must return false");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::EndOfFile,
		           "Status after reading empty PCAP must be EndOfFile");
		std::cout << "  - Clean empty PCAP (0 pkts -> Ok on open, EndOfFile on read): PASSED\n";
	}

	// 2. Truncated global header (10 bytes)
	{
		const std::string path = "/tmp/test_trunc_global.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t junk[10] = { 0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00 };
		f.write(reinterpret_cast<const char*>(junk), 10);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "Truncated global header (< 24 B) must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Truncated global header (10 bytes -> FormatError): PASSED\n";
	}

	// 3. Invalid magic number
	{
		const std::string path = "/tmp/test_invalid_magic.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0x11223344, false);  // Bogus magic
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "Invalid magic number must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Invalid magic number (FormatError): PASSED\n";
	}

	// 4. Kuznetsov modified PCAP rejection (0xa1b2cd34)
	{
		const std::string path = "/tmp/test_kuznetsov_reject.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2cd34, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "Kuznetsov format must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Kuznetsov magic rejection (FormatError on open): PASSED\n";
	}

	// 5. Unsupported PCAP version (major=3, minor=0)
	{
		const std::string path = "/tmp/test_unsupported_ver.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 3, false);  // Version 3.0
		write16(gh + 6, 0, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "Version 3.0 must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Unsupported version (v3.0 -> FormatError): PASSED\n";
	}

	// 6. Zero snapshot length (snaplen == 0)
	{
		const std::string path = "/tmp/test_zero_snaplen.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 0, false);  // snaplen = 0
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "snaplen == 0 must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Zero snaplen (FormatError): PASSED\n";
	}

	// 7. Oversized snapshot length (snaplen > 1048576)
	{
		const std::string path = "/tmp/test_oversized_snaplen.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 2097152, false);  // 2 MiB > MAX_SNAPLEN
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(!r.open(), "snaplen > 1 MiB must fail open()");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Oversized snaplen (2 MiB -> FormatError): PASSED\n";
	}

	// 8. Truncated packet header at EOF (24 bytes + 7 bytes)
	{
		const std::string path = "/tmp/test_trunc_hdr.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);
		char junk[7] = { 1, 2, 3, 4, 5, 6, 7 };
		f.write(junk, 7);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed on valid 24B header");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail on truncated record header");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Truncated packet header (7 bytes at EOF -> FormatError): PASSED\n";
	}

	// 9. Truncated packet payload at EOF (header says 100 bytes, only 20 bytes exist)
	{
		const std::string path = "/tmp/test_trunc_payload.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);

		uint8_t ph[16];
		write32(ph + 0, 100, false);
		write32(ph + 4, 200, false);
		write32(ph + 8, 100, false);
		write32(ph + 12, 100, false);
		f.write(reinterpret_cast<const char*>(ph), 16);
		char payload[20] = { 0 };
		f.write(payload, 20);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed on valid header");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail on truncated payload");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Truncated packet payload (FormatError): PASSED\n";
	}

	// 10. Packet caplen > origlen
	{
		const std::string path = "/tmp/test_caplen_exceeds_orig.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);

		uint8_t ph[16];
		write32(ph + 0, 100, false);
		write32(ph + 4, 200, false);
		write32(ph + 8, 200, false);  // caplen = 200 > len = 100!
		write32(ph + 12, 100, false);
		f.write(reinterpret_cast<const char*>(ph), 16);
		std::vector<char> pld(200, 0);
		f.write(pld.data(), 200);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed on valid header");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail when caplen > origlen");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Packet caplen > origlen (FormatError): PASSED\n";
	}

	// 11. Packet caplen > snaplen
	{
		const std::string path = "/tmp/test_caplen_exceeds_snap.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 100, false);  // Snaplen = 100
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);

		uint8_t ph[16];
		write32(ph + 0, 100, false);
		write32(ph + 4, 200, false);
		write32(ph + 8, 200, false);  // Caplen = 200 > 100!
		write32(ph + 12, 200, false);
		f.write(reinterpret_cast<const char*>(ph), 16);
		std::vector<char> pld(200, 0);
		f.write(pld.data(), 200);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail when caplen > snaplen");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Packet caplen > snaplen (FormatError): PASSED\n";
	}

	// 12. Invalid microsecond timestamp (usec >= 1,000,000)
	{
		const std::string path = "/tmp/test_invalid_usec.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b2c3d4, false);
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);

		uint8_t ph[16];
		write32(ph + 0, 100, false);
		write32(ph + 4, 1500000, false);  // usec = 1,500,000 >= 1,000,000!
		write32(ph + 8, 50, false);
		write32(ph + 12, 50, false);
		f.write(reinterpret_cast<const char*>(ph), 16);
		std::vector<char> pld(50, 0);
		f.write(pld.data(), 50);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail on usec >= 1,000,000");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Invalid microsecond timestamp (usec >= 1M -> FormatError): PASSED\n";
	}

	// 13. Invalid nanosecond timestamp (nsec >= 1,000,000,000)
	{
		const std::string path = "/tmp/test_invalid_nsec.pcap";
		std::ofstream f(path, std::ios::binary);
		uint8_t gh[24];
		write32(gh + 0, 0xa1b23c4d, false);  // Nsec magic
		write16(gh + 4, 2, false);
		write16(gh + 6, 4, false);
		write32(gh + 8, 0, false);
		write32(gh + 12, 0, false);
		write32(gh + 16, 65535, false);
		write32(gh + 20, 1, false);
		f.write(reinterpret_cast<const char*>(gh), 24);

		uint8_t ph[16];
		write32(ph + 0, 100, false);
		write32(ph + 4, 1500000000, false);  // nsec = 1.5B >= 1B!
		write32(ph + 8, 50, false);
		write32(ph + 12, 50, false);
		f.write(reinterpret_cast<const char*>(ph), 16);
		std::vector<char> pld(50, 0);
		f.write(pld.data(), 50);
		f.close();

		pcpp::IoUringPcapReaderDevice r(path);
		ReaderScopeGuard guard(&r);
		TEST_CHECK(r.open(), "open() should succeed");
		pcpp::RawPacket pkt;
		TEST_CHECK(!r.getNextPacket(pkt), "getNextPacket must fail on nsec >= 1,000,000,000");
		TEST_CHECK(r.getStatus() == pcpp::IoUringReaderStatus::FormatError, "Status must be FormatError");
		std::cout << "  - Invalid nanosecond timestamp (nsec >= 1B -> FormatError): PASSED\n";
	}

	return true;
}

int main(int argc, char* argv[])
{
	std::string testPcap = "/tmp/test_uring_accuracy.pcap";
	std::string testNano = "/tmp/test_uring_nano.pcap";
	std::string testSwapped = "/tmp/test_uring_swapped.pcap";
	std::string testNanoSwapped = "/tmp/test_uring_nano_swapped.pcap";

	if (argc >= 2)
	{
		testPcap = argv[1];
	}

	std::cout << "=== Running Production IoUringPcapReaderDevice Test Suite ===\n\n";

	const std::vector<size_t> testBufferSizes = { 4096, 16384, 65536, 262144, 1048576, 4194304 };

	// 1. Differential testing: owning getNextPacket across buffer sizes
	for (size_t bufSize : testBufferSizes)
	{
		if (!testDifferential(testPcap, bufSize, 3, false))
		{
			return 1;
		}
	}

	// 2. Differential testing: zero-copy getNextPacketView across buffer sizes
	for (size_t bufSize : testBufferSizes)
	{
		if (!testDifferential(testPcap, bufSize, 3, true))
		{
			return 1;
		}
	}

	// 3. Nanosecond timestamp file (Little Endian)
	if (!testDifferential(testNano, 65536, 3, false))
	{
		return 1;
	}

	// 4. Swapped microsecond timestamp file (Big Endian)
	if (!testDifferential(testSwapped, 65536, 3, false))
	{
		return 1;
	}

	// 5. Swapped nanosecond timestamp file (Big Endian)
	if (!testDifferential(testNanoSwapped, 65536, 3, false))
	{
		return 1;
	}

	// 6. Owning vector safety across buffer reuse
	if (!testOwningVectorSafety(testPcap))
	{
		return 1;
	}

	// 7. Zero-copy lifetime and buffer stability test
	if (!testZeroCopyViewLifetime(testPcap))
	{
		return 1;
	}

	// 8. Device open/close/re-open lifecycle (partial, EOF, error recovery)
	if (!testReopenLifecycle(testPcap))
	{
		return 1;
	}

	// 9. Deterministic chunk boundary splits (offsets 1, 7, 15, and multi-chunk gathering)
	if (!testDeterministicChunkBoundaries())
	{
		return 1;
	}

	// 10. Malformed and edge case inputs
	if (!testMalformedCases())
	{
		return 1;
	}

	std::cout << "\n=== All IoUringPcapReaderDevice Tests Passed ===\n";
	return 0;
}
