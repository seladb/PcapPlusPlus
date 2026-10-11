#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <chrono>

#pragma pack(push, 1)
struct PcapGlobalHeader
{
	uint32_t magic = 0xa1b2c3d4;
	uint16_t version_major = 2;
	uint16_t version_minor = 4;
	int32_t thiszone = 0;
	uint32_t sigfigs = 0;
	uint32_t snaplen = 65535;
	uint32_t linktype = 1;  // LINKTYPE_ETHERNET
};

struct PcapPacketHeader
{
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

struct EthHeader
{
	uint8_t dstMac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t srcMac[6] = { 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
	uint16_t etherType = 0x0008;  // 0x0800 in network order (little-endian: 0x0008)
};

struct IPv4Header
{
	uint8_t verIhl = 0x45;
	uint8_t tos = 0x00;
	uint16_t totalLength;
	uint16_t id = 0x1234;
	uint16_t flagsFragment = 0x0040;  // Don't fragment
	uint8_t ttl = 64;
	uint8_t protocol = 6;  // TCP
	uint16_t checksum = 0;
	uint32_t srcIP = 0x0100a8c0;  // 192.168.0.1
	uint32_t dstIP = 0x0200a8c0;  // 192.168.0.2
};

struct TcpHeader
{
	uint16_t srcPort = 0x901f;  // 8080
	uint16_t dstPort = 0x5000;  // 80
	uint32_t seqNum = 1000;
	uint32_t ackNum = 0;
	uint8_t dataOffset = 0x50;  // 5 * 4 = 20 bytes
	uint8_t flags = 0x18;       // PSH, ACK
	uint16_t window = 0xffff;
	uint16_t checksum = 0;
	uint16_t urgentPtr = 0;
};
#pragma pack(pop)

inline void write16(uint8_t* dst, uint16_t v, bool bigEndian)
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

inline void write32(uint8_t* dst, uint32_t v, bool bigEndian)
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

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		std::cout << "Usage: " << argv[0] << " <output.pcap> <size_in_mb> [nanosec=0] [swapped=0]\n";
		std::cout << "Example: " << argv[0] << " /tmp/large.pcap 1024\n";
		return 1;
	}

	std::string outputPath = argv[1];
	size_t targetSizeBytes = std::stoull(argv[2]) * 1024ULL * 1024ULL;
	bool nanosec = (argc >= 4 && std::stoi(argv[3]) != 0);
	bool swapped = (argc >= 5 && std::stoi(argv[4]) != 0);

	std::ofstream out(outputPath, std::ios::binary);
	if (!out.is_open())
	{
		std::cerr << "Failed to open output file: " << outputPath << "\n";
		return 1;
	}

	std::cout << "Generating " << argv[2] << " MB PCAP file: " << outputPath << "\n";
	auto startTime = std::chrono::steady_clock::now();

	uint8_t ghBytes[24];
	uint32_t magic = 0xa1b2c3d4;
	if (nanosec)
	{
		magic = swapped ? 0x4d3cb2a1 : 0xa1b23c4d;
	}
	else
	{
		magic = swapped ? 0xd4c3b2a1 : 0xa1b2c3d4;
	}

	write32(ghBytes + 0, magic, false);  // magic written in exact target endian bytes
	write16(ghBytes + 4, 2, swapped);
	write16(ghBytes + 6, 4, swapped);
	write32(ghBytes + 8, 0, swapped);
	write32(ghBytes + 12, 0, swapped);
	write32(ghBytes + 16, 65535, swapped);
	write32(ghBytes + 20, 1, swapped);  // LINKTYPE_ETHERNET

	out.write(reinterpret_cast<const char*>(ghBytes), 24);
	size_t totalBytesWritten = 24;

	// Buffer 8MB of packets before writing to disk
	constexpr size_t BATCH_SIZE = 8 * 1024 * 1024;
	std::vector<uint8_t> batchBuffer;
	batchBuffer.reserve(BATCH_SIZE + 4096);

	// Varied packet sizes to test real-world boundary crossings
	const std::vector<uint32_t> packetSizes = { 64, 128, 256, 512, 1024, 1460, 1514, 800, 320 };
	size_t sizeIdx = 0;
	uint32_t sec = 1700000000;
	uint32_t usec = 0;
	uint64_t packetCount = 0;

	while (totalBytesWritten < targetSizeBytes)
	{
		uint32_t pktLen = packetSizes[sizeIdx % packetSizes.size()];
		sizeIdx++;

		size_t prevSize = batchBuffer.size();
		batchBuffer.resize(prevSize + 16 + pktLen);
		uint8_t* dst = batchBuffer.data() + prevSize;

		write32(dst + 0, sec, swapped);
		write32(dst + 4, usec, swapped);
		write32(dst + 8, pktLen, swapped);
		write32(dst + 12, pktLen, swapped);
		dst += 16;

		usec += 100;
		if (usec >= 1000000)
		{
			sec++;
			usec = 0;
		}

		EthHeader eth;
		std::memcpy(dst, &eth, sizeof(eth));

		IPv4Header ip;
		ip.totalLength = __builtin_bswap16(pktLen - sizeof(EthHeader));
		std::memcpy(dst + sizeof(EthHeader), &ip, sizeof(ip));

		TcpHeader tcp;
		std::memcpy(dst + sizeof(EthHeader) + sizeof(IPv4Header), &tcp, sizeof(tcp));

		size_t headersLen = sizeof(EthHeader) + sizeof(IPv4Header) + sizeof(TcpHeader);
		if (pktLen > headersLen)
		{
			for (size_t i = headersLen; i < pktLen; ++i)
			{
				dst[i] = static_cast<uint8_t>((i + packetCount) & 0xFF);
			}
		}

		packetCount++;

		if (batchBuffer.size() >= BATCH_SIZE)
		{
			out.write(reinterpret_cast<const char*>(batchBuffer.data()), batchBuffer.size());
			totalBytesWritten += batchBuffer.size();
			batchBuffer.clear();
		}
	}

	if (!batchBuffer.empty())
	{
		out.write(reinterpret_cast<const char*>(batchBuffer.data()), batchBuffer.size());
		totalBytesWritten += batchBuffer.size();
		batchBuffer.clear();
	}

	out.flush();
	out.close();

	auto endTime = std::chrono::steady_clock::now();
	double elapsedSec = std::chrono::duration<double>(endTime - startTime).count();

	std::cout << "Done! Generated " << (totalBytesWritten / (1024.0 * 1024.0)) << " MB (" << packetCount
	          << " packets) in " << elapsedSec << " s (" << (totalBytesWritten / (1024.0 * 1024.0) / elapsedSec)
	          << " MB/s)\n";

	return 0;
}
