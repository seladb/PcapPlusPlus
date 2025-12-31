#include "../TestDefinition.h"
#include "Logger.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "../Common/PcapFileNamesDef.h"
#include "../Common/TestUtils.h"
#include <array>
#include <fstream>
#include <chrono>

class FileReaderTeardown
{
private:
	pcpp::IFileReaderDevice* m_Reader;

public:
	explicit FileReaderTeardown(pcpp::IFileReaderDevice* reader)
	{
		m_Reader = reader;
	}

	~FileReaderTeardown()
	{
		if (m_Reader != nullptr)
		{
			delete m_Reader;
		}
	}
};

constexpr uint32_t TCPDUMP_MAGIC = 0xa1b2c3d4;
constexpr uint32_t TCPDUMP_MAGIC_SWAPPED = 0xd4c3b2a1;
constexpr uint32_t NSEC_TCPDUMP_MAGIC = 0xa1b23c4d;
constexpr uint32_t NSEC_TCPDUMP_MAGIC_SWAPPED = 0x4d3cb2a1;

enum class PcapHeaderParam
{
	Magic,
	MajorVersion,
	MinorVersion,
	Snaplen,
	LinkType,
};

std::vector<uint8_t> createPcapHeader(const std::unordered_map<PcapHeaderParam, uint32_t>& params, bool swapped = false)
{
	constexpr uint16_t PCAP_MAJOR_VERSION = 2;
	constexpr uint16_t PCAP_MINOR_VERSION = 4;
	constexpr uint32_t DEFAULT_SNAPLEN = 65535;

	auto swap16 = [](uint16_t value) { return static_cast<uint16_t>((value >> 8) | (value << 8)); };

	auto swap32 = [](uint32_t value) {
		return (value >> 24) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | (value << 24);
	};

	struct pcap_file_header
	{
		uint32_t magic;
		uint16_t version_major;
		uint16_t version_minor;
		int32_t thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;
		uint32_t linktype;
	};

	pcap_file_header header = { swapped ? TCPDUMP_MAGIC_SWAPPED : TCPDUMP_MAGIC,
		                        swapped ? swap16(PCAP_MAJOR_VERSION) : PCAP_MAJOR_VERSION,
		                        swapped ? swap16(PCAP_MINOR_VERSION) : PCAP_MINOR_VERSION,
		                        0,
		                        0,
		                        swapped ? swap32(DEFAULT_SNAPLEN) : DEFAULT_SNAPLEN,
		                        swapped ? swap32(pcpp::LINKTYPE_ETHERNET) : pcpp::LINKTYPE_ETHERNET };

	for (auto& param : params)
	{
		switch (param.first)
		{
		case PcapHeaderParam::Magic:
		{
			header.magic = param.second;
			break;
		}
		case PcapHeaderParam::MajorVersion:
		{
			header.version_major = static_cast<uint16_t>(param.second);
			break;
		}
		case PcapHeaderParam::MinorVersion:
		{
			header.version_minor = static_cast<uint16_t>(param.second);
			break;
		}
		case PcapHeaderParam::LinkType:
		{
			header.linktype = param.second;
			break;
		}
		case PcapHeaderParam::Snaplen:
		{
			header.snaplen = param.second;
			break;
		}
		}
	}

	std::vector<uint8_t> result(sizeof(pcap_file_header));
	std::memcpy(result.data(), &header, sizeof(pcap_file_header));
	return result;
}

enum class PcapPacketHeaderParam
{
	TimestampSec,
	TimestampUsec,
	Caplen,
	Len
};

std::vector<uint8_t> createPcapPacketHeader(
    const std::unordered_map<PcapPacketHeaderParam, uint32_t>& params,
    pcpp::FileTimestampPrecision precision = pcpp::FileTimestampPrecision::Microseconds)
{
	struct packet_header
	{
		uint32_t tv_sec;
		uint32_t tv_usec;
		uint32_t caplen;
		uint32_t len;
	};

	auto now = std::chrono::system_clock::now();
	auto duration = now.time_since_epoch();

	auto subSec = duration % std::chrono::seconds(1);
	auto sec = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
	auto nsec = precision == pcpp::FileTimestampPrecision::Nanoseconds
	                ? std::chrono::duration_cast<std::chrono::nanoseconds>(subSec).count()
	                : std::chrono::duration_cast<std::chrono::microseconds>(subSec).count();
	packet_header header = { static_cast<uint32_t>(sec), static_cast<uint32_t>(nsec), 1514, 1514 };

	for (const auto& param : params)
	{
		switch (param.first)
		{
		case PcapPacketHeaderParam::TimestampSec:
		{
			header.tv_sec = param.second;
			break;
		}
		case PcapPacketHeaderParam::TimestampUsec:
		{
			header.tv_usec = param.second;
			break;
		}
		case PcapPacketHeaderParam::Caplen:
		{
			header.caplen = param.second;
			break;
		}
		case PcapPacketHeaderParam::Len:
		{
			header.len = param.second;
			break;
		}
		}
	}

	std::vector<uint8_t> result(sizeof(packet_header));
	std::memcpy(result.data(), &header, sizeof(packet_header));
	return result;
}

PTF_TEST_CASE(TestPcapFileReadWrite)
{
	// Read and write packets
	{
		pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
		pcpp::PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
		PTF_ASSERT_TRUE(readerDev.open());
		PTF_ASSERT_TRUE(readerDev.isOpened());
		PTF_ASSERT_TRUE(writerDev.open());
		PTF_ASSERT_TRUE(writerDev.isOpened());
		PTF_ASSERT_EQUAL(readerDev.getFileName(), EXAMPLE_PCAP_PATH);
		PTF_ASSERT_EQUAL(writerDev.getFileName(), EXAMPLE_PCAP_WRITE_PATH);
		PTF_ASSERT_EQUAL(readerDev.getFileSize(), 3812643);
		pcpp::RawPacket rawPacket;
		int packetCount = 0;
		int ethCount = 0;
		int sllCount = 0;
		int ipCount = 0;
		int tcpCount = 0;
		int udpCount = 0;
		while (readerDev.getNextPacket(rawPacket))
		{
			packetCount++;
			pcpp::Packet packet(&rawPacket);
			if (packet.isPacketOfType(pcpp::Ethernet))
				ethCount++;
			if (packet.isPacketOfType(pcpp::SLL))
				sllCount++;
			if (packet.isPacketOfType(pcpp::IPv4))
				ipCount++;
			if (packet.isPacketOfType(pcpp::TCP))
				tcpCount++;
			if (packet.isPacketOfType(pcpp::UDP))
				udpCount++;

			PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket));
		}

		pcpp::IPcapDevice::PcapStats readerStatistics;
		pcpp::IPcapDevice::PcapStats writerStatistics;

		readerDev.getStatistics(readerStatistics);
		PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 4631);
		PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

		writerDev.getStatistics(writerStatistics);
		PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 4631);
		PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

		PTF_ASSERT_EQUAL(packetCount, 4631);
		PTF_ASSERT_EQUAL(ethCount, 4631);
		PTF_ASSERT_EQUAL(sllCount, 0);
		PTF_ASSERT_EQUAL(ipCount, 4631);
		PTF_ASSERT_EQUAL(tcpCount, 4492);
		PTF_ASSERT_EQUAL(udpCount, 139);

		readerDev.close();
		PTF_ASSERT_FALSE(readerDev.isOpened());
		writerDev.close();
		PTF_ASSERT_FALSE(writerDev.isOpened());
	}

	// Read and write packets in a bulk
	{
		pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
		PTF_ASSERT_TRUE(readerDev.open());
		PTF_ASSERT_TRUE(readerDev.isOpened());

		pcpp::RawPacketVector packetVec;
		int numOfPacketsRead = readerDev.getNextPackets(packetVec);
		PTF_ASSERT_EQUAL(numOfPacketsRead, 4631);
		PTF_ASSERT_EQUAL(packetVec.size(), numOfPacketsRead);

		pcpp::PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
		PTF_ASSERT_TRUE(writerDev.open());
		PTF_ASSERT_TRUE(writerDev.writePackets(packetVec));
		pcpp::IPcapDevice::PcapStats writerStatistics;
		writerDev.getStatistics(writerStatistics);
		PTF_ASSERT_EQUAL(writerStatistics.packetsRecv, numOfPacketsRead);
	}
}  // TestPcapFileReadWrite

PTF_TEST_CASE(TestPcapFileMicroPrecision)
{
	std::array<uint8_t, 16> testPayload = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	pcpp::RawPacket rawPacketMicro(testPayload.data(), testPayload.size(), timeval({ 1, 2 }), false);     // 1.000002000
	pcpp::RawPacket rawPacketNano(testPayload.data(), testPayload.size(), timespec({ 1, 1234 }), false);  // 1.000001234

	// Write micro precision file
	pcpp::PcapFileWriterDevice writerDevMicro(EXAMPLE_PCAP_MICRO_WRITE_PATH, pcpp::LINKTYPE_ETHERNET, false);
	PTF_ASSERT_EQUAL(writerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds, enumclass);
	PTF_ASSERT_TRUE(writerDevMicro.open());
	PTF_ASSERT_EQUAL(writerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds, enumclass);

	// File precision should remain Micro. Nano precision will be truncated to micro precision.
	PTF_ASSERT_TRUE(writerDevMicro.writePacket(rawPacketMicro));
	PTF_ASSERT_TRUE(writerDevMicro.writePacket(rawPacketNano));
	writerDevMicro.close();

	// Read micro precision file, both original and written
	for (auto const path : { EXAMPLE_PCAP_MICRO_PATH, EXAMPLE_PCAP_MICRO_WRITE_PATH })
	{
		// Read micro precision file
		pcpp::PcapFileReaderDevice readerDevMicro(path);
		PTF_ASSERT_EQUAL(readerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
		PTF_ASSERT_TRUE(readerDevMicro.open());
		PTF_ASSERT_EQUAL(readerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds, enumclass);

		pcpp::RawPacket readPacketNano2, readPacketMicro2;
		PTF_ASSERT_TRUE(readerDevMicro.getNextPacket(readPacketMicro2));
		PTF_ASSERT_EQUAL(readPacketMicro2.getPacketTimeStamp().tv_sec, 1);
		PTF_ASSERT_EQUAL(readPacketMicro2.getPacketTimeStamp().tv_nsec, 2000);

		PTF_ASSERT_TRUE(readerDevMicro.getNextPacket(readPacketNano2));
		PTF_ASSERT_EQUAL(readPacketNano2.getPacketTimeStamp().tv_sec, 1);
		PTF_ASSERT_EQUAL(readPacketNano2.getPacketTimeStamp().tv_nsec, 1000);
		readerDevMicro.close();
	}

	// Big endian pcap file
	{
		pcpp::PcapFileReaderDevice readerDevMicroBE(EXAMPLE_PCAP_MICRO_BIG_ENDIAN_PATH);
		PTF_ASSERT_EQUAL(readerDevMicroBE.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
		PTF_ASSERT_TRUE(readerDevMicroBE.open());
		PTF_ASSERT_EQUAL(readerDevMicroBE.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds,
		                 enumclass);

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(readerDevMicroBE.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_sec, 1474059824);
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_nsec, 864984000);
	}
}  // TestPcapFileMicroPrecision

PTF_TEST_CASE(TestPcapFileNanoPrecision)
{
	std::array<uint8_t, 16> testPayload = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	pcpp::RawPacket rawPacketMicro(testPayload.data(), testPayload.size(), timeval({ 1, 2 }), false);     // 1.000002000
	pcpp::RawPacket rawPacketNano(testPayload.data(), testPayload.size(), timespec({ 1, 1234 }), false);  // 1.000001234

	// Write nano precision file
	pcpp::PcapFileWriterDevice writerDevNano(EXAMPLE_PCAP_NANO_WRITE_PATH, pcpp::LINKTYPE_ETHERNET, true);
	PTF_ASSERT_EQUAL(writerDevNano.getTimestampPrecision(), pcpp::FileTimestampPrecision::Nanoseconds, enumclass);
	PTF_ASSERT_TRUE(writerDevNano.open());
	PTF_ASSERT_EQUAL(writerDevNano.getTimestampPrecision(), pcpp::FileTimestampPrecision::Nanoseconds, enumclass);

	// File precision should remain Nano. Micro precision packet will be scaled to Nano precision.
	PTF_ASSERT_TRUE(writerDevNano.writePacket(rawPacketMicro));
	PTF_ASSERT_TRUE(writerDevNano.writePacket(rawPacketNano));
	writerDevNano.close();

	// Read nano precision file, both original and written
	for (auto const path : { EXAMPLE_PCAP_NANO_PATH, EXAMPLE_PCAP_NANO_WRITE_PATH })
	{
		pcpp::PcapFileReaderDevice readerDevNano(path);
		PTF_ASSERT_EQUAL(readerDevNano.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
		PTF_ASSERT_TRUE(readerDevNano.open());
		PTF_ASSERT_EQUAL(readerDevNano.getTimestampPrecision(), pcpp::FileTimestampPrecision::Nanoseconds, enumclass);

		pcpp::RawPacket readPacketNano, readPacketMicro;
		PTF_ASSERT_TRUE(readerDevNano.getNextPacket(readPacketMicro));
		PTF_ASSERT_EQUAL(readPacketMicro.getPacketTimeStamp().tv_sec, 1);
		PTF_ASSERT_EQUAL(readPacketMicro.getPacketTimeStamp().tv_nsec, 2000);

		PTF_ASSERT_TRUE(readerDevNano.getNextPacket(readPacketNano));
		PTF_ASSERT_EQUAL(readPacketNano.getPacketTimeStamp().tv_sec, 1);
		PTF_ASSERT_EQUAL(readPacketNano.getPacketTimeStamp().tv_nsec, 1234);
		readerDevNano.close();
	}

	// Big endian pcap file
	{
		pcpp::PcapFileReaderDevice readerDevNanoBE(EXAMPLE_PCAP_NANO_BIG_ENDIAN_PATH);
		PTF_ASSERT_EQUAL(readerDevNanoBE.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
		PTF_ASSERT_TRUE(readerDevNanoBE.open());
		PTF_ASSERT_EQUAL(readerDevNanoBE.getTimestampPrecision(), pcpp::FileTimestampPrecision::Nanoseconds, enumclass);

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(readerDevNanoBE.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_sec, 1766361926);
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_nsec, 167647291);
	}
}  // TestPcapFileNanoPrecision

PTF_TEST_CASE(TestPcapFileReadAdv)
{
	SuppressLogs logSuppress;

	std::array<uint8_t, 5> packetData = { 0x1, 0x2, 0x3, 0x4, 0x5 };

	// Reopen after close
	{
		pcpp::RawPacket rawPacket, rawPacket2;
		pcpp::PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));

		reader.close();

		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));

		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), rawPacket2.getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), rawPacket2.getRawData(), rawPacket.getRawDataLen());
	}

	// Filter packets
	{
		constexpr int expectedTotalPacketCount = 4631;
		constexpr int expectedFilteredPacketCount = 1813;

		pcpp::PcapFileReaderDevice reader(EXAMPLE_PCAP_PATH);
		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_TRUE(reader.setFilter("ip src 10.0.0.6"));

		pcpp::RawPacketVector rawPackets;

		PTF_ASSERT_EQUAL(reader.getNextPackets(rawPackets), expectedFilteredPacketCount);
		PTF_ASSERT_EQUAL(rawPackets.size(), expectedFilteredPacketCount);
		pcpp::IPcapDevice::PcapStats stats;
		reader.getStatistics(stats);
		PTF_ASSERT_EQUAL(stats.packetsRecv, expectedFilteredPacketCount);
		PTF_ASSERT_EQUAL(stats.packetsDrop, 0);

		reader.close();
		PTF_ASSERT_TRUE(reader.open());

		PTF_ASSERT_TRUE(reader.clearFilter());
		rawPackets.clear();

		PTF_ASSERT_EQUAL(reader.getNextPackets(rawPackets), expectedTotalPacketCount);
		PTF_ASSERT_EQUAL(rawPackets.size(), expectedTotalPacketCount);

		PTF_ASSERT_FALSE(reader.setFilter("invalid"));
	}

	// File doesn't exist
	{
		pcpp::PcapFileReaderDevice reader("file_does_not_exist.pcap");
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Cannot open pcap reader device for filename 'file_does_not_exist.pcap'");
	}

	// Empty file
	{
		TempFile pcapFile("pcap");
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Cannot read pcap file header");
	}

	// File content is shorter than a pcap header
	{
		TempFile pcapFile("pcap");
		pcapFile << 0xa1b2;
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Cannot read pcap file header");
	}

	// Invalid magic number
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Magic, 0xdeadbeef }
        });
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Invalid magic number: 0xdeadbeef");
	}

	// Older pcap version
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::MajorVersion, 2 },
            { PcapHeaderParam::MinorVersion, 3 }
        });
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
	}

	// Invalid pcap version
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::MajorVersion, 1 }
        });
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Unsupported pcap file version: 1.4");
	}

	// Snapshot length is zero
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Snaplen, 0 }
        });
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Invalid snapshot length: 0");
	}

	// Snapshot length is too large
	{
		TempFile pcapFile("pcap");
		constexpr uint32_t LARGE_SNAPLEN = 1024 * 1024 + 1;
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Snaplen, LARGE_SNAPLEN }
        });
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_FALSE(reader.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Invalid snapshot length: " + std::to_string(LARGE_SNAPLEN));
	}

	// File with a header but no packets
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
	}

	// Unsupported link type
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::LinkType, 300 }
        });

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, packetData.size() }
        });
		pcapFile << packetData;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_EQUAL(reader.getLinkLayerType(), pcpp::LINKTYPE_INVALID, enum);

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), pcpp::LINKTYPE_INVALID, enum);
	}

	// Zero timestamp
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::TimestampSec,  0                 },
		    { PcapPacketHeaderParam::TimestampUsec, 0                 },
		    { PcapPacketHeaderParam::Caplen,        packetData.size() }
        });
		pcapFile << packetData;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_sec, 0);
		PTF_ASSERT_EQUAL(rawPacket.getPacketTimeStamp().tv_nsec, 0);
	}

	// Invalid microseconds timestamp
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::TimestampUsec, 1'000'001 }
        });

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Invalid microsecond timestamp: 1000001");
	}

	// Invalid nanoseconds timestamp
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Magic, NSEC_TCPDUMP_MAGIC }
        });

		pcapFile << createPcapPacketHeader(
		    {
		        { PcapPacketHeaderParam::TimestampUsec, 1'000'000'001 }
        },
		    pcpp::FileTimestampPrecision::Nanoseconds);

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_EQUAL(reader.getTimestampPrecision(), pcpp::FileTimestampPrecision::Nanoseconds, enumclass);

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Invalid nanosecond timestamp: 1000000001");
	}

	// Snapshot length is smaller than packet length
	{
		constexpr uint32_t snapshotLen = 2;

		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Snaplen, snapshotLen }
        });

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, packetData.size() }
        });
		pcapFile << packetData;

		std::array<uint8_t, snapshotLen> secondPacketData = { 0x11, 0x12 };
		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, secondPacketData.size() }
        });
		pcapFile << secondPacketData;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;

		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), snapshotLen);
		PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), packetData.data(), snapshotLen);

		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), snapshotLen);
		PTF_ASSERT_BUF_COMPARE(rawPacket.getRawData(), secondPacketData.data(), snapshotLen);
	}

	// Captured length is smaller than actual length
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, packetData.size()     },
		    { PcapPacketHeaderParam::Len,    packetData.size() + 1 }
        });
		pcapFile << packetData;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), packetData.size());
		PTF_ASSERT_EQUAL(rawPacket.getFrameLength(), packetData.size() + 1);
	}

	// Captured length is larger than actual length
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});

		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, packetData.size() },
            { PcapPacketHeaderParam::Len,    1                 }
        });

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Packet captured length 5 exceeds packet length 1");
	}

	// Captured length is zero
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, 0 }
        });

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), 0);
		PTF_ASSERT_NULL(rawPacket.getRawData());
	}

	// Captured length is too large
	{
		constexpr uint32_t tooLargeCapturedLength = 256 * 1024 + 1;

		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Snaplen, tooLargeCapturedLength }
        });
		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, tooLargeCapturedLength },
		    { PcapPacketHeaderParam::Len,    tooLargeCapturedLength }
        });

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Packet captured length " + std::to_string(tooLargeCapturedLength) + " is suspiciously large");
	}

	// Incomplete packet header
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcapFile << 0x11 << 0x22;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Failed to read packet metadata");
	}

	// Incomplete packet data
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcapFile << createPcapPacketHeader({});
		pcapFile << 0x11;

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());

		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Failed to read packet data");
	}
}  // TestPcapFileReadAdv

PTF_TEST_CASE(TestPcapFileWriteAdv)
{
	SuppressLogs logSuppress;

	std::array<uint8_t, 5> packetData = { 0x00, 0x01, 0x02, 0x03, 0x04 };
	pcpp::RawPacket rawPacket(packetData.data(), packetData.size(), timespec({ 1, 1234 }), false);

	// Reopen after close
	{
		TempFile pcapFile("pcap");
		pcapFile.close();
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open());
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));

		writer.close();

		PTF_ASSERT_TRUE(writer.open());
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
	}

	// Filter packets
	{
		constexpr int expectedTotalPacketCount = 4631;
		constexpr int expectedFilteredPacketCount = 1813;

		pcpp::RawPacketVector rawPackets;
		pcpp::PcapFileReaderDevice reader(EXAMPLE_PCAP_PATH);
		PTF_ASSERT_TRUE(reader.open());
		PTF_ASSERT_EQUAL(reader.getNextPackets(rawPackets), expectedTotalPacketCount);

		TempFile pcapFile("pcap");
		pcapFile.close();
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open());

		PTF_ASSERT_TRUE(writer.setFilter("ip src 10.0.0.6"));
		PTF_ASSERT_FALSE(writer.writePackets(rawPackets));
		pcpp::IPcapDevice::PcapStats stats;
		writer.getStatistics(stats);
		PTF_ASSERT_EQUAL(stats.packetsRecv, expectedFilteredPacketCount);
		PTF_ASSERT_EQUAL(stats.packetsDrop, 0);

		PTF_ASSERT_FALSE(writer.setFilter("invalid"));
		writer.close();

		pcpp::PcapFileReaderDevice reader2(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader2.open());
		PTF_ASSERT_EQUAL(reader2.getNextPackets(rawPackets), expectedFilteredPacketCount);
	}

	// File already open
	{
		TempFile pcapFile("pcap");
		pcapFile.close();
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open());
		PTF_ASSERT_FALSE(writer.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "File already opened");
	}

	// Cannot open file for write
	{
		pcpp::PcapFileWriterDevice writer("/non/existent/directory/file.pcap");
		PTF_ASSERT_FALSE(writer.open());
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Failed to open file: /non/existent/directory/file.pcap");
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Failed to open file: /non/existent/directory/file.pcap");
	}

	// Write when file isn't open
	{
		TempFile pcapFile("pcap");
		pcapFile.close();
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_FALSE(writer.writePacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "File is not open");
		pcpp::RawPacketVector rawPackets;
		PTF_ASSERT_FALSE(writer.writePackets(rawPackets));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "File is not open");
	}

	// Write packet with a different link type
	{
		TempFile pcapFile("pcap");
		pcapFile.close();
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName(), pcpp::LINKTYPE_RAW);

		PTF_ASSERT_TRUE(writer.open());
		PTF_ASSERT_FALSE(writer.writePacket(rawPacket));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Cannot write a packet with a different link type");
	}
}  // TestPcapFileWriteAdv

PTF_TEST_CASE(TestPcapNgFilePrecision)
{
	std::array<uint8_t, 16> testPayload = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	pcpp::RawPacket rawPacketNano(testPayload.data(), testPayload.size(), timespec({ 1722196160, 123456789 }),
	                              false);  // 1722196160.123456789

	pcpp::PcapNgFileWriterDevice writerDev(EXAMPLE_PCAPNG_NANO_PATH);
	PTF_ASSERT_TRUE(writerDev.open());
	PTF_ASSERT_TRUE(writerDev.writePacket(rawPacketNano));
	writerDev.close();

	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_NANO_PATH);
	PTF_ASSERT_TRUE(readerDev.open());
	pcpp::RawPacket readPacket;
	PTF_ASSERT_TRUE(readerDev.getNextPacket(readPacket));
	PTF_ASSERT_EQUAL(readPacket.getPacketTimeStamp().tv_sec, 1722196160);
	PTF_ASSERT_EQUAL(readPacket.getPacketTimeStamp().tv_nsec, 123456789);
	readerDev.close();
}  // TestPcapNgFilePrecision

PTF_TEST_CASE(TestPcapSllFileReadWrite)
{
	pcpp::PcapFileReaderDevice readerDev(SLL_PCAP_PATH);
	pcpp::PcapFileWriterDevice writerDev(SLL_PCAP_WRITE_PATH, pcpp::LINKTYPE_LINUX_SLL);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int sllCount = 0;
	int ethCount = 0;
	int ipCount = 0;
	int tcpCount = 0;
	int udpCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::SLL))
			sllCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;

		PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket));
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;
	pcpp::IPcapDevice::PcapStats writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 518);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 518);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 518);
	PTF_ASSERT_EQUAL(ethCount, 0);
	PTF_ASSERT_EQUAL(sllCount, 518);
	PTF_ASSERT_EQUAL(ipCount, 510);
	PTF_ASSERT_EQUAL(tcpCount, 483);
	PTF_ASSERT_EQUAL(udpCount, 28);

	readerDev.close();
	writerDev.close();
}  // TestPcapSllFileReadWrite

PTF_TEST_CASE(TestPcapSll2FileReadWrite)
{
	pcpp::PcapFileReaderDevice readerDev(SLL2_PCAP_PATH);
	pcpp::PcapFileWriterDevice writerDev(SLL2_PCAP_WRITE_PATH, pcpp::LINKTYPE_LINUX_SLL2);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
	PTF_ASSERT_EQUAL(writerDev.getLinkLayerType(), pcpp::LINKTYPE_LINUX_SLL2, enum);
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int sll2Count = 0;
	int ipCount = 0;

	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::SLL2))
			sll2Count++;
		if (packet.isPacketOfType(pcpp::IP))
			ipCount++;

		PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket));
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 3);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	pcpp::IPcapDevice::PcapStats writerStatistics;
	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 3);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);
	writerDev.close();

	PTF_ASSERT_EQUAL(packetCount, 3);
	PTF_ASSERT_EQUAL(sll2Count, 3);
	PTF_ASSERT_EQUAL(ipCount, 3);

	readerDev.close();
}  // TestPcapSll2FileReadWrite

PTF_TEST_CASE(TestPcapRawIPFileReadWrite)
{
	pcpp::PcapFileReaderDevice readerDev(RAW_IP_PCAP_PATH);
	pcpp::PcapFileWriterDevice writerDev(RAW_IP_PCAP_WRITE_PATH, pcpp::LINKTYPE_DLT_RAW1);
	pcpp::PcapNgFileWriterDevice writerNgDev(RAW_IP_PCAPNG_PATH);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
	PTF_ASSERT_EQUAL(writerDev.getLinkLayerType(), pcpp::LINKTYPE_RAW, enum);
	PTF_ASSERT_TRUE(writerNgDev.open());
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int ethCount = 0;
	int ipv4Count = 0;
	int ipv6Count = 0;
	int tcpCount = 0;
	int udpCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipv4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipv6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;

		writerDev.writePacket(rawPacket);
		writerNgDev.writePacket(rawPacket);
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;
	pcpp::IPcapDevice::PcapStats writerStatistics;
	pcpp::IPcapDevice::PcapStats writerNgStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 100);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 100);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

	writerNgDev.getStatistics(writerNgStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerNgStatistics.packetsRecv, 100);
	PTF_ASSERT_EQUAL((uint32_t)writerNgStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 100);
	PTF_ASSERT_EQUAL(ethCount, 0);
	PTF_ASSERT_EQUAL(ipv4Count, 50);
	PTF_ASSERT_EQUAL(ipv6Count, 50);
	PTF_ASSERT_EQUAL(tcpCount, 92);
	PTF_ASSERT_EQUAL(udpCount, 8);

	readerDev.close();
	writerDev.close();
	writerNgDev.close();
}  // TestPcapRawIPFileReadWrite

PTF_TEST_CASE(TestPcapFileAppend)
{
	std::array<uint8_t, 5> packetData = { 0x00, 0x01, 0x02, 0x03, 0x04 };
	pcpp::RawPacket rawPacket(packetData.data(), packetData.size(), timespec({ 1, 1234 }), false);

	// File does not exist
	{
		TempFile pcapFile("pcap", "", false);

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open(true));
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
		writer.flush();

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		pcpp::RawPacket rawPacket2;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
		PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), packetData.data(), packetData.size());
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket2));
	}

	// Empty file
	{
		TempFile pcapFile("pcap");
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open(true));
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
		writer.flush();

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		pcpp::RawPacket rawPacket2;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
		PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), packetData.data(), packetData.size());
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket2));
	}

	// File with header and no packets
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open(true));
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
		writer.flush();

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		pcpp::RawPacket rawPacket2;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
		PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), packetData.data(), packetData.size());
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket2));
	}

	// File with packets
	{
		std::array<uint8_t, 5> anotherPacketData = { 0x05, 0x06, 0x07, 0x08, 0x09 };
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({});
		pcapFile << createPcapPacketHeader({
		    { PcapPacketHeaderParam::Caplen, 5 }
        });
		pcapFile << anotherPacketData;
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());
		PTF_ASSERT_TRUE(writer.open(true));
		PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
		writer.flush();

		pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
		PTF_ASSERT_TRUE(reader.open());
		pcpp::RawPacket rawPacket2;
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
		PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), anotherPacketData.data(), anotherPacketData.size());
		PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
		PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), packetData.data(), packetData.size());
		PTF_ASSERT_FALSE(reader.getNextPacket(rawPacket2));
	}

	// Malformed file header
	{
		TempFile pcapFile("pcap");
		pcapFile << 0x01 << 0x02;
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());

		SuppressLogs logSuppress;
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Malformed file header or not a pcap file");
	}

	// Precision mismatch
	{
		TempFile pcapFile("pcap");
		// File with nanoseconds precision
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Magic, NSEC_TCPDUMP_MAGIC }
        });
		pcapFile.close();

		// Create the device with microseconds precision
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());

		SuppressLogs logSuppress;
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(
		    pcpp::Logger::getInstance().getLastError(),
		    "Existing file precision (Nanoseconds) does not match the requested device precision (Microseconds)");
	}

	// Link type mismatch
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::LinkType, pcpp::LINKTYPE_C_HDLC }
        });
		pcapFile.close();

		// Create the device with the default link type (Ethernet)
		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());

		SuppressLogs logSuppress;
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(),
		                 "Existing file link type does not match the requested device link type");
	}

	// Unsupported magic number
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::Magic, 1234 }
        });
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());

		SuppressLogs logSuppress;
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Unsupported pcap file format");
	}

	// Unsupported version
	{
		TempFile pcapFile("pcap");
		pcapFile << createPcapHeader({
		    { PcapHeaderParam::MajorVersion, 5 }
        });
		pcapFile.close();

		pcpp::PcapFileWriterDevice writer(pcapFile.getFileName());

		SuppressLogs logSuppress;
		PTF_ASSERT_FALSE(writer.open(true));
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "Unsupported pcap file version");
	}

	// All magic numbers - micro/nano precision and little/big endian
	{
		std::vector<std::tuple<uint32_t, bool, bool>> magicNumberVariations = {
			{ TCPDUMP_MAGIC,              false, false },
			{ TCPDUMP_MAGIC_SWAPPED,      false, true  },
			{ NSEC_TCPDUMP_MAGIC,         true,  false },
			{ NSEC_TCPDUMP_MAGIC_SWAPPED, true,  true  }
		};

		for (auto const& magicNumberVariation : magicNumberVariations)
		{
			TempFile pcapFile("pcap");
			pcapFile << createPcapHeader(
			    {
			        { PcapHeaderParam::Magic, std::get<0>(magicNumberVariation) }
            },
			    std::get<2>(magicNumberVariation));
			pcapFile.close();

			pcpp::PcapFileWriterDevice writer(pcapFile.getFileName(), pcpp::LINKTYPE_ETHERNET,
			                                  std::get<1>(magicNumberVariation));
			PTF_ASSERT_TRUE(writer.open(true));
			PTF_ASSERT_TRUE(writer.writePacket(rawPacket));
			writer.flush();

			pcpp::PcapFileReaderDevice reader(pcapFile.getFileName());
			PTF_ASSERT_TRUE(reader.open());
			pcpp::RawPacket rawPacket2;
			PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket2));
			PTF_ASSERT_EQUAL(rawPacket2.getPacketTimeStamp().tv_sec, 1);
			auto expectedNsec = std::get<1>(magicNumberVariation) ? 1234 : 1000;
			PTF_ASSERT_EQUAL(rawPacket2.getPacketTimeStamp().tv_nsec, expectedNsec);
			PTF_ASSERT_BUF_COMPARE(rawPacket2.getRawData(), packetData.data(), packetData.size());
		}
	}
}  // TestPcapFileAppend

PTF_TEST_CASE(TestPcapNgFileReadWrite)
{
	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_PATH);
	pcpp::PcapNgFileWriterDevice writerDev(EXAMPLE_PCAPNG_WRITE_PATH);
	pcpp::PcapNgFileWriterDevice writerCompressDev(EXAMPLE_PCAPNG_ZSTD_WRITE_PATH, 5);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
	PTF_ASSERT_TRUE(writerCompressDev.open());
	PTF_ASSERT_EQUAL(readerDev.getFileName(), EXAMPLE_PCAPNG_PATH);
	PTF_ASSERT_EQUAL(writerDev.getFileName(), EXAMPLE_PCAPNG_WRITE_PATH);
	PTF_ASSERT_EQUAL(writerCompressDev.getFileName(), EXAMPLE_PCAPNG_ZSTD_WRITE_PATH);
	PTF_ASSERT_EQUAL(readerDev.getFileSize(), 20704);
	PTF_ASSERT_EQUAL(readerDev.getOS(), "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)");
	PTF_ASSERT_EQUAL(readerDev.getCaptureApplication(), "Dumpcap 1.12.6 (v1.12.6-0-gee1fce6 from master-1.12)");
	PTF_ASSERT_EQUAL(readerDev.getCaptureFileComment(), "");
	PTF_ASSERT_EQUAL(readerDev.getHardware(), "");
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int ethLinkLayerCount = 0;
	int nullLinkLayerCount = 0;
	int otherLinkLayerCount = 0;
	int ethCount = 0;
	int nullLoopbackCount = 0;
	int ipCount = 0;
	int tcpCount = 0;
	int udpCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;

		pcpp::LinkLayerType linkType = rawPacket.getLinkLayerType();
		if (linkType == pcpp::LINKTYPE_ETHERNET)
			ethLinkLayerCount++;
		else if (linkType == pcpp::LINKTYPE_NULL)
			nullLinkLayerCount++;
		else
			otherLinkLayerCount++;

		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::NULL_LOOPBACK))
			nullLoopbackCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;

		PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket));
		PTF_ASSERT_TRUE(writerCompressDev.writePacket(rawPacket));
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;
	pcpp::IPcapDevice::PcapStats writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 64);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 64);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

	writerCompressDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 64);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 64);
	PTF_ASSERT_EQUAL(ethLinkLayerCount, 62);
	PTF_ASSERT_EQUAL(nullLinkLayerCount, 2);
	PTF_ASSERT_EQUAL(otherLinkLayerCount, 0);
	PTF_ASSERT_EQUAL(ethCount, 62);
	PTF_ASSERT_EQUAL(nullLoopbackCount, 2);
	PTF_ASSERT_EQUAL(ipCount, 64);
	PTF_ASSERT_EQUAL(tcpCount, 32);
	PTF_ASSERT_EQUAL(udpCount, 32);

	readerDev.close();
	writerDev.close();
	writerCompressDev.close();

}  // TestPcapNgFileReadWrite

PTF_TEST_CASE(TestPcapNgFileReadWriteAdv)
{
	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE2_PCAPNG_PATH);

	// negative tests
	readerDev.close();
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_EQUAL(readerDev.getOS(), "");
	pcpp::Logger::getInstance().enableLogs();
	// --------------

	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_EQUAL(readerDev.getOS(), "Linux 3.18.1-1-ARCH");
	PTF_ASSERT_EQUAL(readerDev.getCaptureApplication(), "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)");
	PTF_ASSERT_EQUAL(
	    readerDev.getCaptureFileComment(),
	    "CLIENT_RANDOM E39B5BF4903C68684E8512FB2F60213E9EE843A0810B4982B607914D8092D482 95A5D39B02693BC1FB39254B179E9293007F6D37C66172B1EE4EF0D5E25CE1DABE878B6143DC3B266883E51A75E99DF9                                                   ");
	PTF_ASSERT_EQUAL(readerDev.getHardware(), "");

	pcpp::PcapNgFileWriterDevice writerDev(EXAMPLE2_PCAPNG_WRITE_PATH);
	pcpp::PcapNgFileWriterDevice writerCompressDev(EXAMPLE2_PCAPNG_ZSTD_WRITE_PATH, 5);

	// negative tests
	writerDev.close();
	writerCompressDev.close();
	// --------------

	PTF_ASSERT_TRUE(writerDev.open(readerDev.getOS().c_str(), "My Hardware", readerDev.getCaptureApplication().c_str(),
	                               "This is a comment in a pcap-ng file"));
	PTF_ASSERT_TRUE(writerCompressDev.open(readerDev.getOS().c_str(), "My Hardware",
	                                       readerDev.getCaptureApplication().c_str(),
	                                       "This is a comment in a pcap-ng file"));

	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int capLenNotMatchOrigLen = 0;
	int ethCount = 0;
	int sllCount = 0;
	int ip4Count = 0;
	int ip6Count = 0;
	int tcpCount = 0;
	int udpCount = 0;
	int httpCount = 0;
	int commentCount = 0;
	std::string pktComment;

	while (readerDev.getNextPacket(rawPacket, pktComment))
	{
		packetCount++;

		if (rawPacket.getRawDataLen() != rawPacket.getFrameLength())
			capLenNotMatchOrigLen++;

		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::SLL))
			sllCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpCount++;

		if (pktComment != "")
		{
			PTF_ASSERT_EQUAL(pktComment.compare(0, 8, "Packet #"), 0, ptr);
			commentCount++;
		}

		PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket, pktComment.c_str()));
		PTF_ASSERT_TRUE(writerCompressDev.writePacket(rawPacket, pktComment.c_str()));
	}

	PTF_ASSERT_EQUAL(packetCount, 159);
	PTF_ASSERT_EQUAL(capLenNotMatchOrigLen, 39);
	PTF_ASSERT_EQUAL(ethCount, 59);
	PTF_ASSERT_EQUAL(sllCount, 100);
	PTF_ASSERT_EQUAL(ip4Count, 155);
	PTF_ASSERT_EQUAL(ip6Count, 4);
	PTF_ASSERT_EQUAL(tcpCount, 159);
	PTF_ASSERT_EQUAL(udpCount, 0);
	PTF_ASSERT_EQUAL(httpCount, 1);
	PTF_ASSERT_EQUAL(commentCount, 100);

	pcpp::IPcapDevice::PcapStats readerStatistics;
	pcpp::IPcapDevice::PcapStats writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 159);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 159);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);

	readerDev.close();
	writerDev.close();
	writerCompressDev.close();

	// -------

	pcpp::PcapNgFileReaderDevice readerDevCompress(EXAMPLE2_PCAPNG_ZSTD_WRITE_PATH);
	pcpp::PcapNgFileReaderDevice readerDev2(EXAMPLE2_PCAPNG_WRITE_PATH);
	pcpp::PcapNgFileReaderDevice readerDev3(EXAMPLE2_PCAPNG_PATH);

	PTF_ASSERT_TRUE(readerDevCompress.open());
	PTF_ASSERT_TRUE(readerDev2.open());
	PTF_ASSERT_TRUE(readerDev3.open());

	PTF_ASSERT_EQUAL(readerDevCompress.getOS(), "Linux 3.18.1-1-ARCH\0");
	PTF_ASSERT_EQUAL(readerDevCompress.getCaptureApplication(),
	                 "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)");
	PTF_ASSERT_EQUAL(readerDevCompress.getCaptureFileComment(), "This is a comment in a pcap-ng file");
	PTF_ASSERT_EQUAL(readerDevCompress.getHardware(), "My Hardware");

	PTF_ASSERT_EQUAL(readerDev2.getOS(), "Linux 3.18.1-1-ARCH\0");
	PTF_ASSERT_EQUAL(readerDev2.getCaptureApplication(), "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)");
	PTF_ASSERT_EQUAL(readerDev2.getCaptureFileComment(), "This is a comment in a pcap-ng file");
	PTF_ASSERT_EQUAL(readerDev2.getHardware(), "My Hardware");

	packetCount = 0;
	ethCount = 0;
	sllCount = 0;
	ip4Count = 0;
	ip6Count = 0;
	tcpCount = 0;
	udpCount = 0;
	httpCount = 0;
	commentCount = 0;

	pcpp::RawPacket rawPacket2, rawPacketCompress;

	while (readerDev2.getNextPacket(rawPacket, pktComment))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::SLL))
			sllCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpCount++;

		if (pktComment != "")
		{
			PTF_ASSERT_EQUAL(pktComment.compare(0, 8, "Packet #"), 0, ptr);
			commentCount++;
		}

		readerDev3.getNextPacket(rawPacket2);
		readerDevCompress.getNextPacket(rawPacketCompress);

		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), rawPacket2.getRawDataLen());
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), rawPacketCompress.getRawDataLen());

		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), rawPacket2.getLinkLayerType(), enum);
		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), rawPacketCompress.getLinkLayerType(), enum);

		PTF_ASSERT_EQUAL(rawPacket.getFrameLength(), rawPacket2.getFrameLength());
		PTF_ASSERT_EQUAL(rawPacket.getFrameLength(), rawPacketCompress.getFrameLength());

		timespec packet1_timestamp = rawPacket.getPacketTimeStamp();
		timespec packet2_timestamp = rawPacket2.getPacketTimeStamp();
		timespec packetCompress_timestamp = rawPacketCompress.getPacketTimeStamp();
		if (packet1_timestamp.tv_sec < packet2_timestamp.tv_sec)
		{
			uint64_t timeDiff = (uint64_t)(packet2_timestamp.tv_sec - packet1_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_sec - packet2_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2);
		}

		if (packet1_timestamp.tv_nsec < packet2_timestamp.tv_nsec)
		{
			uint64_t timeDiff = (uint64_t)(packet2_timestamp.tv_nsec - packet1_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_nsec - packet2_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000);
		}

		if (packet1_timestamp.tv_sec < packetCompress_timestamp.tv_sec)
		{
			uint64_t timeDiff = (uint64_t)(packetCompress_timestamp.tv_sec - packet1_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_sec - packetCompress_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2);
		}

		if (packet1_timestamp.tv_nsec < packetCompress_timestamp.tv_nsec)
		{
			uint64_t timeDiff = (uint64_t)(packetCompress_timestamp.tv_nsec - packet1_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_nsec - packetCompress_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000);
		}
	}

	PTF_ASSERT_EQUAL(packetCount, 159);
	PTF_ASSERT_EQUAL(ethCount, 59);
	PTF_ASSERT_EQUAL(sllCount, 100);
	PTF_ASSERT_EQUAL(ip4Count, 155);
	PTF_ASSERT_EQUAL(ip6Count, 4);
	PTF_ASSERT_EQUAL(tcpCount, 159);
	PTF_ASSERT_EQUAL(udpCount, 0);
	PTF_ASSERT_EQUAL(httpCount, 1);
	PTF_ASSERT_EQUAL(commentCount, 100);

	readerDevCompress.close();
	readerDev2.close();
	readerDev3.close();

	// For now appends are not fully supported with compressed pcapng files
	pcpp::PcapNgFileWriterDevice appendDev(EXAMPLE2_PCAPNG_WRITE_PATH);
	PTF_ASSERT_TRUE(appendDev.open(true));

	PTF_ASSERT_TRUE(appendDev.writePacket(rawPacket2, "Additional packet #1"));
	PTF_ASSERT_TRUE(appendDev.writePacket(rawPacket2, "Additional packet #2"));

	appendDev.close();

	pcpp::PcapNgFileReaderDevice readerDev4(EXAMPLE2_PCAPNG_WRITE_PATH);
	PTF_ASSERT_TRUE(readerDev4.open());

	packetCount = 0;

	while (readerDev4.getNextPacket(rawPacket, pktComment))
	{
		packetCount++;
	}

	PTF_ASSERT_EQUAL(packetCount, 161);

	// -------

	// copy the .zstd file to a similar file with .zst extension
	std::ifstream zstdFile(EXAMPLE2_PCAPNG_ZSTD_WRITE_PATH, std::ios::binary);
	std::ofstream zstFile(EXAMPLE2_PCAPNG_ZST_WRITE_PATH, std::ios::binary);
	zstFile << zstdFile.rdbuf();
	zstdFile.close();
	zstFile.close();

	pcpp::IFileReaderDevice* genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE2_PCAP_PATH);
	FileReaderTeardown genericReaderTeardown1(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapFileReaderDevice*>(genericReader));
	PTF_ASSERT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));

	genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE2_PCAPNG_PATH);
	FileReaderTeardown genericReaderTeardown2(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));

	genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE_PCAPNG_ZSTD_WRITE_PATH);
	FileReaderTeardown genericReaderTeardown3(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));
	PTF_ASSERT_TRUE(genericReader->open());

	genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE2_PCAPNG_ZST_WRITE_PATH);
	FileReaderTeardown genericReaderTeardown4(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));
	PTF_ASSERT_TRUE(genericReader->open());

	genericReader->close();

	// -------

	pcpp::PcapNgFileReaderDevice readerDev5(EXAMPLE2_PCAPNG_PATH);
	PTF_ASSERT_TRUE(readerDev5.open());
	PTF_ASSERT_FALSE(readerDev5.setFilter("bla bla bla"));
	PTF_ASSERT_TRUE(readerDev5.setFilter("src net 130.217.250.129"));

	pcpp::PcapNgFileWriterDevice writerDev2(EXAMPLE2_PCAPNG_WRITE_PATH);
	PTF_ASSERT_TRUE(writerDev2.open(true));
	PTF_ASSERT_FALSE(writerDev2.setFilter("bla bla bla"));
	PTF_ASSERT_TRUE(writerDev2.setFilter("dst port 35938"));

	pcpp::PcapNgFileWriterDevice writerCompressDev2(EXAMPLE2_PCAPNG_ZSTD_WRITE_PATH, 5);
	PTF_ASSERT_TRUE(writerCompressDev2.open());  // Do not try append mode on compressed files!!!
	PTF_ASSERT_FALSE(writerCompressDev2.setFilter("bla bla bla"));
	PTF_ASSERT_TRUE(writerCompressDev2.setFilter("dst port 35938"));

	int filteredReadPacketCount = 0;
	int filteredWritePacketCount = 0, filteredCompressWritePacketCount = 0;

	while (readerDev5.getNextPacket(rawPacket, pktComment))
	{
		filteredReadPacketCount++;
		if (writerDev2.writePacket(rawPacket))
			filteredWritePacketCount++;
		if (writerCompressDev2.writePacket(rawPacket))
			filteredCompressWritePacketCount++;
	}

	PTF_ASSERT_EQUAL(filteredReadPacketCount, 14);
	PTF_ASSERT_EQUAL(filteredWritePacketCount, 3);
	PTF_ASSERT_EQUAL(filteredCompressWritePacketCount, 3);

	writerCompressDev2.close();
	readerDev5.close();
	writerDev2.close();
}  // TestPcapNgFileReadWriteAdv

PTF_TEST_CASE(TestPcapNgFileTooManyInterfaces)
{
	pcpp::Logger::getInstance().suppressLogs();
	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_INTERFACES_PATH);
	PTF_ASSERT_TRUE(readerDev.open());
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), pcpp::LINKTYPE_INVALID, enum);
		const timespec timestamp = rawPacket.getPacketTimeStamp();
		pcpp::Logger::getInstance().enableLogs();
		PTF_ASSERT_EQUAL(timestamp.tv_sec, 0);
		PTF_ASSERT_EQUAL(timestamp.tv_nsec, 0);
	}
	PTF_ASSERT_EQUAL(packetCount, 1);
	readerDev.close();
}  // TestPcapNgFileTooManyInterfaces

PTF_TEST_CASE(TestPcapFileReadLinkTypeIPv6)
{
	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_LINKTYPE_IPV6);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(readerDev.isOpened());
	PTF_ASSERT_EQUAL(readerDev.getFileSize(), 120);
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int ethCount = 0;
	int ipCount = 0;
	int tcpCount = 0;
	int udpCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 1);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 1);
	PTF_ASSERT_EQUAL(ethCount, 0);
	PTF_ASSERT_EQUAL(ipCount, 1);
	PTF_ASSERT_EQUAL(tcpCount, 1);
	PTF_ASSERT_EQUAL(udpCount, 0);

	readerDev.close();
	PTF_ASSERT_FALSE(readerDev.isOpened());

}  // TestPcapFileReadLinkTypeIPv6

PTF_TEST_CASE(TestPcapFileReadLinkTypeIPv4)
{
	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_LINKTYPE_IPV4);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(readerDev.isOpened());
	PTF_ASSERT_EQUAL(readerDev.getFileSize(), 266);
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int ethCount = 0;
	int ipCount = 0;
	int tcpCount = 0;
	int udpCount = 0;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 2);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 2);
	PTF_ASSERT_EQUAL(ethCount, 0);
	PTF_ASSERT_EQUAL(ipCount, 2);
	PTF_ASSERT_EQUAL(tcpCount, 0);
	PTF_ASSERT_EQUAL(udpCount, 2);

	readerDev.close();
	PTF_ASSERT_FALSE(readerDev.isOpened());

}  // TestPcapFileReadLinkTypeIPv4

PTF_TEST_CASE(TestSolarisSnoopFileRead)
{
	pcpp::SnoopFileReaderDevice readerDev(EXAMPLE_SOLARIS_SNOOP);
	PTF_ASSERT_TRUE(readerDev.open());
	pcpp::RawPacket rawPacket;
	int packetCount = 0;
	int ethCount = 0;
	int ethDot3Count = 0;
	int ipCount = 0;
	int tcpCount = 0;
	int udpCount = 0;
	std::vector<timespec> timeStamps;
	while (readerDev.getNextPacket(rawPacket))
	{
		packetCount++;
		pcpp::Packet packet(&rawPacket);
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::EthernetDot3))
			ethDot3Count++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		timeStamps.push_back(rawPacket.getPacketTimeStamp());
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 250);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	PTF_ASSERT_EQUAL(packetCount, 250);
	PTF_ASSERT_EQUAL(ethCount, 142);
	PTF_ASSERT_EQUAL(ethDot3Count, 108);
	PTF_ASSERT_EQUAL(ipCount, 71);
	PTF_ASSERT_EQUAL(tcpCount, 15);
	PTF_ASSERT_EQUAL(udpCount, 55);
	PTF_ASSERT_EQUAL(timeStamps[0].tv_sec, 911274719);
	PTF_ASSERT_EQUAL(timeStamps[0].tv_nsec, 885516000);
	PTF_ASSERT_EQUAL(timeStamps[249].tv_sec, 911274726);
	PTF_ASSERT_EQUAL(timeStamps[249].tv_nsec, 499893000);

	readerDev.close();
}  // TestSolarisSnoopFileRead

PTF_TEST_CASE(TestPcapFileWriterDeviceDestructor)
{
	std::array<uint8_t, 16> testPayload = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	pcpp::RawPacket rawPacket1(testPayload.data(), testPayload.size(), timeval{}, false);
	pcpp::RawPacket rawPacket2(testPayload.data(), testPayload.size(), timeval{}, false);

	// Create some pcaps in a nested scope to test cleanup on destruction.
	{
		// create a file to leave open on destruction. If close is properly done on destruction, the contents & size of
		// this file should match the next explicitly closed file.
		pcpp::PcapFileWriterDevice writerDevDestructorNoClose(EXAMPLE_PCAP_DESTRUCTOR1_PATH, pcpp::LINKTYPE_ETHERNET,
		                                                      false);
		PTF_ASSERT_TRUE(writerDevDestructorNoClose.open());
		PTF_ASSERT_TRUE(writerDevDestructorNoClose.writePacket(rawPacket1));
		PTF_ASSERT_TRUE(writerDevDestructorNoClose.writePacket(rawPacket2));

		// create a file that will be explicitly closed before construction
		pcpp::PcapFileWriterDevice writerDevDestructorExplicitClose(EXAMPLE_PCAP_DESTRUCTOR2_PATH,
		                                                            pcpp::LINKTYPE_ETHERNET, false);
		PTF_ASSERT_TRUE(writerDevDestructorExplicitClose.open());
		PTF_ASSERT_TRUE(writerDevDestructorExplicitClose.writePacket(rawPacket1));
		PTF_ASSERT_TRUE(writerDevDestructorExplicitClose.writePacket(rawPacket2));
		writerDevDestructorExplicitClose.close();
	}

	// Check that file sizes are equal. This should fail if the pcpp::PcapFileWriterDevice destructor does not close
	// properly.
	std::ifstream fileDestructorNoClose(EXAMPLE_PCAP_DESTRUCTOR1_PATH, std::ios::binary | std::ios::in);
	fileDestructorNoClose.seekg(0, std::ios::end);
	auto posNoClose = fileDestructorNoClose.tellg();

	std::ifstream fileDestructorExplicitClose(EXAMPLE_PCAP_DESTRUCTOR2_PATH, std::ios::binary | std::ios::in);
	fileDestructorExplicitClose.seekg(0, std::ios::end);
	auto posExplicitClose = fileDestructorExplicitClose.tellg();

	// sizes should be non-zero and match if files both got closed properly
	PTF_ASSERT_NOT_EQUAL(0, posNoClose);
	PTF_ASSERT_NOT_EQUAL(0, posExplicitClose);
	PTF_ASSERT_EQUAL(posNoClose, posExplicitClose);
}  // TestPcapFileWriterDeviceDestructor
