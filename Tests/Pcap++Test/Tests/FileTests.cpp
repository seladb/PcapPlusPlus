#include "../TestDefinition.h"
#include "Logger.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "../Common/PcapFileNamesDef.h"
#include <array>
#include <fstream>

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

PTF_TEST_CASE(TestPcapFileReadWrite)
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

	// read all packets in a bulk
	pcpp::PcapFileReaderDevice readerDev2(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(readerDev2.open());
	PTF_ASSERT_TRUE(readerDev2.isOpened());

	pcpp::RawPacketVector packetVec;
	int numOfPacketsRead = readerDev2.getNextPackets(packetVec);
	PTF_ASSERT_EQUAL(numOfPacketsRead, 4631);
	PTF_ASSERT_EQUAL(packetVec.size(), 4631);

	readerDev2.close();
	PTF_ASSERT_FALSE(readerDev2.isOpened());
}  // TestPcapFileReadWrite

PTF_TEST_CASE(TestPcapFilePrecision)
{
	std::array<uint8_t, 16> testPayload = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	pcpp::RawPacket rawPacketNano(testPayload.data(), testPayload.size(), timespec({ 1, 1234 }), false);  // 1.000001234
	pcpp::RawPacket rawPacketMicro(testPayload.data(), testPayload.size(), timeval({ 1, 2 }), false);     // 1.000002000

	// Writer precision support should equal to reader precision support
	PTF_ASSERT_EQUAL(pcpp::PcapFileWriterDevice::isNanoSecondPrecisionSupported(),
	                 pcpp::PcapFileReaderDevice::isNanoSecondPrecisionSupported());

	// Write nano precision file
	pcpp::Logger::getInstance().suppressLogs();
	pcpp::PcapFileWriterDevice writerDevNano(EXAMPLE_PCAP_NANO_PATH, pcpp::LINKTYPE_ETHERNET, true);
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_EQUAL(writerDevNano.getTimestampPrecision(),
	                 pcpp::PcapFileWriterDevice::isNanoSecondPrecisionSupported()
	                     ? pcpp::FileTimestampPrecision::Nanoseconds
	                     : pcpp::FileTimestampPrecision::Microseconds,
	                 enumclass);
	PTF_ASSERT_TRUE(writerDevNano.open());
	PTF_ASSERT_EQUAL(writerDevNano.getTimestampPrecision(),
	                 pcpp::PcapFileWriterDevice::isNanoSecondPrecisionSupported()
	                     ? pcpp::FileTimestampPrecision::Nanoseconds
	                     : pcpp::FileTimestampPrecision::Microseconds,
	                 enumclass);
	PTF_ASSERT_TRUE(writerDevNano.writePacket(rawPacketMicro));
	PTF_ASSERT_TRUE(writerDevNano.writePacket(rawPacketNano));
	writerDevNano.close();

	// Write micro precision file
	pcpp::PcapFileWriterDevice writerDevMicro(EXAMPLE_PCAP_MICRO_PATH, pcpp::LINKTYPE_ETHERNET, false);
	PTF_ASSERT_EQUAL(writerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds, enumclass);
	PTF_ASSERT_TRUE(writerDevMicro.open());
	PTF_ASSERT_EQUAL(writerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Microseconds, enumclass);
	PTF_ASSERT_TRUE(writerDevMicro.writePacket(rawPacketMicro));
	PTF_ASSERT_TRUE(writerDevMicro.writePacket(rawPacketNano));
	writerDevMicro.close();

	// Read nano precision file
	pcpp::PcapFileReaderDevice readerDevNano(EXAMPLE_PCAP_NANO_PATH);
	PTF_ASSERT_EQUAL(readerDevNano.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
	PTF_ASSERT_TRUE(readerDevNano.open());
	PTF_ASSERT_EQUAL(readerDevNano.getTimestampPrecision(),
	                 pcpp::PcapFileReaderDevice::isNanoSecondPrecisionSupported()
	                     ? pcpp::FileTimestampPrecision::Nanoseconds
	                     : pcpp::FileTimestampPrecision::Microseconds,
	                 enumclass);

	pcpp::RawPacket readPacketNano, readPacketMicro;
	PTF_ASSERT_TRUE(readerDevNano.getNextPacket(readPacketMicro));
	PTF_ASSERT_EQUAL(readPacketMicro.getPacketTimeStamp().tv_sec, 1);
	PTF_ASSERT_EQUAL(readPacketMicro.getPacketTimeStamp().tv_nsec, 2000);

	PTF_ASSERT_TRUE(readerDevNano.getNextPacket(readPacketNano));
	PTF_ASSERT_EQUAL(readPacketNano.getPacketTimeStamp().tv_sec, 1);
	PTF_ASSERT_EQUAL(readPacketNano.getPacketTimeStamp().tv_nsec,
	                 pcpp::PcapFileReaderDevice::isNanoSecondPrecisionSupported() ? 1234 : 1000);

	readerDevNano.close();

	// Read micro precision file
	pcpp::PcapFileReaderDevice readerDevMicro(EXAMPLE_PCAP_MICRO_PATH);
	PTF_ASSERT_EQUAL(readerDevMicro.getTimestampPrecision(), pcpp::FileTimestampPrecision::Unknown, enumclass);
	PTF_ASSERT_TRUE(readerDevMicro.open());
	PTF_ASSERT_EQUAL(readerDevMicro.getTimestampPrecision(),
	                 pcpp::PcapFileReaderDevice::isNanoSecondPrecisionSupported()
	                     ? pcpp::FileTimestampPrecision::Nanoseconds
	                     : pcpp::FileTimestampPrecision::Microseconds,
	                 enumclass);

	pcpp::RawPacket readPacketNano2, readPacketMicro2;
	PTF_ASSERT_TRUE(readerDevMicro.getNextPacket(readPacketMicro2));
	PTF_ASSERT_EQUAL(readPacketMicro2.getPacketTimeStamp().tv_sec, 1);
	PTF_ASSERT_EQUAL(readPacketMicro2.getPacketTimeStamp().tv_nsec, 2000);

	PTF_ASSERT_TRUE(readerDevMicro.getNextPacket(readPacketNano2));
	PTF_ASSERT_EQUAL(readPacketNano2.getPacketTimeStamp().tv_sec, 1);
	PTF_ASSERT_EQUAL(readPacketNano2.getPacketTimeStamp().tv_nsec, 1000);

	readerDevMicro.close();
}  // TestPcapFilePrecision

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
	// SLL2 is not supported in all libpcap versions
	auto canOpenWriterDevice = writerDev.open();
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

		if (canOpenWriterDevice)
		{
			PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket));
		}
	}

	pcpp::IPcapDevice::PcapStats readerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsRecv, 3);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.packetsDrop, 0);

	if (canOpenWriterDevice)
	{
		pcpp::IPcapDevice::PcapStats writerStatistics;
		writerDev.getStatistics(writerStatistics);
		PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsRecv, 3);
		PTF_ASSERT_EQUAL((uint32_t)writerStatistics.packetsDrop, 0);
		writerDev.close();
	}

	PTF_ASSERT_EQUAL(packetCount, 3);
	PTF_ASSERT_EQUAL(sll2Count, 3);
	PTF_ASSERT_EQUAL(ipCount, 3);

	readerDev.close();
}  // TestPcapSll2FileReadWrite

PTF_TEST_CASE(TestPcapRawIPFileReadWrite)
{
	pcpp::Logger::getInstance().suppressLogs();
	pcpp::PcapFileWriterDevice tempWriter(RAW_IP_PCAP_WRITE_PATH, pcpp::LINKTYPE_RAW);
	PTF_ASSERT_FALSE(tempWriter.open());
	pcpp::Logger::getInstance().enableLogs();
	pcpp::PcapFileReaderDevice readerDev(RAW_IP_PCAP_PATH);
	pcpp::PcapFileWriterDevice writerDev(RAW_IP_PCAP_WRITE_PATH, pcpp::LINKTYPE_DLT_RAW1);
	pcpp::PcapNgFileWriterDevice writerNgDev(RAW_IP_PCAPNG_PATH);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
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
	// opening the file for the first time just to delete all packets in it
	pcpp::PcapFileWriterDevice wd(EXAMPLE_PCAP_WRITE_PATH);
	PTF_ASSERT_TRUE(wd.open());
	wd.close();

	for (int i = 0; i < 5; i++)
	{
		pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
		pcpp::PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
		PTF_ASSERT_TRUE(writerDev.open(true));
		PTF_ASSERT_TRUE(readerDev.open());

		pcpp::RawPacket rawPacket;
		while (readerDev.getNextPacket(rawPacket))
		{
			writerDev.writePacket(rawPacket);
		}

		writerDev.close();
		readerDev.close();
	}

	pcpp::PcapFileReaderDevice readerDev(EXAMPLE_PCAP_WRITE_PATH);
	PTF_ASSERT_TRUE(readerDev.open());
	int counter = 0;
	pcpp::RawPacket rawPacket;
	while (readerDev.getNextPacket(rawPacket))
		counter++;

	PTF_ASSERT_EQUAL(counter, (4631 * 5));

	pcpp::Logger::getInstance().suppressLogs();
	pcpp::PcapFileWriterDevice writerDev2(EXAMPLE_PCAP_WRITE_PATH, pcpp::LINKTYPE_LINUX_SLL);
	PTF_ASSERT_FALSE(writerDev2.open(true));
	pcpp::Logger::getInstance().enableLogs();

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
