#include "../TestDefinition.h"
#include "Logger.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "../Common/PcapFileNamesDef.h"


class FileReaderTeardown
{
private:
	pcpp::IFileReaderDevice* m_Reader;

public:
	FileReaderTeardown(pcpp::IFileReaderDevice* reader)
	{
		m_Reader = reader;
	}

	~FileReaderTeardown()
	{
		if (m_Reader != NULL)
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
	PTF_ASSERT_EQUAL(readerDev.getFileName(), EXAMPLE_PCAP_PATH, string);
	PTF_ASSERT_EQUAL(writerDev.getFileName(), EXAMPLE_PCAP_WRITE_PATH, string);
	PTF_ASSERT_EQUAL(readerDev.getFileSize(), 3812643, u64);
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


	pcap_stat readerStatistics;
	pcap_stat writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_recv, 4631, u32);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_drop, 0, u32);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 4631, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

	PTF_ASSERT_EQUAL(ethCount, 4631, int);
	PTF_ASSERT_EQUAL(sllCount, 0, int);
	PTF_ASSERT_EQUAL(ipCount, 4631, int);
	PTF_ASSERT_EQUAL(tcpCount, 4492, int);
	PTF_ASSERT_EQUAL(udpCount, 139, int);

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
	PTF_ASSERT_EQUAL(numOfPacketsRead, 4631, int);
	PTF_ASSERT_EQUAL(packetVec.size(), 4631, size);

	readerDev2.close();
	PTF_ASSERT_FALSE(readerDev2.isOpened());
} // TestPcapFileReadWrite



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

	pcap_stat readerStatistics;
	pcap_stat writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_recv, 518, u32);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_drop, 0, u32);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 518, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

	PTF_ASSERT_EQUAL(ethCount, 0, int);
	PTF_ASSERT_EQUAL(sllCount, 518, int);
	PTF_ASSERT_EQUAL(ipCount, 510, int);
	PTF_ASSERT_EQUAL(tcpCount, 483, int);
	PTF_ASSERT_EQUAL(udpCount, 28, int);

	readerDev.close();
	writerDev.close();
} // TestPcapSllFileReadWrite



PTF_TEST_CASE(TestPcapRawIPFileReadWrite)
{
	pcpp::LoggerPP::getInstance().supressErrors();
	pcpp::PcapFileWriterDevice tempWriter(RAW_IP_PCAP_WRITE_PATH, pcpp::LINKTYPE_RAW);
	PTF_ASSERT_FALSE(tempWriter.open());
	pcpp::LoggerPP::getInstance().enableErrors();

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

	pcap_stat readerStatistics;
	pcap_stat writerStatistics;
	pcap_stat writerNgStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_recv, 100, u32);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_drop, 0, u32);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 100, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

	writerNgDev.getStatistics(writerNgStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerNgStatistics.ps_recv, 100, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerNgStatistics.ps_drop, 0, u32);

	PTF_ASSERT_EQUAL(ethCount, 0, int);
	PTF_ASSERT_EQUAL(ipv4Count, 50, int);
	PTF_ASSERT_EQUAL(ipv6Count, 50, int);
	PTF_ASSERT_EQUAL(tcpCount, 92, int);
	PTF_ASSERT_EQUAL(udpCount, 8, int);

	readerDev.close();
	writerDev.close();
	writerNgDev.close();
} // TestPcapRawIPFileReadWrite



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

	PTF_ASSERT_EQUAL(counter, (4631*5), int);

	pcpp::LoggerPP::getInstance().supressErrors();
	pcpp::PcapFileWriterDevice writerDev2(EXAMPLE_PCAP_WRITE_PATH, pcpp::LINKTYPE_LINUX_SLL);
	PTF_ASSERT_FALSE(writerDev2.open(true));
	pcpp::LoggerPP::getInstance().enableErrors();

} // TestPcapFileAppend



PTF_TEST_CASE(TestPcapNgFileReadWrite)
{
	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_PATH);
	pcpp::PcapNgFileWriterDevice writerDev(EXAMPLE_PCAPNG_WRITE_PATH);
	pcpp::PcapNgFileWriterDevice writerCompressDev(EXAMPLE_PCAPNG_ZSTD_WRITE_PATH, 5);
	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_TRUE(writerDev.open());
	PTF_ASSERT_TRUE(writerCompressDev.open());
	PTF_ASSERT_EQUAL(readerDev.getFileName(), EXAMPLE_PCAPNG_PATH, string);
	PTF_ASSERT_EQUAL(writerDev.getFileName(), EXAMPLE_PCAPNG_WRITE_PATH, string);
	PTF_ASSERT_EQUAL(writerCompressDev.getFileName(), EXAMPLE_PCAPNG_ZSTD_WRITE_PATH, string);
	PTF_ASSERT_EQUAL(readerDev.getFileSize(), 20704, u64);
	PTF_ASSERT_EQUAL(readerDev.getOS(), "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)", string);
	PTF_ASSERT_EQUAL(readerDev.getCaptureApplication(), "Dumpcap 1.12.6 (v1.12.6-0-gee1fce6 from master-1.12)", string);
	PTF_ASSERT_EQUAL(readerDev.getCaptureFileComment(), "", string);
	PTF_ASSERT_EQUAL(readerDev.getHardware(), "", string);
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

	pcap_stat readerStatistics;
	pcap_stat writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_recv, 64, u32);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_drop, 0, u32);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 64, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

	writerCompressDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 64, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

	PTF_ASSERT_EQUAL(ethLinkLayerCount, 62, int);
	PTF_ASSERT_EQUAL(nullLinkLayerCount, 2, int);
	PTF_ASSERT_EQUAL(otherLinkLayerCount, 0, int);
	PTF_ASSERT_EQUAL(ethCount, 62, int);
	PTF_ASSERT_EQUAL(nullLoopbackCount, 2, int);
	PTF_ASSERT_EQUAL(ipCount, 64, int);
	PTF_ASSERT_EQUAL(tcpCount, 32, int);
	PTF_ASSERT_EQUAL(udpCount, 32, int);

	readerDev.close();
	writerDev.close();
	writerCompressDev.close();

} // TestPcapNgFileReadWrite



PTF_TEST_CASE(TestPcapNgFileReadWriteAdv)
{
	pcpp::PcapNgFileReaderDevice readerDev(EXAMPLE2_PCAPNG_PATH);

	// negative tests
	readerDev.close();
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_EQUAL(readerDev.getOS(), "", string);
	pcpp::LoggerPP::getInstance().enableErrors();
	// --------------

	PTF_ASSERT_TRUE(readerDev.open());
	PTF_ASSERT_EQUAL(readerDev.getOS(), "Linux 3.18.1-1-ARCH", string);
	PTF_ASSERT_EQUAL(readerDev.getCaptureApplication(), "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", string);
	PTF_ASSERT_EQUAL(readerDev.getCaptureFileComment(), "CLIENT_RANDOM E39B5BF4903C68684E8512FB2F60213E9EE843A0810B4982B607914D8092D482 95A5D39B02693BC1FB39254B179E9293007F6D37C66172B1EE4EF0D5E25CE1DABE878B6143DC3B266883E51A75E99DF9                                                   ", string);
	PTF_ASSERT_EQUAL(readerDev.getHardware(), "", string);

 	pcpp::PcapNgFileWriterDevice writerDev(EXAMPLE2_PCAPNG_WRITE_PATH);
	pcpp::PcapNgFileWriterDevice writerCompressDev(EXAMPLE2_PCAPNG_ZSTD_WRITE_PATH, 5);

	// negative tests
	writerDev.close();
	writerCompressDev.close();
	// --------------

	PTF_ASSERT_TRUE(writerDev.open(readerDev.getOS().c_str(), "My Hardware", readerDev.getCaptureApplication().c_str(), "This is a comment in a pcap-ng file"));
	PTF_ASSERT_TRUE(writerCompressDev.open(readerDev.getOS().c_str(), "My Hardware", readerDev.getCaptureApplication().c_str(), "This is a comment in a pcap-ng file"));

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
			PTF_ASSERT_TRUE(pktComment.compare(0, 8, "Packet #") == 0);
			commentCount++;
		}

		PTF_ASSERT_TRUE(writerDev.writePacket(rawPacket, pktComment.c_str()));
		PTF_ASSERT_TRUE(writerCompressDev.writePacket(rawPacket, pktComment.c_str()));
	}

	PTF_ASSERT_EQUAL(packetCount, 159, int);
	PTF_ASSERT_EQUAL(capLenNotMatchOrigLen, 39, int);
	PTF_ASSERT_EQUAL(ethCount, 59, int);
	PTF_ASSERT_EQUAL(sllCount, 100, int);
	PTF_ASSERT_EQUAL(ip4Count, 155, int);
	PTF_ASSERT_EQUAL(ip6Count, 4, int);
	PTF_ASSERT_EQUAL(tcpCount, 159, int);
	PTF_ASSERT_EQUAL(udpCount, 0, int);
	PTF_ASSERT_EQUAL(httpCount, 1, int);
	PTF_ASSERT_EQUAL(commentCount, 100, int);

	pcap_stat readerStatistics;
	pcap_stat writerStatistics;

	readerDev.getStatistics(readerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_recv, 159, u32);
	PTF_ASSERT_EQUAL((uint32_t)readerStatistics.ps_drop, 0, u32);

	writerDev.getStatistics(writerStatistics);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_recv, 159, u32);
	PTF_ASSERT_EQUAL((uint32_t)writerStatistics.ps_drop, 0, u32);

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

	PTF_ASSERT_EQUAL(readerDevCompress.getOS(), "Linux 3.18.1-1-ARCH\0", string);
	PTF_ASSERT_EQUAL(readerDevCompress.getCaptureApplication(), "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", string);
	PTF_ASSERT_EQUAL(readerDevCompress.getCaptureFileComment(), "This is a comment in a pcap-ng file", string);
	PTF_ASSERT_EQUAL(readerDevCompress.getHardware(), "My Hardware", string);

	PTF_ASSERT_EQUAL(readerDev2.getOS(), "Linux 3.18.1-1-ARCH\0", string);
	PTF_ASSERT_EQUAL(readerDev2.getCaptureApplication(), "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", string);
	PTF_ASSERT_EQUAL(readerDev2.getCaptureFileComment(), "This is a comment in a pcap-ng file", string);
	PTF_ASSERT_EQUAL(readerDev2.getHardware(), "My Hardware", string);

	packetCount = 0;
	ethCount = 0;
	sllCount = 0;
	ip4Count = 0;
	ip6Count = 0;
	tcpCount = 0;
	udpCount = 0;
	httpCount = 0;
	commentCount = 0;


	pcpp::RawPacket rawPacket2,rawPacketCompress;

	int packet_count = 0;
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
			PTF_ASSERT_TRUE(pktComment.compare(0, 8, "Packet #") == 0);
			commentCount++;
		}

		readerDev3.getNextPacket(rawPacket2);
		readerDevCompress.getNextPacket(rawPacketCompress);

		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), rawPacket2.getRawDataLen(), int);
		PTF_ASSERT_EQUAL(rawPacket.getRawDataLen(), rawPacketCompress.getRawDataLen(), int);

		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), rawPacket2.getLinkLayerType(), enum);
		PTF_ASSERT_EQUAL(rawPacket.getLinkLayerType(), rawPacketCompress.getLinkLayerType(), enum);

		PTF_ASSERT_EQUAL(rawPacket.getFrameLength(), rawPacket2.getFrameLength(), int);
		PTF_ASSERT_EQUAL(rawPacket.getFrameLength(), rawPacketCompress.getFrameLength(), int);

		timespec packet1_timestamp = rawPacket.getPacketTimeStamp();
		timespec packet2_timestamp = rawPacket2.getPacketTimeStamp();
		timespec packetCompress_timestamp = rawPacketCompress.getPacketTimeStamp();
		if (packet1_timestamp.tv_sec < packet2_timestamp.tv_sec)
		{
			uint64_t timeDiff = (uint64_t)(packet2_timestamp.tv_sec - packet1_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2, u64);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_sec - packet2_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2, u64);
		}

		if (packet1_timestamp.tv_nsec < packet2_timestamp.tv_nsec)
		{
			uint64_t timeDiff = (uint64_t)(packet2_timestamp.tv_nsec - packet1_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000, u64);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_nsec - packet2_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000, u64);
		}

		if (packet1_timestamp.tv_sec < packetCompress_timestamp.tv_sec)
		{
			uint64_t timeDiff = (uint64_t)(packetCompress_timestamp.tv_sec - packet1_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff,2, u64);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_sec - packetCompress_timestamp.tv_sec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 2, u64);
		}

		if (packet1_timestamp.tv_nsec < packetCompress_timestamp.tv_nsec)
		{
			uint64_t timeDiff = (uint64_t)(packetCompress_timestamp.tv_nsec - packet1_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000, u64);
		}
		else
		{
			uint64_t timeDiff = (uint64_t)(packet1_timestamp.tv_nsec - packetCompress_timestamp.tv_nsec);
			PTF_ASSERT_LOWER_THAN(timeDiff, 100000, u64);
		}
		packet_count++;
	}

	PTF_ASSERT_EQUAL(packetCount, 159, int);
	PTF_ASSERT_EQUAL(ethCount, 59, int);
	PTF_ASSERT_EQUAL(sllCount, 100, int);
	PTF_ASSERT_EQUAL(ip4Count, 155, int);
	PTF_ASSERT_EQUAL(ip6Count, 4, int);
	PTF_ASSERT_EQUAL(tcpCount, 159, int);
	PTF_ASSERT_EQUAL(udpCount, 0, int);
	PTF_ASSERT_EQUAL(httpCount, 1, int);
	PTF_ASSERT_EQUAL(commentCount, 100, int);

	readerDevCompress.close();
	readerDev2.close();
	readerDev3.close();

	//For now appends are not fully supported with compressed pcapng files
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

	PTF_ASSERT_EQUAL(packetCount, 161, int);

	// -------

	pcpp::IFileReaderDevice* genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE2_PCAP_PATH);
	FileReaderTeardown genericReaderTeardown1(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapFileReaderDevice*>(genericReader));
	PTF_ASSERT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));

	genericReader = pcpp::IFileReaderDevice::getReader(EXAMPLE2_PCAPNG_PATH);
	FileReaderTeardown genericReaderTeardown2(genericReader);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapNgFileReaderDevice*>(genericReader));

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
	PTF_ASSERT_TRUE(writerCompressDev2.open());	//Do not try append mode on compressed files!!!
	PTF_ASSERT_FALSE(writerCompressDev2.setFilter("bla bla bla"));
	PTF_ASSERT_TRUE(writerCompressDev2.setFilter("dst port 35938"));

	int filteredReadPacketCount = 0;
	int filteredWritePacketCount = 0, filteredCompressWritePacketCount = 0;

	while (readerDev5.getNextPacket(rawPacket, pktComment))
	{
		filteredReadPacketCount++;
		if(writerDev2.writePacket(rawPacket))
			filteredWritePacketCount++;
		if (writerCompressDev2.writePacket(rawPacket))
			filteredCompressWritePacketCount++;
	}

	PTF_ASSERT_EQUAL(filteredReadPacketCount, 14, int);
	PTF_ASSERT_EQUAL(filteredWritePacketCount, 3, int);
	PTF_ASSERT_EQUAL(filteredCompressWritePacketCount, 3, int);

	writerCompressDev2.close();
	readerDev5.close();
	writerDev2.close();
} // TestPcapNgFileReadWriteAdv