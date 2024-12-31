#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "PcapLiveDeviceList.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include "Logger.h"

extern PcapTestArgs PcapTestGlobalArgs;

#ifdef USE_XDP

struct XdpPacketData
{
	int packetCount;
	int byteCount;
	uint64_t latestTimestamp;

	XdpPacketData() : packetCount(0), byteCount(0), latestTimestamp(0)
	{}
};

bool assertConfig(const pcpp::XdpDevice::XdpDeviceConfiguration* config,
                  const pcpp::XdpDevice::XdpDeviceConfiguration::AttachMode expectedAttachMode,
                  const uint16_t expectedUmemNumFrames, const uint16_t expectedUmemFrameSize,
                  const uint32_t expectedFillRingSize, const uint32_t expectedCompletionRingSize,
                  const uint32_t expectedRxSize, const uint32_t expectedTxSize, const uint16_t expectedRxTxBatchSize)
{
	return (config != nullptr && config->attachMode == expectedAttachMode &&
	        config->umemNumFrames == expectedUmemNumFrames && config->umemFrameSize == expectedUmemFrameSize &&
	        config->fillRingSize == expectedFillRingSize && config->completionRingSize == expectedCompletionRingSize &&
	        config->rxSize == expectedRxSize && config->txSize == expectedTxSize &&
	        config->rxTxBatchSize == expectedRxTxBatchSize);
}

std::string getDeviceName()
{
	auto pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	if (pcapLiveDev)
	{
		return pcapLiveDev->getName();
	}

	return "";
}

#endif  // USE_XDP

PTF_TEST_CASE(TestXdpDeviceReceivePackets)
{
#ifdef USE_XDP
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	PTF_ASSERT_NULL(device.getConfig());

	PTF_ASSERT_TRUE(device.open());

	PTF_ASSERT_TRUE(assertConfig(device.getConfig(), pcpp::XdpDevice::XdpDeviceConfiguration::AutoMode, 4096, 4096,
	                             4096, 2048, 2048, 2048, 64));

	XdpPacketData packetData;

	auto onPacketsArrive = [](pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device,
	                          void* userCookie) -> void {
		auto packetData = static_cast<XdpPacketData*>(userCookie);

		for (uint32_t i = 0; i < packetCount; i++)
		{
			if (packets[i].getRawDataLen() > 0)
			{
				packetData->packetCount++;
				packetData->byteCount += packets[i].getRawDataLen();
				packetData->latestTimestamp = 1000 * 1000 * 1000 * packets[i].getPacketTimeStamp().tv_sec +
				                              packets[i].getPacketTimeStamp().tv_nsec;
			}
		}

		if (packetData->packetCount >= 5)
		{
			device->stopReceivePackets();
		}
	};

	timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	uint64_t curTimestamp = 1000 * 1000 * 1000 * ts.tv_sec + ts.tv_nsec;

	PTF_ASSERT_TRUE(device.receivePackets(onPacketsArrive, &packetData, 20000));

	PTF_ASSERT_GREATER_OR_EQUAL_THAN(packetData.packetCount, 5);
	PTF_ASSERT_GREATER_THAN(packetData.latestTimestamp, curTimestamp);

	auto stats = device.getStatistics();
	PTF_ASSERT_GREATER_THAN(stats.umemAllocatedFrames, 0);
	PTF_ASSERT_GREATER_THAN(stats.umemFreeFrames, 0);

	device.close();

	stats = device.getStatistics();

	PTF_ASSERT_EQUAL(stats.rxPackets, packetData.packetCount);
	PTF_ASSERT_EQUAL(stats.rxBytes, packetData.byteCount);
	PTF_ASSERT_EQUAL(stats.rxDroppedTotalPackets, 0);
	PTF_ASSERT_EQUAL(stats.txSentPackets, 0);
	PTF_ASSERT_EQUAL(stats.txSentBytes, 0);
	PTF_ASSERT_EQUAL(stats.txCompletedPackets, 0);
	PTF_ASSERT_EQUAL(stats.txDroppedInvalidPackets, 0);
	PTF_ASSERT_EQUAL(stats.txSentBytesPerSec, 0);
	PTF_ASSERT_EQUAL(stats.txSentPacketsPerSec, 0);
	PTF_ASSERT_EQUAL(stats.txCompletedPacketsPerSec, 0);
	PTF_ASSERT_EQUAL(stats.umemAllocatedFrames, 0);
	PTF_ASSERT_EQUAL(stats.umemFreeFrames, 0);
	PTF_ASSERT_GREATER_THAN(stats.rxRingId, 0);
	PTF_ASSERT_GREATER_THAN(stats.fqRingId, 0);
	PTF_ASSERT_EQUAL(stats.txRingId, 0);
	PTF_ASSERT_EQUAL(stats.cqRingId, 0);

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(device.receivePackets(onPacketsArrive, nullptr));
	pcpp::Logger::getInstance().enableLogs();
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
}  // TestXdpDeviceReceivePackets

PTF_TEST_CASE(TestXdpDeviceSendPackets)
{
#ifdef USE_XDP
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	pcpp::PcapFileReaderDevice reader("PcapExamples/one_http_stream_fin.pcap");
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacketVector packets;
	reader.getNextPackets(packets);

	PTF_ASSERT_TRUE(device.open());

	PTF_ASSERT_TRUE(device.sendPackets(packets, true));

	auto stats = device.getStatistics();
	PTF_ASSERT_EQUAL(stats.rxPackets, 0);
	PTF_ASSERT_EQUAL(stats.rxBytes, 0);
	PTF_ASSERT_EQUAL(stats.rxDroppedTotalPackets, 0);
	PTF_ASSERT_EQUAL(stats.txSentPackets, 15);
	PTF_ASSERT_EQUAL(stats.txSentBytes, 4808);
	PTF_ASSERT_EQUAL(stats.txCompletedPackets, 15);
	PTF_ASSERT_EQUAL(stats.txDroppedInvalidPackets, 0);
	PTF_ASSERT_GREATER_THAN(stats.umemAllocatedFrames, 0);
	PTF_ASSERT_GREATER_THAN(stats.umemFreeFrames, 0);
	PTF_ASSERT_EQUAL(stats.rxRingId, 0);
	PTF_ASSERT_EQUAL(stats.fqRingId, 0);
	PTF_ASSERT_GREATER_THAN(stats.txRingId, 0);
	PTF_ASSERT_GREATER_THAN(stats.cqRingId, 0);

	PTF_ASSERT_TRUE(device.sendPackets(packets));

	stats = device.getStatistics();
	PTF_ASSERT_NOT_EQUAL(stats.txSentPackets, stats.txCompletedPackets);

	device.close();

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(device.sendPackets(packets));
	pcpp::Logger::getInstance().enableLogs();
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
}  // TestXdpDeviceSendPackets

PTF_TEST_CASE(TestXdpDeviceNonDefaultConfig)
{
#ifdef USE_XDP
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	auto config = pcpp::XdpDevice::XdpDeviceConfiguration(pcpp::XdpDevice::XdpDeviceConfiguration::SkbMode, 1000, 4096,
	                                                      512, 512, 512, 512, 20);
	PTF_ASSERT_TRUE(device.open(config));

	PTF_ASSERT_TRUE(assertConfig(device.getConfig(), pcpp::XdpDevice::XdpDeviceConfiguration::SkbMode, 1000, 4096, 512,
	                             512, 512, 512, 20));

	int numPackets = 0;

	auto onPacketsArrive = [](pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device,
	                          void* userCookie) -> void {
		int* totalPacketCount = static_cast<int*>(userCookie);

		for (uint32_t i = 0; i < packetCount; i++)
		{
			if (packets[i].getRawDataLen() > 0)
			{
				(*totalPacketCount)++;
			}
		}

		if (*totalPacketCount >= 5)
		{
			device->stopReceivePackets();
		}
	};

	PTF_ASSERT_TRUE(device.receivePackets(onPacketsArrive, &numPackets, 20000));

	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numPackets, 5);
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
}  // TestXdpDeviceNonDefaultConfig

PTF_TEST_CASE(TestXdpDeviceInvalidConfig)
{
#ifdef USE_XDP
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	pcpp::Logger::getInstance().suppressLogs();

	// Frame size is not a power of 2
	auto config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.umemFrameSize = 1000;

	PTF_ASSERT_FALSE(device.open(config));

	// Fill ring size is not a power of 2
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.fillRingSize = 100;

	PTF_ASSERT_FALSE(device.open(config));

	// Completion ring size is not a power of 2
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.completionRingSize = 100;

	PTF_ASSERT_FALSE(device.open(config));

	// RX ring size is not a power of 2
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.rxSize = 100;

	PTF_ASSERT_FALSE(device.open(config));

	// TX ring size is not a power of 2
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.txSize = 100;

	PTF_ASSERT_FALSE(device.open(config));

	// Fill ring size is larger than total number of frames
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.fillRingSize = 8192;

	PTF_ASSERT_FALSE(device.open(config));

	// Completion ring size is larger than total number of frames
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.completionRingSize = 8192;

	PTF_ASSERT_FALSE(device.open(config));

	// RX ring size is larger than total number of frames
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.rxSize = 8192;

	PTF_ASSERT_FALSE(device.open(config));

	// TX ring size is larger than total number of frames
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.txSize = 8192;

	PTF_ASSERT_FALSE(device.open(config));

	// Batch ring size is larger than RX/TX size
	config = pcpp::XdpDevice::XdpDeviceConfiguration();
	config.rxTxBatchSize = 8192;

	PTF_ASSERT_FALSE(device.open(config));

	pcpp::Logger::getInstance().enableLogs();
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
}  // TestXdpDeviceInvalidConfig
