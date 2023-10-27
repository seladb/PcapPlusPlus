#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "PcapLiveDeviceList.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include "Logger.h"


extern PcapTestArgs PcapTestGlobalArgs;

#if USE_XDP

void onPacketsArrive(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
{
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
		device->stopCapture();
	}
}

void onPacketsArriveTemp(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
{
	printf("**** Callback called for %d packets\n", packetCount);
	for (uint32_t i = 0; i < packetCount; i++)
	{
		pcpp::Packet parsePacket(&packets[i]);
		std::cout << parsePacket << std::endl << std::endl;
	}

//	pcpp::RawPacketVector packetsVec;
//	for (uint32_t i = 0; i < packetCount; i++)
//	{
//		printf("sending raw packet with size %d\n", packets[i].getRawDataLen());
//		auto rawPacket = new pcpp::RawPacket(packets[i]);
//		packetsVec.pushBack(rawPacket);
//	}
//	device->sendPackets(packetsVec);

	//	device->sendPackets(packets, packetCount);

	int* cycles = static_cast<int*>(userCookie);
	(*cycles)++;
	if (*cycles >= 3000)
	{
		device->stopCapture();
	}

	auto stats = device->getStatistics();
	std::cout
		<< "RX packets: " << stats.rxPackets << std::endl
		<< "RX packets per sec: " << stats.rxPacketsPerSec << std::endl
		<< "RX bytes: " << stats.rxBytes << std::endl
		<< "RX bytes per sec: " << stats.rxBytesPerSec << std::endl
		<< "TX sent packets: " << stats.txSentPackets << std::endl
		<< "TX sent bytes: " << stats.txSentBytes << std::endl
		<< "TX completed packets: " << stats.txCompletedPackets << std::endl
		<< "RX dropped packets: " << stats.rxDroppedTotalPackets << std::endl
		<< "TX dropped invalid packets: " << stats.txDroppedInvalidPackets << std::endl
		<< "RX ring id: " << stats.rxRingId << std::endl
		<< "TX ring id: " << stats.txRingId << std::endl
		<< "Fill ring id: " << stats.fqRingId << std::endl
		<< "Completion ring id: " << stats.cqRingId << std::endl
		<< "UMEM free frames: " << stats.umemFreeFrames << std::endl
		<< "UMEM allocated frames: " << stats.umemAllocatedFrames << std::endl;
}

bool assertConfig(const pcpp::XdpDevice::XdpDeviceConfiguration* config,
				  const pcpp::XdpDevice::XdpDeviceConfiguration::AttachMode expectedAttachMode,
				  const uint16_t expectedUmemNumFrames,
				  const uint16_t expectedUmemFrameSize,
				  const uint32_t expectedFillRingSize,
				  const uint32_t expectedCompletionRingSize,
				  const uint32_t expectedRxSize,
				  const uint32_t expectedTxSize,
				  const uint16_t expectedRxTxBatchSize)
{
	return (
			config != nullptr &&
			config->attachMode == expectedAttachMode &&
			config->umemNumFrames == expectedUmemNumFrames &&
			config->umemFrameSize == expectedUmemFrameSize &&
			config->fillRingSize == expectedFillRingSize &&
			config->completionRingSize == expectedCompletionRingSize &&
			config->rxSize == expectedRxSize &&
			config->txSize == expectedTxSize &&
			config->rxTxBatchSize == expectedRxTxBatchSize);
}

std::string getDeviceName()
{
	auto pcapLiveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	if (pcapLiveDev)
	{
		return pcapLiveDev->getName();
	}

	return "";
}


#endif // USE_XDP

PTF_TEST_CASE(TestXdpDeviceCapturePackets)
{
#if USE_XDP
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	PTF_ASSERT_NULL(device.getConfig());

	PTF_ASSERT_TRUE(device.open());

	PTF_ASSERT_TRUE(
		assertConfig(device.getConfig(),
					pcpp::XdpDevice::XdpDeviceConfiguration::AutoMode,
					4096, 4096,4096,2048,2048,2048,64));

	int numPackets = 0;
	device.startCapture(onPacketsArrive, &numPackets, 20000);

	auto stats = device.getStatistics();
	PTF_ASSERT_GREATER_THAN(stats.umemAllocatedFrames, 0);
	PTF_ASSERT_GREATER_THAN(stats.umemFreeFrames, 0);

	device.close();

	stats = device.getStatistics();

	PTF_ASSERT_EQUAL(stats.rxPackets, 5);
	PTF_ASSERT_GREATER_THAN(stats.rxBytes, 0);
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

#else
	PTF_SKIP_TEST("XDP not configured");
#endif
} // TestXdpDeviceCapturePackets


PTF_TEST_CASE(TestXdpDeviceSendPackets)
{
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	pcpp::PcapFileReaderDevice reader("PcapExamples/one_http_stream_fin.pcap");
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacketVector packets;
	reader.getNextPackets(packets);

	PTF_ASSERT_TRUE(device.open());

	device.sendPackets(packets, true);

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

	device.sendPackets(packets);

	stats = device.getStatistics();
	PTF_ASSERT_NOT_EQUAL(stats.txSentPackets, stats.txCompletedPackets);
} // TestXdpDeviceSendPackets


PTF_TEST_CASE(TestXdpDeviceNonDefaultConfig)
{
	std::string devName = getDeviceName();
	PTF_ASSERT_FALSE(devName.empty());
	pcpp::XdpDevice device(devName);

	auto config = pcpp::XdpDevice::XdpDeviceConfiguration(pcpp::XdpDevice::XdpDeviceConfiguration::SkbMode,
														  1000, 4096, 512, 512, 512, 512, 20);
	PTF_ASSERT_TRUE(device.open(config));

	PTF_ASSERT_TRUE(
		assertConfig(device.getConfig(),
					 pcpp::XdpDevice::XdpDeviceConfiguration::SkbMode,
					 1000, 4096,512,512,512,512,20));

	int numPackets = 0;
	device.startCapture(onPacketsArrive, &numPackets, 20000);

	PTF_ASSERT_EQUAL(numPackets, 5);
} // TestXdpDeviceNonDefaultConfig


PTF_TEST_CASE(TestXdpDeviceInvalidConfig)
{
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
} // TestXdpDeviceInvalidConfig


PTF_TEST_CASE(TestXdpDeviceTemp)
{
#if USE_XDP
	int cycles = 0;
	pcpp::XdpDevice device("enp0s3");
	//	PTF_ASSERT_TRUE(device.loadProgram("/home/elad/PcapPlusPlus/Kernel/XDP/xdp_kern.o"));
	PTF_ASSERT_TRUE(device.open());
	auto deviceConfig = device.getConfig();
	std::cout
		<< "UMEM frame size: " << deviceConfig->umemFrameSize << std::endl
		<< "UMEM frame count: " << deviceConfig->umemNumFrames << std::endl
		<< "Attach mode: " << deviceConfig->attachMode << std::endl
		<< "RX ring size: " << deviceConfig->rxSize << std::endl
		<< "TX ring size: " << deviceConfig->txSize << std::endl
		<< "Fill ring size: " << deviceConfig->fillRingSize << std::endl
		<< "Completion ring size: " << deviceConfig->completionRingSize << std::endl
		<< "Batch size: " << deviceConfig->rxTxBatchSize << std::endl;

	device.startCapture(onPacketsArriveTemp, &cycles, 0);
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
} // TestXdpDevice


PTF_TEST_CASE(TestXdpDeviceSendPacketsTemp)
{
#if USE_XDP
	pcpp::XdpDevice device("enp0s3");
	pcpp::PcapFileReaderDevice reader("PcapExamples/one_http_stream_fin.pcap");
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacketVector packets;
	reader.getNextPackets(packets);

	for (int x = 0; x < 500; x++)
	{
		PTF_ASSERT_TRUE(device.open());
		for (int i = 0; i < 100; i++)
		{
			device.sendPackets(packets);
			//		sleep(1);

			auto stats = device.getStatistics();
			std::cout
				<< "RX packets: " << stats.rxPackets << std::endl
				<< "RX bytes: " << stats.rxBytes << std::endl
				<< "TX sent packets: " << stats.txSentPackets << std::endl
				<< "TX sent packets per sec: " << stats.txSentPacketsPerSec << std::endl
				<< "TX sent bytes: " << stats.txSentBytes << std::endl
				<< "TX sent bytes per sec: " << stats.txSentBytesPerSec << std::endl
				<< "TX completed packets: " << stats.txCompletedPackets << std::endl
				<< "TX completed packets per sec: " << stats.txCompletedPacketsPerSec << std::endl
				<< "RX dropped packets: " << stats.rxDroppedTotalPackets << std::endl
				<< "TX dropped invalid packets: " << stats.txDroppedInvalidPackets << std::endl
				<< "RX ring id: " << stats.rxRingId << std::endl
				<< "TX ring id: " << stats.txRingId << std::endl
				<< "Fill ring id: " << stats.fqRingId << std::endl
				<< "Completion ring id: " << stats.cqRingId << std::endl
				<< "UMEM free frames: " << stats.umemFreeFrames << std::endl
				<< "UMEM allocated frames: " << stats.umemAllocatedFrames << std::endl;
		}
		device.close();

	}
#else
	PTF_SKIP_TEST("XDP not configured");
#endif
} // TestXdpDeviceSendPackets


PTF_TEST_CASE(TestXdpDeviceInvalidConfiguration)
{

} // TestXdpDeviceInvalidConfiguration