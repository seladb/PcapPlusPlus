#include "../TestDefinition.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include <unistd.h>


#if USE_XDP

void onPacketsArrive(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
{
	printf("**** Callback called for %d packets\n", packetCount);
//	for (uint32_t i = 0; i < packetCount; i++)
//	{
//		printf("got raw packet with size %d\n", packets[i].getRawDataLen());
//	}
//	printf("\n");
//	sleep(3);

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
	device->sendPackets(packets, packetCount);

	int* cycles = static_cast<int*>(userCookie);
	(*cycles)++;
	if (*cycles >= 15)
	{
		device->stopCapture();
	}
}

#endif // USE_XDP

PTF_TEST_CASE(TestXdpDevice)
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

	device.startCapture(onPacketsArrive, &cycles, 0);
#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestXdpDevice


PTF_TEST_CASE(TestXdpDeviceSendPackets)
{
#if USE_XDP
	pcpp::PcapFileReaderDevice reader("PcapExamples/one_http_stream_fin.pcap");
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacketVector packets;
	reader.getNextPackets(packets);
	pcpp::XdpDevice device("enp0s3");
	PTF_ASSERT_TRUE(device.open());
	for (int i = 0; i < 10; i++)
	{
		device.sendPackets(packets, true);
		sleep(1);
	}
#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestXdpDeviceSendPackets
