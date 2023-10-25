#include "../TestDefinition.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include "Packet.h"


#if USE_XDP

void onPacketsArrive(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
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
	device->sendPackets(packets, packetCount);

	int* cycles = static_cast<int*>(userCookie);
	(*cycles)++;
	if (*cycles >= 15)
	{
		device->stopCapture();
	}

	auto stats = device->getStatistics();
	std::cout
		<< "RX packets: " << stats.rxPackets << std::endl
		<< "RX bytes: " << stats.rxBytes << std::endl
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
	PTF_SKIP_TEST("XDP not configured");
#endif
} // TestXdpDevice


PTF_TEST_CASE(TestXdpDeviceSendPackets)
{
#if USE_XDP
	pcpp::XdpDevice device("enp0s3");
	pcpp::PcapFileReaderDevice reader("PcapExamples/one_http_stream_fin.pcap");
	PTF_ASSERT_TRUE(reader.open());
	pcpp::RawPacketVector packets;
	reader.getNextPackets(packets);

	for (int x = 0; x < 5; x++)
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
