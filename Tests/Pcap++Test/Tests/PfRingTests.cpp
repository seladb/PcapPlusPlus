#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "../Common/PcapFileNamesDef.h"

#ifdef USE_PF_RING
#	include "Logger.h"
#	include "PacketUtils.h"
#	include "IPv4Layer.h"
#	include "PfRingDeviceList.h"
#	include "PcapFileDevice.h"
#	include "PcapLiveDeviceList.h"
#	include <thread>
#endif

extern PcapTestArgs PcapTestGlobalArgs;

#ifdef USE_PF_RING

struct PfRingPacketData
{
	uint8_t ThreadId;
	int PacketCount;
	int EthCount;
	int IpCount;
	int TcpCount;
	int UdpCount;
	std::unordered_map<uint32_t, pcpp::RawPacketVector> FlowKeys;

	PfRingPacketData() : ThreadId(-1), PacketCount(0), EthCount(0), IpCount(0), TcpCount(0), UdpCount(0)
	{}
	void clear()
	{
		ThreadId = -1;
		PacketCount = 0;
		EthCount = 0;
		IpCount = 0;
		TcpCount = 0;
		UdpCount = 0;
		FlowKeys.clear();
	}
};

struct SetFilterInstruction
{
	int Instruction;
	std::string Data;
	int PacketCount;
};

static void pfRingPacketsArrive(pcpp::RawPacket* packets, uint32_t numOfPackets, uint8_t threadId,
                                pcpp::PfRingDevice* device, void* userCookie)
{
	PfRingPacketData* data = static_cast<PfRingPacketData*>(userCookie);

	data->ThreadId = threadId;
	data->PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		pcpp::Packet packet(&packets[i]);
		if (packet.isPacketOfType(pcpp::Ethernet))
			data->EthCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			data->IpCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			data->TcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			data->UdpCount++;
	}
}

static void pfRingPacketsArriveMultiThread(pcpp::RawPacket* packets, uint32_t numOfPackets, uint8_t threadId,
                                           pcpp::PfRingDevice* device, void* userCookie)
{
	PfRingPacketData* data = static_cast<PfRingPacketData*>(userCookie);

	data[threadId].ThreadId = threadId;
	data[threadId].PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		pcpp::Packet packet(&packets[i]);
		if (packet.isPacketOfType(pcpp::Ethernet))
			data[threadId].EthCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			data[threadId].IpCount++;
		if (packet.isPacketOfType(pcpp::TCP))
		{
			data[threadId].TcpCount++;
			if (packet.isPacketOfType(pcpp::IPv4))
			{
				pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(packets[i]);
				data[threadId].FlowKeys[pcpp::hash5Tuple(&packet)].pushBack(newRawPacket);
			}
		}
		if (packet.isPacketOfType(pcpp::UDP))
			data[threadId].UdpCount++;
	}
}

void pfRingPacketsArriveSetFilter(pcpp::RawPacket* packets, uint32_t numOfPackets, uint8_t threadId,
                                  pcpp::PfRingDevice* device, void* userCookie)
{
	SetFilterInstruction* instruction = static_cast<SetFilterInstruction*>(userCookie);
	switch (instruction->Instruction)
	{
	case 1:  // verify TCP packet
		for (uint32_t i = 0; i < numOfPackets; i++)
		{
			pcpp::Packet packet(&packets[i]);
			if (!packet.isPacketOfType(pcpp::TCP))
			{
				instruction->Instruction = 0;
			}
			instruction->PacketCount++;
		}
		break;

	case 2:  // verify IP filter
		pcpp::IPv4Address addr(instruction->Data);
		for (uint32_t i = 0; i < numOfPackets; i++)
		{
			pcpp::Packet packet(&packets[i]);
			if (!packet.isPacketOfType(pcpp::IPv4))
			{
				instruction->Instruction = 0;
			}
			pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (!(ipv4Layer->getSrcIPAddress() == addr))
			{
				instruction->Instruction = 0;
			}
			instruction->PacketCount++;
		}
		break;
	}
}

int incSleep(int maxSleepTime, const PfRingPacketData& packetData)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxSleepTime)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
		totalSleepTime += 1;
		if (packetData.PacketCount > 0)
			break;
	}

	return totalSleepTime;
}

int incSleepMultiThread(int maxSleepTime, PfRingPacketData packetData[], int totalNumOfCores, int numOfCoresInUse,
                        pcpp::CoreMask coreMask)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxSleepTime)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
		totalSleepTime += 1;

		int coresWithPacketCountNotZero = 0;
		for (int i = 0; i < totalNumOfCores; i++)
		{
			if ((pcpp::SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
				continue;

			if (packetData[i].PacketCount > 0)
				coresWithPacketCountNotZero++;
		}

		if (coresWithPacketCountNotZero >= numOfCoresInUse)
			break;
	}

	return totalSleepTime;
}

int incSleepSetFilter(int maxSleepTime, const SetFilterInstruction& packetData)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxSleepTime)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
		totalSleepTime += 1;
		if (packetData.PacketCount > 0)
			break;
	}

	return totalSleepTime;
}

static pcpp::CoreMask TestPfRingMultiThreadCoreMask;

#endif

PTF_TEST_CASE(TestPfRingDevice)
{
#ifdef USE_PF_RING

	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	PTF_ASSERT_GREATER_THAN(devList.getPfRingDevicesList().size(), 0);
	PTF_ASSERT_NOT_EQUAL(devList.getPfRingVersion(), "");
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());

	PTF_ASSERT_NOT_NULL(dev);
	PTF_ASSERT_GREATER_THAN(dev->getInterfaceIndex(), 0);
	PTF_ASSERT_GREATER_THAN(dev->getTotalNumOfRxChannels(), 0);
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxChannels(), 0);
	PTF_ASSERT_TRUE(dev->open());
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(dev->open());
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxChannels(), 1);

	PfRingPacketData packetData;
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData));
	int totalSleepTime = incSleep(10, packetData);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	PTF_ASSERT_GREATER_THAN(packetData.PacketCount, 0);
	PTF_ASSERT_NOT_EQUAL(packetData.ThreadId, -1);

	pcpp::PfRingDevice::PfRingStats stats;
	stats.recv = 0;
	stats.drop = 0;
	dev->getStatistics(stats);
	PTF_ASSERT_EQUAL(stats.recv, (uint64_t)packetData.PacketCount);
	dev->close();

	PTF_PRINT_VERBOSE("Thread ID: " << packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: " << packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: " << packetData.EthCount);
	PTF_PRINT_VERBOSE("IP packets: " << packetData.IpCount);
	PTF_PRINT_VERBOSE("TCP packets: " << packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: " << packetData.UdpCount);
	PTF_PRINT_VERBOSE("Device statistics:");
	PTF_PRINT_VERBOSE("Packets captured: " << stats.recv);
	PTF_PRINT_VERBOSE("Packets dropped: " << stats.drop);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingDevice

PTF_TEST_CASE(TestPfRingDeviceSingleChannel)
{
#ifdef USE_PF_RING

	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());
	PTF_ASSERT_NOT_NULL(dev);

	PfRingPacketData packetData;
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels() + 1));
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels() - 1));
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData));
	int totalSleepTime = incSleep(10, packetData);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	PTF_ASSERT_GREATER_THAN(packetData.PacketCount, 0);
	PTF_ASSERT_NOT_EQUAL(packetData.ThreadId, -1);
	pcpp::PfRingDevice::PfRingStats stats;
	dev->getStatistics(stats);
	PTF_ASSERT_EQUAL(stats.recv, (uint64_t)packetData.PacketCount);
	PTF_PRINT_VERBOSE("Thread ID: " << packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: " << packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: " << packetData.EthCount);
	PTF_PRINT_VERBOSE("IP packets: " << packetData.IpCount);
	PTF_PRINT_VERBOSE("TCP packets: " << packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: " << packetData.UdpCount);
	PTF_PRINT_VERBOSE("Packets captured: " << stats.recv);
	PTF_PRINT_VERBOSE("Packets dropped: " << stats.drop);

	dev->close();
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxChannels(), 0);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingDeviceSingleChannel

PTF_TEST_CASE(TestPfRingDeviceMultiThread)
{
#ifdef USE_PF_RING
	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());
	PTF_ASSERT_NOT_NULL(dev);

	uint8_t numOfChannels = dev->getTotalNumOfRxChannels();
	PTF_ASSERT_TRUE(dev->openMultiRxChannels(numOfChannels * 2.5, pcpp::PfRingDevice::PerFlow));
	DeviceTeardown devTeardown(dev);
	dev->close();
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxChannels(), 0);
	int totalnumOfCores = pcpp::getNumOfCores();
	int numOfCoresInUse = 0;
	pcpp::CoreMask tempCoreMask = TestPfRingMultiThreadCoreMask;
	for (int i = 0; i < totalnumOfCores; ++i)
	{
		if (!tempCoreMask)
			break;

		if (tempCoreMask & 1)
			++numOfCoresInUse;
		tempCoreMask = tempCoreMask >> 1;
	}

	PTF_ASSERT_TRUE(dev->openMultiRxChannels((uint8_t)numOfCoresInUse, pcpp::PfRingDevice::PerFlow));
	PfRingPacketData packetDataMultiThread[totalnumOfCores];
	PTF_ASSERT_TRUE(dev->startCaptureMultiThread(pfRingPacketsArriveMultiThread, packetDataMultiThread,
	                                             TestPfRingMultiThreadCoreMask));
	int totalSleepTime =
	    incSleepMultiThread(15, packetDataMultiThread, totalnumOfCores, numOfCoresInUse, TestPfRingMultiThreadCoreMask);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	pcpp::PfRingDevice::PfRingStats aggrStats;
	aggrStats.recv = 0;
	aggrStats.drop = 0;

	pcpp::PfRingDevice::PfRingStats stats;
	for (int i = 0; i < totalnumOfCores; i++)
	{
		if ((pcpp::SystemCores::IdToSystemCore[i].Mask & TestPfRingMultiThreadCoreMask) == 0)
			continue;

		dev->getThreadStatistics(pcpp::SystemCores::IdToSystemCore[i], stats);
		aggrStats.recv += stats.recv;
		aggrStats.drop += stats.drop;

		if (PTF_IS_VERBOSE_MODE)
		{
			PTF_PRINT_VERBOSE("____Thread ID: " << packetDataMultiThread[i].ThreadId << "____");
			PTF_PRINT_VERBOSE("Total packets captured: " << packetDataMultiThread[i].PacketCount);
			PTF_PRINT_VERBOSE("Eth packets: " << packetDataMultiThread[i].EthCount);
			PTF_PRINT_VERBOSE("IP packets: " << packetDataMultiThread[i].IpCount);
			PTF_PRINT_VERBOSE("TCP packets: " << packetDataMultiThread[i].TcpCount);
			PTF_PRINT_VERBOSE("UDP packets: " << packetDataMultiThread[i].UdpCount);
			PTF_PRINT_VERBOSE("Packets captured: " << stats.recv);
			PTF_PRINT_VERBOSE("Packets dropped: " << stats.drop);
			PTF_PRINT_VERBOSE("Total flows: " << packetDataMultiThread[i].FlowKeys.size());
			for (const auto& iter : packetDataMultiThread[i].FlowKeys)
			{
				PTF_PRINT_VERBOSE("Key=0x" << std::hex << iter.first << "; Value=" << std::dec << iter.second.size());
			}
		}

		PTF_ASSERT_EQUAL(stats.recv, (uint64_t)packetDataMultiThread[i].PacketCount);
	}

	dev->getStatistics(stats);
	PTF_ASSERT_EQUAL(aggrStats.recv, stats.recv);
	PTF_ASSERT_EQUAL(aggrStats.drop, stats.drop);

	for (int firstCoreId = 0; firstCoreId < totalnumOfCores; firstCoreId++)
	{
		for (int secondCoreId = firstCoreId + 1; secondCoreId < totalnumOfCores; secondCoreId++)
		{
			std::unordered_map<uint32_t, std::pair<pcpp::RawPacketVector, pcpp::RawPacketVector>> res;
			intersectMaps<uint32_t, pcpp::RawPacketVector, pcpp::RawPacketVector>(
			    packetDataMultiThread[firstCoreId].FlowKeys, packetDataMultiThread[secondCoreId].FlowKeys, res);
			PTF_ASSERT_EQUAL(res.size(), 0);
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();

		dev->close();
	}

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingDeviceMultiThread (internal test case)

PTF_TEST_CASE(TestPfRingMultiThreadAllCores)
{
#ifdef USE_PF_RING
	int numOfCores = pcpp::getNumOfCores();
	pcpp::CoreMask coreMask = 0;
	std::ostringstream cores;
	for (int i = 0; i < numOfCores; i++)
	{
		cores << i << ",";
		coreMask |= pcpp::SystemCores::IdToSystemCore[i].Mask;
	}

	PTF_PRINT_VERBOSE("Participating cores: " << cores.str());

	TestPfRingMultiThreadCoreMask = coreMask;
	PTF_INTERNAL_RUN(TestPfRingDeviceMultiThread);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingMultiThreadAllCores

PTF_TEST_CASE(TestPfRingMultiThreadSomeCores)
{
#ifdef USE_PF_RING
	int numOfCores = pcpp::getNumOfCores();
	pcpp::CoreMask coreMask = 0;
	std::ostringstream cores;
	for (int i = 0; i < numOfCores; i++)
	{
		if (i % 2 != 0)
			continue;

		cores << i << ",";
		coreMask |= pcpp::SystemCores::IdToSystemCore[i].Mask;
	}

	PTF_PRINT_VERBOSE("Participating cores: " << cores.str());

	TestPfRingMultiThreadCoreMask = coreMask;
	PTF_INTERNAL_RUN(TestPfRingDeviceMultiThread);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingMultiThreadSomeCores

PTF_TEST_CASE(TestPfRingSendPacket)
{
#ifdef USE_PF_RING
	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());
	PTF_ASSERT_NOT_NULL(dev);
	PTF_ASSERT_TRUE(dev->open());
	DeviceTeardown devTeardown(dev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	PTF_ASSERT_GREATER_THAN(dev->getMtu(), 0);
	uint16_t mtu = dev->getMtu();
	int buffLen = mtu + 1;
	uint8_t buff[buffLen];
	memset(buff, 0, buffLen);

	pcpp::RawPacket rawPacket;
	int packetsSent = 0;
	int packetsRead = 0;
	while (fileReaderDev.getNextPacket(rawPacket))
	{
		packetsRead++;

		pcpp::RawPacket origRawPacket = rawPacket;
		// send packet as RawPacket
		PTF_ASSERT_TRUE(dev->sendPacket(rawPacket));

		// send packet as raw data
		PTF_ASSERT_TRUE(dev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()));

		// send packet as parsed EthPacekt
		pcpp::Packet packet(&rawPacket);
		PTF_ASSERT_TRUE(dev->sendPacket(packet));

		packetsSent++;
	}

	PTF_ASSERT_EQUAL(packetsRead, packetsSent);

	dev->close();

	fileReaderDev.close();

	// send some packets with single channel open
	PTF_ASSERT_TRUE(dev->openSingleRxChannel(0));
	fileReaderDev.open();
	while (fileReaderDev.getNextPacket(rawPacket))
	{
		PTF_ASSERT_TRUE(dev->sendPacket(rawPacket));
	}

	dev->close();

	fileReaderDev.close();

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingSendPacket

PTF_TEST_CASE(TestPfRingSendPackets)
{
#ifdef USE_PF_RING
	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());
	PTF_ASSERT_NOT_NULL(dev);
	PTF_ASSERT_TRUE(dev->open());
	DeviceTeardown devTeardown(dev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	pcpp::RawPacket rawPacketArr[10000];
	pcpp::PointerVector<pcpp::Packet> packetVec;
	const pcpp::Packet* packetArr[10000];
	int packetsRead = 0;
	while (fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
	{
		packetVec.pushBack(new pcpp::Packet(&rawPacketArr[packetsRead]));
		packetsRead++;
	}

	// send packets as RawPacket array
	int packetsSentAsRaw = dev->sendPackets(rawPacketArr, packetsRead);

	// send packets as parsed EthPacekt array
	std::copy(packetVec.begin(), packetVec.end(), packetArr);
	int packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead);

	PTF_ASSERT_EQUAL(packetsSentAsRaw, packetsRead);
	PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead);

	dev->close();
	fileReaderDev.close();

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}  // TestPfRingSendPackets

PTF_TEST_CASE(TestPfRingFilters)
{
#ifdef USE_PF_RING
	pcpp::PfRingDeviceList& devList = pcpp::PfRingDeviceList::getInstance();
	pcpp::PcapLiveDevice* pcapLiveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(pcapLiveDev);
	pcpp::PfRingDevice* dev = devList.getPfRingDeviceByName(pcapLiveDev->getName());
	PTF_ASSERT_NOT_NULL(dev);

	PTF_ASSERT_FALSE(dev->isFilterCurrentlySet());
	PTF_ASSERT_TRUE(dev->clearFilter());
	pcpp::ProtoFilter protocolFilter(pcpp::TCP);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(dev->setFilter(protocolFilter));
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(dev->open());
	DeviceTeardown devTeardown(dev);
	PTF_ASSERT_TRUE(dev->setFilter(protocolFilter));

	// verify TCP filter
	SetFilterInstruction instruction = { 1, "", 0 };  // instruction #1: verify all packets are of type TCP
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction));
	int totalSleepTime = incSleepSetFilter(10, instruction);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time TCP filter: " << totalSleepTime);
	PTF_ASSERT_EQUAL(instruction.Instruction, 1);

	instruction.Instruction = 2;
	instruction.Data = PcapTestGlobalArgs.ipToSendReceivePackets;
	instruction.PacketCount = 0;
	pcpp::IPFilter ipFilter(PcapTestGlobalArgs.ipToSendReceivePackets, pcpp::SRC);
	PTF_ASSERT_TRUE(dev->setFilter(ipFilter));
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction));
	totalSleepTime = incSleepSetFilter(10, instruction);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time IP filter: " << totalSleepTime);
	PTF_ASSERT_EQUAL(instruction.Instruction, 2);

	// remove filter and test again
	instruction.Instruction = 1;
	instruction.Data = "";
	instruction.PacketCount = 0;
	PTF_ASSERT_TRUE(dev->isFilterCurrentlySet());
	PTF_ASSERT_TRUE(dev->clearFilter());
	PTF_ASSERT_FALSE(dev->isFilterCurrentlySet());

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}
