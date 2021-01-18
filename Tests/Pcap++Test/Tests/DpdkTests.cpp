#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "../Common/PcapFileNamesDef.h"
#include <map>
#include <stdlib.h>
#include <sstream>
#include "Logger.h"
#include "PacketUtils.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"


extern PcapTestArgs PcapTestGlobalArgs;

#ifdef USE_DPDK
struct DpdkPacketData
{
	uint8_t ThreadId;
	int PacketCount;
	int EthCount;
	int ArpCount;
	int Ip4Count;
	int Ip6Count;
	int TcpCount;
	int UdpCount;
	int HttpCount;

	std::map<uint32_t, pcpp::RawPacketVector> FlowKeys;

	DpdkPacketData() : ThreadId(-1), PacketCount(0), EthCount(0), ArpCount(0), Ip4Count(0), Ip6Count(0), TcpCount(0), UdpCount(0), HttpCount(0) {}
	void clear() { ThreadId = -1; PacketCount = 0; EthCount = 0; ArpCount = 0; Ip4Count = 0; Ip6Count = 0; TcpCount = 0; UdpCount = 0; HttpCount = 0; FlowKeys.clear(); }
};

int incSleep(int maxSleepTime, int minPacketCount, const DpdkPacketData& packetData)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxSleepTime)
	{
		pcpp::multiPlatformSleep(1);
		totalSleepTime += 1;
		if (packetData.PacketCount > minPacketCount)
			break;
	}

	return totalSleepTime;
}

int incSleepMultiThread(int maxSleepTime, DpdkPacketData packetData[], int totalNumOfCores, int numOfCoresInUse, pcpp::CoreMask coreMask)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxSleepTime)
	{
		pcpp::multiPlatformSleep(1);
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

void dpdkPacketsArrive(pcpp::MBufRawPacket* packets, uint32_t numOfPackets, uint8_t threadId, pcpp::DpdkDevice* device, void* userCookie)
{
	DpdkPacketData* data = (DpdkPacketData*)userCookie;

	data->ThreadId = threadId;
	data->PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		pcpp::Packet packet(&packets[i]);
		if (packet.isPacketOfType(pcpp::Ethernet))
			data->EthCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			data->ArpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			data->Ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			data->Ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			data->TcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			data->UdpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			data->HttpCount++;

	}
}

void dpdkPacketsArriveMultiThread(pcpp::MBufRawPacket* packets, uint32_t numOfPackets, uint8_t threadId, pcpp::DpdkDevice* device, void* userCookie)
{
	DpdkPacketData* data = (DpdkPacketData*)userCookie;

	data[threadId].ThreadId = threadId;
	data[threadId].PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		pcpp::Packet packet(&packets[i]);
		if (packet.isPacketOfType(pcpp::Ethernet))
			data[threadId].EthCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			data[threadId].ArpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			data[threadId].Ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			data[threadId].Ip6Count++;
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
		{
			data[threadId].UdpCount++;
			if (packet.isPacketOfType(pcpp::IPv4))
			{
				pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(packets[i]);
				data[threadId].FlowKeys[pcpp::hash5Tuple(&packet)].pushBack(newRawPacket);
			}
		}
		if (packet.isPacketOfType(pcpp::HTTP))
			data[threadId].HttpCount++;


	}
}

class DpdkTestWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	uint32_t m_CoreId;
	pcpp::DpdkDevice* m_DpdkDevice;
	bool m_Stop;
	pthread_mutex_t* m_QueueLock;
	uint16_t m_QueueId;
	int m_PacketCount;
	bool m_Initialized;
	bool m_RanAndStopped;
public:
	DpdkTestWorkerThread()
	{
		m_DpdkDevice = NULL;
		m_QueueId = -1;
		m_QueueLock = NULL;
		m_CoreId = -1;
		m_Stop = false;
		m_PacketCount = 0;
		m_Initialized = false;
		m_RanAndStopped = false;
	}

	void init(pcpp::DpdkDevice* dpdkDevice, uint16_t queueId, pthread_mutex_t* queueLock)
	{
		m_DpdkDevice = dpdkDevice;
		m_QueueId = queueId;
		m_QueueLock = queueLock;
		m_Initialized = true;
	}

	bool run(uint32_t coreId)
	{
		if (!m_Initialized)
		{
			printf("Error: Thread %d was not initialized\n", coreId);
			return false;
		}

		m_CoreId = coreId;

		if (m_DpdkDevice == NULL)
		{
			printf("Error: DpdkDevice is NULL");
			return false;
		}

		m_PacketCount = 0;
		pcpp::MBufRawPacket* mBufArr[32] = {};

		while (!m_Stop)
		{
			pthread_mutex_lock(m_QueueLock);
			uint16_t packetReceived = m_DpdkDevice->receivePackets(mBufArr, 32, m_QueueId);
			pthread_mutex_unlock(m_QueueLock);
			m_PacketCount += packetReceived;
			pthread_mutex_lock(m_QueueLock);
			uint16_t packetsSent = m_DpdkDevice->sendPackets(mBufArr, packetReceived, m_QueueId);
			if (packetsSent != packetReceived)
			{
				printf("Error: Couldn't send all received packets on thread %d", m_CoreId);
				pthread_mutex_unlock(m_QueueLock);
				return false;
			}
			pthread_mutex_unlock(m_QueueLock);
		}

		for (int i = 0; i < 32; i++)
		{
			if (mBufArr[i] != NULL)
				delete mBufArr[i];
		}

		m_RanAndStopped = true;
		return true;
	}

	void stop() { m_Stop = true; }

	uint32_t getCoreId() const { return m_CoreId; }

	int getPacketCount() const { return m_PacketCount; }

	bool threadRanAndStopped() { return m_RanAndStopped; }
};

#endif // USE_DPDK





PTF_TEST_CASE(TestDpdkInitDevice)
{
#ifdef USE_DPDK
	pcpp::DpdkDeviceList& devList = pcpp::DpdkDeviceList::getInstance();
	PTF_ASSERT_GREATER_THAN(devList.getDpdkDeviceList().size(), 0, size);

	PTF_ASSERT_EQUAL(devList.getDpdkLogLevel(), pcpp::LoggerPP::Normal, enum);
	devList.setDpdkLogLevel(pcpp::LoggerPP::Debug);
	PTF_ASSERT_EQUAL(devList.getDpdkLogLevel(), pcpp::LoggerPP::Debug, enum);
	devList.setDpdkLogLevel(pcpp::LoggerPP::Normal);
#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkInitDevice




PTF_TEST_CASE(TestDpdkDevice)
{
#ifdef USE_DPDK
	PTF_ASSERT_GREATER_THAN(pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList().size(), 0, size);

	pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(PcapTestGlobalArgs.dpdkPort);
	PTF_ASSERT_NOT_NULL(dev);

	PTF_ASSERT_TRUE(dev->getMacAddress().isValid());
	PTF_ASSERT_NOT_EQUAL(dev->getMacAddress(), pcpp::MacAddress::Zero, object);
	PTF_ASSERT_GREATER_THAN(dev->getTotalNumOfRxQueues(), 0, u16);
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxQueues(), 0, u16);
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedTxQueues(), 0, u16);
	PTF_ASSERT_GREATER_THAN(dev->getMtu(), 0, u16);

	// Changing the MTU isn't supported for all PMDs so can't use it in the unit-tests, as they may
	// fail on environment using such PMDs. Tested it on EM PMD and verified it works
	// uint16_t origMtu = dev->getMtu();
	// uint16_t newMtu = origMtu > 1600 ? 1500 : 9000;
	// PTF_ASSERT_TRUE(dev->setMtu(newMtu));
	// PTF_ASSERT_EQUAL(dev->getMtu(), newMtu, u16);
	// PTF_ASSERT_TRUE(dev->setMtu(origMtu));

	if (dev->getPMDName() == "net_e1000_em")
	{
		uint64_t rssHF = 0;
		PTF_ASSERT_TRUE(dev->isDeviceSupportRssHashFunction(rssHF));
		PTF_ASSERT_EQUAL(dev->getSupportedRssHashFunctions(), rssHF, u64);
	}
	else if (dev->getPMDName() == "net_vmxnet3")
	{
		uint64_t rssHF = pcpp::DpdkDevice::RSS_IPV4 | \
				pcpp::DpdkDevice::RSS_NONFRAG_IPV4_TCP | \
				pcpp::DpdkDevice::RSS_IPV6 | \
				pcpp::DpdkDevice::RSS_NONFRAG_IPV6_TCP;

		PTF_ASSERT_TRUE(dev->isDeviceSupportRssHashFunction(rssHF));
		PTF_ASSERT_EQUAL(dev->getSupportedRssHashFunctions(), rssHF, u64);
	}

	PTF_ASSERT_TRUE(dev->open());
	DeviceTeardown devTeardown(dev);
	pcpp::LoggerPP::getInstance().suppressErrors();
	PTF_ASSERT_FALSE(dev->open());
	pcpp::LoggerPP::getInstance().enableErrors();
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxQueues(), 1, u16);
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedTxQueues(), 1, u16);
	pcpp::DpdkDevice::LinkStatus linkStatus;
	dev->getLinkStatus(linkStatus);
	PTF_ASSERT_TRUE(linkStatus.linkUp);
	PTF_ASSERT_GREATER_THAN(linkStatus.linkSpeedMbps, 0, int);

	DpdkPacketData packetData;
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData));
	int totalSleepTime = incSleep(10, 0, packetData);
	dev->stopCapture();

	PTF_PRINT_VERBOSE("Total sleep time: %d", totalSleepTime);

	PTF_PRINT_VERBOSE("Thread ID: %d", packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: %d", packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: %d", packetData.EthCount);
	PTF_PRINT_VERBOSE("ARP packets: %d", packetData.ArpCount);
	PTF_PRINT_VERBOSE("IPv4 packets: %d", packetData.Ip4Count);
	PTF_PRINT_VERBOSE("IPv6 packets: %d", packetData.Ip6Count);
	PTF_PRINT_VERBOSE("TCP packets: %d", packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: %d", packetData.UdpCount);
	PTF_PRINT_VERBOSE("HTTP packets: %d", packetData.HttpCount);

	pcpp::DpdkDevice::DpdkDeviceStats stats;
	dev->getStatistics(stats);
	PTF_PRINT_VERBOSE("Packets captured according to stats: %lu", stats.aggregatedRxStats.packets);
	PTF_PRINT_VERBOSE("Bytes captured according to stats: %lu", stats.aggregatedRxStats.bytes);
	PTF_PRINT_VERBOSE("Packets dropped according to stats: %lu", stats.rxPacketsDropeedByHW);
	PTF_PRINT_VERBOSE("Erroneous packets according to stats: %lu", stats.rxErroneousPackets);
	for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
	{
		PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
		PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);
	}
	PTF_ASSERT_GREATER_THAN(packetData.PacketCount, 0, int);
	PTF_ASSERT_NOT_EQUAL(packetData.ThreadId, -1, u8);

	int statsVsPacketCount = stats.aggregatedRxStats.packets > (uint64_t)packetData.PacketCount ? stats.aggregatedRxStats.packets-(uint64_t)packetData.PacketCount : (uint64_t)packetData.PacketCount-stats.aggregatedRxStats.packets;
	PTF_ASSERT_LOWER_OR_EQUAL_THAN(statsVsPacketCount, 20, int);

	dev->close();

#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkDevice




PTF_TEST_CASE(TestDpdkMultiThread)
{
#ifdef USE_DPDK
	PTF_ASSERT_GREATER_THAN(pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList().size(), 0, size);

	pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(PcapTestGlobalArgs.dpdkPort);
	PTF_ASSERT_NOT_NULL(dev);
	DeviceTeardown devTeardown(dev);

	// take min value between number of cores and number of available RX queues
	int numOfRxQueuesToOpen = pcpp::getNumOfCores()-1; //using num of cores minus one since 1 core is the master core and cannot be used
	if (dev->getTotalNumOfRxQueues() < numOfRxQueuesToOpen)
		numOfRxQueuesToOpen = dev->getTotalNumOfRxQueues();

	// verfiy num of RX queues is power of 2 due to DPDK limitation
	bool isRxQueuePowerOfTwo = !(numOfRxQueuesToOpen == 0) && !(numOfRxQueuesToOpen & (numOfRxQueuesToOpen - 1));
	while (!isRxQueuePowerOfTwo)
	{
		numOfRxQueuesToOpen--;
		isRxQueuePowerOfTwo = !(numOfRxQueuesToOpen == 0) && !(numOfRxQueuesToOpen & (numOfRxQueuesToOpen - 1));
	}

	if (dev->getTotalNumOfRxQueues() > 1)
	{
		pcpp::LoggerPP::getInstance().suppressErrors();
		PTF_ASSERT_FALSE(dev->openMultiQueues(numOfRxQueuesToOpen+1, 1));
		pcpp::LoggerPP::getInstance().enableErrors();
	}

	PTF_ASSERT_TRUE(dev->openMultiQueues(numOfRxQueuesToOpen, 1));

	if (numOfRxQueuesToOpen > 1)
	{
		pcpp::LoggerPP::getInstance().suppressErrors();
		DpdkPacketData dummyPacketData;
		PTF_ASSERT_FALSE(dev->startCaptureSingleThread(dpdkPacketsArrive, &dummyPacketData));
		pcpp::LoggerPP::getInstance().enableErrors();
	}

	PTF_ASSERT_EQUAL(dev->getNumOfOpenedRxQueues(), (uint16_t)numOfRxQueuesToOpen, u16);
	PTF_ASSERT_EQUAL(dev->getNumOfOpenedTxQueues(), 1, u16);

	DpdkPacketData packetDataMultiThread[pcpp::getNumOfCores()];
	for (int i = 0; i < pcpp::getNumOfCores(); i++)
	{
		packetDataMultiThread[i].PacketCount = 0;
	}

	pcpp::CoreMask coreMask = 0;
	pcpp::SystemCore masterCore = pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore();
	int numOfCoresInUse = 0;
	for (int coreId = 0; coreId < pcpp::getNumOfCores(); coreId++)
	{
		if (numOfCoresInUse == numOfRxQueuesToOpen)
			break;

		if (coreId != masterCore.Id)
		{
			coreMask |= pcpp::SystemCores::IdToSystemCore[coreId].Mask;
			numOfCoresInUse++;
		}
	}

	PTF_ASSERT_TRUE(dev->startCaptureMultiThreads(dpdkPacketsArriveMultiThread, packetDataMultiThread, coreMask));
	int totalSleepTime = incSleepMultiThread(20, packetDataMultiThread, pcpp::getNumOfCores(), numOfCoresInUse, coreMask);
	dev->stopCapture();
	PTF_PRINT_VERBOSE("Total sleep time: %d", totalSleepTime);
	uint64_t packetCount = 0;

	for (int i = 0; i < pcpp::getNumOfCores(); i++)
	{
		if ((pcpp::SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
			continue;

		PTF_PRINT_VERBOSE("Thread ID: %d", packetDataMultiThread[i].ThreadId);
		PTF_PRINT_VERBOSE("Total packets captured: %d", packetDataMultiThread[i].PacketCount);
		PTF_PRINT_VERBOSE("Eth packets: %d", packetDataMultiThread[i].EthCount);
		PTF_PRINT_VERBOSE("ARP packets: %d", packetDataMultiThread[i].ArpCount);
		PTF_PRINT_VERBOSE("IPv4 packets: %d", packetDataMultiThread[i].Ip4Count);
		PTF_PRINT_VERBOSE("IPv6 packets: %d", packetDataMultiThread[i].Ip6Count);
		PTF_PRINT_VERBOSE("TCP packets: %d", packetDataMultiThread[i].TcpCount);
		PTF_PRINT_VERBOSE("UDP packets: %d", packetDataMultiThread[i].UdpCount);
		packetCount += packetDataMultiThread[i].PacketCount;
	}

	PTF_ASSERT_GREATER_THAN(packetCount, 0, u64);

	pcpp::DpdkDevice::DpdkDeviceStats stats;
	dev->getStatistics(stats);
	PTF_PRINT_VERBOSE("Packets captured according to stats: %lu", stats.aggregatedRxStats.packets);
	PTF_PRINT_VERBOSE("Bytes captured according to stats: %lu", stats.aggregatedRxStats.bytes);
	PTF_PRINT_VERBOSE("Packets dropped according to stats: %lu", stats.rxPacketsDropeedByHW);
	PTF_PRINT_VERBOSE("Erroneous packets according to stats: %lu", stats.rxErroneousPackets);
	for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
	{
		PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
		PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);

	}
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(stats.aggregatedRxStats.packets, packetCount, u64);
	PTF_ASSERT_EQUAL(stats.rxPacketsDropeedByHW, 0, u64);

	for (int firstCoreId = 0; firstCoreId < pcpp::getNumOfCores(); firstCoreId++)
	{
		if ((pcpp::SystemCores::IdToSystemCore[firstCoreId].Mask & coreMask) == 0)
			continue;

		for (int secondCoreId = firstCoreId+1; secondCoreId < pcpp::getNumOfCores(); secondCoreId++)
		{
			if ((pcpp::SystemCores::IdToSystemCore[secondCoreId].Mask & coreMask) == 0)
				continue;

			std::map<uint32_t, std::pair<pcpp::RawPacketVector, pcpp::RawPacketVector> > res;
			intersectMaps<uint32_t, pcpp::RawPacketVector, pcpp::RawPacketVector>(packetDataMultiThread[firstCoreId].FlowKeys, packetDataMultiThread[secondCoreId].FlowKeys, res);
			PTF_ASSERT_EQUAL(res.size(), 0, size);
			if (PTF_IS_VERBOSE_MODE)
			{
				for (std::map<uint32_t, std::pair<pcpp::RawPacketVector, pcpp::RawPacketVector> >::iterator iter = res.begin(); iter != res.end(); iter++)
				{
					PTF_PRINT_VERBOSE("Same flow exists in core %d and core %d. Flow key = %X", firstCoreId, secondCoreId, iter->first);
					std::ostringstream stream;
					stream << "Core" << firstCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					pcpp::PcapFileWriterDevice writerDev(stream.str());
					writerDev.open();
					writerDev.writePackets(iter->second.first);
					writerDev.close();

					std::ostringstream stream2;
					stream2 << "Core" << secondCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					pcpp::PcapFileWriterDevice writerDev2(stream2.str());
					writerDev2.open();
					writerDev2.writePackets(iter->second.second);
					writerDev2.close();

					iter->second.first.clear();
					iter->second.second.clear();

				}
			}
		}
		PTF_PRINT_VERBOSE("____Core %d____", firstCoreId);
		PTF_PRINT_VERBOSE("Total flows: %d", (int)packetDataMultiThread[firstCoreId].FlowKeys.size());

		if (PTF_IS_VERBOSE_MODE)
		{
			for(std::map<uint32_t, pcpp::RawPacketVector>::iterator iter = packetDataMultiThread[firstCoreId].FlowKeys.begin(); iter != packetDataMultiThread[firstCoreId].FlowKeys.end(); iter++) {
				PTF_PRINT_VERBOSE("Key=%X; Value=%d", (int)iter->first, (int)iter->second.size());
				iter->second.clear();
			}
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();
	}

	dev->close();

#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkMultiThread




PTF_TEST_CASE(TestDpdkDeviceSendPackets)
{
#ifdef USE_DPDK
	PTF_ASSERT_GREATER_THAN(pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList().size(), 0, size);

	pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(PcapTestGlobalArgs.dpdkPort);
	PTF_ASSERT_NOT_NULL(dev);
	DeviceTeardown devTeardown(dev);

	pcpp::LoggerPP::getInstance().suppressErrors();
	PTF_ASSERT_FALSE(dev->openMultiQueues(1, 255));
	pcpp::LoggerPP::getInstance().enableErrors();

	pcpp::DpdkDevice::DpdkDeviceConfiguration customConfig(128, 1024);
	PTF_ASSERT_TRUE(dev->openMultiQueues(1, dev->getTotalNumOfTxQueues(), customConfig));

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	pcpp::PointerVector<pcpp::Packet> packetVec;
	pcpp::RawPacketVector rawPacketVec;
	pcpp::Packet* packetArr[10000];
	uint16_t packetsRead = 0;
	pcpp::RawPacket rawPacket;
	while(fileReaderDev.getNextPacket(rawPacket))
	{
		if (packetsRead == 100)
			break;

		pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(rawPacket);
		rawPacketVec.pushBack(newRawPacket);
		pcpp::Packet* newPacket = new pcpp::Packet(newRawPacket, false);
		packetVec.pushBack(newPacket);
		packetArr[packetsRead] = newPacket;

		packetsRead++;
	}

	//send packets as parsed EthPacekt array
	uint16_t packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead, 0, false);
	PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead, u16);

	//send packets are RawPacketVector
	uint16_t packetsSentAsRawVector = dev->sendPackets(rawPacketVec);
	PTF_ASSERT_EQUAL(packetsSentAsRawVector, packetsRead, u16);

	if (dev->getTotalNumOfTxQueues() > 1)
	{
		packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead, dev->getTotalNumOfTxQueues()-1);
		packetsSentAsRawVector = dev->sendPackets(rawPacketVec, dev->getTotalNumOfTxQueues()-1);
		PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead, u16);
		PTF_ASSERT_EQUAL(packetsSentAsRawVector, packetsRead, u16);
	}

	pcpp::LoggerPP::getInstance().suppressErrors();
	PTF_ASSERT_EQUAL(dev->sendPackets(rawPacketVec, dev->getTotalNumOfTxQueues()+1), 0, u16);
	pcpp::LoggerPP::getInstance().enableErrors();

	PTF_ASSERT_TRUE(dev->sendPacket(*(rawPacketVec.at(packetsRead/3)), 0));
	PTF_ASSERT_TRUE(dev->sendPacket(*(packetArr[packetsRead/2]), 0));

	dev->close();
	fileReaderDev.close();

#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkDeviceSendPackets




PTF_TEST_CASE(TestDpdkDeviceWorkerThreads)
{
#ifdef USE_DPDK
	PTF_ASSERT_GREATER_THAN(pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList().size(), 0, size);

	pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(PcapTestGlobalArgs.dpdkPort);
	PTF_ASSERT_NOT_NULL(dev);
	DeviceTeardown devTeardown(dev);

	pcpp::MBufRawPacketVector rawPacketVec;
	pcpp::MBufRawPacket* mBufRawPacketArr[32] = {};
	size_t mBufRawPacketArrLen = 32;
	pcpp::Packet* packetArr[32] = {};
	size_t packetArrLen = 32;

	// negative tests
	// --------------
	pcpp::LoggerPP::getInstance().suppressErrors();
	PTF_ASSERT_EQUAL(dev->receivePackets(rawPacketVec, 0), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(packetArr, packetArrLen, 0), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, 0), 0, u16);

	PTF_ASSERT_TRUE(dev->open());
	PTF_ASSERT_EQUAL(dev->receivePackets(rawPacketVec, dev->getTotalNumOfRxQueues()+1), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(packetArr, packetArrLen, dev->getTotalNumOfRxQueues()+1), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, dev->getTotalNumOfRxQueues()+1), 0, u16);

	DpdkPacketData packetData;
	mBufRawPacketArrLen = 32;
	packetArrLen = 32;
	PTF_ASSERT_TRUE(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData));
	PTF_ASSERT_EQUAL(dev->receivePackets(rawPacketVec, 0), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(packetArr, packetArrLen, 0), 0, u16);
	PTF_ASSERT_EQUAL(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, 0), 0, u16);
	pcpp::LoggerPP::getInstance().enableErrors();
	dev->stopCapture();
	dev->close();
	
	PTF_ASSERT_TRUE(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()));

	// receive packets to packet vector
	// --------------------------------
	int numOfAttempts = 0;
	int numOfRxQueues = dev->getTotalNumOfRxQueues();
	int rxQueueId = 0;
	bool isPacketRecvd = false;
	while (numOfAttempts < 20)
	{
		while (rxQueueId < numOfRxQueues)
		{
			dev->receivePackets(rawPacketVec, rxQueueId);
			pcpp::multiPlatformSleep(1);
			if (rawPacketVec.size() > 0)
			{
				isPacketRecvd = true;
				break;
			}
			++rxQueueId;
		}
		if (isPacketRecvd)
			break;

		numOfAttempts++;
	}

	PTF_ASSERT_LOWER_THAN(numOfAttempts, 20, int);
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using RawPacketVector", (int)rawPacketVec.size(), numOfAttempts);

	// receive packets to mbuf array
	// -----------------------------
	numOfAttempts = 0;
	isPacketRecvd = false;
	rxQueueId = 0;
	while (numOfAttempts < 20)
	{
		while (rxQueueId < numOfRxQueues)
		{
			mBufRawPacketArrLen = dev->receivePackets(mBufRawPacketArr, 32, rxQueueId);
			pcpp::multiPlatformSleep(1);
			if (mBufRawPacketArrLen > 0)
			{
				isPacketRecvd = true;
				break;
			}
			++rxQueueId;
		}
		if (isPacketRecvd)
			break;
		numOfAttempts++;
	}

	PTF_ASSERT_LOWER_THAN(numOfAttempts, 20, int);
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using mBuf raw packet arr", (int)mBufRawPacketArrLen, numOfAttempts);

	for (int i = 0; i < 32; i++)
	{
		if (mBufRawPacketArr[i] != NULL)
			delete mBufRawPacketArr[i];
	}

	// receive packets to packet array
	// -------------------------------
	numOfAttempts = 0;
	isPacketRecvd = false;
	rxQueueId = 0;
	while (numOfAttempts < 20)
	{
		while (rxQueueId < numOfRxQueues)
		{
			packetArrLen = dev->receivePackets(packetArr, 32, rxQueueId);
			pcpp::multiPlatformSleep(1);
			if (packetArrLen > 0)
			{
				isPacketRecvd = true;
				break;
			}
			++rxQueueId;
		}
		if (isPacketRecvd)
			break;
		numOfAttempts++;
	}

	PTF_ASSERT_LOWER_THAN(numOfAttempts, 20, int);
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using packet arr", (int)packetArrLen, numOfAttempts);

	for (int i = 0; i < 32; i++)
	{
		if (packetArr[i] != NULL)
			delete packetArr[i];
	}

	// test worker threads
	// -------------------
	pthread_mutex_t queueMutexArr[numOfRxQueues];
	for (int i = 0; i < numOfRxQueues; i++)
		pthread_mutex_init(&queueMutexArr[i], NULL);

	std::vector<pcpp::DpdkWorkerThread*> workerThreadVec;
	pcpp::CoreMask workerThreadCoreMask = 0;
	for (int i = 0; i < pcpp::getNumOfCores(); i++)
	{
		pcpp::SystemCore core = pcpp::SystemCores::IdToSystemCore[i];
		if (core == pcpp::DpdkDeviceList::getInstance().getDpdkMasterCore())
			continue;
		DpdkTestWorkerThread* newWorkerThread = new DpdkTestWorkerThread();
		int queueId = core.Id % numOfRxQueues;
		PTF_PRINT_VERBOSE("Assigning queue #%d to core %d", queueId, core.Id);
		newWorkerThread->init(dev, queueId, &queueMutexArr[queueId]);
		workerThreadVec.push_back((pcpp::DpdkWorkerThread*)newWorkerThread);
		workerThreadCoreMask |= core.Mask;
	}
	PTF_PRINT_VERBOSE("Initiating %d worker threads", (int)workerThreadVec.size());

	pcpp::LoggerPP::getInstance().suppressErrors();
	// negative test - start worker thread with core mask 0
	PTF_ASSERT_FALSE(pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(0, workerThreadVec));
	pcpp::LoggerPP::getInstance().enableErrors();

	PTF_ASSERT_TRUE(pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workerThreadCoreMask, workerThreadVec));
	PTF_PRINT_VERBOSE("Worker threads started");

	pcpp::DpdkDevice::DpdkDeviceStats initStats;
	dev->getStatistics(initStats);
	uint64_t curPackets = initStats.aggregatedRxStats.packets;
	numOfAttempts = 0;
	while (numOfAttempts < 20)
	{
		pcpp::DpdkDevice::DpdkDeviceStats stats;
		dev->getStatistics(stats);
		PTF_PRINT_VERBOSE("Packets captured   : %lu", stats.aggregatedRxStats.packets);
		PTF_PRINT_VERBOSE("Bytes captured     : %lu", stats.aggregatedRxStats.bytes);
		PTF_PRINT_VERBOSE("Bits per second    : %lu", stats.aggregatedRxStats.bytesPerSec*8);
		PTF_PRINT_VERBOSE("Packets per second : %lu", stats.aggregatedRxStats.packetsPerSec);
		PTF_PRINT_VERBOSE("Packets dropped    : %lu", stats.rxPacketsDropeedByHW);
		PTF_PRINT_VERBOSE("Erroneous packets  : %lu", stats.rxErroneousPackets);
		for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
		{
			PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
			PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);

		}

		pcpp::multiPlatformSleep(1);

		if (stats.aggregatedRxStats.packets > curPackets)
			break;
		numOfAttempts++;
	}

	PTF_PRINT_VERBOSE("Worker threads stopping");
	pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
	PTF_PRINT_VERBOSE("Worker threads stopped");

	// we can't guarantee all threads receive packets, it depends on the NIC load balancing and the traffic. So we check that all threads were run and
	// that total amount of packets received by all threads is greater than zero

	int packetCount = 0;
	for (std::vector<pcpp::DpdkWorkerThread*>::iterator iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
	{
		DpdkTestWorkerThread* thread = (DpdkTestWorkerThread*)(*iter);
		PTF_ASSERT_TRUE(thread->threadRanAndStopped());
		packetCount += thread->getPacketCount();
		PTF_PRINT_VERBOSE("Worker thread on core %d captured %d packets", thread->getCoreId(), thread->getPacketCount());
		delete thread;
	}

	for (int i = 0; i < numOfRxQueues; i++)
		pthread_mutex_destroy(&queueMutexArr[i]);


	PTF_PRINT_VERBOSE("Total packet count for all worker threads: %d", packetCount);

	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);

	dev->close();

#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkDeviceWorkerThreads




PTF_TEST_CASE(TestDpdkMbufRawPacket)
{
#ifdef USE_DPDK
	PTF_ASSERT_GREATER_THAN(pcpp::DpdkDeviceList::getInstance().getDpdkDeviceList().size(), 0, size);

	pcpp::DpdkDevice* dev = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(PcapTestGlobalArgs.dpdkPort);
	PTF_ASSERT_NOT_NULL(dev);

	PTF_ASSERT_TRUE(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()));
	DeviceTeardown devTeardown(dev);


	// Test load from PCAP to MBufRawPacket
	// ------------------------------------
	pcpp::PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PTF_ASSERT_TRUE(reader.open());

	int tcpCount = 0;
	int udpCount = 0;
	int ip6Count = 0;
	int vlanCount = 0;
	int numOfPackets = 0;
	while (true)
	{
		pcpp::MBufRawPacket mBufRawPacket;
		PTF_ASSERT_TRUE(mBufRawPacket.init(dev));
		if (!(reader.getNextPacket(mBufRawPacket)))
			break;

		numOfPackets++;

		pcpp::Packet packet(&mBufRawPacket);
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ip6Count++;
		if (packet.isPacketOfType(pcpp::VLAN))
			vlanCount++;

		if (numOfPackets < 100)
		{
			PTF_ASSERT_TRUE(dev->sendPacket(packet, 0));
		}
	}

	PTF_ASSERT_EQUAL(numOfPackets, 4709, int);
	PTF_ASSERT_EQUAL(tcpCount, 4321, int);
	PTF_ASSERT_EQUAL(udpCount, 269, int);
	PTF_ASSERT_EQUAL(ip6Count, 16, int);
	PTF_ASSERT_EQUAL(vlanCount, 24, int);

	reader.close();

	// Test save MBufRawPacket to PCAP
	// -------------------------------
	pcpp::MBufRawPacketVector rawPacketVec;
	int numOfAttempts = 0;
	while (numOfAttempts < 30)
	{
		bool foundTcpOrUdpPacket = false;
		for (int i = 0; i < dev->getNumOfOpenedRxQueues(); i++)
		{
			dev->receivePackets(rawPacketVec, i);
			pcpp::multiPlatformSleep(1);
			for (pcpp::MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
			{
				pcpp::Packet packet(*iter);
				if ((packet.isPacketOfType(pcpp::TCP) || packet.isPacketOfType(pcpp::UDP)) && packet.isPacketOfType(pcpp::IPv4))
				{
					foundTcpOrUdpPacket = true;
					break;
				}
			}
		}

		if (foundTcpOrUdpPacket)
			break;

		numOfAttempts++;
	}

	PTF_ASSERT_LOWER_THAN(numOfAttempts, 30, int);
	PTF_PRINT_VERBOSE("Total sleep time: %d", numOfAttempts);

	pcpp::PcapFileWriterDevice writer(DPDK_PCAP_WRITE_PATH);
	PTF_ASSERT_TRUE(writer.open());
	for (pcpp::MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		PTF_ASSERT_TRUE(writer.writePacket(**iter));
	}
	writer.close();

	pcpp::PcapFileReaderDevice reader2(DPDK_PCAP_WRITE_PATH);
	PTF_ASSERT_TRUE(reader2.open());
	pcpp::RawPacket rawPacket;
	int readerPacketCount = 0;
	while (reader2.getNextPacket(rawPacket))
	{
		readerPacketCount++;
	}
	reader2.close();

	PTF_ASSERT_EQUAL(readerPacketCount, (int)rawPacketVec.size(), int);

	// Test packet manipulation
	// ------------------------

	pcpp::MBufRawPacket* rawPacketToManipulate = NULL;
	for (pcpp::MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if ((packet.isPacketOfType(pcpp::TCP) || packet.isPacketOfType(pcpp::UDP)) && packet.isPacketOfType(pcpp::IPv4))
		{
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			if (tcpLayer != NULL && tcpLayer->getNextLayer() != NULL)
			{
				rawPacketToManipulate = (pcpp::MBufRawPacket*)*iter;
				break;
			}

			pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
			if (udpLayer != NULL && udpLayer->getNextLayer() != NULL)
			{
				rawPacketToManipulate = (pcpp::MBufRawPacket*)*iter;
				break;
			}
		}
	}

	PTF_ASSERT_NOT_NULL(rawPacketToManipulate);
	int initialRawPacketLen = rawPacketToManipulate->getRawDataLen();
	pcpp::Packet packetToManipulate(rawPacketToManipulate);
	pcpp::IPv4Layer* ipLayer = packetToManipulate.getLayerOfType<pcpp::IPv4Layer>();
	
	// remove all layers above IP
	PTF_ASSERT_TRUE(packetToManipulate.removeAllLayersAfter(ipLayer));

	PTF_ASSERT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_LOWER_THAN(rawPacketToManipulate->getRawDataLen(), initialRawPacketLen, int);

	// create DNS packet out of this packet

	pcpp::UdpLayer udpLayer(2233, 53);
	PTF_ASSERT_TRUE(packetToManipulate.addLayer(&udpLayer));

	pcpp::DnsLayer dnsQueryLayer;
	dnsQueryLayer.getDnsHeader()->recursionDesired = true;
	dnsQueryLayer.getDnsHeader()->transactionID = htobe16(0xb179);
	pcpp::DnsQuery* newQuery = dnsQueryLayer.addQuery("no-name", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
	PTF_ASSERT_NOT_NULL(newQuery);

	packetToManipulate.addLayer(&dnsQueryLayer);

	// change the query name and transmit the generated packet
	for (int i = 0; i < 10; i++)
	{
		// generate random string with random length < 40
		int nameLength = rand()%60;
		char name[nameLength+1];
		for (int j = 0; j < nameLength; ++j)
		{
			int randomChar = rand()%(26+26+10);
			if (randomChar < 26)
				name[j] = 'a' + randomChar;
			else if (randomChar < 26+26)
				name[j] = 'A' + randomChar - 26;
			else
				name[j] = '0' + randomChar - 26 - 26;
		}
		name[nameLength] = 0;

		//set name for query
		newQuery->setName(std::string(name));
		packetToManipulate.computeCalculateFields();

		//transmit packet
		PTF_ASSERT_TRUE(dev->sendPacket(packetToManipulate, 0));
	}

	dev->close();

#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
} // TestDpdkMbufRawPacket
