#include "../TestDefinition.h"
#include "Logger.h"
#include "PcapLiveDeviceList.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "PlatformSpecificUtils.h"


extern PcapTestArgs PcapTestGlobalArgs;

static void packetArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* pDevice, void* userCookie)
{
	(*(int*)userCookie)++;
}

static void statsUpdate(pcap_stat& stats, void* userCookie)
{
	(*(int*)userCookie)++;
}

static bool packetArrivesBlockingModeTimeout(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	return false;
}

static bool packetArrivesBlockingModeNoTimeout(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeStartCapture(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	pcpp::LoggerPP::getInstance().supressErrors();
	if (dev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5) != 0)
		return false;

	int temp = 0;
	if (dev->startCapture(packetArrives, &temp) != 0)
		return false;

	pcpp::LoggerPP::getInstance().enableErrors();

	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeStopCapture(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	// shouldn't do anything
	dev->stopCapture();

	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeNoTimeoutPacketCount(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	int* packetCount = (int*)userCookie;
	(*packetCount)++;
	return false;
}





PTF_TEST_CASE(TestPcapLiveDeviceList)
{
	std::vector<pcpp::PcapLiveDevice*> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	pcpp::IPv4Address defaultGateway = pcpp::IPv4Address::Zero;
	for(std::vector<pcpp::PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		PTF_ASSERT_NOT_NULL((*iter)->getName());
		if (defaultGateway == pcpp::IPv4Address::Zero)
			defaultGateway = (*iter)->getDefaultGateway();
	}

	PTF_ASSERT_NOT_EQUAL(defaultGateway, pcpp::IPv4Address::Zero, object);

	std::vector<pcpp::IPv4Address> dnsServers = pcpp::PcapLiveDeviceList::getInstance().getDnsServers();
	size_t dnsServerCount = dnsServers.size();

	// reset the device list and make sure devices are back and there is no memory leak
	pcpp::PcapLiveDeviceList::getInstance().reset();

	devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	for(std::vector<pcpp::PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		PTF_ASSERT_NOT_NULL((*iter)->getName());
	}

	PTF_ASSERT_EQUAL(pcpp::PcapLiveDeviceList::getInstance().getDnsServers().size(), dnsServerCount, size);
} // TestPcapLiveDeviceList



PTF_TEST_CASE(TestPcapLiveDeviceListSearch)
{
	pcpp::PcapLiveDevice* liveDev = NULL;
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);

	std::string devName(liveDev->getName());
	pcpp::PcapLiveDevice* liveDev2 = NULL;
	liveDev2 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(devName);
	PTF_ASSERT_NOT_NULL(liveDev2);
	PTF_ASSERT_EQUAL(strcmp(liveDev->getName(), liveDev2->getName()), 0, int);

	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("255.255.255.250");
	PTF_ASSERT_NULL(liveDev);
} // TestPcapLiveDeviceListSearch



PTF_TEST_CASE(TestPcapLiveDevice)
{
	pcpp::PcapLiveDevice* liveDev = NULL;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0, u32);
	PTF_ASSERT_TRUE(liveDev->open());
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	int totalSleepTime = 0;
	while (totalSleepTime <= 20)
	{
		PCAP_SLEEP(2);
		totalSleepTime += 2;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);
	
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);
	PTF_ASSERT_GREATER_THAN(numOfTimeStatsWereInvoked, totalSleepTime*0.8, int);
	pcap_stat statistics;
	liveDev->getStatistics(statistics);
	//Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	//PTF_ASSERT_EQUALS((uint32_t)statistics.ps_drop, 0, u32);
	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(liveDev->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	pcpp::LoggerPP::getInstance().enableErrors();
} // TestPcapLiveDevice



PTF_TEST_CASE(TestPcapLiveDeviceNoNetworking)
{
	PTF_ASSERT_NOT_EQUAL(pcpp::IPcapDevice::getPcapLibVersionInfo(), "", string);

	pcpp::PcapLiveDevice* liveDev = NULL;

	std::vector<pcpp::PcapLiveDevice*> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	for(std::vector<pcpp::PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		if (!(*iter)->getLoopback() && (*iter)->getIPv4Address() != pcpp::IPv4Address::Zero)
		{
			liveDev = *iter;
			break;
		}
	}

	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_NOT_NULL(liveDev->getName());
	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0, u32);
	PTF_ASSERT_NOT_EQUAL(liveDev->getMacAddress(), pcpp::MacAddress::Zero, object);

	// a negative test - check invalid IP address
	liveDev = NULL;
	pcpp::LoggerPP::getInstance().supressErrors();
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("eth0");
	pcpp::LoggerPP::getInstance().enableErrors();
	PTF_ASSERT_NULL(liveDev);

} // TestPcapLiveDeviceNoNetworking



PTF_TEST_CASE(TestPcapLiveDeviceStatsMode)
{
	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	sendURLRequest("www.ebay.com");
	int totalSleepTime = 0;
	while (totalSleepTime <= 6)
	{
		PCAP_SLEEP(2);
		totalSleepTime +=2;
		pcap_stat statistics;
		liveDev->getStatistics(statistics);
		if (statistics.ps_recv > 2)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);
	
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime-1, int);
	pcap_stat statistics;
	liveDev->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN((uint32_t)statistics.ps_recv, 2, u32);
	//Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	//PTF_ASSERT_EQUAL((uint32_t)statistics.ps_drop, 0, u32);
	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(liveDev->startCapture(1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	pcpp::LoggerPP::getInstance().enableErrors();
} // TestPcapLiveDeviceStatsMode



PTF_TEST_CASE(TestPcapLiveDeviceBlockingMode)
{
	// open device
	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());

	// sanity - test blocking mode returns with timeout
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5), -1, int);

	// sanity - test blocking mode returns before timeout
	int packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1, int);
	PTF_ASSERT_EQUAL(packetCount, 5, int);

	// verify stop capture doesn't do any effect on blocking mode
	liveDev->stopCapture();
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1), -1, int);
	packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1, int);
	PTF_ASSERT_EQUAL(packetCount, 5, int);

	// verify it's possible to capture non-blocking mode after blocking mode
	packetCount = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(packetArrives, &packetCount));

	int totalSleepTime = 0;
	while (totalSleepTime <= 5)
	{
		PCAP_SLEEP(1);
		totalSleepTime += 1;
		if (packetCount > 0)
			break;
	}

	liveDev->stopCapture();

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);

	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);

	// verify it's possible to capture blocking mode after non-blocking mode
	packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1, int);
	PTF_ASSERT_EQUAL(packetCount, 5, int);

	// try to start capture from within the callback, verify no error
	packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStartCapture, &packetCount, 30), 1, int);
	PTF_ASSERT_EQUAL(packetCount, 5, int);

	// try to stop capture from within the callback, verify no impact on capturing
	packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStopCapture, &packetCount, 10), 1, int);
	PTF_ASSERT_EQUAL(packetCount, 5, int);

	// verify it's possible to capture non-blocking after the mess done in previous lines
	packetCount = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(packetArrives, &packetCount));

	// verify an error returns if trying capture blocking while non-blocking is running
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1), 0, int);
	pcpp::LoggerPP::getInstance().enableErrors();

	totalSleepTime = 0;
	while (totalSleepTime <= 5)
	{
		PCAP_SLEEP(1);
		totalSleepTime += 1;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);

	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(liveDev->startCapture(packetArrives, &packetCount));
	pcpp::LoggerPP::getInstance().enableErrors();
} // TestPcapLiveDeviceBlockingMode




PTF_TEST_CASE(TestPcapLiveDeviceSpecialCfg)
{
	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);

	// open device in default mode
	PTF_ASSERT_TRUE(liveDev->open());

	// sanity test - make sure packets are captured in default mode
	int packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7), -1, int);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);

	packetCount = 0;

	// create a non-default configuration with timeout of 10ms and open the device again
	pcpp::PcapLiveDevice::DeviceConfiguration devConfig(pcpp::PcapLiveDevice::Promiscuous, 10, 2000000);
	liveDev->open(devConfig);
	PTF_ASSERT_TRUE(liveDev->isOpened());

	// start capturing in non-default configuration
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7), -1, int);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);

#ifdef HAS_SET_DIRECTION_ENABLED
	// create a non-default configuration with only cpturing incoming packets and open the device again
	pcpp::PcapLiveDevice::DeviceConfiguration devConfigWithDirection(pcpp::PcapLiveDevice::Promiscuous, 10, 2000000, pcpp::PcapLiveDevice::PCPP_IN);
    	
	liveDev->open(devConfigWithDirection);
		
	packetCount = 0;

	// start capturing in non-default configuration witch only captures incoming traffics
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7), -1, int);

	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);
	liveDev->close();
#endif 

} // TestPcapLiveDeviceSpecialCfg



PTF_TEST_CASE(TestWinPcapLiveDevice)
{
#ifdef WIN32

	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::WinPcapDevice, enum);

	pcpp::WinPcapLiveDevice* winPcapLiveDevice = static_cast<pcpp::WinPcapLiveDevice*>(liveDev);
	int defaultDataToCopy = winPcapLiveDevice->getMinAmountOfDataToCopyFromKernelToApplication();
	PTF_ASSERT_EQUAL(defaultDataToCopy, 16000, int);
	PTF_ASSERT_TRUE(winPcapLiveDevice->open());
	PTF_ASSERT_TRUE(winPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(100000));
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(winPcapLiveDevice->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	for (int i = 0; i < 5; i++)
	{
		sendURLRequest("www.ebay.com");
	}

	pcap_stat statistics;
	winPcapLiveDevice->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN(statistics.ps_recv, 20, int);
	PTF_ASSERT_EQUAL((uint32_t)statistics.ps_drop, 0, int);
	winPcapLiveDevice->stopCapture();
	PTF_ASSERT_TRUE(winPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(defaultDataToCopy));
	winPcapLiveDevice->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(winPcapLiveDevice->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	pcpp::LoggerPP::getInstance().enableErrors();

#else
	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::LibPcapDevice, enum);
#endif

} // TestWinPcapLiveDevice