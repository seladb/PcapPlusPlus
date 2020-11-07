#include "../TestDefinition.h"
#include "Logger.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PcapRemoteDevice.h"
#include "PcapRemoteDeviceList.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "../Common/PcapFileNamesDef.h"
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <windows.h>
#endif

extern PcapTestArgs PcapTestGlobalArgs;

static void packetArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* pDevice, void* userCookie)
{
	(*(int*)userCookie)++;
}

static void statsUpdate(pcpp::IPcapDevice::PcapStats& stats, void* userCookie)
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

static bool packetArrivesBlockingModeWithSnaplen(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie) 
{
	int snaplen = *(int*)userCookie;
	return rawPacket->getRawDataLen() > snaplen;
}

#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

class RpcapdServerInitializer
{
private:
	HANDLE m_ProcessHandle;

public:

	RpcapdServerInitializer(bool activateRemoteDevice, std::string ip, uint16_t port)
	{
		m_ProcessHandle = NULL;
		if (!activateRemoteDevice)
			return;

		char portAsString[10];
		sprintf(portAsString, "%d", port);
		std::string cmd = "rpcapd\\rpcapd.exe";
		std::string args = "rpcapd\\rpcapd.exe -b " + ip + " -p " + std::string(portAsString) + " -n";

		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi, sizeof(pi) );
		if (!CreateProcess
				(
				TEXT(cmd.c_str()),
				(char*)TEXT(args.c_str()),
				NULL,NULL,FALSE,
				CREATE_NEW_CONSOLE,
				NULL,NULL,
				&si,
				&pi
				)
				)
			{
				m_ProcessHandle = NULL;
			}

		m_ProcessHandle = pi.hProcess;
	}

	~RpcapdServerInitializer()
	{
		if (m_ProcessHandle != NULL)
		{
			TerminateProcess(m_ProcessHandle, 0);
		}
	}

	HANDLE getHandle() { return m_ProcessHandle; }
};

#endif // defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)





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
	DeviceTeardown devTeardown(liveDev);
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	int totalSleepTime = 0;
	while (totalSleepTime <= 20)
	{
		pcpp::multiPlatformSleep(2);
		totalSleepTime += 2;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);
	
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0, int);
	PTF_ASSERT_GREATER_THAN(numOfTimeStatsWereInvoked, totalSleepTime*0.8, int);
	pcpp::IPcapDevice::PcapStats statistics;
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
	DeviceTeardown devTeardown(liveDev);
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	sendURLRequest("www.ebay.com");
	int totalSleepTime = 0;
	while (totalSleepTime <= 6)
	{
		pcpp::multiPlatformSleep(2);
		totalSleepTime +=2;
		pcpp::IPcapDevice::PcapStats statistics;
		liveDev->getStatistics(statistics);
		if (statistics.packetsRecv > 2)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);
	
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime-1, int);
	pcpp::IPcapDevice::PcapStats statistics;
	liveDev->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN((uint32_t)statistics.packetsRecv, 2, u32);
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
	DeviceTeardown devTeardown(liveDev);

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
		pcpp::multiPlatformSleep(1);
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
		pcpp::multiPlatformSleep(1);
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
	DeviceTeardown devTeardown(liveDev);

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

	// create a non-default configuration with a snapshot length of 10 bytes
	int snaplen = 20;
	pcpp::PcapLiveDevice::DeviceConfiguration devConfigWithSnaplen(pcpp::PcapLiveDevice::Promiscuous, 0, 0, pcpp::PcapLiveDevice::PCPP_INOUT, snaplen);

	liveDev->open(devConfigWithSnaplen);

	// start capturing in non-default configuration witch only captures incoming traffics
	// TODO: for some reason snaplen change doesn't work in Windows (WinPcap and Npcap). Setting the check as NON_CRITICAL until we figure it out
	PTF_NON_CRITICAL_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeWithSnaplen, &snaplen, 3), -1, int);

	liveDev->close();

} // TestPcapLiveDeviceSpecialCfg



PTF_TEST_CASE(TestWinPcapLiveDevice)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	pcpp::PcapLiveDevice* liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::WinPcapDevice, enum);

	pcpp::WinPcapLiveDevice* winPcapLiveDevice = static_cast<pcpp::WinPcapLiveDevice*>(liveDev);
	int defaultDataToCopy = winPcapLiveDevice->getMinAmountOfDataToCopyFromKernelToApplication();
	PTF_ASSERT_EQUAL(defaultDataToCopy, 16000, int);
	PTF_ASSERT_TRUE(winPcapLiveDevice->open());
	DeviceTeardown devTeardown(winPcapLiveDevice);
	PTF_ASSERT_TRUE(winPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(100000));
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(winPcapLiveDevice->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked));
	for (int i = 0; i < 5; i++)
	{
		sendURLRequest("www.ebay.com");
	}

	pcpp::IPcapDevice::PcapStats statistics;
	winPcapLiveDevice->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN(statistics.packetsRecv, 20, int);
	PTF_ASSERT_EQUAL((uint32_t)statistics.packetsDrop, 0, int);
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
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::LibPcapDevice, enum);
#endif

} // TestWinPcapLiveDevice



PTF_TEST_CASE(TestSendPacket)
{
	pcpp::PcapLiveDevice* liveDev = NULL;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0, u32);
	uint32_t mtu = liveDev->getMtu();
	int buffLen = mtu+1;
	uint8_t* buff = new uint8_t[buffLen];
	memset(buff, 0, buffLen);
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(liveDev->sendPacket(buff, buffLen));
	pcpp::LoggerPP::getInstance().enableErrors();

	pcpp::RawPacket rawPacket;
	int packetsSent = 0;
	int packetsRead = 0;
	while(fileReaderDev.getNextPacket(rawPacket))
	{
		packetsRead++;

		//send packet as RawPacket
		PTF_ASSERT_TRUE(liveDev->sendPacket(rawPacket));

		//send packet as raw data
		PTF_ASSERT_TRUE(liveDev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()));

		//send packet as parsed EthPacekt
		pcpp::Packet packet(&rawPacket);
		PTF_ASSERT_TRUE(liveDev->sendPacket(&packet));

		packetsSent++;
	}

	PTF_ASSERT_EQUAL(packetsRead, packetsSent, int);

	liveDev->close();
	fileReaderDev.close();

	delete[] buff;
} // TestSendPacket




PTF_TEST_CASE(TestSendPackets)
{
	pcpp::PcapLiveDevice* liveDev = NULL;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	pcpp::RawPacket rawPacketArr[10000];
	pcpp::PointerVector<pcpp::Packet> packetVec;
	pcpp::Packet* packetArr[10000];
	int packetsRead = 0;
	while(fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
	{
		packetVec.pushBack(new pcpp::Packet(&rawPacketArr[packetsRead]));
		packetsRead++;
	}

	//send packets as RawPacket array
	int packetsSentAsRaw = liveDev->sendPackets(rawPacketArr, packetsRead);

	//send packets as parsed EthPacekt array
	std::copy(packetVec.begin(), packetVec.end(), packetArr);
	int packetsSentAsParsed = liveDev->sendPackets(packetArr, packetsRead);

	PTF_ASSERT_EQUAL(packetsSentAsRaw, packetsRead, int);
	PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead, int);

	liveDev->close();
	fileReaderDev.close();
} // TestSendPackets




PTF_TEST_CASE(TestRemoteCapture)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	bool useRemoteDevicesFromArgs = (PcapTestGlobalArgs.remoteIp != "") && (PcapTestGlobalArgs.remotePort > 0);
	std::string remoteDeviceIP = (useRemoteDevicesFromArgs ? PcapTestGlobalArgs.remoteIp : PcapTestGlobalArgs.ipToSendReceivePackets);
	uint16_t remoteDevicePort = (useRemoteDevicesFromArgs ? PcapTestGlobalArgs.remotePort : 12321);

	RpcapdServerInitializer rpcapdInitializer(!useRemoteDevicesFromArgs, remoteDeviceIP, remoteDevicePort);

	PTF_ASSERT_NOT_NULL(rpcapdInitializer.getHandle());

	pcpp::IPv4Address remoteDeviceIPAddr(remoteDeviceIP);
	pcpp::PcapRemoteDeviceList* remoteDevices = pcpp::PcapRemoteDeviceList::getRemoteDeviceList(remoteDeviceIPAddr, remoteDevicePort);
	PTF_ASSERT_NOT_NULL(remoteDevices);
	for (pcpp::PcapRemoteDeviceList::RemoteDeviceListIterator remoteDevIter = remoteDevices->begin(); remoteDevIter != remoteDevices->end(); remoteDevIter++)
	{
		PTF_ASSERT_NOT_NULL((*remoteDevIter)->getName());
	}
	PTF_ASSERT_EQUAL(remoteDevices->getRemoteMachineIpAddress().toString(), remoteDeviceIP, string);
	PTF_ASSERT_EQUAL(remoteDevices->getRemoteMachinePort(), remoteDevicePort, u16);

	pcpp::PcapRemoteDevice* remoteDevice = remoteDevices->getRemoteDeviceByIP(remoteDeviceIPAddr);
	PTF_ASSERT_EQUAL(remoteDevice->getDeviceType(), pcpp::PcapLiveDevice::RemoteDevice, enum);
	PTF_ASSERT_EQUAL(remoteDevice->getMtu(), 0, u32);
	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_EQUAL(remoteDevice->getMacAddress(), pcpp::MacAddress::Zero, object);
	pcpp::LoggerPP::getInstance().enableErrors();
	PTF_ASSERT_TRUE(remoteDevice->open());
	DeviceTeardown devTeardown(remoteDevice);
	pcpp::RawPacketVector capturedPackets;
	PTF_ASSERT_TRUE(remoteDevice->startCapture(capturedPackets));

	if (!useRemoteDevicesFromArgs)
		PTF_ASSERT_TRUE(sendURLRequest("www.yahoo.com"));

	int totalSleepTime = 0;
	while (totalSleepTime < 10)
	{
		if (capturedPackets.size() > 2)
		{
			break;
		}

		pcpp::multiPlatformSleep(1);
		totalSleepTime += 1;
	}

	remoteDevice->stopCapture();

	PTF_PRINT_VERBOSE("Total sleep time: %d secs", totalSleepTime);

	PTF_ASSERT_GREATER_THAN(capturedPackets.size(), 2, size);

	// send single packet
	PTF_ASSERT_TRUE(remoteDevice->sendPacket(*capturedPackets.front()));

	// send multiple packets
	pcpp::RawPacketVector packetsToSend;
	std::vector<pcpp::RawPacket*>::iterator iter = capturedPackets.begin();

	size_t capturedPacketsSize = capturedPackets.size();
	while (iter != capturedPackets.end())
	{
		if ((*iter)->getRawDataLen() <= (int)remoteDevice->getMtu())
		{
			packetsToSend.pushBack(capturedPackets.getAndRemoveFromVector(iter));
		}
		else
			++iter;
	}
	int packetsSent = remoteDevice->sendPackets(packetsToSend);
	PTF_ASSERT_EQUAL(packetsSent, (int)packetsToSend.size(), int);

	//check statistics
	pcpp::IPcapDevice::PcapStats stats;
	remoteDevice->getStatistics(stats);
	PTF_ASSERT_EQUAL((uint32_t)stats.packetsRecv, capturedPacketsSize, u32);

	remoteDevice->close();

	delete remoteDevices;

	// the device object is already deleted, cannot close it
	devTeardown.cancelTeardown();
#endif

} // TestRemoteCapture
