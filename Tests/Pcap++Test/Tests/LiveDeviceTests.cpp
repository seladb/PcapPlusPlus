#include "../TestDefinition.h"
#include "Logger.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "../Common/PcapFileNamesDef.h"
#include <array>
#include <vector>
#include <iterator>
#include <algorithm>
#include <cstdio>
#if defined(_WIN32)
#	include "PcapRemoteDevice.h"
#	include "PcapRemoteDeviceList.h"
#	include "WinPcapLiveDevice.h"
#	include <windows.h>
#endif

extern PcapTestArgs PcapTestGlobalArgs;

static void packetArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* pDevice, void* userCookie)
{
	(*static_cast<int*>(userCookie))++;
}

static void statsUpdate(pcpp::IPcapDevice::PcapStats& stats, void* userCookie)
{
	(*static_cast<int*>(userCookie))++;
}

static bool packetArrivesBlockingModeTimeout(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	return false;
}

static bool packetArrivesBlockingModeNoTimeout(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userCookie)
{
	int* packetCount = static_cast<int*>(userCookie);
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeStartCapture(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev,
                                                  void* userCookie)
{
	pcpp::Logger::getInstance().suppressLogs();
	if (dev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, nullptr, 5) != 0)
		return false;

	int temp = 0;
	if (dev->startCapture(packetArrives, &temp) != 0)
		return false;

	pcpp::Logger::getInstance().enableLogs();

	int* packetCount = static_cast<int*>(userCookie);
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeStopCapture(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev,
                                                 void* userCookie)
{
	// shouldn't do anything
	dev->stopCapture();

	int* packetCount = static_cast<int*>(userCookie);
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeNoTimeoutPacketCount(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev,
                                                          void* userCookie)
{
	int* packetCount = static_cast<int*>(userCookie);
	(*packetCount)++;
	return false;
}

static bool packetArrivesBlockingModeWithSnaplen(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev,
                                                 void* userCookie)
{
	int snaplen = *static_cast<int*>(userCookie);
	return rawPacket->getRawDataLen() > snaplen;
}

#if defined(_WIN32)

class RpcapdServerInitializer
{
private:
	HANDLE m_ProcessHandle;
	HANDLE m_JobHandle;

	void killProcessAndCloseHandles()
	{
		if (m_ProcessHandle != nullptr)
		{
			TerminateProcess(m_ProcessHandle, 0);
			CloseHandle(m_ProcessHandle);
			m_ProcessHandle = nullptr;
		}

		if (m_JobHandle != nullptr)
		{
			CloseHandle(m_JobHandle);
			m_JobHandle = nullptr;
		}
	}

public:
	RpcapdServerInitializer(bool activateRemoteDevice, const std::string& ip, uint16_t port)
	    : m_ProcessHandle(nullptr), m_JobHandle(nullptr)
	{
		if (!activateRemoteDevice)
			return;

		std::string cmd = "rpcapd\\rpcapd.exe";
		std::array<char, 256> args;
		int res = std::snprintf(args.data(), args.size(), "%s -b %s -p %d -n", cmd.c_str(), ip.c_str(), port);
		if (res < 0)
		{
			throw std::runtime_error("Error during string formatting");
		}
		else if (res >= args.size())
		{
			// We should never get here with reasonable input but you never know.
			throw std::runtime_error("Buffer overflow. Are you sure the IP is a valid string?");
		}

		m_JobHandle = CreateJobObject(nullptr, nullptr);
		if (m_JobHandle == nullptr)
		{
			throw std::runtime_error("Failed to create a job object with error code: " +
			                         std::to_string(GetLastError()));
		}

		// Sets up the job limits so closing the job will automatically kill all processes assigned to the job.
		// This will prevent the subprocess continuing to live if the current process is killed without unwinding the
		// stack (i.e. std::terminate is called), as the OS itself will kill the subprocesses when the last job handle
		// is closed.
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimitInfo{};
		jobLimitInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(m_JobHandle, JobObjectExtendedLimitInformation, &jobLimitInfo,
		                             sizeof(jobLimitInfo)))
		{
			DWORD errCode = GetLastError();
			CloseHandle(m_JobHandle);
			throw std::runtime_error("Failed to set settings to job object with error code: " +
			                         std::to_string(errCode));
		}

		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcess(
		        TEXT(cmd.c_str()),
		        // CreateProcessW (Unicode version) modifies the argument string inplace during internal processing.
		        TEXT(args.data()), nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi))
		{
			DWORD errCode = GetLastError();
			CloseHandle(m_JobHandle);
			throw std::runtime_error("Create process failed with error code: " + std::to_string(errCode));
		}

		m_ProcessHandle = pi.hProcess;
		CloseHandle(pi.hThread);  // We don't need the thread handle, so we can close it.

		if (!AssignProcessToJobObject(m_JobHandle, m_ProcessHandle))
		{
			DWORD errCode = GetLastError();
			killProcessAndCloseHandles();
			throw std::runtime_error("Failed assigning process to job object with code: " + std::to_string(errCode));
		}
	}

	RpcapdServerInitializer(const RpcapdServerInitializer&) = delete;
	RpcapdServerInitializer(RpcapdServerInitializer&& other) noexcept
	    : m_ProcessHandle(other.m_ProcessHandle), m_JobHandle(other.m_JobHandle)
	{
		other.m_ProcessHandle = nullptr;
		other.m_JobHandle = nullptr;
	}
	RpcapdServerInitializer& operator=(const RpcapdServerInitializer&) = delete;
	RpcapdServerInitializer& operator=(RpcapdServerInitializer&& other) noexcept
	{
		killProcessAndCloseHandles();
		m_ProcessHandle = other.m_ProcessHandle;
		m_JobHandle = other.m_JobHandle;
		other.m_ProcessHandle = nullptr;
		other.m_JobHandle = nullptr;
		return *this;
	}

	~RpcapdServerInitializer()
	{
		killProcessAndCloseHandles();
	}

	HANDLE getHandle() const
	{
		return m_ProcessHandle;
	}
};

#endif  // defined(_WIN32)

PTF_TEST_CASE(TestPcapLiveDeviceList)
{
	std::vector<pcpp::PcapLiveDevice*> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	pcpp::IPv4Address defaultGateway = pcpp::IPv4Address::Zero;
	for (const auto& iter : devList)
	{
		PTF_ASSERT_FALSE(iter->getName().empty());
		if (defaultGateway == pcpp::IPv4Address::Zero)
			defaultGateway = iter->getDefaultGateway();
	}

	PTF_ASSERT_NOT_EQUAL(defaultGateway, pcpp::IPv4Address::Zero);

	std::vector<pcpp::IPv4Address> dnsServers = pcpp::PcapLiveDeviceList::getInstance().getDnsServers();
	size_t dnsServerCount = dnsServers.size();

	// reset the device list and make sure devices are back and there is no memory leak
	pcpp::PcapLiveDeviceList::getInstance().reset();

	devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	for (const auto& iter : devList)
	{
		PTF_ASSERT_FALSE(iter->getName().empty());
	}

	pcpp::PcapLiveDeviceList* clonedDevList = pcpp::PcapLiveDeviceList::getInstance().clone();
	PTF_ASSERT_NOT_NULL(clonedDevList);

	std::vector<pcpp::PcapLiveDevice*> clonedDevListVector = clonedDevList->getPcapLiveDevicesList();
	PTF_ASSERT_EQUAL(clonedDevListVector.size(), devList.size());

	auto iterCloned = clonedDevListVector.begin();
	for (auto iter = devList.begin(); iter != devList.end(); ++iter, ++iterCloned)
	{
		PTF_ASSERT_EQUAL((*iter)->getName(), (*iterCloned)->getName());
	}
	delete clonedDevList;

	PTF_ASSERT_EQUAL(pcpp::PcapLiveDeviceList::getInstance().getDnsServers().size(), dnsServerCount);
}  // TestPcapLiveDeviceList

PTF_TEST_CASE(TestPcapLiveDeviceListSearch)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);

	std::string devName(liveDev->getName());
	pcpp::PcapLiveDevice* liveDev2 = nullptr;
	liveDev2 = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(devName);
	PTF_ASSERT_NOT_NULL(liveDev2);
	PTF_ASSERT_EQUAL(liveDev->getName(), liveDev2->getName());

	pcpp::PcapLiveDevice* liveDev3 = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(devName);
	PTF_ASSERT_EQUAL(liveDev3, liveDev2, ptr);
	liveDev3 = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(PcapTestGlobalArgs.ipToSendReceivePackets);
	PTF_ASSERT_EQUAL(liveDev3, liveDev, ptr);

	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp("255.255.255.250");
	PTF_ASSERT_NULL(liveDev);
}  // TestPcapLiveDeviceListSearch

PTF_TEST_CASE(TestPcapLiveDevice)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0);
	PTF_ASSERT_TRUE(liveDev->open());

	PTF_ASSERT_EQUAL(liveDev->getIPv4Address(), ipToSearch);
	{
		// Should probably be refactored as PTF_ASSERT_CONTAINS or similar.
		auto const ipAddresses = liveDev->getIPAddresses();
		PTF_ASSERT_TRUE(std::any_of(ipAddresses.begin(), ipAddresses.end(),
		                            [ipToSearch](pcpp::IPAddress const& addr) { return addr == ipToSearch; }));
	}

	DeviceTeardown devTeardown(liveDev);
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                      static_cast<void*>(&numOfTimeStatsWereInvoked)));
	int totalSleepTime = 0;
	while (totalSleepTime <= 20)
	{
		std::this_thread::sleep_for(std::chrono::seconds(2));
		totalSleepTime += 2;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0);
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime - 2);

	pcpp::IPcapDevice::PcapStats statistics;
	liveDev->getStatistics(statistics);
	// Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	// PTF_ASSERT_EQUALS((uint32_t)statistics.ps_drop, 0);
	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                       static_cast<void*>(&numOfTimeStatsWereInvoked)));
	pcpp::Logger::getInstance().enableLogs();
}  // TestPcapLiveDevice

PTF_TEST_CASE(TestPcapLiveDeviceClone)
{
	// Test of clone device should be same with original
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());

	{
		pcpp::PcapLiveDevice* originalDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
		PTF_ASSERT_NOT_NULL(originalDev);

#ifdef _WIN32
		// Tests if device pointer points to a Windows Live Device on a Windows machine.
		PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::WinPcapLiveDevice*>(originalDev));
#endif  // _WIN32

		liveDev = originalDev->clone();
	}

	PTF_ASSERT_NOT_NULL(liveDev);

#ifdef _WIN32
	// Tests if the clone is correctly returns a Windows Live Device on Windows systems.
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::WinPcapLiveDevice*>(liveDev));
#endif  // _WIN32

	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev, true);
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                      static_cast<void*>(&numOfTimeStatsWereInvoked)));
	int totalSleepTime = 0;
	while (totalSleepTime <= 20)
	{
		std::this_thread::sleep_for(std::chrono::seconds(2));
		totalSleepTime += 2;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0);
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime - 1);
	pcpp::IPcapDevice::PcapStats statistics;
	liveDev->getStatistics(statistics);
	// Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	// PTF_ASSERT_EQUALS((uint32_t)statistics.ps_drop, 0);
	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                       static_cast<void*>(&numOfTimeStatsWereInvoked)));
	pcpp::Logger::getInstance().enableLogs();

}  // TestPcapLiveDeviceClone

PTF_TEST_CASE(TestPcapLiveDeviceNoNetworking)
{
	PTF_ASSERT_NOT_EQUAL(pcpp::IPcapDevice::getPcapLibVersionInfo(), "");

	pcpp::PcapLiveDevice* liveDev = nullptr;

	std::vector<pcpp::PcapLiveDevice*> devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT_FALSE(devList.empty());

	auto iter = std::find_if(devList.begin(), devList.end(), [](const pcpp::PcapLiveDevice* dev) {
		return !dev->getLoopback() && dev->getIPv4Address() != pcpp::IPv4Address::Zero;
	});
	if (iter != devList.end())
	{
		liveDev = *iter;
	}

	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_FALSE(liveDev->getName().empty());
	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0);
	PTF_ASSERT_NOT_EQUAL(liveDev->getMacAddress(), pcpp::MacAddress::Zero);

	// a negative test - check invalid IP address
	liveDev = nullptr;
	pcpp::Logger::getInstance().suppressLogs();
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp("eth0");
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_NULL(liveDev);

}  // TestPcapLiveDeviceNoNetworking

PTF_TEST_CASE(TestPcapLiveDeviceStatsMode)
{
	pcpp::PcapLiveDevice* liveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(liveDev->startCapture(1, &statsUpdate, static_cast<void*>(&numOfTimeStatsWereInvoked)));
	sendURLRequest("www.ebay.com");
	int totalSleepTime = 0;
	while (totalSleepTime <= 6)
	{
		std::this_thread::sleep_for(std::chrono::seconds(2));
		totalSleepTime += 2;
		pcpp::IPcapDevice::PcapStats statistics;
		liveDev->getStatistics(statistics);
		if (statistics.packetsRecv > 2)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime - 1);
	pcpp::IPcapDevice::PcapStats statistics;
	liveDev->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN((uint32_t)statistics.packetsRecv, 2);
	// Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	// PTF_ASSERT_EQUAL((uint32_t)statistics.ps_drop, 0);
	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->startCapture(1, &statsUpdate, static_cast<void*>(&numOfTimeStatsWereInvoked)));
	pcpp::Logger::getInstance().enableLogs();
}  // TestPcapLiveDeviceStatsMode

PTF_TEST_CASE(TestPcapLiveDeviceBlockingMode)
{
	std::vector<pcpp::PcapLiveDevice::DeviceConfiguration> configs;
	configs.emplace_back();  // the default config

#if !defined(_WIN32)
	configs.emplace_back();  // the config used poll
	configs[1].usePoll = true;
#endif

	// test the common behaviour for all configs
	for (const auto& config : configs)
	{
		// open device
		pcpp::PcapLiveDevice* liveDev =
		    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
		PTF_ASSERT_NOT_NULL(liveDev);
		PTF_ASSERT_TRUE(liveDev->open(config));
		DeviceTeardown devTeardown(liveDev);

		// sanity - test blocking mode returns with timeout
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, nullptr, 5), -1);

		// sanity - test blocking mode returns before timeout
		int packetCount = 0;
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1);
		PTF_ASSERT_EQUAL(packetCount, 5);

		// verify stop capture doesn't do any effect on blocking mode
		liveDev->stopCapture();
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, nullptr, 1), -1);
		packetCount = 0;
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1);
		PTF_ASSERT_EQUAL(packetCount, 5);

		// verify it's possible to capture non-blocking mode after blocking mode
		packetCount = 0;
		PTF_ASSERT_TRUE(liveDev->startCapture(packetArrives, &packetCount));

		int totalSleepTime = 0;
		while (totalSleepTime <= 5)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			totalSleepTime += 1;
			if (packetCount > 0)
				break;
		}

		liveDev->stopCapture();

		PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

		PTF_ASSERT_GREATER_THAN(packetCount, 0);

		// verify it's possible to capture blocking mode after non-blocking mode
		packetCount = 0;
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30), 1);
		PTF_ASSERT_EQUAL(packetCount, 5);

		// try to start capture from within the callback, verify no error
		packetCount = 0;
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStartCapture, &packetCount, 30), 1);
		PTF_ASSERT_EQUAL(packetCount, 5);

		// try to stop capture from within the callback, verify no impact on capturing
		packetCount = 0;
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStopCapture, &packetCount, 10), 1);
		PTF_ASSERT_EQUAL(packetCount, 5);

		// verify it's possible to capture non-blocking after the mess done in previous lines
		packetCount = 0;
		PTF_ASSERT_TRUE(liveDev->startCapture(packetArrives, &packetCount));

		// verify an error returns if trying capture blocking while non-blocking is running
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, nullptr, 1), 0);
		pcpp::Logger::getInstance().enableLogs();

		totalSleepTime = 0;
		while (totalSleepTime <= 5)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			totalSleepTime += 1;
			if (packetCount > 0)
				break;
		}

		PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

		liveDev->stopCapture();
		PTF_ASSERT_GREATER_THAN(packetCount, 0);

		liveDev->close();

		// a negative test
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_FALSE(liveDev->startCapture(packetArrives, &packetCount));
		pcpp::Logger::getInstance().enableLogs();
	}
}  // TestPcapLiveDeviceBlockingMode

PTF_TEST_CASE(TestPcapLiveDeviceWithLambda)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;

	auto packetArrivesLambda = [](pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* pDevice, void* userCookie) {
		(*static_cast<int*>(userCookie))++;
	};

	auto statsUpdateLambda = [](pcpp::IPcapDevice::PcapStats& stats, void* userCookie) {
		(*static_cast<int*>(userCookie))++;
	};

	PTF_ASSERT_TRUE(liveDev->startCapture(packetArrivesLambda, static_cast<void*>(&packetCount), 1, statsUpdateLambda,
	                                      static_cast<void*>(&numOfTimeStatsWereInvoked)));
	int totalSleepTime = 0;
	while (totalSleepTime <= 20)
	{
		std::this_thread::sleep_for(std::chrono::seconds(2));
		totalSleepTime += 2;
		if (packetCount > 0)
			break;
	}

	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

	liveDev->stopCapture();
	PTF_ASSERT_GREATER_THAN(packetCount, 0);
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(numOfTimeStatsWereInvoked, totalSleepTime - 2);
}  // TestPcapLiveDeviceWithLambda

PTF_TEST_CASE(TestPcapLiveDeviceBlockingModeWithLambda)
{
	auto packetArrivesBlockingModeNoTimeoutLambda = [](pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev,
	                                                   void* userCookie) {
		int* packetCount = static_cast<int*>(userCookie);
		if ((*packetCount) == 5)
			return true;

		(*packetCount)++;
		return false;
	};

	// open device
	pcpp::PcapLiveDevice* liveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	int packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutLambda, &packetCount, 30), 1);
	PTF_ASSERT_EQUAL(packetCount, 5);

	liveDev->close();

	// a negative test
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->startCapture(packetArrives, &packetCount));
	pcpp::Logger::getInstance().enableLogs();
}  // TestPcapLiveDeviceBlockingModeWithLambda

PTF_TEST_CASE(TestPcapLiveDeviceSpecialCfg)
{
	pcpp::PcapLiveDevice* liveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);

	// open device in default mode
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	// sanity test - make sure packets are captured in default mode
	int packetCount = 0;
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7),
	                 -1);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	PTF_ASSERT_GREATER_THAN(packetCount, 0);

	packetCount = 0;

	// create a non-default configuration with timeout of 10ms and open the device again
	pcpp::PcapLiveDevice::DeviceConfiguration devConfig(pcpp::PcapLiveDevice::Promiscuous, 10, 2000000);
	PTF_ASSERT_TRUE(liveDev->open(devConfig));

	// start capturing in non-default configuration
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7),
	                 -1);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	PTF_ASSERT_GREATER_THAN(packetCount, 0);

	packetCount = 0;

	// Setting direction isn't available on Windows, and setting "outgoing only" isn't available on macOS
#if !defined(_WIN32) && !defined(__APPLE__)
	// create a non-default configuration with only capturing incoming packets and open the device again
	pcpp::PcapLiveDevice::DeviceConfiguration devConfigWithDirection(pcpp::PcapLiveDevice::Promiscuous, 10, 2000000,
	                                                                 pcpp::PcapLiveDevice::PCPP_OUT);
	PTF_ASSERT_TRUE(liveDev->open(devConfigWithDirection));

	// start capturing in non-default configuration witch only captures incoming traffics
	PTF_ASSERT_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7),
	                 -1);

	liveDev->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	PTF_ASSERT_GREATER_THAN(packetCount, 0);
#endif

	// create a non-default configuration with a snapshot length of 10 bytes
	int snaplen = 20;
	pcpp::PcapLiveDevice::DeviceConfiguration devConfigWithSnaplen(pcpp::PcapLiveDevice::Promiscuous, 0, 0,
	                                                               pcpp::PcapLiveDevice::PCPP_INOUT, snaplen);

	liveDev->open(devConfigWithSnaplen);

	// start capturing in non-default configuration witch only captures incoming traffics
	// TODO: for some reason snaplen change doesn't work in Windows (WinPcap and Npcap). Setting the check as
	// NON_CRITICAL until we figure it out
	PTF_NON_CRITICAL_EQUAL(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeWithSnaplen, &snaplen, 3), -1);

	liveDev->close();

}  // TestPcapLiveDeviceSpecialCfg

PTF_TEST_CASE(TestWinPcapLiveDevice)
{
#if defined(_WIN32)

	pcpp::PcapLiveDevice* liveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::WinPcapDevice, enum);

	pcpp::WinPcapLiveDevice* winPcapLiveDevice = static_cast<pcpp::WinPcapLiveDevice*>(liveDev);
	int defaultDataToCopy = winPcapLiveDevice->getMinAmountOfDataToCopyFromKernelToApplication();
	PTF_ASSERT_EQUAL(defaultDataToCopy, 16000);
	PTF_ASSERT_TRUE(winPcapLiveDevice->open());
	DeviceTeardown devTeardown(winPcapLiveDevice);
	PTF_ASSERT_TRUE(winPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(100000));
	int packetCount = 0;
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT_TRUE(winPcapLiveDevice->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                                static_cast<void*>(&numOfTimeStatsWereInvoked)));
	for (int i = 0; i < 5; i++)
	{
		sendURLRequest("www.ebay.com");
	}

	pcpp::IPcapDevice::PcapStats statistics;
	winPcapLiveDevice->getStatistics(statistics);
	PTF_ASSERT_GREATER_THAN(statistics.packetsRecv, 20);
	// Bad test - on high traffic libpcap/WinPcap/Npcap sometimes drop packets
	// PTF_ASSERT_EQUAL((uint32_t)statistics.packetsDrop, 0);
	winPcapLiveDevice->stopCapture();
	PTF_ASSERT_TRUE(winPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(defaultDataToCopy));
	winPcapLiveDevice->close();
	PTF_ASSERT_FALSE(liveDev->isOpened());

	// a negative test
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(winPcapLiveDevice->startCapture(&packetArrives, static_cast<void*>(&packetCount), 1, &statsUpdate,
	                                                 static_cast<void*>(&numOfTimeStatsWereInvoked)));
	pcpp::Logger::getInstance().enableLogs();

#else
	pcpp::PcapLiveDevice* liveDev =
	    pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_EQUAL(liveDev->getDeviceType(), pcpp::PcapLiveDevice::LibPcapDevice, enum);
#endif

}  // TestWinPcapLiveDevice

PTF_TEST_CASE(TestSendPacket)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	PTF_ASSERT_GREATER_THAN(liveDev->getMtu(), 0);
	uint32_t mtu = liveDev->getMtu();
	int buffLen = mtu + 1 + sizeof(pcpp::ether_header);
	uint8_t* buff = new uint8_t[buffLen];
	memset(buff, 0, buffLen);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->sendPacket(buff, buffLen, true));
	pcpp::Logger::getInstance().enableLogs();

	pcpp::RawPacket rawPacket;
	int packetsSent = 0;
	int packetsRead = 0;
	while (fileReaderDev.getNextPacket(rawPacket))
	{
		packetsRead++;

		// send packet as RawPacket
		PTF_ASSERT_TRUE(liveDev->sendPacket(rawPacket));

		// send packet as raw data
		PTF_ASSERT_TRUE(liveDev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()));

		// send packet as parsed EthPacekt
		pcpp::Packet packet(&rawPacket);
		PTF_ASSERT_TRUE(liveDev->sendPacket(&packet));

		packetsSent++;
	}

	PTF_ASSERT_EQUAL(packetsRead, packetsSent);

	liveDev->close();
	fileReaderDev.close();

	delete[] buff;
}  // TestSendPacket

PTF_TEST_CASE(TestSendPackets)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev.open());

	std::vector<pcpp::RawPacket> rawPacketArr(10000);
	pcpp::PointerVector<pcpp::Packet> packetVec;
	int packetsRead = 0;
	while (fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
	{
		packetVec.pushBack(new pcpp::Packet(&rawPacketArr[packetsRead]));
		packetsRead++;
	}

	// send packets as RawPacket array
	int packetsSentAsRaw = liveDev->sendPackets(rawPacketArr.data(), packetsRead);

	// send packets as parsed EthPacekt array
	std::vector<pcpp::Packet*> packetArr;
	packetArr.reserve(10000);
	std::copy(packetVec.begin(), packetVec.end(), std::back_inserter(packetArr));
	int packetsSentAsParsed = liveDev->sendPackets(packetArr.data(), packetsRead);

	PTF_ASSERT_EQUAL(packetsSentAsRaw, packetsRead);
	PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead);

	liveDev->close();
	fileReaderDev.close();
}  // TestSendPackets

PTF_TEST_CASE(TestMtuSize)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTearDown(liveDev);

	// Construct a packet within the MTU and assert that it should send
	// Source and destination addresses are somewhat arbitrary. Only important thing is that the packet is valid
	pcpp::EthLayer smallEthernetLayer(liveDev->getMacAddress(), pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

	pcpp::IPv4Address remoteIpAddress;
	try
	{
		remoteIpAddress = pcpp::IPv4Address(PcapTestGlobalArgs.remoteIp.c_str());
	}
	catch (...)
	{
		remoteIpAddress = pcpp::IPv4Address::Zero;
	}
	pcpp::IPv4Layer smallIPLayer(ipToSearch, remoteIpAddress);
	// Port 9 is the discard protocol
	pcpp::UdpLayer smallUdpLayer(12345, 9);

	pcpp::Packet smallPacket(liveDev->getMtu() + smallEthernetLayer.getDataLen());

	smallPacket.addLayer(&smallEthernetLayer);
	smallPacket.addLayer(&smallIPLayer);
	smallPacket.addLayer(&smallUdpLayer);

	// Pad the small packet with extra bytes to fill it exactly to the MTU
	size_t smallDataLen = liveDev->getMtu() - (smallIPLayer.getDataLen());
	uint8_t* smallData = new uint8_t[smallDataLen];
	memset(smallData, 0xFF, smallDataLen);
	pcpp::PayloadLayer smallPayload(smallData, smallDataLen);
	smallPacket.addLayer(&smallPayload);

	// Check the size of the small Packet
	PTF_PRINT_VERBOSE("Mtu: " << liveDev->getMtu());
	PTF_PRINT_VERBOSE("Small packet: " << smallPacket.getLayerOfType<pcpp::IPv4Layer>()->getDataLen());
	PTF_ASSERT_EQUAL(smallPacket.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), (size_t)liveDev->getMtu(), ptr);
	// Try sending the packet
	PTF_ASSERT_TRUE(liveDev->sendPacket(&smallPacket));
	pcpp::RawPacket* rawSmallPacketPtr = smallPacket.getRawPacket();
	pcpp::RawPacket& rawSmallPacketRef = *rawSmallPacketPtr;
	PTF_ASSERT_TRUE(liveDev->sendPacket(rawSmallPacketRef, true));
	PTF_ASSERT_TRUE(liveDev->sendPacket(rawSmallPacketPtr->getRawData(), rawSmallPacketPtr->getRawDataLen(), true,
	                                    pcpp::LINKTYPE_ETHERNET));

	delete[] smallData;

	// Construct a packet larger than the MTU and assert that it doesn't send
	pcpp::EthLayer largeEthernetLayer(liveDev->getMacAddress(), pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));
	pcpp::IPv4Layer largeIPLayer(ipToSearch, remoteIpAddress);
	// Port 9 is the discard protocol
	pcpp::UdpLayer largeUdpLayer(12345, 9);

	pcpp::Packet largePacket(liveDev->getMtu() + smallEthernetLayer.getDataLen() + 1);

	largePacket.addLayer(&largeEthernetLayer);
	largePacket.addLayer(&largeIPLayer);
	largePacket.addLayer(&largeUdpLayer);

	// Pad the large packet with extra bytes to fill it to 1 byte more than the MTU
	size_t largeDataLen = liveDev->getMtu() - largeIPLayer.getDataLen() + 1;
	uint8_t* largeData = new uint8_t[largeDataLen];
	memset(largeData, 0xFF, largeDataLen);
	pcpp::PayloadLayer largePayload(largeData, largeDataLen);
	largePacket.addLayer(&largePayload);

	// Check the size of the large Packet
	PTF_PRINT_VERBOSE("Large packet: " << largePacket.getLayerOfType<pcpp::IPv4Layer>()->getDataLen());
	PTF_ASSERT_EQUAL(largePacket.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), (size_t)(liveDev->getMtu() + 1), ptr);
	// Try sending the packet
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(liveDev->sendPacket(&largePacket));

	pcpp::RawPacket* rawLargePacketPtr = largePacket.getRawPacket();
	pcpp::RawPacket& rawLargePacketRef = *rawLargePacketPtr;
	PTF_ASSERT_FALSE(liveDev->sendPacket(rawLargePacketRef, true));
	PTF_ASSERT_FALSE(liveDev->sendPacket(rawLargePacketPtr->getRawData(), rawLargePacketPtr->getRawDataLen(), true,
	                                     pcpp::LINKTYPE_ETHERNET));
	pcpp::Logger::getInstance().enableLogs();

	delete[] largeData;
}  // TestMtuSize

PTF_TEST_CASE(TestRemoteCapture)
{
#if defined(_WIN32)

	bool useRemoteDevicesFromArgs = (PcapTestGlobalArgs.remoteIp != "") && (PcapTestGlobalArgs.remotePort > 0);
	std::string remoteDeviceIP =
	    (useRemoteDevicesFromArgs ? PcapTestGlobalArgs.remoteIp : PcapTestGlobalArgs.ipToSendReceivePackets);
	uint16_t remoteDevicePort = (useRemoteDevicesFromArgs ? PcapTestGlobalArgs.remotePort : 12321);

	RpcapdServerInitializer rpcapdInitializer(!useRemoteDevicesFromArgs, remoteDeviceIP, remoteDevicePort);

	PTF_ASSERT_NOT_NULL(rpcapdInitializer.getHandle());

	pcpp::IPv4Address remoteDeviceIPAddr(remoteDeviceIP);
	pcpp::PcapRemoteDeviceList* remoteDevices =
	    pcpp::PcapRemoteDeviceList::getRemoteDeviceList(remoteDeviceIPAddr, remoteDevicePort);
	PTF_ASSERT_NOT_NULL(remoteDevices);
	for (pcpp::PcapRemoteDeviceList::RemoteDeviceListIterator remoteDevIter = remoteDevices->begin();
	     remoteDevIter != remoteDevices->end(); remoteDevIter++)
	{
		PTF_ASSERT_FALSE((*remoteDevIter)->getName().empty());
	}
	PTF_ASSERT_EQUAL(remoteDevices->getRemoteMachineIpAddress().toString(), remoteDeviceIP);
	PTF_ASSERT_EQUAL(remoteDevices->getRemoteMachinePort(), remoteDevicePort);

	pcpp::PcapRemoteDevice* remoteDevice = remoteDevices->getRemoteDeviceByIP(remoteDeviceIPAddr);
	PTF_ASSERT_NOT_NULL(remoteDevice);
	PTF_ASSERT_EQUAL(remoteDevice->getDeviceType(), pcpp::PcapLiveDevice::RemoteDevice, enum);
	PTF_ASSERT_EQUAL(remoteDevice->getMtu(), 0);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_EQUAL(remoteDevice->getMacAddress(), pcpp::MacAddress::Zero);
	pcpp::Logger::getInstance().enableLogs();
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

		std::this_thread::sleep_for(std::chrono::seconds(1));
		totalSleepTime += 1;
	}

	remoteDevice->stopCapture();

	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime << " secs");

	PTF_ASSERT_GREATER_THAN(capturedPackets.size(), 2);

	// send single packet
	PTF_ASSERT_TRUE(remoteDevice->sendPacket(*capturedPackets.front()));

	// send multiple packets
	pcpp::RawPacketVector packetsToSend;
	std::vector<pcpp::RawPacket*>::iterator iter = capturedPackets.begin();

	size_t capturedPacketsSize = capturedPackets.size();
	while (iter != capturedPackets.end())
	{
		if ((*iter)->getRawDataLen() <= static_cast<int>(remoteDevice->getMtu()))
		{
			packetsToSend.pushBack(capturedPackets.getAndDetach(iter));
		}
		else
			++iter;
	}
	int packetsSent = remoteDevice->sendPackets(packetsToSend);
	PTF_ASSERT_EQUAL(packetsSent, static_cast<int>(packetsToSend.size()));

	// check statistics
	pcpp::IPcapDevice::PcapStats stats;
	remoteDevice->getStatistics(stats);
	PTF_ASSERT_EQUAL(static_cast<uint32_t>(stats.packetsRecv), capturedPacketsSize);

	remoteDevice->close();

	// Check clone method produces correct pointer.
	pcpp::PcapLiveDevice* remoteDeviceCloned = remoteDevice->clone();
	auto devCopyTeardown = DeviceTeardown(remoteDeviceCloned, true);
	PTF_ASSERT_NOT_NULL(remoteDeviceCloned);
	PTF_ASSERT_NOT_NULL(dynamic_cast<pcpp::PcapRemoteDevice*>(remoteDeviceCloned));

	delete remoteDevices;

	// the device object is already deleted, cannot close it
	devTeardown.cancelTeardown();
#else
	PTF_SKIP_TEST("This test can only run in Windows environment");
#endif

}  // TestRemoteCapture
