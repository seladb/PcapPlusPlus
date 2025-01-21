#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/PcapFileNamesDef.h"

#ifdef USE_DPDK_KNI
#	include "KniDeviceList.h"
#	include "PcapFileDevice.h"
#	include "RawSocketDevice.h"
#	include "SystemUtils.h"
#	include <thread>

extern PcapTestArgs PcapTestGlobalArgs;

#	define KNI_TEST_NAME "tkni"

struct KniRequestsCallbacksMock
{
	static int change_mtu_new(uint16_t, unsigned int)
	{
		return 0;
	}
	static int change_mtu_old(uint8_t, unsigned int)
	{
		return 0;
	}
	static int config_network_if_new(uint16_t, uint8_t)
	{
		return 0;
	}
	static int config_network_if_old(uint8_t, uint8_t)
	{
		return 0;
	}
	static int config_mac_address(uint16_t, uint8_t[])
	{
		return 0;
	}
	static int config_promiscusity(uint16_t, uint8_t)
	{
		return 0;
	}

	static bool onPacketsCallbackSingleBurst(pcpp::MBufRawPacket*, uint32_t numOfPackets, pcpp::KniDevice*,
	                                         void* userCookie)
	{
		unsigned int* counter = static_cast<unsigned int*>(userCookie);
		*counter = numOfPackets;
		// Break after first burst
		return false;
	}
	static bool onPacketsMock(pcpp::MBufRawPacket*, uint32_t, pcpp::KniDevice*, void*)
	{
		return true;
	}
	static bool onPacketsCallback(pcpp::MBufRawPacket*, uint32_t numOfPackets, pcpp::KniDevice*, void* userCookie)
	{
		unsigned int* counter = static_cast<unsigned int*>(userCookie);
		*counter = *counter + numOfPackets;
		return true;
	}

	static pcpp::KniDevice::KniIoctlCallbacks cb_new;
	static pcpp::KniDevice::KniOldIoctlCallbacks cb_old;
	static void setCallbacks()
	{
		cb_new.change_mtu = change_mtu_new;
		cb_new.config_network_if = config_network_if_new;
		cb_new.config_mac_address = config_mac_address;
		cb_new.config_promiscusity = config_promiscusity;
		cb_old.change_mtu = change_mtu_old;
		cb_old.config_network_if = config_network_if_old;
	}
};

pcpp::KniDevice::KniIoctlCallbacks KniRequestsCallbacksMock::cb_new;
pcpp::KniDevice::KniOldIoctlCallbacks KniRequestsCallbacksMock::cb_old;

enum
{
	KNI_TEST_PORT_ID0 = 42,
	KNI_TEST_PORT_ID1 = 43,
	KNI_DEVICE0 = 0,
	KNI_DEVICE1 = 1,
	KNI_TEST_MEMPOOL_CAPACITY = 512
};

static bool setKniDeviceIp(const pcpp::IPAddress& ip, int kniDeviceId)
{
	std::ostringstream command;
	command << "ip a add " << ip << "/24 dev " << KNI_TEST_NAME << kniDeviceId;
	pcpp::executeShellCommand(command.str());
	command.str("");
	command << "ip a | grep " << ip;
	std::string result = pcpp::executeShellCommand(command.str());
	return result != "" && result != "ERROR";
}

class KniDeviceTeardown
{
private:
	pcpp::KniDevice* m_KniDevice;

public:
	explicit KniDeviceTeardown(pcpp::KniDevice* dev)
	{
		m_KniDevice = dev;
	}

	~KniDeviceTeardown()
	{
		if (m_KniDevice != NULL && m_KniDevice->isInitialized() && m_KniDevice->isOpened())
		{
			m_KniDevice->stopRequestHandlerThread();
			m_KniDevice->close();
		}
	}
};

#endif  // USE_DPDK_KNI

PTF_TEST_CASE(TestKniDevice)
{
#ifdef USE_DPDK_KNI

	if (PcapTestGlobalArgs.kniIp == "")
	{
		PTF_SKIP_TEST("KNI IP not provided");
	}

	// Assume that DPDK was initialized correctly in DpdkDevice tests
	uint16_t KNI_TEST_MTU = 1540;
	bool isLinkUp = true;
	pcpp::KniDevice* device = NULL;
	pcpp::KniDevice::KniDeviceConfiguration devConfig;
	std::ostringstream deviceNameStream;
	deviceNameStream << KNI_TEST_NAME << KNI_DEVICE0;
	std::string deviceName = deviceNameStream.str();
	devConfig.name = deviceName;
	KniRequestsCallbacksMock::setCallbacks();
	if (pcpp::KniDeviceList::callbackVersion() == pcpp::KniDeviceList::CALLBACKS_NEW)
	{
		devConfig.callbacks = &KniRequestsCallbacksMock::cb_new;
	}
	else
	{
		devConfig.oldCallbacks = &KniRequestsCallbacksMock::cb_old;
	}
	devConfig.mac = pcpp::MacAddress("00:11:33:55:77:99");
	devConfig.portId = KNI_TEST_PORT_ID0;
	devConfig.mtu = KNI_TEST_MTU;
	devConfig.bindKthread = false;
	pcpp::KniDeviceList& kniDeviceList = pcpp::KniDeviceList::getInstance();
	PTF_ASSERT_TRUE(kniDeviceList.isInitialized());
	device = kniDeviceList.createDevice(devConfig, KNI_TEST_MEMPOOL_CAPACITY);
	PTF_ASSERT_NOT_NULL(device);
	PTF_ASSERT_TRUE(device->isInitialized());
	KniDeviceTeardown devTeardown(device);
	PTF_ASSERT_EQUAL(device, kniDeviceList.getDeviceByPort(KNI_TEST_PORT_ID0), ptr);
	PTF_ASSERT_EQUAL(device, kniDeviceList.getDeviceByName(deviceName), ptr);

	{
		std::string devName = device->getName();
		PTF_ASSERT_EQUAL(devName, deviceName);
	}
	{
		uint16_t port = device->getPort();
		PTF_ASSERT_EQUAL(port, (uint16_t)KNI_TEST_PORT_ID0);
	}

	PTF_ASSERT_EQUAL(device->getLinkState(), pcpp::KniDevice::LINK_NOT_SUPPORTED, enum);

	{
		pcpp::KniDevice::KniLinkState linkState = device->getLinkState(pcpp::KniDevice::INFO_RENEW);
		PTF_ASSERT_TRUE(linkState == pcpp::KniDevice::LINK_DOWN || linkState == pcpp::KniDevice::LINK_UP);
		if (linkState == pcpp::KniDevice::LINK_DOWN)
			isLinkUp = false;
	}
	{
		pcpp::MacAddress mac = device->getMacAddress();
		PTF_ASSERT_EQUAL(mac, devConfig.mac);
		mac = device->getMacAddress(pcpp::KniDevice::INFO_RENEW);
		PTF_ASSERT_EQUAL(mac, devConfig.mac);
	}
	{
		uint16_t mtu = device->getMtu();
		PTF_ASSERT_EQUAL(mtu, KNI_TEST_MTU);
		mtu = device->getMtu(pcpp::KniDevice::INFO_RENEW);
		PTF_ASSERT_EQUAL(mtu, KNI_TEST_MTU);
	}
	{
		pcpp::KniDevice::KniPromiscuousMode pm = device->getPromiscuous();
		PTF_ASSERT_EQUAL(pm, pcpp::KniDevice::PROMISC_DISABLE, enum);
	}

	PTF_ASSERT_TRUE(device->open());
	PTF_ASSERT_TRUE(device->startRequestHandlerThread(0, 150000000));
	std::this_thread::sleep_for(std::chrono::seconds(2));  // Wait for thread to start
	if (pcpp::KniDeviceList::isCallbackSupported(pcpp::KniDeviceList::CALLBACK_PROMISC))
	{
		bool modeSet = device->setPromiscuous(pcpp::KniDevice::PROMISC_ENABLE);
		PTF_NON_CRITICAL_TRUE(modeSet);
		if (modeSet)
		{
			pcpp::KniDevice::KniPromiscuousMode pm = device->getPromiscuous(pcpp::KniDevice::INFO_RENEW);
			PTF_NON_CRITICAL_EQUAL(pm, pcpp::KniDevice::PROMISC_ENABLE, enum);
			modeSet = device->setPromiscuous(pcpp::KniDevice::PROMISC_DISABLE);
			PTF_NON_CRITICAL_TRUE(modeSet);
			if (modeSet)
			{
				pm = device->getPromiscuous(pcpp::KniDevice::INFO_RENEW);
				PTF_NON_CRITICAL_EQUAL(pm, pcpp::KniDevice::PROMISC_DISABLE, enum);
			}
		}
	}
	if (pcpp::KniDeviceList::isCallbackSupported(pcpp::KniDeviceList::CALLBACK_MTU))
	{
		uint16_t KNI_NEW_MTU = 1500;
		bool mtuSet = device->setMtu(KNI_NEW_MTU);
		PTF_NON_CRITICAL_TRUE(mtuSet);
		if (mtuSet)
		{
			uint16_t mtu = device->getMtu(pcpp::KniDevice::INFO_RENEW);
			PTF_NON_CRITICAL_EQUAL(mtu, KNI_NEW_MTU);
		}
	}
	if (pcpp::KniDeviceList::isCallbackSupported(pcpp::KniDeviceList::CALLBACK_MAC))
	{
		pcpp::MacAddress kniNewMac = pcpp::MacAddress("00:22:44:66:88:AA");
		bool macSet = device->setMacAddress(kniNewMac);
		PTF_NON_CRITICAL_TRUE(macSet);
		if (macSet)
		{
			pcpp::MacAddress mac = device->getMacAddress(pcpp::KniDevice::INFO_RENEW);
			PTF_NON_CRITICAL_EQUAL(mac, kniNewMac);
		}
	}
	if (pcpp::KniDeviceList::isCallbackSupported(pcpp::KniDeviceList::CALLBACK_LINK))
	{
		pcpp::KniDevice::KniLinkState nls = isLinkUp ? pcpp::KniDevice::LINK_DOWN : pcpp::KniDevice::LINK_UP;
		pcpp::KniDevice::KniLinkState ols = isLinkUp ? pcpp::KniDevice::LINK_UP : pcpp::KniDevice::LINK_DOWN;
		bool linkSet = device->setLinkState(nls);
		PTF_NON_CRITICAL_TRUE(linkSet);
		if (linkSet)
		{
			pcpp::KniDevice::KniLinkState ls = device->getLinkState(pcpp::KniDevice::INFO_RENEW);
			PTF_NON_CRITICAL_EQUAL(ls, nls, enum);
			linkSet = device->setLinkState(ols);
			if (linkSet)
			{
				ls = device->getLinkState(pcpp::KniDevice::INFO_RENEW);
				PTF_NON_CRITICAL_EQUAL(ls, ols, enum);
			}
			else
			{
				isLinkUp = !isLinkUp;
			}
		}
	}
	{
		pcpp::KniDevice::KniLinkState ls =
		    device->updateLinkState(isLinkUp ? pcpp::KniDevice::LINK_DOWN : pcpp::KniDevice::LINK_UP);
		switch (ls)
		{
		case pcpp::KniDevice::LINK_NOT_SUPPORTED:
		{
			PTF_PRINT_VERBOSE("KNI updateLinkState not supported");
			break;
		}
		case pcpp::KniDevice::LINK_ERROR:
		{
			PTF_PRINT_VERBOSE("KNI updateLinkState have failed with LINK_ERROR");
			break;
		}
		case pcpp::KniDevice::LINK_DOWN:
		{  // If previous known state was UP -> yield an error
			PTF_ASSERT_FALSE(isLinkUp);
			break;
		}
		case pcpp::KniDevice::LINK_UP:
		{  // If previous known state was DOWN -> yield an error
			PTF_ASSERT_TRUE(isLinkUp);
			break;
		}
		}
	}
	device->stopRequestHandlerThread();
	device->close();
	// Device will be destroyed later

#else
	PTF_SKIP_TEST("DPDK and DPDK_KNI not configured");
#endif
}  // TestKniDevice

PTF_TEST_CASE(TestKniDeviceSendReceive)
{
#ifdef USE_DPDK_KNI

	if (PcapTestGlobalArgs.kniIp == "")
	{
		PTF_SKIP_TEST("KNI IP not provided");
	}

	// Assume that DPDK was initialized correctly in DpdkDevice tests
	enum
	{
		KNI_MTU = 1500,
		BLOCK_TIMEOUT = 3
	};
	pcpp::KniDevice* device = NULL;
	unsigned int counter = 0;
	pcpp::KniDevice::KniDeviceConfiguration devConfig;
	pcpp::IPv4Address kniIp = PcapTestGlobalArgs.kniIp;

	// KNI device setup
	std::ostringstream deviceName;
	deviceName << KNI_TEST_NAME << KNI_DEVICE1;
	devConfig.name = deviceName.str();
	KniRequestsCallbacksMock::setCallbacks();
	if (pcpp::KniDeviceList::callbackVersion() == pcpp::KniDeviceList::CALLBACKS_NEW)
	{
		devConfig.callbacks = &KniRequestsCallbacksMock::cb_new;
	}
	else
	{
		devConfig.oldCallbacks = &KniRequestsCallbacksMock::cb_old;
	}
	devConfig.portId = KNI_TEST_PORT_ID1;
	devConfig.mtu = KNI_MTU;
	devConfig.bindKthread = false;

	pcpp::KniDeviceList& kniDeviceList = pcpp::KniDeviceList::getInstance();
	PTF_ASSERT_TRUE(kniDeviceList.isInitialized());
	device = kniDeviceList.createDevice(devConfig, KNI_TEST_MEMPOOL_CAPACITY);
	PTF_ASSERT_NOT_NULL(device);
	PTF_ASSERT_TRUE(device->isInitialized());
	PTF_ASSERT_TRUE(device->open());
	PTF_ASSERT_TRUE(device->startRequestHandlerThread(0, 250000000));
	KniDeviceTeardown devTeardown(device);

	std::this_thread::sleep_for(std::chrono::seconds(1));  // Wait for thread to start

	// KNI device management
	PTF_ASSERT_TRUE(setKniDeviceIp(kniIp, KNI_DEVICE1));
	PTF_ASSERT_TRUE(device->setPromiscuous(pcpp::KniDevice::PROMISC_ENABLE));
	PTF_ASSERT_TRUE(device->setLinkState(pcpp::KniDevice::LINK_UP));

	// Other devices needed
	pcpp::RawSocketDevice rsdevice(kniIp);
	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT_TRUE(rsdevice.open());

	{  // Receive test part
		pcpp::RawPacket rawPacket;
		pcpp::RawPacketVector rawPacketVec;
		pcpp::MBufRawPacketVector mbufRawPacketVec;
		pcpp::MBufRawPacket* mBufRawPacketArr[32] = {};
		size_t mBufRawPacketArrLen = 32;
		pcpp::Packet* packetArr[32] = {};
		size_t packetArrLen = 32;
		PTF_ASSERT_TRUE(fileReaderDev.open());

		PTF_ASSERT_TRUE(device->startCapture(KniRequestsCallbacksMock::onPacketsCallbackSingleBurst, &counter));
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_FALSE(device->startCapture(KniRequestsCallbacksMock::onPacketsMock, NULL));
		pcpp::Logger::getInstance().enableLogs();
		std::this_thread::sleep_for(std::chrono::seconds(1));  // Give some time to start capture thread
		for (int i = 0; i < 10; ++i)
		{
			fileReaderDev.getNextPacket(rawPacket);
			pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		pcpp::Logger::getInstance().suppressLogs();
		rsdevice.sendPackets(rawPacketVec);
		pcpp::Logger::getInstance().enableLogs();
		rawPacketVec.clear();
		std::this_thread::sleep_for(std::chrono::seconds(1));  // Give some time to receive packets
		device->stopCapture();
		PTF_PRINT_VERBOSE("KNI have captured " << counter << " packets in single burst on device " << KNI_DEVICE1);
		counter = 0;
		PTF_ASSERT_TRUE(device->startCapture(KniRequestsCallbacksMock::onPacketsCallback, &counter));
		std::this_thread::sleep_for(std::chrono::seconds(1));  // Give some time to start capture thread
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_EQUAL(device->receivePackets(mbufRawPacketVec), 0);
		PTF_ASSERT_EQUAL(device->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen), 0);
		PTF_ASSERT_EQUAL(device->receivePackets(packetArr, packetArrLen), 0);
		pcpp::Logger::getInstance().enableLogs();
		for (int i = 0; i < 10; ++i)
		{
			fileReaderDev.getNextPacket(rawPacket);
			pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		pcpp::Logger::getInstance().suppressLogs();
		rsdevice.sendPackets(rawPacketVec);
		pcpp::Logger::getInstance().enableLogs();
		rawPacketVec.clear();
		std::this_thread::sleep_for(std::chrono::seconds(1));  // Give some time to receive packets
		device->stopCapture();
		PTF_PRINT_VERBOSE("KNI have captured " << counter << " packets on device " << KNI_DEVICE1);
		counter = 0;
		while (fileReaderDev.getNextPacket(rawPacket))
		{
			pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		pcpp::Logger::getInstance().suppressLogs();
		rsdevice.sendPackets(rawPacketVec);
		pcpp::Logger::getInstance().enableLogs();
		rawPacketVec.clear();
		//? Note(echo-Mike): Some amount of packets are always queued inside kernel
		//? so blocking mode has a slight chance to obtain this packets
		int blockResult = device->startCaptureBlockingMode(KniRequestsCallbacksMock::onPacketsCallbackSingleBurst,
		                                                   &counter, BLOCK_TIMEOUT);
		switch (blockResult)
		{
		case -1:
		{
			PTF_PRINT_VERBOSE("KNI startCaptureBlockingMode have exited by timeout");
			break;
		}
		case 0:
		{
			PTF_PRINT_VERBOSE("KNI startCaptureBlockingMode have exited by an ERROR");
			break;
		}
		case 1:
		{
			PTF_PRINT_VERBOSE("KNI have captured " << counter << " packets (blocking mode) on device " << KNI_DEVICE1);
			break;
		}
		}
	}

	pcpp::Logger::getInstance().suppressLogs();
	fileReaderDev.close();
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(fileReaderDev.open());

	{  // Send test part
		pcpp::PointerVector<pcpp::Packet> packetVec;
		pcpp::RawPacketVector sendRawPacketVec;
		pcpp::RawPacketVector receiveRawPacketVec;
		pcpp::Packet* packetArr[10000];
		uint16_t packetsRead = 0;
		int packetsReceived = 0;
		pcpp::RawPacket rawPacket;
		while (fileReaderDev.getNextPacket(rawPacket))
		{
			if (packetsRead == 100)
				break;
			pcpp::RawPacket* newRawPacket = new pcpp::RawPacket(rawPacket);
			sendRawPacketVec.pushBack(newRawPacket);
			pcpp::Packet* newPacket = new pcpp::Packet(newRawPacket, false);
			packetVec.pushBack(newPacket);
			packetArr[packetsRead] = newPacket;

			packetsRead++;
		}

		// send packets as parsed EthPacekt array
		uint16_t packetsSentAsParsed = device->sendPackets(packetArr, packetsRead);
		PTF_ASSERT_EQUAL(packetsSentAsParsed, packetsRead);

		// Check raw device for packets to come
		{
			int unused;
			packetsReceived += rsdevice.receivePackets(receiveRawPacketVec, 3, unused);
			receiveRawPacketVec.clear();
		}
		PTF_ASSERT_NOT_EQUAL(packetsReceived, 0);
		packetsReceived = 0;

		// send packets are RawPacketVector
		uint16_t packetsSentAsRawVector = device->sendPackets(sendRawPacketVec);
		PTF_ASSERT_EQUAL(packetsSentAsRawVector, packetsRead);

		// Check raw device for packets to come
		{
			int unused;
			packetsReceived += rsdevice.receivePackets(receiveRawPacketVec, 3, unused);
			receiveRawPacketVec.clear();
		}
		PTF_ASSERT_NOT_EQUAL(packetsReceived, 0);
		packetsReceived = 0;

		//? Note (echo-Mike): this will not be checked by raw socket because there is
		//? a chance that packets will be thrown away before we can receive them
		PTF_ASSERT_TRUE(device->sendPacket(*(sendRawPacketVec.at(packetsRead / 3))));
		PTF_ASSERT_TRUE(device->sendPacket(*(packetArr[packetsRead / 2])));
	}

	//! Note(echo-Mike): RawSocket device must be closed before KNI
	rsdevice.close();
	device->stopRequestHandlerThread();
	device->close();
	fileReaderDev.close();

#else
	PTF_SKIP_TEST("DPDK and DPDK_KNI not configured");
#endif

}  // TestKniDeviceSendReceive
