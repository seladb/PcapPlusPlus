#define LOG_MODULE PcapLogModuleLiveDevice

#include <PcapLiveDevice.h>
#include <pthread.h>
#include <Logger.h>
#include <PlatformSpecificUtils.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <IpUtils.h>
#ifdef WIN32
#include <ws2tcpip.h>
#include <Packet32.h>
#include <ntddndis.h>
#else
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#endif

struct PcapThread
{
	pthread_t pthread;
};

PcapLiveDevice::PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU) : IPcapDevice(),
		m_xMacAddress("")
{

	m_pName = NULL;
	m_pDescription = NULL;
	m_DeviceMtu = 0;

	m_IsLoopback = (pInterface->flags & 0x1) == PCAP_IF_LOOPBACK;

	int strLength = strlen(pInterface->name)+1;
	m_pName = new char[strLength];
	strncpy((char*)m_pName, pInterface->name, strLength);

	strLength = 1;
	if (pInterface->description != NULL)
		strLength += strlen(pInterface->description);
	m_pDescription = new char[strLength];
	if (pInterface->description != NULL)
		strncpy((char*)m_pDescription, pInterface->description, strLength);
	else
		strncpy((char*)m_pDescription, "", strLength);
	LOG_DEBUG("Added live device: name=%s; desc=%s", m_pName, m_pDescription);
	LOG_DEBUG("   Addresses:");
	while (pInterface->addresses != NULL)
	{
		m_xAddresses.insert(m_xAddresses.end(), *(pInterface->addresses));
		pInterface->addresses = pInterface->addresses->next;
		if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && pInterface->addresses != NULL && pInterface->addresses->addr != NULL)
		{
			char addrAsString[INET6_ADDRSTRLEN];
			sockaddr2string(pInterface->addresses->addr, addrAsString);
			LOG_DEBUG("      %s", addrAsString);
		}
	}

	if (calculateMTU)
	{
		setDeviceMtu();
		LOG_DEBUG("   MTU: %d", m_DeviceMtu);
	}

	//init all other members
	m_CaptureThreadStarted = false;
	m_StatsThreadStarted = false;  m_IsLoopback = false;
	m_StopThread = false;
	m_pCaptureThread = new PcapThread();
	m_pStatsThread = new PcapThread();
	memset(m_pCaptureThread, 0, sizeof(PcapThread));
	memset(m_pStatsThread, 0, sizeof(PcapThread));
	m_cbOnPacketArrives = NULL;
	m_cbOnStatsUpdate = NULL;
	m_IntervalToUpdateStats = 0;
	m_cbOnPacketArrivesUserCookie = NULL;
	m_cbOnStatsUpdateUserCookie = NULL;
	m_CaptureCallbackMode = true;
	m_pCapturedPackets = NULL;
	setDeviceMacAddress();
	if (m_xMacAddress.isValid())
		LOG_DEBUG("   MAC addr: %s", m_xMacAddress.toString().c_str());
}

void PcapLiveDevice::onPacketArrives(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)user;
	if (pThis == NULL)
	{
		LOG_ERROR("Unable to extract PcapLiveDevice instance");
		return;
	}

	RawPacket rawPacket(packet, pkthdr->caplen, pkthdr->ts, false);

	if (pThis->m_cbOnPacketArrives != NULL)
		pThis->m_cbOnPacketArrives(&rawPacket, pThis, pThis->m_cbOnPacketArrivesUserCookie);
}

void PcapLiveDevice::onPacketArrivesNoCallback(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)user;
	if (pThis == NULL)
	{
		LOG_ERROR("Unable to extract PcapLiveDevice instance");
		return;
	}

	RawPacket* rawPacketPtr = new RawPacket(packet, pkthdr->caplen, pkthdr->ts, false);
	pThis->m_pCapturedPackets->pushBack(rawPacketPtr);
}

void* PcapLiveDevice::captureThreadMain(void *ptr)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)ptr;
	if (pThis == NULL)
	{
		LOG_ERROR("Capture thread: Unable to extract PcapLiveDevice instance");
		return 0;
	}

	LOG_DEBUG("Started capture thread for device '%s'", pThis->m_pName);
	if (pThis->m_CaptureCallbackMode)
	{
		while (!pThis->m_StopThread)
			pcap_dispatch(pThis->m_pPcapDescriptor, -1, onPacketArrives, (uint8_t*)pThis);
	}
	else
	{
		while (!pThis->m_StopThread)
			pcap_dispatch(pThis->m_pPcapDescriptor, 100, onPacketArrivesNoCallback, (uint8_t*)pThis);

	}
	LOG_DEBUG("Ended capture thread for device '%s'", pThis->m_pName);
	return 0;
}

void* PcapLiveDevice::statsThreadMain(void *ptr)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)ptr;
	if (pThis == NULL)
	{
		LOG_ERROR("Stats thread: Unable to extract PcapLiveDevice instance");
		return 0;
	}

	LOG_DEBUG("Started stats thread for device '%s'", pThis->m_pName);
	while (!pThis->m_StopThread)
	{
		pcap_stat stats;
		pThis->getStatistics(stats);
		pThis->m_cbOnStatsUpdate(stats, pThis->m_cbOnStatsUpdateUserCookie);
		PCAP_SLEEP(pThis->m_IntervalToUpdateStats);
	}
	LOG_DEBUG("Ended stats thread for device '%s'", pThis->m_pName);
	return 0;
}

bool PcapLiveDevice::open(DeviceMode mode)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	m_pPcapDescriptor = pcap_open_live(m_pName, BUFSIZ, mode, -1, errbuf);
	if (m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("%s", errbuf);
		m_DeviceOpened = false;
		return false;
	}

	LOG_DEBUG("Device '%s' opened", m_pName);

	m_DeviceOpened = true;
	return true;
}

bool PcapLiveDevice::open()
{
	return open(Promiscuous);
}

void PcapLiveDevice::close()
{
	if (m_pPcapDescriptor == NULL)
	{
		LOG_DEBUG("Device '%s' already closed", m_pName);
		return;
	}
	pcap_close(m_pPcapDescriptor);
	LOG_DEBUG("Device '%s' closed", m_pName);
}

bool PcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie)
{
	return startCapture(onPacketArrives, onPacketArrivesUserCookie, 0, NULL, NULL);
}

bool PcapLiveDevice::startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie)
{
	return startCapture(NULL, NULL, intervalInSecondsToUpdateStats, onStatsUpdate, onStatsUpdateUserCookie);
}

bool PcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie)
{
	m_IntervalToUpdateStats = intervalInSecondsToUpdateStats;

	if (m_CaptureThreadStarted || m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("Device '%s' already capturing or not opened", m_pName);
		return false;
	}

	m_CaptureCallbackMode = true;
	m_cbOnPacketArrives = onPacketArrives;
	m_cbOnPacketArrivesUserCookie = onPacketArrivesUserCookie;
	int err = pthread_create(&(m_pCaptureThread->pthread), NULL, getCaptureThreadStart(), (void*)this);
	if (err != 0)
	{
		LOG_ERROR("Cannot create LiveCapture thread for device '%s': [%s]", m_pName, strerror(err));
		return false;
	}
	m_CaptureThreadStarted = true;
	LOG_DEBUG("Successfully created capture thread for device '%s'. Thread id: %s", m_pName, printThreadId(m_pCaptureThread).c_str());

	if (onStatsUpdate != NULL && intervalInSecondsToUpdateStats > 0)
	{
		m_cbOnStatsUpdate = onStatsUpdate;
		m_cbOnStatsUpdateUserCookie = onStatsUpdateUserCookie;
		int err = pthread_create(&(m_pStatsThread->pthread), NULL, &statsThreadMain, (void*)this);
		if (err != 0)
		{
			LOG_ERROR("Cannot create LiveCapture Statistics thread for device '%s': [%s]", m_pName, strerror(err));
			return false;
		}
		m_StatsThreadStarted = true;
		LOG_DEBUG("Successfully created stats thread for device '%s'. Thread id: %s", m_pName, printThreadId(m_pStatsThread).c_str());
	}

	return true;
}

bool PcapLiveDevice::startCapture(RawPacketVector& rCapturedPacketsVector)
{
	m_pCapturedPackets = &rCapturedPacketsVector;
	m_pCapturedPackets->clear();

	if (m_CaptureThreadStarted || m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("Device '%s' already capturing or not opened", m_pName);
		return false;
	}

	m_CaptureCallbackMode = false;
	int err = pthread_create(&(m_pCaptureThread->pthread), NULL, getCaptureThreadStart(), (void*)this);
	if (err != 0)
	{
		LOG_ERROR("Cannot create LiveCapture thread for device '%s': [%s]", m_pName, strerror(err));
		return false;
	}
	m_CaptureThreadStarted = true;
	LOG_DEBUG("Successfully created capture thread for device '%s'. Thread id: %s", m_pName, printThreadId(m_pCaptureThread).c_str());

	return true;
}

void PcapLiveDevice::stopCapture()
{
	m_StopThread = true;
	LOG_DEBUG("Stopping capture thread, waiting for it to join...");
	pthread_join(m_pCaptureThread->pthread, NULL);
	m_CaptureThreadStarted = false;
	LOG_DEBUG("Capture thread stopped for device '%s'", m_pName);
	if (m_StatsThreadStarted)
	{
		LOG_DEBUG("Stopping stats thread, waiting for it to join...");
		pthread_join(m_pStatsThread->pthread, NULL);
		m_StatsThreadStarted = false;
		LOG_DEBUG("Stats thread stopped for device '%s'", m_pName);
	}
	PCAP_SLEEP(1);
	m_StopThread = false;
}

void PcapLiveDevice::getStatistics(pcap_stat& stats)
{
	if(pcap_stats(m_pPcapDescriptor, &stats) < 0)
	{
		LOG_ERROR("Error getting statistics from live device '%s'", m_pName);
	}
}

bool PcapLiveDevice::sendPacket(RawPacket const& rawPacket)
{
	return sendPacket(((RawPacket&)rawPacket).getRawData(), ((RawPacket&)rawPacket).getRawDataLen());
}

bool PcapLiveDevice::sendPacket(const uint8_t* packetData, int packetDataLength)
{
	if (!m_DeviceOpened)
	{
		LOG_ERROR("Device '%s' not opened!", m_pName);
		return false;
	}

	if (packetDataLength == 0)
	{
		LOG_ERROR("Trying to send a packet with length 0");
		return false;
	}

	if (packetDataLength > m_DeviceMtu)
	{
		LOG_ERROR("Packet length [%d] is larger than device MTU [%d]\n", packetDataLength, m_DeviceMtu);
		return false;
	}

	if (pcap_sendpacket(m_pPcapDescriptor, packetData, packetDataLength) == -1)
	{
		LOG_ERROR("Error sending packet: %s\n", pcap_geterr(m_pPcapDescriptor));
		return false;
	}

	LOG_DEBUG("Packet sent successfully. Packet length: %d", packetDataLength);
	return true;
}

bool PcapLiveDevice::sendPacket(Packet* packet)
{
	RawPacket* rawPacket = packet->getRawPacket();
	return sendPacket(*rawPacket);
}

int PcapLiveDevice::sendPackets(RawPacket* rawPacketsArr, int arrLength)
{
	int packetsSent = 0;
	for (int i = 0; i < arrLength; i++)
	{
		if (sendPacket(rawPacketsArr[i]))
			packetsSent++;
	}

	LOG_DEBUG("%d packets sent successfully. %d packets not sent", packetsSent, arrLength-packetsSent);
	return packetsSent;
}

int PcapLiveDevice::sendPackets(Packet** packetsArr, int arrLength)
{
	int packetsSent = 0;
	for (int i = 0; i < arrLength; i++)
	{
		if (sendPacket(packetsArr[i]))
			packetsSent++;
	}

	LOG_DEBUG("%d packets sent successfully. %d packets not sent", packetsSent, arrLength-packetsSent);
	return packetsSent;
}

string PcapLiveDevice::printThreadId(PcapThread* id)
{
    size_t i;
    string result("");
    pthread_t pthread = id->pthread;
    for (i = sizeof(pthread); i; --i)
    {
    	char currByte[3];
    	snprintf(currByte, 3, "%02x", *(((unsigned char*) &pthread) + i - 1));
    	result += currByte;
    }

    return result;
}

void PcapLiveDevice::setDeviceMtu()
{
#ifdef WIN32

	uint32_t mtuValue = 0;
	LPADAPTER pAdapter = PacketOpenAdapter((char*)m_pName);
	if (pAdapter == NULL)
	{
		LOG_ERROR("Error in retrieving MTU: Adapter is NULL");
		return;
	}
	PACKET_OID_DATA oidData;
    oidData.Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;
    oidData.Length = sizeof(uint32_t);
    memcpy(oidData.Data, &mtuValue, sizeof(uint32_t));
    bool status = PacketRequest(pAdapter, false, &oidData);
    if(status)
    {
        if(oidData.Length <= sizeof(uint32_t))
        {
            /* copy value from driver */
            memcpy(&mtuValue, oidData.Data, oidData.Length);
            m_DeviceMtu = mtuValue;
        } else
        {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
            LOG_ERROR("Error in retrieving MTU: Size of Oid larger than uint32_t, OidLen:%lu", oidData.Length);
            return;
        }
    }
    else
    {
    	LOG_ERROR("Error in retrieving MTU: PacketRequest failed");
    }

#else
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, m_pName, sizeof(ifr.ifr_name));

	int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (ioctl(socketfd, SIOCGIFMTU, &ifr) == -1)
	{
		LOG_DEBUG("Error in retrieving MTU: ioctl() returned -1");
		m_DeviceMtu = 0;
		return;
	}

	m_DeviceMtu = ifr.ifr_mtu;
#endif
}

void PcapLiveDevice::setDeviceMacAddress()
{
#ifdef WIN32

	LPADAPTER pAdapter = PacketOpenAdapter((char*)m_pName);
	if (pAdapter == NULL)
	{
		LOG_ERROR("Error in retrieving MAC address: Adapter is NULL");
		return;
	}
	PACKET_OID_DATA oidData;
    oidData.Oid = OID_802_3_CURRENT_ADDRESS;
    oidData.Length = 6;
    oidData.Data[0] = 0;
    bool status = PacketRequest(pAdapter, false, &oidData);
    if(status)
    {
        if(oidData.Length == 6)
        {
            /* copy value from driver */
        	m_xMacAddress = MacAddress(oidData.Data[0], oidData.Data[1], oidData.Data[2], oidData.Data[3], oidData.Data[4], oidData.Data[5]);
        	LOG_DEBUG("   MAC address: %s", m_xMacAddress.toString().c_str());
        } else
        {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
        	LOG_DEBUG("Error in retrieving MAC address: Size of Oid larger than 6, OidLen:%lu", oidData.Length);
            return;
        }
    }
    else
    {
    	LOG_DEBUG("Error in retrieving MAC address: PacketRequest failed");
    }
#else
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, m_pName, sizeof(ifr.ifr_name));

	int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (ioctl(socketfd, SIOCGIFHWADDR, &ifr) == -1)
	{
		LOG_DEBUG("Error in retrieving MAC address: ioctl() returned -1");
		return;
	}

    m_xMacAddress = MacAddress(ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1], ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3], ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
#endif
}

IPv4Address PcapLiveDevice::getIPv4Address()
{
	for(vector<pcap_addr_t>::iterator addrIter = m_xAddresses.begin(); addrIter != m_xAddresses.end(); addrIter++)
	{
		if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter->addr != NULL)
		{
			char addrAsString[INET6_ADDRSTRLEN];
			sockaddr2string(addrIter->addr, addrAsString);
			LOG_DEBUG("Searching address %s", addrAsString);
		}

		in_addr* currAddr = sockaddr2in_addr(addrIter->addr);
		if (currAddr == NULL)
		{
			LOG_DEBUG("Address is NULL");
			continue;
		}

		return IPv4Address(currAddr);
	}

	return IPv4Address((uint32_t)0);
}

ThreadStart PcapLiveDevice::getCaptureThreadStart()
{
	return &captureThreadMain;
}

PcapLiveDevice::~PcapLiveDevice()
{
	if (m_pName != NULL)
		delete [] m_pName;
	if (m_pDescription != NULL)
		delete [] m_pDescription;
	delete m_pCaptureThread;
	delete m_pStatsThread;
}
