#define LOG_MODULE PcapLogModuleLiveDevice

#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#ifndef  _MSC_VER
#include <unistd.h>
#endif // ! _MSC_VER
#include <pthread.h>
#include "Logger.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "IpUtils.h"
#if defined(WIN32) || defined(WINx64)
#include <ws2tcpip.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#endif
#ifdef MAC_OS_X
#include <net/if_dl.h>
#endif

// On Mac OS X timeout of -1 causes pcap_open_live to fail so value of 1ms is set here.
// On Linux and Windows this is not the case so we keep the -1 value
#ifdef MAC_OS_X
#define LIBPCAP_OPEN_LIVE_TIMEOUT 1
#else
#define LIBPCAP_OPEN_LIVE_TIMEOUT -1
#endif

static const int DEFAULT_SNAPLEN = 9000;

namespace pcpp
{

struct PcapThread
{
	pthread_t pthread;
};

PcapLiveDevice::PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway) : IPcapDevice(),
		m_MacAddress(""), m_DefaultGateway(IPv4Address::Zero)
{

	m_Name = NULL;
	m_Description = NULL;
	m_DeviceMtu = 0;

	m_IsLoopback = (pInterface->flags & 0x1) == PCAP_IF_LOOPBACK;

	int strLength = strlen(pInterface->name)+1;
	m_Name = new char[strLength];
	strncpy((char*)m_Name, pInterface->name, strLength);

	strLength = 1;
	if (pInterface->description != NULL)
		strLength += strlen(pInterface->description);
	m_Description = new char[strLength];
	if (pInterface->description != NULL)
		strncpy((char*)m_Description, pInterface->description, strLength);
	else
		strncpy((char*)m_Description, "", strLength);
	LOG_DEBUG("Added live device: name=%s; desc=%s", m_Name, m_Description);
	LOG_DEBUG("   Addresses:");
	while (pInterface->addresses != NULL)
	{
		m_Addresses.insert(m_Addresses.end(), *(pInterface->addresses));
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

	if (calculateDefaultGateway)
	{
		setDefaultGateway();
		LOG_DEBUG("   Default Gateway: %s", m_DefaultGateway.toString().c_str());
	}

	//init all other members
	m_CaptureThreadStarted = false;
	m_StatsThreadStarted = false;  m_IsLoopback = false;
	m_StopThread = false;
	m_CaptureThread = new PcapThread();
	m_StatsThread = new PcapThread();
	memset(m_CaptureThread, 0, sizeof(PcapThread));
	memset(m_StatsThread, 0, sizeof(PcapThread));
	m_cbOnPacketArrives = NULL;
	m_cbOnStatsUpdate = NULL;
	m_cbOnPacketArrivesBlockingMode = NULL;
	m_cbOnPacketArrivesBlockingModeUserCookie = NULL;
	m_IntervalToUpdateStats = 0;
	m_cbOnPacketArrivesUserCookie = NULL;
	m_cbOnStatsUpdateUserCookie = NULL;
	m_CaptureCallbackMode = true;
	m_CapturedPackets = NULL;
	if (calculateMacAddress)
	{
		setDeviceMacAddress();
		if (m_MacAddress.isValid())
			LOG_DEBUG("   MAC addr: %s", m_MacAddress.toString().c_str());
	}
}

void PcapLiveDevice::onPacketArrives(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)user;
	if (pThis == NULL)
	{
		LOG_ERROR("Unable to extract PcapLiveDevice instance");
		return;
	}

	RawPacket rawPacket(packet, pkthdr->caplen, pkthdr->ts, false, LINKTYPE_ETHERNET);

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

	uint8_t* packetData = new uint8_t[pkthdr->caplen];
	memcpy(packetData, packet, pkthdr->caplen);
	RawPacket* rawPacketPtr = new RawPacket(packetData, pkthdr->caplen, pkthdr->ts, true, LINKTYPE_ETHERNET);
	pThis->m_CapturedPackets->pushBack(rawPacketPtr);
}

void PcapLiveDevice::onPacketArrivesBlockingMode(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)user;
	if (pThis == NULL)
	{
		LOG_ERROR("Unable to extract PcapLiveDevice instance");
		return;
	}

	RawPacket rawPacket(packet, pkthdr->caplen, pkthdr->ts, false, LINKTYPE_ETHERNET);

	if (pThis->m_cbOnPacketArrivesBlockingMode != NULL)
		if (pThis->m_cbOnPacketArrivesBlockingMode(&rawPacket, pThis, pThis->m_cbOnPacketArrivesBlockingModeUserCookie))
			pThis->m_StopThread = true;
}

void* PcapLiveDevice::captureThreadMain(void *ptr)
{
	PcapLiveDevice* pThis = (PcapLiveDevice*)ptr;
	if (pThis == NULL)
	{
		LOG_ERROR("Capture thread: Unable to extract PcapLiveDevice instance");
		return 0;
	}

	LOG_DEBUG("Started capture thread for device '%s'", pThis->m_Name);
	if (pThis->m_CaptureCallbackMode)
	{
		while (!pThis->m_StopThread)
			pcap_dispatch(pThis->m_PcapDescriptor, -1, onPacketArrives, (uint8_t*)pThis);
	}
	else
	{
		while (!pThis->m_StopThread)
			pcap_dispatch(pThis->m_PcapDescriptor, 100, onPacketArrivesNoCallback, (uint8_t*)pThis);

	}
	LOG_DEBUG("Ended capture thread for device '%s'", pThis->m_Name);
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

	LOG_DEBUG("Started stats thread for device '%s'", pThis->m_Name);
	while (!pThis->m_StopThread)
	{
		pcap_stat stats;
		pThis->getStatistics(stats);
		pThis->m_cbOnStatsUpdate(stats, pThis->m_cbOnStatsUpdateUserCookie);
		PCAP_SLEEP(pThis->m_IntervalToUpdateStats);
	}
	LOG_DEBUG("Ended stats thread for device '%s'", pThis->m_Name);
	return 0;
}

pcap_t* PcapLiveDevice::doOpen(DeviceMode mode)
{
	char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
	pcap_t* pcap = pcap_create(m_Name, errbuf);
	if (!pcap)
	{
		LOG_ERROR("%s", errbuf);
		return pcap;
	}
	int ret = pcap_set_snaplen(pcap, DEFAULT_SNAPLEN);
	if (ret != 0)
	{
		LOG_ERROR("%s", pcap_geterr(pcap));
	}
	ret = pcap_set_promisc(pcap, mode);
	if (ret != 0)
	{
		LOG_ERROR("%s", pcap_geterr(pcap));
	}
	ret = pcap_set_timeout(pcap, LIBPCAP_OPEN_LIVE_TIMEOUT);
	if (ret != 0)
	{
		LOG_ERROR("%s", pcap_geterr(pcap));
	}

#ifdef HAS_PCAP_IMMEDIATE_MODE
	ret = pcap_set_immediate_mode(pcap, 1);
	if (ret == 0)
	{
		LOG_DEBUG("Immediate mode is activated");
	} else {
		LOG_ERROR("Failed to activate immediate mode, error code: '%d', error message: '%s'",
			       ret, pcap_geterr(pcap));
	}
#endif
	LOG_DEBUG("LibPcap version: %s", pcap_lib_version());
	ret = pcap_activate(pcap);
	if (ret != 0)
	{
		LOG_ERROR("%s", pcap_geterr(pcap));
		pcap_close(pcap);
		pcap = NULL;
	}
	return pcap;
}

bool PcapLiveDevice::open(DeviceMode mode)
{
	m_PcapDescriptor = doOpen(mode);
	m_PcapSendDescriptor = doOpen(mode);
	if (m_PcapDescriptor == NULL || m_PcapSendDescriptor == NULL)
	{
		m_DeviceOpened = false;
		return false;
	}

	LOG_DEBUG("Device '%s' opened", m_Name);

	m_DeviceOpened = true;

	return true;
}

bool PcapLiveDevice::open()
{
	return open(Promiscuous);
}

void PcapLiveDevice::close()
{
	if (m_PcapDescriptor == NULL && m_PcapSendDescriptor == NULL)
	{
		LOG_DEBUG("Device '%s' already closed", m_Name);
		return;
	}

	bool sameDescriptor = (m_PcapDescriptor == m_PcapSendDescriptor);
	pcap_close(m_PcapDescriptor);
	LOG_DEBUG("Receive pcap descriptor closed");
	if (!sameDescriptor)
	{ 
		pcap_close(m_PcapSendDescriptor);
		LOG_DEBUG("Send pcap descriptor closed");
	}
	LOG_DEBUG("Device '%s' closed", m_Name);
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

	if (m_CaptureThreadStarted || m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Device '%s' already capturing or not opened", m_Name);
		return false;
	}

	m_CaptureCallbackMode = true;
	m_cbOnPacketArrives = onPacketArrives;
	m_cbOnPacketArrivesUserCookie = onPacketArrivesUserCookie;
	int err = pthread_create(&(m_CaptureThread->pthread), NULL, getCaptureThreadStart(), (void*)this);
	if (err != 0)
	{
		LOG_ERROR("Cannot create LiveCapture thread for device '%s': [%s]", m_Name, strerror(err));
		return false;
	}
	m_CaptureThreadStarted = true;
	LOG_DEBUG("Successfully created capture thread for device '%s'. Thread id: %s", m_Name, printThreadId(m_CaptureThread).c_str());

	if (onStatsUpdate != NULL && intervalInSecondsToUpdateStats > 0)
	{
		m_cbOnStatsUpdate = onStatsUpdate;
		m_cbOnStatsUpdateUserCookie = onStatsUpdateUserCookie;
		int err = pthread_create(&(m_StatsThread->pthread), NULL, &statsThreadMain, (void*)this);
		if (err != 0)
		{
			LOG_ERROR("Cannot create LiveCapture Statistics thread for device '%s': [%s]", m_Name, strerror(err));
			return false;
		}
		m_StatsThreadStarted = true;
		LOG_DEBUG("Successfully created stats thread for device '%s'. Thread id: %s", m_Name, printThreadId(m_StatsThread).c_str());
	}

	return true;
}

bool PcapLiveDevice::startCapture(RawPacketVector& capturedPacketsVector)
{
	m_CapturedPackets = &capturedPacketsVector;
	m_CapturedPackets->clear();

	if (m_CaptureThreadStarted || m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Device '%s' already capturing or not opened", m_Name);
		return false;
	}

	m_CaptureCallbackMode = false;
	int err = pthread_create(&(m_CaptureThread->pthread), NULL, getCaptureThreadStart(), (void*)this);
	if (err != 0)
	{
		LOG_ERROR("Cannot create LiveCapture thread for device '%s': [%s]", m_Name, strerror(err));
		return false;
	}
	m_CaptureThreadStarted = true;
	LOG_DEBUG("Successfully created capture thread for device '%s'. Thread id: %s", m_Name, printThreadId(m_CaptureThread).c_str());

	return true;
}


int PcapLiveDevice::startCaptureBlockingMode(OnPacketArrivesStopBlocking onPacketArrives, void* userCookie, int timeout)
{
	if (m_CaptureThreadStarted || m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Device '%s' already capturing or not opened", m_Name);
		return 0;
	}

	m_cbOnPacketArrives = NULL;
	m_cbOnStatsUpdate = NULL;
	m_cbOnPacketArrivesUserCookie = NULL;
	m_cbOnStatsUpdateUserCookie = NULL;

	m_cbOnPacketArrivesBlockingMode = onPacketArrives;
	m_cbOnPacketArrivesBlockingModeUserCookie = userCookie;

	clock_t startTime = clock();
	double diffSec = 0;

	m_CaptureThreadStarted = true;
	m_StopThread = false;

	if (timeout <= 0)
	{
		while (!m_StopThread)
		{
			pcap_dispatch(m_PcapDescriptor, -1, onPacketArrivesBlockingMode, (uint8_t*)this);
		}
		diffSec = timeout;
	}
	else
	{

		while (!m_StopThread && diffSec <= (double)timeout)
		{
			pcap_dispatch(m_PcapDescriptor, -1, onPacketArrivesBlockingMode, (uint8_t*)this);
			double diffTicks = clock() - startTime;
			diffSec = diffTicks/CLOCKS_PER_SEC;
		}
	}

	m_CaptureThreadStarted = false;

	m_StopThread = false;

	m_cbOnPacketArrivesBlockingMode = NULL;
	m_cbOnPacketArrivesBlockingModeUserCookie = NULL;

	if (diffSec > (double)timeout)
		return -1;
	return 1;
}

void PcapLiveDevice::stopCapture()
{
	// in blocking mode stop capture isn't relevant
	if (m_cbOnPacketArrivesBlockingMode != NULL)
		return;

	m_StopThread = true;
	if (m_CaptureThreadStarted)
	{
		LOG_DEBUG("Stopping capture thread, waiting for it to join...");
		pthread_join(m_CaptureThread->pthread, NULL);
		m_CaptureThreadStarted = false;
	}
	LOG_DEBUG("Capture thread stopped for device '%s'", m_Name);
	if (m_StatsThreadStarted)
	{
		LOG_DEBUG("Stopping stats thread, waiting for it to join...");
		pthread_join(m_StatsThread->pthread, NULL);
		m_StatsThreadStarted = false;
		LOG_DEBUG("Stats thread stopped for device '%s'", m_Name);
	}

	PCAP_SLEEP(1);
	m_StopThread = false;
}

void PcapLiveDevice::getStatistics(pcap_stat& stats)
{
	if(pcap_stats(m_PcapDescriptor, &stats) < 0)
	{
		LOG_ERROR("Error getting statistics from live device '%s'", m_Name);
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
		LOG_ERROR("Device '%s' not opened!", m_Name);
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

	if (pcap_sendpacket(m_PcapSendDescriptor, packetData, packetDataLength) == -1)
	{
		LOG_ERROR("Error sending packet: %s\n", pcap_geterr(m_PcapSendDescriptor));
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

int PcapLiveDevice::sendPackets(const RawPacketVector& rawPackets)
{
	int packetsSent = 0;
	for (RawPacketVector::ConstVectorIterator iter = rawPackets.begin(); iter != rawPackets.end(); iter++)
	{
		if (sendPacket(**iter))
			packetsSent++;
	}

	LOG_DEBUG("%d packets sent successfully. %d packets not sent", packetsSent, (int)rawPackets.size()-packetsSent);
	return packetsSent;
}

std::string PcapLiveDevice::printThreadId(PcapThread* id)
{
    size_t i;
    std::string result("");
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
#if defined(WIN32) || defined(WINx64)

	uint32_t mtuValue = 0;
	LPADAPTER adapter = PacketOpenAdapter((char*)m_Name);
	if (adapter == NULL)
	{
		LOG_ERROR("Error in retrieving MTU: Adapter is NULL");
		return;
	}

	uint8_t buffer[512];
	PACKET_OID_DATA* oidData = (PACKET_OID_DATA*)buffer;
    oidData->Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;
    oidData->Length = sizeof(uint32_t);
    memcpy(oidData->Data, &mtuValue, sizeof(uint32_t));
    bool status = PacketRequest(adapter, false, oidData);
    if(status)
    {
        if(oidData->Length <= sizeof(uint32_t))
        {
            /* copy value from driver */
            memcpy(&mtuValue, oidData->Data, oidData->Length);
            m_DeviceMtu = mtuValue;
        } else
        {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
            LOG_ERROR("Error in retrieving MTU: Size of Oid larger than uint32_t, OidLen:%lu", oidData->Length);
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
	strncpy(ifr.ifr_name, m_Name, sizeof(ifr.ifr_name));

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
#if defined(WIN32) || defined(WINx64)

	LPADAPTER adapter = PacketOpenAdapter((char*)m_Name);
	if (adapter == NULL)
	{
		LOG_ERROR("Error in retrieving MAC address: Adapter is NULL");
		return;
	}

	uint8_t buffer[512];
	PACKET_OID_DATA* oidData = (PACKET_OID_DATA*)buffer;
    oidData->Oid = OID_802_3_CURRENT_ADDRESS;
    oidData->Length = 6;
    oidData->Data[0] = 0;
    bool status = PacketRequest(adapter, false, oidData);
    if(status)
    {
        if(oidData->Length == 6)
        {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
            /* copy value from driver */
        	m_MacAddress = MacAddress(oidData->Data[0], oidData->Data[1], oidData->Data[2], oidData->Data[3], oidData->Data[4], oidData->Data[5]);
#pragma GCC diagnostic pop
        	LOG_DEBUG("   MAC address: %s", m_MacAddress.toString().c_str());
        } else
        {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
        	LOG_DEBUG("Error in retrieving MAC address: Size of Oid larger than 6, OidLen:%lu", oidData->Length);
            return;
        }
    }
    else
    {
    	LOG_DEBUG("Error in retrieving MAC address: PacketRequest failed");
    }
#elif LINUX
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, m_Name, sizeof(ifr.ifr_name));

	int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (ioctl(socketfd, SIOCGIFHWADDR, &ifr) == -1)
	{
		LOG_DEBUG("Error in retrieving MAC address: ioctl() returned -1");
		return;
	}

    m_MacAddress = MacAddress(ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1], ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3], ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
#elif MAC_OS_X
    int	mib[6];
    size_t len;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	mib[5] = if_nametoindex(m_Name);

	if (mib[5] == 0){
		LOG_ERROR("Error in retrieving MAC address: if_nametoindex error");
		return;
	}

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
		LOG_ERROR("Error in retrieving MAC address: sysctl 1 error");
		return;
	}

	uint8_t buf[len];

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		LOG_ERROR("Error in retrieving MAC address: sysctl 2 error");
		return;
	}

	struct if_msghdr*ifm = (struct if_msghdr *)buf;
	struct sockaddr_dl* sdl = (struct sockaddr_dl *)(ifm + 1);
	uint8_t* ptr = (uint8_t*)LLADDR(sdl);
	m_MacAddress = MacAddress(ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#endif
}

void PcapLiveDevice::setDefaultGateway()
{
#if defined(WIN32) || defined(WINx64)
	ULONG outBufLen = sizeof (IP_ADAPTER_INFO);
	uint8_t* buffer = new uint8_t[outBufLen];
	PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)buffer;
	DWORD retVal = 0;

	retVal = GetAdaptersInfo(adapterInfo, &outBufLen);
	uint8_t* buffer2 = new uint8_t[outBufLen];
    if (retVal == ERROR_BUFFER_OVERFLOW)
        adapterInfo = (IP_ADAPTER_INFO *)buffer2;

    retVal = GetAdaptersInfo(adapterInfo, &outBufLen);

	if (retVal == NO_ERROR)
	{
		PIP_ADAPTER_INFO curAdapterInfo = adapterInfo;
		while (curAdapterInfo != NULL)
		{
			std::string name(m_Name);
			if (name.find(curAdapterInfo->AdapterName) != std::string::npos)
				m_DefaultGateway = IPv4Address(curAdapterInfo->GatewayList.IpAddress.String);

            curAdapterInfo = curAdapterInfo->Next;
		}
	}
	else
	{
		LOG_ERROR("Error retrieving default gateway address");
	}

	delete[] buffer;
	delete[] buffer2;
#elif LINUX
	std::ifstream routeFile("/proc/net/route");
	std::string line;
	while (std::getline(routeFile, line))
	{
	    std::stringstream lineStream(line);
	    std::string interfaceName;
	    std::getline(lineStream, interfaceName, '\t');
	    if (interfaceName != std::string(m_Name))
	    	continue;

	    std::string interfaceDest;
	    std::getline(lineStream, interfaceDest, '\t');
	    if (interfaceDest != "00000000")
	    	continue;

	    std::string interfaceGateway;
	    std::getline(lineStream, interfaceGateway, '\t');

	    uint32_t interfaceGatewayIPInt;
	    std::stringstream interfaceGatewayStream;
	    interfaceGatewayStream << std::hex << interfaceGateway;
	    interfaceGatewayStream >> interfaceGatewayIPInt;
	    m_DefaultGateway = IPv4Address(interfaceGatewayIPInt);
	}
#elif MAC_OS_X
	std::string ifaceStr = std::string(m_Name);
	std::string command = "netstat -nr | grep default | grep " + ifaceStr;
	std::string ifaceInfo = executeShellCommand(command);
	if (ifaceInfo == "")
	{
		LOG_DEBUG("Error retrieving default gateway address: couldn't get netstat output");
		return;
	}

	// remove the word "default"
	ifaceInfo.erase(0, 7);

	// remove spaces
	while (ifaceInfo.at(0) == ' ')
		ifaceInfo.erase(0,1);

	// erase string after gateway IP address
	ifaceInfo.resize(ifaceInfo.find(' ', 0));

	m_DefaultGateway = IPv4Address(ifaceInfo);
#endif
}

IPv4Address PcapLiveDevice::getIPv4Address()
{
	for(std::vector<pcap_addr_t>::iterator addrIter = m_Addresses.begin(); addrIter != m_Addresses.end(); addrIter++)
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

	return IPv4Address::Zero;
}


IPv4Address PcapLiveDevice::getDefaultGateway()
{
	return m_DefaultGateway;
}

std::vector<IPv4Address>& PcapLiveDevice::getDnsServers()
{
	return PcapLiveDeviceList::getInstance().getDnsServers();
}

ThreadStart PcapLiveDevice::getCaptureThreadStart()
{
	return &captureThreadMain;
}

PcapLiveDevice::~PcapLiveDevice()
{
	if (m_Name != NULL)
		delete [] m_Name;
	if (m_Description != NULL)
		delete [] m_Description;
	delete m_CaptureThread;
	delete m_StatsThread;
}

} // namespace pcpp
