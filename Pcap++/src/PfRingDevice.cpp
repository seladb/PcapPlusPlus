#ifdef USE_PF_RING

#define LOG_MODULE PcapLogModulePfRingDevice

#include <PfRingDevice.h>
#include <Logger.h>
#include <PlatformSpecificUtils.h>
#include <errno.h>


#define DEFAULT_PF_RING_SNAPLEN 128


PfRingDevice::PfRingDevice(const char* deviceName) : m_MacAddress(MacAddress::Zero)
{
	m_PcapDescriptor = NULL; //not used in this class
	m_NumOfOpenedRxChannels = 0;
	m_DeviceOpened = false;
	strcpy(m_DeviceName, deviceName);
	m_InterfaceIndex = -1;
	m_StopThread = true;
	m_OnPacketsArriveCallback = NULL;
	m_OnPacketsArriveUserCookie = NULL;
	m_ReentrantMode = false;
	m_HwClockEnabled = false;
}

PfRingDevice::~PfRingDevice()
{
	close();
}


bool PfRingDevice::open()
{
	if (m_DeviceOpened)
	{
		LOG_ERROR("Device already opened");
		return false;
	}

	m_NumOfOpenedRxChannels = 0;

	LOG_DEBUG("Trying to open device [%s]", m_DeviceName);
	int res = openSingleRxChannel(m_DeviceName, &m_PfRingDescriptors[0]);
	if (res == 0)
	{
		LOG_DEBUG("Succeeded opening device [%s]", m_DeviceName);
		m_NumOfOpenedRxChannels = 1;
		m_DeviceOpened = true;
		return true;
	}
	else if (res == 1)
		LOG_ERROR("Couldn't open a ring on device [%s]", m_DeviceName);
	else if (res == 2)
		LOG_ERROR("Unable to enable ring for device [%s]", m_DeviceName);

	return false;
}


bool PfRingDevice::openSingleRxChannel(uint8_t channelId)
{
	uint8_t channelIds[1] = { channelId };
	return openMultiRxChannels(channelIds, 1);
}

int PfRingDevice::openSingleRxChannel(const char* deviceName, pfring** ring)
{
	uint32_t flags = PF_RING_PROMISC | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;
	*ring = pfring_open(deviceName, DEFAULT_PF_RING_SNAPLEN, flags);

	if (*ring == NULL)
	{
		return 1;
	}
	LOG_DEBUG("pfring_open Succeeded for device [%s]", deviceName);

	if (getIsHwClockEnable())
	{
		setPfRingDeviceClock(*ring);
		LOG_DEBUG("H/W clock set for device [%s]", deviceName);
	}

	if (pfring_enable_rss_rehash(*ring) < 0 || pfring_enable_ring(*ring) < 0)
	{
	    pfring_close(*ring);
	    return 2;
	}

	LOG_DEBUG("pfring enabled for device [%s]", deviceName);

	return 0;
}

bool PfRingDevice::setPfRingDeviceClock(pfring* ring)
{
    struct timespec ltime;
    if (clock_gettime(CLOCK_REALTIME, &ltime) != 0)
    {
    	LOG_ERROR("Could not set pfring devices clock, clock_gettime failed");
    	return false;
    }

   	if (pfring_set_device_clock(ring, &ltime) < 0)
   	{
   		LOG_DEBUG("Could not set pfring devices clock, pfring_set_device_clock failed");
   		return false;
   	}

    return true;
}

bool PfRingDevice::openMultiRxChannels(const uint8_t* channelIds, int numOfChannelIds)
{
	if (m_DeviceOpened)
	{
		LOG_ERROR("Device already opened");
		return false;
	}

	// I needed to add this verification because PF_RING doesn't provide it.
	// It allows opening the device on a channel that doesn't exist, but of course no packets will be captured
	uint8_t totalChannels = getTotalNumOfRxChannels();
	for (int i = 0; i < numOfChannelIds; i++)
	{
		uint8_t channelId = channelIds[i];
		if (channelId >= totalChannels)
		{
			LOG_ERROR("Trying to open the device with a RX channel that doesn't exist. Total RX channels are [%d], tried to open channel [%d]", totalChannels, channelId);
			return false;
		}
	}

	m_NumOfOpenedRxChannels = 0;

	for (int i = 0; i < numOfChannelIds; i++)
	{
		uint8_t channelId = channelIds[i];
		char ringName[32];
		snprintf(ringName, sizeof(ringName), "%s@%d", m_DeviceName, channelId);
		LOG_DEBUG("Trying to open device [%s] on channel [%d]. Channel name [%s]", m_DeviceName, channelId, ringName);
		int res = openSingleRxChannel(ringName, &m_PfRingDescriptors[i]);
		if (res == 0)
		{
			LOG_DEBUG("Succeeded opening device [%s] on channel [%d]. Channel name [%s]", m_DeviceName, channelId, ringName);
			m_NumOfOpenedRxChannels++;
			continue;
		}
		else if (res == 1)
			LOG_ERROR("Couldn't open a ring on channel [%d] for device [%s]", channelId, m_DeviceName);
		else if (res == 2)
			LOG_ERROR("Unable to enable ring on channel [%d] for device [%s]", channelId, m_DeviceName);

		break;
	}

	if (m_NumOfOpenedRxChannels < numOfChannelIds)
	{
		// if an error occurred, close all rings from index=0 to index=m_NumOfOpenedRxChannels-1
		// there's no need to close m_PfRingDescriptors[m_NumOfOpenedRxChannels] because it has already been
		// closed by openSingleRxChannel
		for (int i = 0; i < m_NumOfOpenedRxChannels-1; i++)
		{
			pfring_close(m_PfRingDescriptors[i]);
		}

		m_NumOfOpenedRxChannels = 0;
		return false;
	}

	m_DeviceOpened = true;

	return true;
}

bool PfRingDevice::openMultiRxChannels(uint8_t numOfRxChannelsToOpen, ChannelDistribution dist)
{
	if (m_DeviceOpened)
		return true;

	m_NumOfOpenedRxChannels = 0;

	if (numOfRxChannelsToOpen > MAX_NUM_RX_CHANNELS)
	{
		LOG_ERROR("Cannot open more than [%d] channels", MAX_NUM_RX_CHANNELS);
		return false;
	}

	uint32_t flags = PF_RING_PROMISC | PF_RING_REENTRANT | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;

	uint8_t numOfRxChannelsOnNIC = getTotalNumOfRxChannels();
	LOG_DEBUG("NIC has %d RX channels", numOfRxChannelsOnNIC);

	uint8_t numOfRingsPerRxChannel = numOfRxChannelsToOpen / numOfRxChannelsOnNIC;
	uint8_t remainderRings = numOfRxChannelsToOpen % numOfRxChannelsOnNIC;

	cluster_type clusterType = (dist == RoundRobin) ? cluster_round_robin : cluster_per_flow;

	int ringsOpen = 0;
	for (uint8_t channelId = 0; channelId < numOfRxChannelsOnNIC; channelId++)
	{
		// no more channels to open
		if (numOfRingsPerRxChannel == 0 && remainderRings == 0)
			break;

		char ringName[32];
		snprintf(ringName, sizeof(ringName), "%s@%d", m_DeviceName, channelId);

		// open numOfRingsPerRxChannel rings per RX channel
		for (uint8_t ringId = 0; ringId < numOfRingsPerRxChannel; ringId++)
		{
			m_PfRingDescriptors[ringsOpen] = pfring_open(ringName, DEFAULT_PF_RING_SNAPLEN, flags);
			if (m_PfRingDescriptors[ringsOpen] == NULL)
			{
				LOG_ERROR("Couldn't open a ring on channel [%d]", channelId);
				break;
			}

			// setting a cluster for all rings in the same channel to enable hashing between them
			if (pfring_set_cluster(m_PfRingDescriptors[ringsOpen], channelId+1, clusterType) < 0)
			{
				LOG_ERROR("Couldn't set ring [%d] in channel [%d] to the cluster [%d]", ringId, channelId, channelId+1);
				break;
			}

			ringsOpen++;
		}

		// open one more ring if remainder > 0
		if (remainderRings > 0)
		{
			m_PfRingDescriptors[ringsOpen] = pfring_open(ringName, DEFAULT_PF_RING_SNAPLEN, flags);
			if (m_PfRingDescriptors[ringsOpen] == NULL)
			{
				LOG_ERROR("Couldn't open a ring on channel [%d]", channelId);
				break;
			}

			// setting a cluster for all rings in the same channel to enable hashing between them
			if (pfring_set_cluster(m_PfRingDescriptors[ringsOpen], channelId, clusterType) < 0)
			{
				LOG_ERROR("Couldn't set ring [%d] in channel [%d] to the cluster [%d]", numOfRingsPerRxChannel+1, channelId, channelId);
				break;

			}

			ringsOpen++;
			remainderRings--;
			LOG_DEBUG("Opened %d rings on channel [%d]", numOfRingsPerRxChannel+1, channelId);
		}
		else
			LOG_DEBUG("Opened %d rings on channel [%d]", numOfRingsPerRxChannel, channelId);
	}

	if (ringsOpen < numOfRxChannelsToOpen)
	{
	    for (uint8_t i = 0; i < ringsOpen; i++)
	    	pfring_close(m_PfRingDescriptors[i]);
	    return false;
	}

	if (getIsHwClockEnable())
	{
		for (int i = 0; i < ringsOpen; i++)
		{
			if (setPfRingDeviceClock(m_PfRingDescriptors[i]))
				LOG_DEBUG("H/W clock set for device [%s]", m_DeviceName);
		}
	}

	// enable all rings
	for (int i = 0; i < ringsOpen; i++)
	{
		if (pfring_enable_rss_rehash(m_PfRingDescriptors[i]) < 0 || pfring_enable_ring(m_PfRingDescriptors[i]) < 0)
		{
		    LOG_ERROR("Unable to enable ring [%d] for device [%s]", i, m_DeviceName);
		    // close all pfring's that were enabled until now
		    for (int j = 0; j <ringsOpen; j++)
		    	pfring_close(m_PfRingDescriptors[j]);
		    return false;
		}
	}

	m_NumOfOpenedRxChannels = ringsOpen;

	m_DeviceOpened = true;
	return true;
}

uint8_t PfRingDevice::getTotalNumOfRxChannels()
{
	if (m_NumOfOpenedRxChannels > 0)
	{
		uint8_t res = pfring_get_num_rx_channels(m_PfRingDescriptors[0]);
		return res;
	}
	else
	{
		uint32_t flags = PF_RING_PROMISC | PF_RING_REENTRANT | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;
		pfring* ring = pfring_open(m_DeviceName, DEFAULT_PF_RING_SNAPLEN, flags);
		uint8_t res = pfring_get_num_rx_channels(ring);
		pfring_close(ring);
		return res;
	}
}


bool PfRingDevice::setFilter(string filterAsString)
{
	for (int i = 0; i < m_NumOfOpenedRxChannels; i++)
	{
		int res = pfring_set_bpf_filter(m_PfRingDescriptors[i], (char*)filterAsString.c_str());
		if(res < 0)
		{
			LOG_ERROR("Couldn't set filter '%s'", filterAsString.c_str());
			return false;
		}
	}

    LOG_DEBUG("Successfully set filter '%s'", filterAsString.c_str());
    return true;
}


void PfRingDevice::close()
{
	for (int i = 0; i < m_NumOfOpenedRxChannels; i++)
		pfring_close(m_PfRingDescriptors[i]);
	m_DeviceOpened = false;
	clearCoreConfiguration();
	m_NumOfOpenedRxChannels = 0;
	LOG_DEBUG("Device [%s] closed", m_DeviceName);
}

bool PfRingDevice::initCoreConfigurationByCoreMask(CoreMask coreMask)
{
	int i = 0;
	int numOfCores = getNumOfCores();
	clearCoreConfiguration();
	while ((coreMask != 0) && (i < numOfCores))
	{
		if (coreMask & 1)
		{
			m_CoreConfiguration[i].IsInUse = true;
		}

		coreMask = coreMask >> 1;
		i++;
	}

	if (coreMask != 0) // this mean coreMask contains a core that doesn't exist
	{
		LOG_ERROR("Trying to use a core [%d] that doesn't exist while machine has %d cores", i, numOfCores);
		clearCoreConfiguration();
		return false;
	}

	return true;
}

bool PfRingDevice::startCaptureMultiThread(OnPfRingPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie, CoreMask coreMask)
{
	if (!initCoreConfigurationByCoreMask(coreMask))
		return false;

	if (m_NumOfOpenedRxChannels != getCoresInUseCount())
	{
		LOG_ERROR("Cannot use a different number of channels and cores. Opened %d channels but set %d cores in core mask", m_NumOfOpenedRxChannels, getCoresInUseCount());
		clearCoreConfiguration();
		return false;
	}

	m_StopThread = false;
	int rxChannel = 0;
	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
		if (!m_CoreConfiguration[coreId].IsInUse)
			continue;

		m_ReentrantMode = true;

		m_OnPacketsArriveCallback = onPacketsArrive;
		m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

		// create a new thread
		m_CoreConfiguration[coreId].Channel = m_PfRingDescriptors[rxChannel++];
		int err = pthread_create(&(m_CoreConfiguration[coreId].RxThread), NULL, captureThreadMain, (void*)this);
		if (err != 0)
		{
			LOG_ERROR("Cannot create capture thread #%d for device '%s': [%s]", coreId, m_DeviceName, strerror(err));
			m_CoreConfiguration[coreId].clear();
			return false;
		}

		// set affinity to cores
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(coreId, &cpuset);
		if((err = pthread_setaffinity_np(m_CoreConfiguration[coreId].RxThread, sizeof(cpu_set_t), &cpuset)) != 0)
		{
			LOG_ERROR("Error while binding thread to core %d: errno=%i", coreId, err);
			clearCoreConfiguration();
			return false;
		}

	}

	return true;
}

bool PfRingDevice::startCaptureSingleThread(OnPfRingPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie)
{
	if (m_NumOfOpenedRxChannels != 1)
	{
		LOG_ERROR("Cannot start capturing on a single thread when more than 1 RX channel is opened");
		return false;
	}

	LOG_DEBUG("Trying to start capturing on a single thread for device [%s]", m_DeviceName);

	clearCoreConfiguration();

	m_OnPacketsArriveCallback = onPacketsArrive;
	m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

	m_StopThread = false;

	m_ReentrantMode = false;

	pthread_t newThread;
	int err = pthread_create(&newThread, NULL, captureThreadMain, (void*)this);
	if (err != 0)
	{
		LOG_ERROR("Cannot create capture thread for device '%s': [%s]", m_DeviceName, strerror(err));
		return false;
	}

	cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
	pthread_getaffinity_np(newThread, sizeof(cpu_set_t), &cpuset);
    for (int i = 0; i < CPU_SETSIZE; i++)
    {
        if (CPU_ISSET(i, &cpuset))
        {
        	m_CoreConfiguration[i].IsInUse = true;
        	m_CoreConfiguration[i].Channel = m_PfRingDescriptors[0];
        	m_CoreConfiguration[i].RxThread = newThread;
        	m_CoreConfiguration[i].IsAffinitySet = false;
        }
    }

	LOG_DEBUG("Capturing started for device [%s]", m_DeviceName);
	return true;
}

void PfRingDevice::stopCapture()
{
	LOG_DEBUG("Trying to stop capturing on device [%s]", m_DeviceName);
	m_StopThread = true;
	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
		if (!m_CoreConfiguration[coreId].IsInUse)
			continue;
		pthread_join(m_CoreConfiguration[coreId].RxThread, NULL);
		LOG_DEBUG("Thread on core [%d] stopped", coreId);
	}

	LOG_DEBUG("All capturing threads stopped");
}

void* PfRingDevice::captureThreadMain(void *ptr)
{
	PfRingDevice* device = (PfRingDevice*)ptr;
	int coreId = device->getCurrentCoreId().Id;
	pfring* ring = NULL;

	LOG_DEBUG("Starting capture thread %d", coreId);

	ring = device->m_CoreConfiguration[coreId].Channel;

	if (ring == NULL)
	{
		LOG_ERROR("Couldn't find ring for core %d. Exiting capture thread", coreId);
		return (void*)NULL;
	}

	while (!device->m_StopThread)
	{
		// if buffer is NULL PF_RING avoids copy of the data
		uint8_t* buffer = NULL;
		uint32_t bufferLen = 0;

		// in multi-threaded mode flag PF_RING_REENTRANT is set, and this flag doesn't work with zero copy
		// so I need to allocate a buffer and set buffer to point to it
		if (device->m_ReentrantMode)
		{
			uint8_t tempBuffer[MAX_PACKET_SIZE];
			buffer = tempBuffer;
			bufferLen = MAX_PACKET_SIZE;
		}

		struct pfring_pkthdr pktHdr;
		int recvRes = pfring_recv(ring, &buffer, bufferLen, &pktHdr, 0);
		if (recvRes > 0)
		{
			// if caplen < len it means we don't have the whole packet. Treat this case as packet drop
			// TODO: add this packet to dropped packet stats
//			if (pktHdr.caplen != pktHdr.len)
//			{
//				LOG_ERROR("Packet dropped due to len != caplen");
//				continue;
//			}

			RawPacket rawPacket(buffer, pktHdr.caplen, pktHdr.ts, false);
			device->m_OnPacketsArriveCallback(&rawPacket, 1, coreId, device, device->m_OnPacketsArriveUserCookie);
		}
		else if (recvRes < 0)
		{
			LOG_ERROR("pfring_recv returned an error: [Err=%d]", recvRes);
		}
	}

	LOG_DEBUG("Exiting capture thread %d", coreId);
	return (void*)NULL;
}

void PfRingDevice::getThreadStatistics(SystemCore core, pcap_stat& stats)
{
	pfring* ring = NULL;
	uint8_t coreId = core.Id;

	ring = m_CoreConfiguration[coreId].Channel;

	if (ring != NULL)
	{
		pfring_stat tempStats;
		if (pfring_stats(ring, &tempStats) < 0)
		{
			LOG_ERROR("Can't retrieve statistics for core [%d], pfring_stats failed", coreId);
			return;
		}
		stats.ps_drop = (u_int)tempStats.drop;
		stats.ps_ifdrop = (u_int)tempStats.drop;
		stats.ps_recv = (u_int)tempStats.recv;
	}
	else
	{
		LOG_ERROR("Core [%d] is not in use, can't retrieve statistics", coreId);
	}
}

void PfRingDevice::getCurrentThreadStatistics(pcap_stat& stats)
{
	getThreadStatistics(getCurrentCoreId(), stats);
}

void PfRingDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_drop = 0;
	stats.ps_ifdrop = 0;
	stats.ps_recv = 0;

	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
		if (!m_CoreConfiguration[coreId].IsInUse)
			continue;

		pcap_stat tempStat;
		getThreadStatistics(SystemCores::IdToSystemCore[coreId], tempStat);
		stats.ps_drop += tempStat.ps_drop;
		stats.ps_ifdrop += tempStat.ps_ifdrop;
		stats.ps_recv += tempStat.ps_recv;

		if (!m_CoreConfiguration[coreId].IsAffinitySet)
			break;
	}
}

void PfRingDevice::clearCoreConfiguration()
{
	for (int i = 0; i < MAX_NUM_OF_CORES; i++)
		m_CoreConfiguration[i].clear();
}

int PfRingDevice::getCoresInUseCount()
{
	int res = 0;
	for (int i = 0; i < MAX_NUM_OF_CORES; i++)
		if (m_CoreConfiguration[i].IsInUse)
			res++;

	return res;
}

void PfRingDevice::setPfRingDeviceAttributes()
{
	if (m_InterfaceIndex > -1)
		return;

	pfring* ring = NULL;
	bool closeRing = false;
	if (m_NumOfOpenedRxChannels > 0)
		ring = m_PfRingDescriptors[0];
	else
	{
		uint32_t flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
		ring = pfring_open(m_DeviceName, DEFAULT_PF_RING_SNAPLEN, flags);
		closeRing = true;
	}

	if (ring == NULL)
	{
		LOG_ERROR("Could not open a pfring for setting device attributes: MAC address, interface index and HW clock");
		return;
	}

	// set device MAC address

	uint8_t macAddress[6];
	if (pfring_get_bound_device_address(ring, macAddress) < 0)
		LOG_ERROR("Unable to read the device MAC address");
	else
	{
		// set interface ID
		m_MacAddress = MacAddress(macAddress);
		if (pfring_get_bound_device_ifindex(ring, &m_InterfaceIndex) < 0)
			LOG_ERROR("Unable to read interface index of device");
		else
		{
			m_HwClockEnabled = setPfRingDeviceClock(ring);
		}
		if (LoggerPP::getInstance().isDebugEnabled(PcapLogModulePfRingDevice))
		{
			string hwEnabled = (m_HwClockEnabled ? "enabled" : "disabled");
			LOG_DEBUG("Capturing from %s [%s][ifIndex: %d], HW clock %s", m_DeviceName, m_MacAddress.toString().c_str(), m_InterfaceIndex, hwEnabled.c_str());
		}
	}

	if (closeRing)
		pfring_close(ring);
}

#endif /* USE_PF_RING */
