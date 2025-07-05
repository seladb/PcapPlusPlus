// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModulePfRingDevice

#include "PfRingDevice.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "Logger.h"
#include <errno.h>
#include <pfring.h>
#include <pthread.h>
#include <chrono>
#include <algorithm>
#include <vector>

#define DEFAULT_PF_RING_SNAPLEN 1600

namespace pcpp
{
	namespace
	{
		void setThreadCoreAffinity(std::thread& thread, int coreId)
		{
			if (thread.get_id() == std::thread::id{})
			{
				throw std::invalid_argument("Can't set core affinity for a non-joinable thread");
			}

			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			CPU_SET(coreId, &cpuset);
			int err = pthread_setaffinity_np(thread.native_handle(), sizeof(cpu_set_t), &cpuset);
			if (err != 0)
			{
				throw std::runtime_error("Error while binding thread to core " + std::to_string(coreId) +
				                         ": errno=" + std::to_string(err));
			}
		}
	}  // namespace

	PfRingDevice::PfRingDevice(const char* deviceName) : m_MacAddress(MacAddress::Zero)
	{
		m_DeviceOpened = false;
		m_DeviceName = std::string(deviceName);
		m_InterfaceIndex = -1;
		m_StopThread = true;
		m_OnPacketsArriveCallback = nullptr;
		m_OnPacketsArriveUserCookie = nullptr;
		m_ReentrantMode = false;
		m_HwClockEnabled = false;
		m_DeviceMTU = 0;
		m_IsFilterCurrentlySet = false;

		m_PfRingDescriptors.reserve(MAX_NUM_RX_CHANNELS);
	}

	PfRingDevice::~PfRingDevice()
	{
		close();
	}

	bool PfRingDevice::open()
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
			return false;
		}

		PCPP_LOG_DEBUG("Trying to open device [" << m_DeviceName << "]");
		pfring* newChannel;
		int res = openSingleRxChannel(m_DeviceName.c_str(), newChannel);
		if (res == 0)
		{
			// Adds the newly opened channel to the list of opened channels
			m_PfRingDescriptors.push_back(newChannel);
			m_DeviceOpened = true;
			PCPP_LOG_DEBUG("Succeeded opening device [" << m_DeviceName << "]");
			return true;
		}
		else if (res == 1)
			PCPP_LOG_ERROR("Couldn't open a ring on device [" << m_DeviceName << "]");
		else if (res == 2)
			PCPP_LOG_ERROR("Unable to enable ring for device [" << m_DeviceName << "]");

		return false;
	}

	bool PfRingDevice::openSingleRxChannel(uint8_t channelId)
	{
		uint8_t channelIds[1] = { channelId };
		return openMultiRxChannels(channelIds, 1);
	}

	int PfRingDevice::openSingleRxChannel(const char* deviceName, pfring*& ring)
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
			return false;
		}

		uint32_t flags = PF_RING_PROMISC | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;
		ring = pfring_open(deviceName, DEFAULT_PF_RING_SNAPLEN, flags);

		if (ring == nullptr)
		{
			return 1;
		}
		PCPP_LOG_DEBUG("pfring_open Succeeded for device [" << m_DeviceName << "]");

		if (getIsHwClockEnable())
		{
			setPfRingDeviceClock(ring);
			PCPP_LOG_DEBUG("H/W clock set for device [" << m_DeviceName << "]");
		}

		if (pfring_enable_rss_rehash(ring) < 0 || pfring_enable_ring(ring) < 0)
		{
			pfring_close(ring);
			return 2;
		}

		PCPP_LOG_DEBUG("pfring enabled for device [" << m_DeviceName << "]");

		return 0;
	}

	void PfRingDevice::closeAllRxChannels()
	{
		for (pfring* rxChannel : m_PfRingDescriptors)
		{
			if (rxChannel != nullptr)
			{
				pfring_close(rxChannel);
			}
		}
		m_PfRingDescriptors.clear();
	}

	bool PfRingDevice::setPfRingDeviceClock(pfring* ring)
	{
		struct timespec ltime;
		if (clock_gettime(CLOCK_REALTIME, &ltime) != 0)
		{
			PCPP_LOG_ERROR("Could not set pfring devices clock, clock_gettime failed");
			return false;
		}

		if (pfring_set_device_clock(ring, &ltime) < 0)
		{
			PCPP_LOG_DEBUG("Could not set pfring devices clock, pfring_set_device_clock failed");
			return false;
		}

		return true;
	}

	bool PfRingDevice::openMultiRxChannels(const uint8_t* channelIds, int numOfChannelIds)
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
			return false;
		}

		if (numOfChannelIds < 0)
		{
			throw std::invalid_argument("numOfChannelIds must be >= 0");
		}

		// I needed to add this verification because PF_RING doesn't provide it.
		// It allows opening the device on a channel that doesn't exist, but of course no packets will be captured
		uint8_t totalChannels = getTotalNumOfRxChannels();
		for (int i = 0; i < numOfChannelIds; i++)
		{
			uint8_t channelId = channelIds[i];
			if (channelId >= totalChannels)
			{
				PCPP_LOG_ERROR("Trying to open the device with a RX channel that doesn't exist. Total RX channels are ["
				               << (int)totalChannels << "], tried to open channel [" << (int)channelId << "]");
				return false;
			}
		}

		for (int i = 0; i < numOfChannelIds; i++)
		{
			uint8_t channelId = channelIds[i];
			std::ostringstream ringNameStream;
			ringNameStream << m_DeviceName << "@" << (int)channelId;
			std::string ringName = ringNameStream.str();
			PCPP_LOG_DEBUG("Trying to open device [" << m_DeviceName << "] on channel [" << channelId
			                                         << "]. Channel name [" << ringName << "]");

			pfring* newChannel;
			int res = openSingleRxChannel(ringName.c_str(), newChannel);
			if (res == 0)
			{
				// Adds the newly opened channel to the list of opened channels
				m_PfRingDescriptors.push_back(newChannel);
				PCPP_LOG_DEBUG("Succeeded opening device [" << m_DeviceName << "] on channel [" << channelId
				                                            << "]. Channel name [" << ringName << "]");
				continue;
			}
			else if (res == 1)
				PCPP_LOG_ERROR("Couldn't open a ring on channel [" << (int)channelId << "] for device [" << m_DeviceName
				                                                   << "]");
			else if (res == 2)
				PCPP_LOG_ERROR("Unable to enable ring on channel [" << (int)channelId << "] for device ["
				                                                    << m_DeviceName << "]");

			break;
		}

		if (m_PfRingDescriptors.size() < static_cast<size_t>(numOfChannelIds))
		{
			// if an error occurred, close all rings from index=0 to index=m_NumOfOpenedRxChannels-1
			// there's no need to close m_PfRingDescriptors[m_NumOfOpenedRxChannels] because it has already been
			// closed by openSingleRxChannel
			closeAllRxChannels();
			return false;
		}

		m_DeviceOpened = true;

		return true;
	}

	bool PfRingDevice::openMultiRxChannels(uint8_t numOfRxChannelsToOpen, ChannelDistribution dist)
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
			return false;
		}

		if (numOfRxChannelsToOpen > MAX_NUM_RX_CHANNELS)
		{
			PCPP_LOG_ERROR("Cannot open more than [" << MAX_NUM_RX_CHANNELS << "] channels");
			return false;
		}

		uint32_t flags = PF_RING_PROMISC | PF_RING_REENTRANT | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;

		uint8_t numOfRxChannelsOnNIC = getTotalNumOfRxChannels();
		PCPP_LOG_DEBUG("NIC has " << (int)numOfRxChannelsOnNIC << " RX channels");

		uint8_t numOfRingsPerRxChannel = numOfRxChannelsToOpen / numOfRxChannelsOnNIC;
		uint8_t remainderRings = numOfRxChannelsToOpen % numOfRxChannelsOnNIC;

		cluster_type clusterType = (dist == RoundRobin) ? cluster_round_robin : cluster_per_flow;

		for (uint8_t channelId = 0; channelId < numOfRxChannelsOnNIC; channelId++)
		{
			// no more channels to open
			if (numOfRingsPerRxChannel == 0 && remainderRings == 0)
				break;

			std::ostringstream ringName;
			ringName << m_DeviceName << "@" << (int)channelId;

			// open numOfRingsPerRxChannel rings per RX channel
			for (uint8_t ringId = 0; ringId < numOfRingsPerRxChannel; ringId++)
			{
				pfring* newChannel = pfring_open(ringName.str().c_str(), DEFAULT_PF_RING_SNAPLEN, flags);
				if (newChannel == nullptr)
				{
					PCPP_LOG_ERROR("Couldn't open a ring on channel [" << (int)channelId << "]");
					break;
				}

				// setting a cluster for all rings in the same channel to enable hashing between them
				if (pfring_set_cluster(newChannel, channelId + 1, clusterType) < 0)
				{
					PCPP_LOG_ERROR("Couldn't set ring [" << (int)ringId << "] in channel [" << (int)channelId
					                                     << "] to the cluster [" << (int)(channelId + 1) << "]");
					pfring_close(newChannel);  // Closes the ring as its initialization was not successful.
					break;
				}

				// Assign the new channel to the list of opened channels
				m_PfRingDescriptors.push_back(newChannel);
			}

			// open one more ring if remainder > 0
			if (remainderRings > 0)
			{
				pfring* newChannel = pfring_open(ringName.str().c_str(), DEFAULT_PF_RING_SNAPLEN, flags);
				if (newChannel == nullptr)
				{
					PCPP_LOG_ERROR("Couldn't open a ring on channel [" << (int)channelId << "]");
					break;
				}

				// setting a cluster for all rings in the same channel to enable hashing between them
				if (pfring_set_cluster(newChannel, channelId + 1, clusterType) < 0)
				{
					PCPP_LOG_ERROR("Couldn't set ring [" << (int)(numOfRingsPerRxChannel + 1) << "] in channel ["
					                                     << (int)channelId << "] to the cluster ["
					                                     << (int)(channelId + 1) << "]");
					pfring_close(newChannel);  // Closes the ring as its initialization was not successful.
					break;
				}

				// Assign the new channel to the list of opened channels
				m_PfRingDescriptors.push_back(newChannel);
				remainderRings--;
				PCPP_LOG_DEBUG("Opened " << (int)(numOfRingsPerRxChannel + 1) << " rings on channel [" << (int)channelId
				                         << "]");
			}
			else
				PCPP_LOG_DEBUG("Opened " << (int)numOfRingsPerRxChannel << " rings on channel [" << (int)channelId
				                         << "]");
		}

		if (m_PfRingDescriptors.size() < numOfRxChannelsToOpen)
		{
			closeAllRxChannels();
			return false;
		}

		if (getIsHwClockEnable())
		{
			for (pfring* rxChannel : m_PfRingDescriptors)
			{
				if (setPfRingDeviceClock(rxChannel))
					PCPP_LOG_DEBUG("H/W clock set for device [" << m_DeviceName << "]");
			}
		}

		// enable all rings
		for (size_t i = 0; i < m_PfRingDescriptors.size(); i++)
		{
			if (pfring_enable_rss_rehash(m_PfRingDescriptors[i]) < 0 || pfring_enable_ring(m_PfRingDescriptors[i]) < 0)
			{
				PCPP_LOG_ERROR("Unable to enable ring [" << i << "] for device [" << m_DeviceName << "]");
				// close all pfring's that were enabled until now
				closeAllRxChannels();  // note: this function will clear the m_PfRingDescriptors vector
				return false;
			}
		}

		m_DeviceOpened = true;
		return true;
	}

	uint8_t PfRingDevice::getTotalNumOfRxChannels() const
	{
		if (m_PfRingDescriptors.size() > 0)
		{
			uint8_t res = pfring_get_num_rx_channels(m_PfRingDescriptors[0]);
			return res;
		}
		else
		{
			uint32_t flags = PF_RING_PROMISC | PF_RING_REENTRANT | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;
			pfring* ring = pfring_open(m_DeviceName.c_str(), DEFAULT_PF_RING_SNAPLEN, flags);
			uint8_t res = pfring_get_num_rx_channels(ring);
			pfring_close(ring);
			return res;
		}
	}

	SystemCore PfRingDevice::getCurrentCoreId() const
	{
		return SystemCores::IdToSystemCore[sched_getcpu()];
	}

	bool PfRingDevice::setFilter(std::string filterAsString)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device not opened");
			return false;
		}

		for (pfring* rxChannel : m_PfRingDescriptors)
		{
			int res = pfring_set_bpf_filter(rxChannel, (char*)filterAsString.c_str());
			if (res < 0)
			{
				if (res == PF_RING_ERROR_NOT_SUPPORTED)
					PCPP_LOG_ERROR(
					    "BPF filtering isn't supported on current PF_RING version. Please re-compile PF_RING with the --enable-bpf flag");
				else
					PCPP_LOG_ERROR("Couldn't set filter '" << filterAsString << "'");
				return false;
			}
		}

		m_IsFilterCurrentlySet = true;

		PCPP_LOG_DEBUG("Successfully set filter '" << filterAsString << "'");
		return true;
	}

	bool PfRingDevice::clearFilter()
	{
		if (!m_IsFilterCurrentlySet)
			return true;

		for (pfring* rxChannel : m_PfRingDescriptors)
		{
			int res = pfring_remove_bpf_filter(rxChannel);
			if (res < 0)
			{
				PCPP_LOG_ERROR("Couldn't remove filter");
				return false;
			}
		}

		m_IsFilterCurrentlySet = false;

		PCPP_LOG_DEBUG("Successfully removed filter from all open RX channels");
		return true;
	}

	bool PfRingDevice::isFilterCurrentlySet() const
	{
		return m_IsFilterCurrentlySet;
	}

	void PfRingDevice::close()
	{
		closeAllRxChannels();
		m_DeviceOpened = false;
		clearCoreConfiguration();
		m_IsFilterCurrentlySet = false;
		PCPP_LOG_DEBUG("Device [" << m_DeviceName << "] closed");
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

		if (coreMask != 0)  // this mean coreMask contains a core that doesn't exist
		{
			PCPP_LOG_ERROR("Trying to use a core [" << i << "] that doesn't exist while machine has " << numOfCores
			                                        << " cores");
			clearCoreConfiguration();
			return false;
		}

		return true;
	}

	bool PfRingDevice::startCaptureMultiThread(OnPfRingPacketsArriveCallback onPacketsArrive,
	                                           void* onPacketsArriveUserCookie, CoreMask coreMask)
	{
		if (!m_StopThread)
		{
			PCPP_LOG_ERROR("Device already capturing. Cannot start 2 capture sessions at the same time");
			return false;
		}

		if (!initCoreConfigurationByCoreMask(coreMask))
			return false;

		if (m_PfRingDescriptors.size() != getCoresInUseCount())
		{
			PCPP_LOG_ERROR("Cannot use a different number of channels and cores. Opened "
			               << m_PfRingDescriptors.size() << " channels but set " << getCoresInUseCount()
			               << " cores in core mask");
			clearCoreConfiguration();
			return false;
		}

		std::shared_ptr<StartupBlock> startupBlock = std::make_shared<StartupBlock>();

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
			m_CoreConfiguration[coreId].RxThread =
			    std::thread(&pcpp::PfRingDevice::captureThreadMain, this, startupBlock);

			try
			{
				setThreadCoreAffinity(m_CoreConfiguration[coreId].RxThread, coreId);
			}
			catch (const std::exception& e)
			{
				// If an exception occurred, stop all threads
				m_StopThread = true;

				// Wake up the threads so they can exit
				startupBlock->notifyStartup();

				// Wait for all threads to exit
				for (int coreId2 = coreId; coreId2 >= 0; coreId2--)
				{
					if (!m_CoreConfiguration[coreId2].IsInUse)
						continue;
					m_CoreConfiguration[coreId2].RxThread.join();
				}

				clearCoreConfiguration();
				PCPP_LOG_ERROR(e.what());
				return false;
			}
		}

		// Initialization complete. Start the capture threads.
		startupBlock->notifyStartup();

		return true;
	}

	bool PfRingDevice::startCaptureSingleThread(OnPfRingPacketsArriveCallback onPacketsArrive,
	                                            void* onPacketsArriveUserCookie)
	{
		if (!m_StopThread)
		{
			PCPP_LOG_ERROR("Device already capturing. Cannot start 2 capture sessions at the same time");
			return false;
		}

		if (m_PfRingDescriptors.size() != 1)
		{
			PCPP_LOG_ERROR("Cannot start capturing on a single thread when more than 1 RX channel is opened");
			return false;
		}

		PCPP_LOG_DEBUG("Trying to start capturing on a single thread for device [" << m_DeviceName << "]");

		clearCoreConfiguration();

		m_OnPacketsArriveCallback = onPacketsArrive;
		m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

		m_StopThread = false;

		m_ReentrantMode = false;

		std::shared_ptr<StartupBlock> startupBlock = std::make_shared<StartupBlock>();

		m_CoreConfiguration[0].IsInUse = true;
		m_CoreConfiguration[0].Channel = m_PfRingDescriptors[0];
		m_CoreConfiguration[0].RxThread = std::thread(&pcpp::PfRingDevice::captureThreadMain, this, startupBlock);
		m_CoreConfiguration[0].IsAffinitySet = false;

		try
		{
			setThreadCoreAffinity(m_CoreConfiguration[0].RxThread, 0);
		}
		catch (const std::exception& e)
		{
			// If an exception occurred, stop the thread
			m_StopThread = true;

			// Wake up the threads so they can exit
			startupBlock->notifyStartup();

			// Wait for the thread to exit
			m_CoreConfiguration[0].RxThread.join();

			clearCoreConfiguration();
			PCPP_LOG_ERROR(e.what());
			return false;
		}

		// Initialization complete. Start the capture thread.
		startupBlock->notifyStartup();

		PCPP_LOG_DEBUG("Capturing started for device [" << m_DeviceName << "]");
		return true;
	}

	void PfRingDevice::stopCapture()
	{
		PCPP_LOG_DEBUG("Trying to stop capturing on device [" << m_DeviceName << "]");
		m_StopThread = true;

		for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
		{
			if (!m_CoreConfiguration[coreId].IsInUse)
				continue;
			m_CoreConfiguration[coreId].RxThread.join();
			PCPP_LOG_DEBUG("Thread on core [" << coreId << "] stopped");
		}

		PCPP_LOG_DEBUG("All capturing threads stopped");
	}

	void PfRingDevice::captureThreadMain(std::shared_ptr<StartupBlock> startupBlock)
	{
		if (startupBlock == nullptr)
		{
			PCPP_LOG_ERROR("Capture thread started without a startup block. Exiting capture thread");
			return;
		}

		startupBlock->waitForStartup();

		if (m_StopThread)
		{
			PCPP_LOG_DEBUG("Capture thread stopped during initialization.");
			return;
		}

		// Startup is complete. The block is no longer needed.
		startupBlock = nullptr;

		int coreId = this->getCurrentCoreId().Id;
		pfring* ring = nullptr;

		PCPP_LOG_DEBUG("Starting capture thread " << coreId);

		ring = this->m_CoreConfiguration[coreId].Channel;

		if (ring == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't find ring for core " << coreId << ". Exiting capture thread");
			return;
		}

		// Zero copy is not supported in reentrant mode
		const bool zeroCopySupported = !m_ReentrantMode;

		// If the `bufferPtr` is set to nullptr, PF_RING will use zero copy mode and sets `bufferPtr` to point to the
		// packet data.
		uint8_t* bufferPtr = nullptr;
		uint32_t bufferLen = 0;
		std::vector<uint8_t> recvBuffer;

		// If zero copy is not supported, allocate a buffer for the packet data.
		if (!zeroCopySupported)
		{
			recvBuffer.resize(PCPP_MAX_PACKET_SIZE);
			bufferPtr = recvBuffer.data();
			bufferLen = recvBuffer.size();
		}

		while (!this->m_StopThread)
		{
			struct pfring_pkthdr pktHdr;
			int recvRes = pfring_recv(ring, &bufferPtr, bufferLen, &pktHdr, 0);
			if (recvRes > 0)
			{
				// if caplen < len it means we don't have the whole packet. Treat this case as packet drop
				// TODO: add this packet to dropped packet stats
				//			if (pktHdr.caplen != pktHdr.len)
				//			{
				//				PCPP_LOG_ERROR("Packet dropped due to len != caplen");
				//				continue;
				//			}

				RawPacket rawPacket(bufferPtr, pktHdr.caplen, pktHdr.ts, false);
				this->m_OnPacketsArriveCallback(&rawPacket, 1, coreId, this, this->m_OnPacketsArriveUserCookie);
			}
			else if (recvRes < 0)
			{
				// cppcheck-suppress shiftNegative
				PCPP_LOG_ERROR("pfring_recv returned an error: [Err=" << recvRes << "]");
			}
		}

		PCPP_LOG_DEBUG("Exiting capture thread " << coreId);
	}

	void PfRingDevice::getThreadStatistics(SystemCore core, PfRingStats& stats) const
	{
		pfring* ring = nullptr;
		uint8_t coreId = core.Id;

		ring = m_CoreConfiguration[coreId].Channel;

		if (ring != nullptr)
		{
			pfring_stat tempStats;
			if (pfring_stats(ring, &tempStats) < 0)
			{
				PCPP_LOG_ERROR("Can't retrieve statistics for core [" << (int)coreId << "], pfring_stats failed");
				return;
			}
			stats.drop = (uint64_t)tempStats.drop;
			stats.recv = (uint64_t)tempStats.recv;
		}
		else
		{
			PCPP_LOG_ERROR("Core [" << (int)coreId << "] is not in use, can't retrieve statistics");
		}
	}

	void PfRingDevice::getCurrentThreadStatistics(PfRingStats& stats) const
	{
		getThreadStatistics(getCurrentCoreId(), stats);
	}

	void PfRingDevice::getStatistics(PfRingStats& stats) const
	{
		stats.drop = 0;
		stats.recv = 0;

		for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
		{
			if (!m_CoreConfiguration[coreId].IsInUse)
				continue;

			PfRingStats tempStat = {};
			getThreadStatistics(SystemCores::IdToSystemCore[coreId], tempStat);
			stats.drop += tempStat.drop;
			stats.recv += tempStat.recv;

			if (!m_CoreConfiguration[coreId].IsAffinitySet)
				break;
		}
	}

	void PfRingDevice::clearCoreConfiguration()
	{
		for (auto& config : m_CoreConfiguration)
			config.clear();
	}

	size_t PfRingDevice::getCoresInUseCount() const
	{
		return std::count_if(m_CoreConfiguration.begin(), m_CoreConfiguration.end(),
		                     [](const CoreConfiguration& config) { return config.IsInUse; });
	}

	void PfRingDevice::setPfRingDeviceAttributes()
	{
		if (m_InterfaceIndex > -1)
			return;

		pfring* ring = nullptr;
		bool closeRing = false;
		if (m_PfRingDescriptors.size() > 0)
			ring = m_PfRingDescriptors[0];
		else
		{
			uint32_t flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
			ring = pfring_open(m_DeviceName.c_str(), DEFAULT_PF_RING_SNAPLEN, flags);
			closeRing = true;
		}

		if (ring == nullptr)
		{
			PCPP_LOG_ERROR(
			    "Could not open a pfring for setting device attributes: MAC address, interface index and HW clock");
			return;
		}

		// set device MAC address

		uint8_t macAddress[6];
		if (pfring_get_bound_device_address(ring, macAddress) < 0)
			PCPP_LOG_ERROR("Unable to read the device MAC address for interface '" << m_DeviceName << "'");
		else
			m_MacAddress = MacAddress(macAddress);

		// set interface ID
		if (pfring_get_bound_device_ifindex(ring, &m_InterfaceIndex) < 0)
			PCPP_LOG_ERROR("Unable to read interface index of device");

		// try to set hardware device clock
		m_HwClockEnabled = setPfRingDeviceClock(ring);

		// set interface MTU
		int mtu = pfring_get_mtu_size(ring);
		if (mtu < 0)
			// cppcheck-suppress shiftNegative
			PCPP_LOG_ERROR("Could not get MTU. pfring_get_mtu_size returned an error: " << mtu);
		else
			m_DeviceMTU = mtu + sizeof(ether_header) + sizeof(vlan_header);

		if (Logger::getInstance().isDebugEnabled(PcapLogModulePfRingDevice))
		{
			std::string hwEnabled = (m_HwClockEnabled ? "enabled" : "disabled");
			PCPP_LOG_DEBUG("Capturing from " << m_DeviceName << " [" << m_MacAddress
			                                 << "][ifIndex: " << m_InterfaceIndex << "][MTU: " << m_DeviceMTU
			                                 << "], HW clock " << hwEnabled);
		}

		if (closeRing)
			pfring_close(ring);
	}

	bool PfRingDevice::sendData(const uint8_t* packetData, int packetDataLength, bool flushTxQueues)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device is not opened. Cannot send packets");
			return false;
		}

		uint8_t flushTxAsUint = (flushTxQueues ? 1 : 0);

		constexpr int MAX_TRIES = 5;
		int tries = 0;
		int res = 0;
		while (tries < MAX_TRIES)
		{
			// don't allow sending of data larger than the MTU, otherwise pfring_send will fail
			if (packetDataLength > m_DeviceMTU)
				packetDataLength = m_DeviceMTU;

			// if the device is opened, m_PfRingDescriptors[0] will always be set and enables
			res = pfring_send(m_PfRingDescriptors[0], (char*)packetData, packetDataLength, flushTxAsUint);

			// res == -1 means it's an error coming from "sendto" which is the Linux API PF_RING is using to send
			// packets errno == ENOBUFS means write buffer is full. PF_RING driver expects the userspace to handle this
			// case My implementation is to sleep for 10 usec and try again
			if (res == -1 && errno == ENOBUFS)
			{
				tries++;
				PCPP_LOG_DEBUG(
				    "Try #"
				    << tries
				    << ": Got ENOBUFS (write buffer full) error while sending packet. Sleeping 20 usec and trying again");
				std::this_thread::sleep_for(std::chrono::microseconds(2000));
			}
			else
				break;
		}

		if (tries >= MAX_TRIES)
		{
			PCPP_LOG_ERROR("Tried to send data " << MAX_TRIES << " times but write buffer is full");
			return false;
		}

		if (res < 0)
		{
			// res == -1 means it's an error coming from "sendto" which is the Linux API PF_RING is using to send
			// packets
			if (res == -1)
				PCPP_LOG_ERROR("Error sending packet: Linux errno: " << strerror(errno) << " [" << errno << "]");
			else
				PCPP_LOG_ERROR("Error sending packet: pfring_send returned an error: "
				               << res << " , errno: " << strerror(errno) << " [" << errno << "]");
			return false;
		}
		else if (res != packetDataLength)
		{
			PCPP_LOG_ERROR("Couldn't send all bytes, only " << res << " bytes out of " << packetDataLength
			                                                << " bytes were sent");
			return false;
		}

		return true;
	}

	bool PfRingDevice::sendPacket(const uint8_t* packetData, int packetDataLength)
	{
		return sendData(packetData, packetDataLength, true);
	}

	bool PfRingDevice::sendPacket(const RawPacket& rawPacket)
	{
		return sendData(rawPacket.getRawData(), rawPacket.getRawDataLen(), true);
	}

	bool PfRingDevice::sendPacket(const Packet& packet)
	{
		return sendData(packet.getRawPacketReadOnly()->getRawData(), packet.getRawPacketReadOnly()->getRawDataLen(),
		                true);
	}

	int PfRingDevice::sendPackets(const RawPacket* rawPacketsArr, int arrLength)
	{
		int packetsSent = 0;
		for (int i = 0; i < arrLength; i++)
		{
			if (!sendData(rawPacketsArr[i].getRawData(), rawPacketsArr[i].getRawDataLen(), false))
				break;
			else
				packetsSent++;
		}

		// In case of failure due to closed device, there are not handles to flush.
		if (m_PfRingDescriptors.size() > 0)
		{
			// The following method isn't supported in PF_RING aware drivers, probably only in DNA and ZC
			pfring_flush_tx_packets(m_PfRingDescriptors[0]);
		}

		PCPP_LOG_DEBUG(packetsSent << " out of " << arrLength << " raw packets were sent successfully");

		return packetsSent;
	}

	int PfRingDevice::sendPackets(const Packet** packetsArr, int arrLength)
	{
		int packetsSent = 0;
		for (int i = 0; i < arrLength; i++)
		{
			if (!sendData(packetsArr[i]->getRawPacketReadOnly()->getRawData(),
			              packetsArr[i]->getRawPacketReadOnly()->getRawDataLen(), false))
				break;
			else
				packetsSent++;
		}

		// In case of failure due to closed device, there are not handles to flush.
		if (m_PfRingDescriptors.size() > 0)
		{
			// The following method isn't supported in PF_RING aware drivers, probably only in DNA and ZC
			pfring_flush_tx_packets(m_PfRingDescriptors[0]);
		}

		PCPP_LOG_DEBUG(packetsSent << " out of " << arrLength << " packets were sent successfully");

		return packetsSent;
	}

	int PfRingDevice::sendPackets(const RawPacketVector& rawPackets)
	{
		int packetsSent = 0;
		for (RawPacketVector::ConstVectorIterator iter = rawPackets.begin(); iter != rawPackets.end(); iter++)
		{
			if (!sendData((*iter)->getRawData(), (*iter)->getRawDataLen(), false))
				break;
			else
				packetsSent++;
		}

		// In case of failure due to closed device, there are not handles to flush.
		if (m_PfRingDescriptors.size() > 0)
		{
			// The following method isn't supported in PF_RING aware drivers, probably only in DNA and ZC
			pfring_flush_tx_packets(m_PfRingDescriptors[0]);
		}

		PCPP_LOG_DEBUG(packetsSent << " out of " << rawPackets.size() << " raw packets were sent successfully");

		return packetsSent;
	}

	PfRingDevice::CoreConfiguration::CoreConfiguration() : Channel(nullptr), IsInUse(false), IsAffinitySet(true)
	{}

	void PfRingDevice::CoreConfiguration::clear()
	{
		Channel = nullptr;
		IsInUse = false;
		IsAffinitySet = true;
	}

	void PfRingDevice::StartupBlock::notifyStartup()
	{
		std::lock_guard<std::mutex> lock(m_Mutex);
		m_Ready = true;
		m_Cv.notify_all();
	}

	void PfRingDevice::StartupBlock::waitForStartup()
	{
		std::unique_lock<std::mutex> lock(m_Mutex);
		m_Cv.wait(lock, [&] { return m_Ready; });
	}

}  // namespace pcpp

// GCOVR_EXCL_STOP
