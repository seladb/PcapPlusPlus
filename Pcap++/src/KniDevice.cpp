// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModuleKniDevice

#include "KniDevice.h"
#include "Logger.h"
#include "SystemUtils.h"

#include <unistd.h>
#include <thread>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <rte_version.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_kni.h>
#include <rte_memory.h>
#include <rte_branch_prediction.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifndef KNI_MEMPOOL_NAME_PREFIX
#	define KNI_MEMPOOL_NAME_PREFIX "kniMempool"
#endif
#ifndef MEMPOOL_CACHE_SIZE
#	define MEMPOOL_CACHE_SIZE 256
#endif
#ifndef MAX_BURST_SIZE
#	define MAX_BURST_SIZE 64
#endif

#define CPP_VLA(TYPE, SIZE) (TYPE*)__builtin_alloca(sizeof(TYPE) * SIZE)

namespace pcpp
{

	/// ==========================
	/// Class KniDevice::KniThread
	/// ==========================

	struct KniDevice::KniThread
	{
		enum KniThreadCleanupState
		{
			JOINABLE,
			DETACHED,
			INVALID
		};
		typedef void (*threadMain)(void*, std::atomic<bool>&);
		KniThread(KniThreadCleanupState s, threadMain tm, void* data);
		~KniThread();

		void cancel();

		std::thread m_Descriptor;
		KniThreadCleanupState m_CleanupState;
		std::atomic<bool> m_StopThread;
	};

	KniDevice::KniThread::KniThread(KniThreadCleanupState s, threadMain tm, void* data) : m_CleanupState(s)
	{
		m_StopThread = false;
		m_Descriptor = std::thread(tm, data, std::ref(m_StopThread));

		if (m_CleanupState == DETACHED)
		{
			m_Descriptor.detach();
		}
	}

	KniDevice::KniThread::~KniThread()
	{
		if (m_CleanupState == JOINABLE)
		{
			m_Descriptor.join();
		}
	}

	void KniDevice::KniThread::cancel()
	{
		m_StopThread = true;
	}

	/// ===============
	/// Class KniDevice
	/// ===============

	namespace
	{

		inline bool destroyKniDevice(struct rte_kni* kni, const char* deviceName)
		{
			if (rte_kni_release(kni) < 0)
			{
				PCPP_LOG_ERROR("Failed to destroy DPDK KNI device " << deviceName);
				return true;
			}
			return false;
		}

		inline KniDevice::KniLinkState setKniDeviceLinkState(struct rte_kni* kni, const char* deviceName,
		                                                     KniDevice::KniLinkState state = KniDevice::LINK_UP)
		{
			KniDevice::KniLinkState oldState = KniDevice::LINK_NOT_SUPPORTED;
			if (kni == nullptr || !(state == KniDevice::LINK_UP || state == KniDevice::LINK_DOWN))
			{
				return oldState = KniDevice::LINK_ERROR;
			}
#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
			oldState = (KniDevice::KniLinkState)rte_kni_update_link(kni, state);
			if (oldState == KniDevice::LINK_ERROR)
			{  //? NOTE(echo-Mike): Not LOG_ERROR because will generate a lot of junk messages on some DPDK versions
				PCPP_LOG_DEBUG("DPDK KNI Failed to update links state for device '" << deviceName << "'");
			}
#else
			// To avoid compiler warnings
			(void)kni;
			(void)deviceName;
#endif
			return oldState;
		}

		inline struct rte_mempool* createMempool(size_t mempoolSize, int unique, const char* deviceName)
		{
			struct rte_mempool* result = nullptr;
			char mempoolName[64];
			snprintf(mempoolName, sizeof(mempoolName), KNI_MEMPOOL_NAME_PREFIX "%d", unique);
			result = rte_pktmbuf_pool_create(mempoolName, mempoolSize, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			                                 rte_socket_id());
			if (result == nullptr)
			{
				PCPP_LOG_ERROR("Failed to create packets memory pool for KNI device '"
				               << deviceName << "', pool name: " << mempoolName);
			}
			else
			{
				PCPP_LOG_DEBUG("Successfully initialized packets pool of size [" << mempoolSize << "] for KNI device ["
				                                                                 << deviceName << "]");
			}
			return result;
		}

	}  // namespace

	KniDevice::KniDevice(const KniDeviceConfiguration& conf, size_t mempoolSize, int unique)
	    : m_Device(nullptr), m_MBufMempool(nullptr)
	{
		struct rte_kni_ops kniOps;
		struct rte_kni_conf kniConf;
		if (!m_DeviceInfo.init(conf))
			return;
		m_Requests.thread = nullptr;
		std::memset(&m_Capturing, 0, sizeof(m_Capturing));
		std::memset(&m_Requests, 0, sizeof(m_Requests));

		if ((m_MBufMempool = createMempool(mempoolSize, unique, conf.name.c_str())) == nullptr)
			return;

		std::memset(&kniOps, 0, sizeof(kniOps));
		std::memset(&kniConf, 0, sizeof(kniConf));
		snprintf(kniConf.name, RTE_KNI_NAMESIZE, "%s", conf.name.c_str());
		kniConf.core_id = conf.kthreadCoreId;
		kniConf.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;
		kniConf.force_bind = conf.bindKthread ? 1 : 0;
#if RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)
		if (conf.mac != MacAddress::Zero)
			conf.mac.copyTo((uint8_t*)kniConf.mac_addr);
		kniConf.mtu = conf.mtu;
#endif

		kniOps.port_id = conf.portId;
#if RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 0)
		if (conf.callbacks != nullptr)
		{
			kniOps.change_mtu = conf.callbacks->change_mtu;
			kniOps.config_network_if = conf.callbacks->config_network_if;
#	if RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)
			kniOps.config_mac_address = conf.callbacks->config_mac_address;
			kniOps.config_promiscusity = conf.callbacks->config_promiscusity;
#	endif
		}
#else
		if (conf.oldCallbacks != nullptr)
		{
			kniOps.change_mtu = conf.oldCallbacks->change_mtu;
			kniOps.config_network_if = conf.oldCallbacks->config_network_if;
		}
#endif

		m_Device = rte_kni_alloc(m_MBufMempool, &kniConf, &kniOps);
		if (m_Device == nullptr)
		{
			PCPP_LOG_ERROR("DPDK have failed to create KNI device " << conf.name);
		}
	}

	KniDevice::~KniDevice()
	{
		m_Requests.cleanup();
		m_Capturing.cleanup();
		if (m_Device != nullptr)
		{
			setKniDeviceLinkState(m_Device, m_DeviceInfo.name.c_str(), KniDevice::LINK_DOWN);
			destroyKniDevice(m_Device, m_DeviceInfo.name.c_str());
		}
		if (m_MBufMempool != nullptr)
			rte_mempool_free(m_MBufMempool);
	}

	bool KniDevice::KniDeviceInfo::init(const KniDeviceConfiguration& conf)
	{
		link = KniDevice::LINK_NOT_SUPPORTED;
		promisc = KniDevice::PROMISC_DISABLE;
		portId = conf.portId;
		mtu = conf.mtu;
		if (conf.name.empty())
		{
			PCPP_LOG_ERROR("Failed to create KNI device. "
			               "Empty name provided");
			return false;
		}
		if (conf.name.size() >= IFNAMSIZ)
		{
			PCPP_LOG_ERROR("Failed to create KNI device. "
			               "Provided name has length more than possible to handle <"
			               << IFNAMSIZ - 1 << ">");
			return false;
		}
		name = conf.name;
		mac = conf.mac;
		return true;
	}

	KniDevice::KniLinkState KniDevice::getLinkState(KniInfoState state)
	{
		if (state == KniDevice::INFO_CACHED)
			return m_DeviceInfo.link;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFFLAGS, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain interface link state from Linux");
			PCPP_LOG_DEBUG("Last known link state for device '" << m_DeviceInfo.name << "' is returned");
			return m_DeviceInfo.link;
		}
		return m_DeviceInfo.link = KniLinkState(req.ifr_flags & IFF_UP);
	}

	MacAddress KniDevice::getMacAddress(KniInfoState state)
	{
		if (state == KniDevice::INFO_CACHED)
			return m_DeviceInfo.mac;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		req.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFHWADDR, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain MAC address from Linux");
			PCPP_LOG_DEBUG("Last known MAC address for device '" << m_DeviceInfo.name << "' is returned");
			return m_DeviceInfo.mac;
		}
		return m_DeviceInfo.mac = MacAddress((uint8_t*)req.ifr_hwaddr.sa_data);
	}

	uint16_t KniDevice::getMtu(KniInfoState state)
	{
		if (state == KniDevice::INFO_CACHED)
			return m_DeviceInfo.mtu;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFMTU, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain interface MTU from Linux");
			PCPP_LOG_DEBUG("Last known MTU for device '" << m_DeviceInfo.name << "' is returned");
			return m_DeviceInfo.mtu;
		}
		return m_DeviceInfo.mtu = req.ifr_mtu;
	}

	KniDevice::KniPromiscuousMode KniDevice::getPromiscuous(KniInfoState state)
	{
		if (state == KniDevice::INFO_CACHED)
			return m_DeviceInfo.promisc;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFFLAGS, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain interface Promiscuous mode from Linux");
			PCPP_LOG_DEBUG("Last known Promiscuous mode for device '" << m_DeviceInfo.name << "' is returned");
			return m_DeviceInfo.promisc;
		}
		return m_DeviceInfo.promisc =
		           (req.ifr_flags & IFF_PROMISC) ? KniDevice::PROMISC_ENABLE : KniDevice::PROMISC_DISABLE;
	}

	bool KniDevice::setLinkState(KniLinkState state)
	{
		if (!(state == KniDevice::LINK_DOWN || state == KniDevice::LINK_UP))
			return false;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFFLAGS, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain interface flags from Linux");
			return false;
		}
		if ((state == KniDevice::LINK_DOWN && req.ifr_flags & IFF_UP) ||
		    (state == KniDevice::LINK_UP && !(req.ifr_flags & IFF_UP)))
		{
			req.ifr_flags ^= IFF_UP;
			if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCSIFFLAGS, &req))
			{
				PCPP_LOG_ERROR("DPDK KNI failed to set '" << m_DeviceInfo.name << "' link mode");
				return false;
			}
		}
		m_DeviceInfo.link = state;
		return true;
	}

	bool KniDevice::setMacAddress(const MacAddress& mac)
	{
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		req.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		mac.copyTo((uint8_t*)req.ifr_hwaddr.sa_data);
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCSIFHWADDR, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to set MAC address");
			return false;
		}
		m_DeviceInfo.mac = mac;
		return true;
	}

	bool KniDevice::setMtu(uint16_t mtu)
	{
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		req.ifr_mtu = mtu;
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCSIFMTU, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to set interface MTU");
			return false;
		}
		m_DeviceInfo.mtu = mtu;
		return true;
	}

	bool KniDevice::setPromiscuous(KniPromiscuousMode mode)
	{
		if (!(mode == KniDevice::PROMISC_DISABLE || mode == KniDevice::PROMISC_ENABLE))
			return false;
		struct ifreq req;
		std::memset(&req, 0, sizeof(req));
		if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCGIFFLAGS, &req))
		{
			PCPP_LOG_ERROR("DPDK KNI failed to obtain interface flags from Linux");
			return false;
		}
		if ((mode == KniDevice::PROMISC_DISABLE && req.ifr_flags & IFF_PROMISC) ||
		    (mode == KniDevice::PROMISC_ENABLE && !(req.ifr_flags & IFF_PROMISC)))
		{
			req.ifr_flags ^= IFF_PROMISC;
			if (!m_DeviceInfo.soc.makeRequest(m_DeviceInfo.name.c_str(), SIOCSIFFLAGS, &req))
			{
				PCPP_LOG_ERROR("DPDK KNI failed to set '" << m_DeviceInfo.name << "' link mode");
				return false;
			}
		}
		m_DeviceInfo.promisc = mode;
		return true;
	}

	KniDevice::KniLinkState KniDevice::updateLinkState(KniLinkState state)
	{
		KniLinkState oldState = setKniDeviceLinkState(m_Device, m_DeviceInfo.name.c_str(), state);
		if (oldState != KniDevice::LINK_NOT_SUPPORTED && oldState != KniDevice::LINK_ERROR)
			m_DeviceInfo.link = state;
		return oldState;
	}

	bool KniDevice::handleRequests()
	{
		return rte_kni_handle_request(m_Device) == 0;
	}

	void KniDevice::KniRequests::cleanup()
	{
		if (thread)
			thread->cancel();
		delete thread;
		thread = nullptr;
		sleepS = sleepNs = 0;
	}

	void KniDevice::KniRequests::runRequests(void* devicePointer, std::atomic<bool>& stopThread)
	{
		KniDevice* device = (KniDevice*)devicePointer;
		struct timespec sleepTime;
		sleepTime.tv_sec = device->m_Requests.sleepS;
		sleepTime.tv_nsec = device->m_Requests.sleepNs;
		struct rte_kni* kni_dev = device->m_Device;
		for (;;)
		{
			std::this_thread::sleep_for(std::chrono::seconds(sleepTime.tv_sec) +
			                            std::chrono::nanoseconds(sleepTime.tv_nsec));
			rte_kni_handle_request(kni_dev);
			if (stopThread)
			{
				return;
			}
		}
	}

	bool KniDevice::startRequestHandlerThread(long sleepSeconds, long sleepNanoSeconds)
	{
		if (m_Requests.thread != nullptr)
		{
			PCPP_LOG_ERROR("KNI request thread is already started for device '" << m_DeviceInfo.name << "'");
			return false;
		}
		m_Requests.sleepS = sleepSeconds;
		m_Requests.sleepNs = sleepNanoSeconds;
		m_Requests.thread = new KniThread(KniThread::DETACHED, KniRequests::runRequests, (void*)this);
		if (m_Requests.thread->m_CleanupState == KniThread::INVALID)
		{
			m_Requests.cleanup();
			return false;
		}
		return true;
	}

	void KniDevice::stopRequestHandlerThread()
	{
		if (m_Requests.thread == nullptr)
		{
			PCPP_LOG_DEBUG("Attempt to stop not running KNI request thread for device '" << m_DeviceInfo.name << "'");
			return;
		}
		m_Requests.cleanup();
	}

	uint16_t KniDevice::receivePackets(MBufRawPacketVector& rawPacketsArr)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}
		if (unlikely(m_Capturing.isRunning()))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name
			                              << "' capture mode is currently running. "
			                                 "Cannot receive packets in parallel");
			return 0;
		}

		struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
		uint32_t numOfPktsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

		// the following line trashes the log with many messages. Uncomment only if necessary
		// PCPP_LOG_DEBUG("KNI Captured %d packets", numOfPktsReceived);

		if (unlikely(!numOfPktsReceived))
		{
			return 0;
		}

		timespec time;
		clock_gettime(CLOCK_REALTIME, &time);

		for (uint32_t index = 0; index < numOfPktsReceived; ++index)
		{
			struct rte_mbuf* mBuf = mBufArray[index];
			MBufRawPacket* newRawPacket = new MBufRawPacket();
			newRawPacket->setMBuf(mBuf, time);
			rawPacketsArr.pushBack(newRawPacket);
		}

		return numOfPktsReceived;
	}

	uint16_t KniDevice::receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}
		if (unlikely(m_Capturing.isRunning()))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name
			                              << "' capture mode is currently running. "
			                                 "Cannot receive packets in parallel");
			return 0;
		}
		if (unlikely(rawPacketsArr == nullptr))
		{
			PCPP_LOG_ERROR("KNI Provided address of array to store packets is nullptr");
			return 0;
		}

		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, rawPacketArrLength);
		uint16_t packetsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

		if (unlikely(!packetsReceived))
		{
			return 0;
		}

		timespec time;
		clock_gettime(CLOCK_REALTIME, &time);

		for (size_t index = 0; index < packetsReceived; ++index)
		{
			struct rte_mbuf* mBuf = mBufArray[index];
			if (rawPacketsArr[index] == nullptr)
				rawPacketsArr[index] = new MBufRawPacket();

			rawPacketsArr[index]->setMBuf(mBuf, time);
		}

		return packetsReceived;
	}

	uint16_t KniDevice::receivePackets(Packet** packetsArr, uint16_t packetsArrLength)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}
		if (unlikely(m_Capturing.isRunning()))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name
			                              << "' capture mode is currently running. "
			                                 "Cannot receive packets in parallel");
			return 0;
		}

		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, packetsArrLength);
		uint16_t packetsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

		if (unlikely(!packetsReceived))
		{
			return 0;
		}

		timespec time;
		clock_gettime(CLOCK_REALTIME, &time);

		for (size_t index = 0; index < packetsReceived; ++index)
		{
			struct rte_mbuf* mBuf = mBufArray[index];
			MBufRawPacket* newRawPacket = new MBufRawPacket();
			newRawPacket->setMBuf(mBuf, time);
			if (packetsArr[index] == nullptr)
				packetsArr[index] = new Packet();

			packetsArr[index]->setRawPacket(newRawPacket, true);
		}

		return packetsReceived;
	}

	uint16_t KniDevice::sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
		for (uint16_t i = 0; i < arrLength; ++i)
		{
			mBufArray[i] = rawPacketsArr[i]->getMBuf();
		}

		uint16_t packetsSent = rte_kni_tx_burst(m_Device, mBufArray, arrLength);
		for (uint16_t i = 0; i < arrLength; ++i)
		{
			rawPacketsArr[i]->setFreeMbuf(i >= packetsSent);
		}

		return packetsSent;
	}

	uint16_t KniDevice::sendPackets(Packet** packetsArr, uint16_t arrLength)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
		MBufRawPacket** mBufRawPacketArr = CPP_VLA(MBufRawPacket*, arrLength);
		MBufRawPacket** allocated = CPP_VLA(MBufRawPacket*, arrLength);
		uint16_t allocated_count = 0, packetsSent = 0;
		MBufRawPacket* rawPacket;

		for (uint16_t i = 0; i < arrLength; ++i)
		{
			const auto* raw_pkt = packetsArr[i]->getRawPacketReadOnly();
			uint8_t raw_type = raw_pkt->getObjectType();
			if (raw_type != MBUFRAWPACKET_OBJECT_TYPE)
			{
				MBufRawPacket* pkt = new MBufRawPacket();
				if (unlikely(!pkt->initFromRawPacket(raw_pkt, this)))
				{
					delete pkt;
					goto error_out;
				}
				rawPacket = allocated[allocated_count++] = pkt;
			}
			else
			{
				rawPacket = (MBufRawPacket*)raw_pkt;
			}
			mBufRawPacketArr[i] = rawPacket;
			mBufArray[i] = rawPacket->getMBuf();
		}

		packetsSent = rte_kni_tx_burst(m_Device, mBufArray, arrLength);
		for (uint16_t i = 0; i < arrLength; ++i)
		{
			mBufRawPacketArr[i]->setFreeMbuf(i >= packetsSent);
		}

	error_out:
		for (uint16_t i = 0; i < allocated_count; ++i)
			delete allocated[i];
		return packetsSent;
	}

	uint16_t KniDevice::sendPackets(MBufRawPacketVector& rawPacketsVec)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		size_t arrLength = rawPacketsVec.size();
		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
		uint16_t pos = 0;
		for (MBufRawPacketVector::VectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); ++iter)
		{
			mBufArray[pos] = (*iter)->getMBuf();
			++pos;
		}

		uint16_t packetsSent = rte_kni_tx_burst(m_Device, mBufArray, arrLength);
		pos = 0;
		for (MBufRawPacketVector::VectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); ++iter)
		{
			(*iter)->setFreeMbuf(pos >= packetsSent);
			++pos;
		}

		return packetsSent;
	}

	uint16_t KniDevice::sendPackets(RawPacketVector& rawPacketsVec)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		size_t arrLength = rawPacketsVec.size();
		struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
		MBufRawPacket** mBufRawPacketArr = CPP_VLA(MBufRawPacket*, arrLength);
		MBufRawPacket** allocated = CPP_VLA(MBufRawPacket*, arrLength);
		uint16_t allocatedCount = 0, packetsSent = 0, pos = 0;
		MBufRawPacket* rawPacket;

		for (RawPacketVector::VectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); ++iter)
		{
			uint8_t raw_type = (*iter)->getObjectType();
			if (raw_type != MBUFRAWPACKET_OBJECT_TYPE)
			{
				MBufRawPacket* pkt = new MBufRawPacket();
				if (unlikely(!pkt->initFromRawPacket(*iter, this)))
				{
					delete pkt;
					goto error_out;
				}
				rawPacket = allocated[allocatedCount++] = pkt;
			}
			else
			{
				rawPacket = (MBufRawPacket*)(*iter);
			}
			mBufRawPacketArr[pos] = rawPacket;
			mBufArray[pos] = rawPacket->getMBuf();
			++pos;
		}

		packetsSent = rte_kni_tx_burst(m_Device, mBufArray, arrLength);
		for (uint16_t i = 0; i < arrLength; ++i)
		{
			mBufRawPacketArr[i]->setFreeMbuf(i >= packetsSent);
		}

	error_out:
		for (uint16_t i = 0; i < allocatedCount; ++i)
			delete allocated[i];
		return packetsSent;
	}

	bool KniDevice::sendPacket(RawPacket& rawPacket)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		struct rte_mbuf* mbuf;
		MBufRawPacket* mbufRawPacket = nullptr;
		bool sent = false;
		bool wasAllocated = false;

		if (rawPacket.getObjectType() != MBUFRAWPACKET_OBJECT_TYPE)
		{
			mbufRawPacket = new MBufRawPacket();
			if (unlikely(!mbufRawPacket->initFromRawPacket(&rawPacket, this)))
			{
				delete mbufRawPacket;
				return sent;
			}
			mbuf = mbufRawPacket->getMBuf();
			wasAllocated = true;
		}
		else
		{
			mbufRawPacket = (MBufRawPacket*)(&rawPacket);
			mbuf = mbufRawPacket->getMBuf();
		}

		sent = rte_kni_tx_burst(m_Device, &mbuf, 1);
		mbufRawPacket->setFreeMbuf(!sent);
		if (wasAllocated)
			delete mbufRawPacket;

		return sent;
	}

	bool KniDevice::sendPacket(MBufRawPacket& rawPacket)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened");
			return 0;
		}

		struct rte_mbuf* mbuf = rawPacket.getMBuf();
		bool sent = false;

		sent = rte_kni_tx_burst(m_Device, &mbuf, 1);
		rawPacket.setFreeMbuf(!sent);

		return sent;
	}

	bool KniDevice::sendPacket(Packet& packet)
	{
		return sendPacket(*packet.getRawPacket());
	}

	void KniDevice::KniCapturing::runCapture(void* devicePointer, std::atomic<bool>& stopThread)
	{
		KniDevice* device = (KniDevice*)devicePointer;
		OnKniPacketArriveCallback callback = device->m_Capturing.callback;
		void* userCookie = device->m_Capturing.userCookie;
		struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
		struct rte_kni* kni = device->m_Device;

		PCPP_LOG_DEBUG("Starting KNI capture thread for device '" << device->m_DeviceInfo.name << "'");

		for (;;)
		{
			uint32_t numOfPktsReceived = rte_kni_rx_burst(kni, mBufArray, MAX_BURST_SIZE);
			if (unlikely(numOfPktsReceived == 0))
			{
				if (stopThread)
				{
					return;
				}
				continue;
			}

			timespec time;
			clock_gettime(CLOCK_REALTIME, &time);

			if (likely(callback != nullptr))
			{
				MBufRawPacket rawPackets[MAX_BURST_SIZE];
				for (uint32_t index = 0; index < numOfPktsReceived; ++index)
				{
					rawPackets[index].setMBuf(mBufArray[index], time);
				}

				if (!callback(rawPackets, numOfPktsReceived, device, userCookie))
					break;
			}
			if (stopThread)
			{
				return;
			}
		}
	}

	void KniDevice::KniCapturing::cleanup()
	{
		if (thread)
			thread->cancel();
		delete thread;
		thread = nullptr;
		callback = nullptr;
		userCookie = nullptr;
	}

	bool KniDevice::startCapture(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened. Can't start capture");
			return false;
		}
		if (unlikely(m_Capturing.thread != nullptr))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is already capturing");
			return false;
		}

		m_Capturing.callback = onPacketArrives;
		m_Capturing.userCookie = onPacketArrivesUserCookie;

		m_Capturing.thread = new KniThread(KniThread::JOINABLE, KniCapturing::runCapture, (void*)this);
		if (m_Capturing.thread->m_CleanupState == KniThread::INVALID)
		{
			PCPP_LOG_DEBUG("KNI failed to start capturing thread on device '" << m_DeviceInfo.name << "'");
			delete m_Capturing.thread;
			return false;
		}

		return true;
	}

	void KniDevice::stopCapture()
	{
		if (m_Capturing.thread == nullptr)
		{
			PCPP_LOG_DEBUG("Attempt to stop not running KNI capturing thread for device '" << m_DeviceInfo.name << "'");
			return;
		}
		m_Capturing.cleanup();
	}

	int KniDevice::startCaptureBlockingMode(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie,
	                                        int timeout)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is not opened. Can't start capture");
			return 0;
		}
		if (unlikely(m_Capturing.thread != nullptr))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is already capturing");
			return 0;
		}
		m_Capturing.callback = onPacketArrives;
		m_Capturing.userCookie = onPacketArrivesUserCookie;
		if (unlikely(m_Capturing.callback == nullptr))
		{
			PCPP_LOG_ERROR("Attempt to start KNI device '" << m_DeviceInfo.name
			                                               << "' capturing in blocking mode without callback");
			return 0;
		}

		struct rte_mbuf* mBufArray[MAX_BURST_SIZE];

		if (timeout <= 0)
		{
			for (;;)
			{
				uint32_t numOfPktsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);
				if (likely(numOfPktsReceived != 0))
				{
					MBufRawPacket rawPackets[MAX_BURST_SIZE];
					timespec time;
					clock_gettime(CLOCK_REALTIME, &time);

					for (uint32_t index = 0; index < numOfPktsReceived; ++index)
					{
						rawPackets[index].setMBuf(mBufArray[index], time);
					}

					if (!m_Capturing.callback(rawPackets, numOfPktsReceived, this, m_Capturing.userCookie))
						return 1;
				}
			}
		}
		else
		{
			long startTimeSec = 0, startTimeNSec = 0;
			long curTimeSec = 0, curTimeNSec = 0;
			clockGetTime(startTimeSec, startTimeNSec);

			while (curTimeSec <= (startTimeSec + timeout))
			{
				clockGetTime(curTimeSec, curTimeNSec);
				uint32_t numOfPktsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);
				if (likely(numOfPktsReceived != 0))
				{
					MBufRawPacket rawPackets[MAX_BURST_SIZE];
					timespec time;
					time.tv_sec = curTimeSec;
					time.tv_nsec = curTimeNSec;

					for (uint32_t index = 0; index < numOfPktsReceived; ++index)
					{
						rawPackets[index].setMBuf(mBufArray[index], time);
					}

					if (!m_Capturing.callback(rawPackets, numOfPktsReceived, this, m_Capturing.userCookie))
						return 1;
				}
			}
		}
		return -1;
	}

	bool KniDevice::open()
	{
		if (unlikely(m_DeviceOpened))
		{
			PCPP_LOG_ERROR("KNI device '" << m_DeviceInfo.name << "' is already opened");
			return false;
		}
		(void)updateLinkState(LINK_UP);
		switch (m_DeviceInfo.link)
		{
		case LINK_ERROR:
			return m_DeviceOpened = false;
		case LINK_NOT_SUPPORTED:
			// fall through
		case LINK_DOWN:
			// fall through
		case LINK_UP:
			return m_DeviceOpened = true;
		}
		return false;
	}

	void KniDevice::close()
	{
		if (m_Capturing.thread != nullptr)
		{
			m_Capturing.cleanup();
		}
		updateLinkState(LINK_DOWN);
		m_DeviceOpened = false;
	}
}  // namespace pcpp

// GCOVR_EXCL_STOP
