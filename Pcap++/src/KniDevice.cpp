#ifdef USE_DPDK

#define LOG_MODULE PcapLogModuleDpdkDevice

#include "KniDevice.h"
#include "Logger.h"
#include "SystemUtils.h"

#include <unistd.h>
#include <pthread.h>

#include <rte_version.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_kni.h>
#include <rte_memory.h>
#include <rte_branch_prediction.h>

#include <cerrno>
#include <cstring>
#include <algorithm>

#define KNI_MEMPOOL_NAME "kni_mempool"
#define MEMPOOL_CACHE_SIZE 256
#define MAX_BURST_SIZE 64
#define MBUF_DATA_SIZE RTE_MBUF_DEFAULT_DATAROOM

#define CPP_VLA(TYPE, SIZE) (TYPE*)__builtin_alloca(sizeof(TYPE) * SIZE)

namespace pcpp
{

/**
 * ==========================
 * Class KniDevice::KniThread
 * ==========================
 */

struct KniDevice::KniThread
{
	enum cleanup_state
	{
		JOINABLE,
		DETACHED,
		INVALID
	};
	typedef void*(*thread_main_f)(void*);
	KniThread(cleanup_state s, thread_main_f main_f, void* data);
	~KniThread();

	bool cancel();

	pthread_t m_Descriptor;
	cleanup_state m_State;
};

KniDevice::KniThread::KniThread(cleanup_state s, thread_main_f main_f, void* data) :
	m_State(s)
{
	int err = pthread_create(&m_Descriptor, NULL, main_f, data);
	if (err != 0)
	{
		const char* errs = std::strerror(err);
		LOG_ERROR("KNI can't start pthread. pthread_create returned an error: %s", errs);
		m_State = INVALID;
		return;
	}
	if (m_State == INVALID)
	{
		err = pthread_detach(m_Descriptor);
		if (err != 0)
		{
			const char* errs = std::strerror(err);
			LOG_ERROR("KNI can't detach pthread. pthread_detach returned an error: %s", errs);
			m_State = INVALID;
			return;
		}
	}
}

KniDevice::KniThread::~KniThread()
{
	if (m_State == JOINABLE)
	{
		int err = pthread_join(m_Descriptor, NULL);
		if (err != 0)
		{
			const char* errs = std::strerror(err);
			LOG_DEBUG("KNI failed to join pthread. pthread_join returned an error: %s", errs);
		}
	}
}

bool KniDevice::KniThread::cancel()
{
	return pthread_cancel(m_Descriptor);
}

/**
 * ===================
 * Class KniDeviceList
 * ===================
 */

namespace
{

inline bool check_kni_driver()
{
	std::string execResult = executeShellCommand("lsmod | grep -s rte_kni");
	if (execResult == "")
	{
		LOG_ERROR("rte_kni driver isn't loaded, DPDK KNI cannot be initialized");
		return false;
	}
	LOG_DEBUG("rte_kni driver is loaded");
	return true;
}

} // namespace

struct KniDeviceList
{
	enum
	{
		MAX_KNI_INTERFACES = 4 // This value have no meaning in current DPDK implementation
	};
	static KniDeviceList& Instance();

	~KniDeviceList();

	inline bool isInitialized() { return m_Initialized; }

private:
	KniDeviceList();

public:
	std::vector<KniDevice*> m_Devices;
	bool m_Initialized;
	int m_KniUniqueId;
};

KniDeviceList::KniDeviceList() :
	m_Devices(MAX_KNI_INTERFACES, (KniDevice*)NULL),
	m_Initialized(true), m_KniUniqueId(0)
{
	if (!check_kni_driver())
	{
		m_Initialized = false;
		return;
	}
	if (rte_kni_init(MAX_KNI_INTERFACES) < 0)
	{
		LOG_ERROR("Failed to initialize KNI DPDK module");
		m_Initialized = false;
	}
}

KniDeviceList::~KniDeviceList()
{
	for (int i = 0; i < m_Devices.size(); ++i)
		delete m_Devices[i];
	rte_kni_close();
}

KniDeviceList& KniDeviceList::Instance()
{
	static KniDeviceList g_KniDeviceList;
	return g_KniDeviceList;
}

/**
 * ==================
 * Class KniRawPacket
 * ==================
 */

bool KniRawPacket::init(KniDevice* device)
{
	if (m_MBuf != NULL)
	{
		LOG_ERROR("KniRawPacket already initialized");
		return false;
	}

	m_MBuf = rte_pktmbuf_alloc(device->m_MBufMempool);
	if (m_MBuf == NULL)
	{
		LOG_ERROR("Couldn't allocate mbuf for KniRawPacket. Device name: \"%s\"", device->m_DeviceInfo.name);
		return false;
	}

	m_KniDevice = device;

	return true;
}

bool KniRawPacket::initFromRawPacket(const RawPacket* rawPacket, KniDevice* device)
{
	if (!init(device))
		return false;

	m_RawPacketSet = false;

	// mbuf is allocated with length of 0, need to adjust it to the size of other
	if (rte_pktmbuf_append(m_MBuf, rawPacket->getRawDataLen()) == NULL)
	{
		LOG_ERROR("KNI Couldn't append %d bytes to mbuf", rawPacket->getRawDataLen());
		return false;
	}

	m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);

	copyDataFrom(*rawPacket, false);

	return true;
}

bool KniRawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	if (rawDataLen > MBUF_DATA_SIZE)
	{
		LOG_ERROR(
			"Cannot set raw data which length is larger than mBuf max size. "
			"mBuf max length: %d; requested length: %d",
			MBUF_DATA_SIZE,
			rawDataLen
		);
		return false;
	}

	if (m_MBuf == NULL)
	{
		if (!(init(m_KniDevice)))
		{
			LOG_ERROR("KNI Couldn't allocate new mBuf");
			return false;
		}
	}

	// adjust the size of the mbuf to the new data
	if (m_RawDataLen < rawDataLen)
	{
		if (rte_pktmbuf_append(m_MBuf, rawDataLen - m_RawDataLen) == NULL)
		{
			LOG_ERROR("KNI Couldn't append %d bytes to mbuf", rawDataLen - m_RawDataLen);
			return false;
		}
	}
	else if (m_RawDataLen > rawDataLen)
	{
		if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - rawDataLen) == NULL)
		{
			LOG_ERROR("KNI Couldn't remove %d bytes to mbuf", m_RawDataLen - rawDataLen);
			return false;
		}
	}

	m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);
	std::memcpy(m_RawData, pRawData, m_RawDataLen);
	delete [] pRawData;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_FrameLength = frameLength;
	m_LinkLayerType = layerType;

	return true;
}

/**
 * ===============
 * Class KniDevice
 * ===============
 */

namespace
{

inline bool destroy_kni_device(struct rte_kni* kni_dev, const char* dev_name)
{
	if (rte_kni_release(kni_dev) < 0)
	{
		LOG_ERROR("Failed to destroy DPDK KNI device %s", dev_name);
	}
}

inline KniDevice::KniLinkState set_kni_device_link_state(
	struct rte_kni* kni_dev,
	const char* dev_name,
	KniDevice::KniLinkState state = KniDevice::KniLinkState::LINK_UP
)
{
	KniDevice::KniLinkState old_state = KniDevice::KniLinkState::LINK_NOT_SUPPORTED;
	if (state != KniDevice::KniLinkState::LINK_UP ||
		state != KniDevice::KniLinkState::LINK_DOWN ||
		kni_dev == NULL
	)
	{
		return old_state = KniDevice::KniLinkState::LINK_ERROR;
	}
	#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 1, 16)
		old_state = (KniDevice::KniLinkState)rte_kni_update_link(kni_dev, state);
		if (old_state == KniDevice::KniLinkState::LINK_ERROR)
		{
			LOG_ERROR("DPDK KNI Failed to update links state for device \"%s\"", dev_name);
		}
	#else
		// To avoid compiler warnings
		(void) kni_dev;
		(void) dev_name;
	#endif
	return old_state;
}

inline struct rte_mempool* create_mempool(size_t mempoolSize, int unique, const char* dev_name)
{
	struct rte_mempool* result = NULL;
	char mempoolName[64];
	std::snprintf(mempoolName, sizeof(mempoolName),
		KNI_MEMPOOL_NAME "_%d",
		unique
	);
	result = rte_pktmbuf_pool_create(
		mempoolName,
		mempoolSize,
		MEMPOOL_CACHE_SIZE,
		0,
		RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id()
	);
	if (result == NULL)
	{
		LOG_ERROR("Failed to create packets memory pool for KNI device %s, pool name: %s", dev_name, mempoolName);
	}
	else
	{
		LOG_DEBUG("Successfully initialized packets pool of size [%d] for KNI device [%s]", mempoolSize, dev_name);
	}
	return result;
}

} // namespace

KniDevice::KniDevice(const KniDeviceConfiguration& conf, size_t mempoolSize, int unique) :
	m_Device(NULL), m_MBufMempool(NULL)
{
	struct rte_kni_ops kni_ops;
	struct rte_kni_conf kni_conf;
	m_DeviceInfo.init(conf);
	m_Requests.thread = NULL;
	std::memset(&m_Capturing, 0, sizeof(m_Capturing));
	std::memset(&m_Requests, 0, sizeof(m_Requests));

	if ((m_MBufMempool = create_mempool(mempoolSize, unique, conf.name)) == NULL)
		return;

	std::memset(&kni_ops, 0, sizeof(kni_ops));
	std::memset(&kni_conf, 0, sizeof(kni_conf));
	std::snprintf(kni_conf.name, RTE_KNI_NAMESIZE, conf.name);
	kni_conf.core_id = conf.kthread_core_id;
	kni_conf.mbuf_size = RTE_MBUF_DEFAULT_DATAROOM;
	kni_conf.force_bind = conf.bind_kthread ? 1 : 0;
	if (conf.mac != NULL)
		conf.mac->copyTo((uint8_t*)kni_conf.mac_addr);
	kni_conf.mtu = conf.mtu;
	kni_ops.port_id = conf.port_id;
	if (conf.callbacks != NULL)
	{
		kni_ops.change_mtu = conf.callbacks->change_mtu;
		kni_ops.config_network_if = conf.callbacks->config_network_if;
		kni_ops.config_mac_address = conf.callbacks->config_mac_address;
		kni_ops.config_promiscusity = conf.callbacks->config_promiscusity;
	}

	m_Device = rte_kni_alloc(m_MBufMempool, &kni_conf, &kni_ops);
	if (m_Device == NULL)
	{
		LOG_ERROR("DPDK have failed to create KNI device %s", conf.name);
	}
}

KniDevice::~KniDevice()
{
	m_Requests.cleanup();
	m_Capturing.cleanup();
	m_DeviceInfo.cleanup();
	set_kni_device_link_state(m_Device, m_DeviceInfo.name, KniLinkState::LINK_DOWN);
	destroy_kni_device(m_Device, m_DeviceInfo.name);
}

KniDevice::KniLinkState KniDevice::updateLinkState(KniLinkState state)
{
	return set_kni_device_link_state(m_Device, m_DeviceInfo.name, state);
}

bool KniDevice::handleRequest()
{
	return rte_kni_handle_request(m_Device);
}

void KniDevice::KniRequests::cleanup()
{
	delete thread;
	thread = NULL;
	sleep_time = 0;
}

void* KniDevice::KniRequests::runRequests(void* p)
{
	KniDevice* device = (KniDevice*)p;
	uint16_t sleep_time = device->m_Requests.sleep_time;
	struct rte_kni* kni_dev = device->m_Device;
	for(;;)
	{
		usleep(sleep_time);
		pthread_testcancel();
		rte_kni_handle_request(kni_dev);
	}
	return NULL;
}

bool KniDevice::startRequestHandlerThread(uint16_t sleep_time)
{
	if (m_Requests.thread != NULL)
	{
		LOG_DEBUG("KNI request thread is already started for device \"%s\"", m_DeviceInfo.name);
		return false;
	}
	m_Requests.sleep_time = sleep_time;
	m_Requests.thread = new KniThread(KniThread::DETACHED, KniRequests::runRequests, (void*)this);
	if (m_Requests.thread->m_State == KniThread::INVALID)
	{
		m_Requests.cleanup();
		return false;
	}
	return true;
}

void KniDevice::stopRequestHandlerThread()
{
	if (m_Requests.thread == NULL)
	{
		LOG_DEBUG("Attempt to stop not running KNI request thread for device \"%s\"", m_DeviceInfo.name);
		return;
	}
	m_Requests.cleanup();
}

uint16_t KniDevice::receivePackets(MBufRawPacketVector& rawPacketsArr)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}
	if (unlikely(m_Capturing.isRunning()))
	{
		LOG_ERROR(
			"KNI device \"%s\" capture mode is currently running. "
			"Cannot recieve packets in parallel",
			m_DeviceInfo.name
		);
		return 0;
	}

	struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
	uint32_t numOfPktsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

	//the following line trashes the log with many messages. Uncomment only if necessary
	//LOG_DEBUG("KNI Captured %d packets", numOfPktsReceived);

	if (unlikely(numOfPktsReceived <= 0))
	{
		return 0;
	}

	timeval time;
	gettimeofday(&time, NULL);

	for (uint32_t index = 0; index < numOfPktsReceived; ++index)
	{
		struct rte_mbuf* mBuf = mBufArray[index];
		KniRawPacket* newRawPacket = new KniRawPacket();
		newRawPacket->setMBuf(mBuf, time);
		rawPacketsArr.pushBack(newRawPacket);
	}

	return numOfPktsReceived;
}

uint16_t KniDevice::receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}
	if (unlikely(m_Capturing.isRunning()))
	{
		LOG_ERROR(
			"KNI device \"%s\" capture mode is currently running. "
			"Cannot recieve packets in parallel",
			m_DeviceInfo.name
		);
		return 0;
	}
	if (unlikely(rawPacketsArr == NULL))
	{
		LOG_ERROR("KNI Provided address of array to store packets is NULL");
		return 0;
	}

	struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, rawPacketArrLength);
	uint16_t packetsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

	//LOG_DEBUG("KNI Captured %d packets", rawPacketArrLength);

	if (unlikely(packetsReceived <= 0))
	{
		return 0;
	}

	timeval time;
	gettimeofday(&time, NULL);

	for (size_t index = 0; index < packetsReceived; ++index)
	{
		struct rte_mbuf* mBuf = mBufArray[index];
		if (rawPacketsArr[index] == NULL)
			rawPacketsArr[index] = new KniRawPacket();

		((KniRawPacket*)rawPacketsArr[index])->setMBuf(mBuf, time);
	}

	return packetsReceived;
}

uint16_t KniDevice::receivePackets(Packet** packetsArr, uint16_t packetsArrLength)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}
	if (unlikely(m_Capturing.isRunning()))
	{
		LOG_ERROR(
			"KNI device \"%s\" capture mode is currently running. "
			"Cannot recieve packets in parallel",
			m_DeviceInfo.name
		);
		return 0;
	}


	struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, packetsArrLength);
	uint16_t packetsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);

	//LOG_DEBUG("KNI Captured %d packets", packetsArrLength);

	if (unlikely(packetsReceived <= 0))
	{
		return 0;
	}

	timeval time;
	gettimeofday(&time, NULL);

	for (size_t index = 0; index < packetsReceived; ++index)
	{
		struct rte_mbuf* mBuf = mBufArray[index];
		KniRawPacket* newRawPacket = new KniRawPacket();
		newRawPacket->setMBuf(mBuf, time);
		if (packetsArr[index] == NULL)
			packetsArr[index] = new Packet();

		packetsArr[index]->setRawPacket(newRawPacket, true);
	}

	return packetsReceived;
}

uint16_t KniDevice::sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
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
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}

	struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
	MBufRawPacket** mBufRawPacketArr = CPP_VLA(MBufRawPacket*, arrLength);
	KniRawPacket** allocated = CPP_VLA(KniRawPacket*, arrLength);
	uint16_t allocated_count = 0, packetsSent = 0;
	MBufRawPacket* rawPacket;
	RawPacket* raw_pkt;

	for (uint16_t i = 0; i < arrLength; ++i)
	{
		raw_pkt = packetsArr[i]->getRawPacketReadOnly();
		uint8_t raw_type = raw_pkt->getObjectType();
		if (!(raw_type == MBUFRAWPACKET_OBJECT_TYPE || raw_type == KNIRAWPACKET_OBJECT_TYPE))
		{
			KniRawPacket* pkt = new KniRawPacket();
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
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
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
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}

	size_t arrLength = rawPacketsVec.size();
	struct rte_mbuf** mBufArray = CPP_VLA(struct rte_mbuf*, arrLength);
	MBufRawPacket** mBufRawPacketArr = CPP_VLA(MBufRawPacket*, arrLength);
	KniRawPacket** allocated = CPP_VLA(KniRawPacket*, arrLength);
	uint16_t allocated_count = 0, packetsSent = 0, pos = 0;
	MBufRawPacket* rawPacket;
	RawPacket* raw_pkt;

	for (RawPacketVector::VectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); ++iter)
	{
		uint8_t raw_type = (*iter)->getObjectType();
		if (!(raw_type == MBUFRAWPACKET_OBJECT_TYPE || raw_type == KNIRAWPACKET_OBJECT_TYPE))
		{
			KniRawPacket* pkt = new KniRawPacket();
			if (unlikely(!pkt->initFromRawPacket(*iter, this)))
			{
				delete pkt;
				goto error_out;
			}
			rawPacket = allocated[allocated_count++] = pkt;
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
	for (uint16_t i = 0; i < allocated_count; ++i)
		delete allocated[i];
	return packetsSent;
}

bool KniDevice::sendPacket(RawPacket& rawPacket)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
		return 0;
	}

	struct rte_mbuf* mbuf;
	MBufRawPacket* raw_packet;
	KniRawPacket* kni_raw = NULL;
	bool sent = false;

	uint8_t raw_type = rawPacket.getObjectType();
	if (!(raw_type == MBUFRAWPACKET_OBJECT_TYPE || raw_type == KNIRAWPACKET_OBJECT_TYPE))
	{
		kni_raw = new KniRawPacket();
		if (unlikely(!kni_raw->initFromRawPacket(&rawPacket, this)))
		{
			delete kni_raw;
			return sent;
		}
		raw_packet = kni_raw;
		mbuf = kni_raw->getMBuf();
	}
	else
	{
		raw_packet = (MBufRawPacket*)(&rawPacket);
		mbuf = raw_packet->getMBuf();
	}

	sent = rte_kni_tx_burst(m_Device, &mbuf, 1);
	raw_packet->setFreeMbuf(!sent);
	if (kni_raw != NULL)
		delete kni_raw;

	return sent;
}

bool KniDevice::sendPacket(MBufRawPacket& rawPacket)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened", m_DeviceInfo.name);
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

void* KniDevice::KniCapturing::runCapture(void* p)
{
	KniDevice* device = (KniDevice*)p;
	OnKniPacketArriveCallback callback = device->m_Capturing.callback;
	void* user_cookie = device->m_Capturing.user_cookie;
	struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
	struct rte_kni* kni_dev = device->m_Device;

	LOG_DEBUG("Starting KNI capture thread for device \"%s\"", device->m_DeviceInfo.name);

	for(;;)
	{
		uint32_t numOfPktsReceived = rte_kni_rx_burst(kni_dev, mBufArray, MAX_BURST_SIZE);
		if (unlikely(numOfPktsReceived == 0))
		{
			pthread_testcancel();
			continue;
		}

		timeval time;
		gettimeofday(&time, NULL);

		if (likely(callback != NULL))
		{
			KniRawPacket rawPackets[MAX_BURST_SIZE];
			for (uint32_t index = 0; index < numOfPktsReceived; ++index)
			{
				rawPackets[index].setMBuf(mBufArray[index], time);
			}

			if (!callback(rawPackets, numOfPktsReceived, device, user_cookie))
				break;
		}
		pthread_testcancel();
	}
	return NULL;
}

void KniDevice::KniCapturing::cleanup()
{
	delete thread;
	thread = NULL;
	callback = NULL;
	user_cookie = NULL;
}

bool KniDevice::startCapture(
	OnKniPacketArriveCallback onPacketArrives,
	void* onPacketArrivesUserCookie
)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened. Can't start capture", m_DeviceInfo.name);
		return false;
	}
	if (unlikely(m_Capturing.thread != NULL))
	{
		LOG_ERROR("KNI device \"%s\" is already capturing", m_DeviceInfo.name);
		return false;
	}

	m_Capturing.callback = onPacketArrives;
	m_Capturing.user_cookie = onPacketArrivesUserCookie;

	m_Capturing.thread = new KniThread(KniThread::JOINABLE, KniCapturing::runCapture, (void*)this);
	if (m_Capturing.thread->m_State == KniThread::INVALID)
	{
		LOG_DEBUG("KNI failed to start capturing thread on device \"%s\"",  m_DeviceInfo.name);
		delete m_Capturing.thread;
		return false;
	}

	return true;
}

void KniDevice::stopCapture()
{
	if (m_Capturing.thread == NULL)
	{
		LOG_DEBUG("Attempt to stop not running KNI capturing thread for device \"%s\"", m_DeviceInfo.name);
		return;
	}
	m_Capturing.cleanup();
}

int KniDevice::startCaptureBlockingMode(
	OnKniPacketArriveCallback onPacketArrives,
	void* onPacketArrivesUserCookie,
	int timeout
)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is not opened. Can't start capture", m_DeviceInfo.name);
		return 0;
	}
	if (unlikely(m_Capturing.thread != NULL))
	{
		LOG_ERROR("KNI device \"%s\" is already capturing", m_DeviceInfo.name);
		return 0;
	}
	if (unlikely(m_Capturing.callback == NULL))
	{
		LOG_ERROR("Attempt to start KNI device \"%s\" capturing in blocking mode without callback", m_DeviceInfo.name);
		return 0;
	}

	struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
	long startTimeSec = 0, startTimeNSec = 0;
	long curTimeSec = 0, curTimeNSec = 0;

	clockGetTime(startTimeSec, startTimeNSec);

	while(curTimeSec <= (startTimeSec + timeout))
	{
		clockGetTime(curTimeSec, curTimeNSec);
		uint32_t numOfPktsReceived = rte_kni_rx_burst(m_Device, mBufArray, MAX_BURST_SIZE);
		if (likely(numOfPktsReceived != 0))
		{
			KniRawPacket rawPackets[MAX_BURST_SIZE];
			timeval time;
			time.tv_sec = curTimeSec;
			time.tv_usec = curTimeNSec / 1000;

			for (uint32_t index = 0; index < numOfPktsReceived; ++index)
			{
				rawPackets[index].setMBuf(mBufArray[index], time);
			}

			if (!m_Capturing.callback(rawPackets, numOfPktsReceived, this, m_Capturing.user_cookie))
				return 1;
		}
	}
	return -1;
}

bool KniDevice::open()
{
	if (unlikely(m_DeviceOpened))
	{
		LOG_ERROR("KNI device \"%s\" is already opened", m_DeviceInfo.name);
		return false;
	}

	switch (updateLinkState(LINK_UP))
	{
		case LINK_ERROR:
			return m_DeviceOpened = false;
		case LINK_NOT_SUPPORTED:
		/* fall through */
		case LINK_DOWN:
		/* fall through */
		case LINK_UP:
			return m_DeviceOpened = true;
	}
	return false;
}

void KniDevice::close()
{
	if (m_Capturing.thread != NULL)
	{
		m_Capturing.cleanup();
	}
	updateLinkState(LINK_DOWN);
}

KniDevice* KniDevice::DeviceFabric(const KniDeviceConfiguration& conf, size_t mempoolSize)
{
	KniDeviceList& list = KniDeviceList::Instance();
	if (!list.isInitialized())
		return NULL;
	KniDevice* kni_dev = getDeviceByName(std::string(conf.name));
	if (kni_dev != NULL)
	{
		LOG_ERROR("Attempt to create DPDK KNI device with same name: \"%s\".", conf.name);
		LOG_DEBUG("Use KniDevice::getDeviceByName or KniDevice::getDeviceByPort.");
		return NULL;
	}
	KniDevice* kni_dev = new KniDevice(conf, mempoolSize, list.m_KniUniqueId++);
	list.m_Devices.push_back(kni_dev);
	return kni_dev;
}

void KniDevice::DestroyDevice(KniDevice* kni_dev)
{
	KniDeviceList& list = KniDeviceList::Instance();
	list.m_Devices.erase(
		std::remove(
			list.m_Devices.begin(),
			list.m_Devices.end(),
			kni_dev
		),
		list.m_Devices.end()
	);
	delete kni_dev;
}

KniDevice* KniDevice::getDeviceByPort(uint16_t port_id)
{
	KniDevice* kni_dev = NULL;
	KniDeviceList& list = KniDeviceList::Instance();
	if (!list.m_Initialized)
		return kni_dev;
	for (int i = 0; i < list.m_Devices.size(); ++i)
	{
		kni_dev = list.m_Devices[i];
		if (kni_dev && kni_dev->m_DeviceInfo.port_id == port_id)
			return kni_dev;
	}
	return kni_dev;
}

KniDevice* KniDevice::getDeviceByName(const std::string& name)
{
	KniDevice* kni_dev = NULL;
	KniDeviceList& list = KniDeviceList::Instance();
	if (!list.m_Initialized)
		return kni_dev;
	for (int i = 0; i < list.m_Devices.size(); ++i)
	{
		kni_dev = list.m_Devices[i];
		if (kni_dev && kni_dev->m_DeviceInfo.name == name)
			return kni_dev;
	}
	return kni_dev;
}

}
#endif /* USE_DPDK */