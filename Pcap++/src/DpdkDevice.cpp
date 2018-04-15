#ifdef USE_DPDK

#define LOG_MODULE PcapLogModuleDpdkDevice

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "Logger.h"
#include "rte_version.h"
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
#include "rte_bus_pci.h"
#endif
#include "rte_pci.h"
#include "rte_config.h"
#include "rte_ethdev.h"
#include "rte_errno.h"
#include "rte_malloc.h"
#include "rte_cycles.h"
#include <string>
#include <stdint.h>
#include <unistd.h>

#define MBUF_DATA_SIZE 2048

#define MBUF_SIZE (MBUF_DATA_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define MAX_BURST_SIZE 64

namespace pcpp
{

/**
 * ===================
 * Class MBufRawPacket
 * ===================
 */

MBufRawPacket::~MBufRawPacket()
{
	if (m_MBuf != NULL)
	{
		rte_pktmbuf_free(m_MBuf);
	}
}

bool MBufRawPacket::init(DpdkDevice* device)
{
	if (m_MBuf != NULL)
	{
		LOG_ERROR("MBufRawPacket already initialized");
		return false;
	}

	m_MBuf = rte_pktmbuf_alloc(device->m_MBufMempool);
	if (m_MBuf == NULL)
	{
		LOG_ERROR("Couldn't allocate mbuf");
		return false;
	}

	m_Device = device;

	return true;
}

bool MBufRawPacket::initFromRawPacket(const RawPacket* rawPacket, DpdkDevice* device)
{
	if (!init(device))
		return false;

	m_RawPacketSet = false;

	// mbuf is allocated with length of 0, need to adjust it to the size of other
	if (rte_pktmbuf_append(m_MBuf, rawPacket->getRawDataLen()) == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to mbuf", rawPacket->getRawDataLen());
		return false;
	}

	m_pRawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);

	copyDataFrom(*rawPacket, false);

	return true;
}

MBufRawPacket::MBufRawPacket(const MBufRawPacket& other)
{
	m_DeleteRawDataAtDestructor = false;
	m_MBuf = NULL;
	m_RawDataLen = 0;
	m_RawPacketSet = false;
	m_pRawData = NULL;
	m_Device = other.m_Device;

	rte_mbuf* newMbuf = rte_pktmbuf_alloc(other.m_MBuf->pool);
	if (newMbuf == NULL)
	{
		LOG_ERROR("Couldn't allocate mbuf");
		return;
	}

	// mbuf is allocated with length of 0, need to adjust it to the size of other
	if (rte_pktmbuf_append(newMbuf, other.m_RawDataLen) == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to mbuf", other.m_RawDataLen);
		return;
	}

	setMBuf(newMbuf, other.m_TimeStamp);

	m_RawPacketSet = false;

	copyDataFrom(other, false);
}

MBufRawPacket& MBufRawPacket::operator=(const MBufRawPacket& other)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket isn't initialized");
		return *this;
	}

	// adjust the size of the mbuf to the new data
	if (m_RawDataLen < other.m_RawDataLen)
	{
		if (rte_pktmbuf_append(m_MBuf, other.m_RawDataLen - m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't append %d bytes to mbuf", other.m_RawDataLen - m_RawDataLen);
			return *this;
		}
	}
	else if (m_RawDataLen > other.m_RawDataLen)
	{
		if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - other.m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't remove %d bytes to mbuf", m_RawDataLen - other.m_RawDataLen);
			return *this;
		}
	}

	m_RawPacketSet = false;

	copyDataFrom(other, false);

	return *this;
}

bool MBufRawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	if (rawDataLen > MBUF_DATA_SIZE)
	{
		LOG_ERROR("Cannot set raw data which length is larger than mBuf max size. mBuf max length: %d; requested length: %d", MBUF_DATA_SIZE, rawDataLen);
		return false;
	}

	if (m_MBuf == NULL)
	{
		if (!(init(m_Device)))
		{
			LOG_ERROR("Couldn't allocate new mBuf");
			return false;
		}
	}

	// adjust the size of the mbuf to the new data
	if (m_RawDataLen < rawDataLen)
	{
		if (rte_pktmbuf_append(m_MBuf, rawDataLen - m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't append %d bytes to mbuf", rawDataLen - m_RawDataLen);
			return false;
		}
	}
	else if (m_RawDataLen > rawDataLen)
	{
		if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - rawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't remove %d bytes to mbuf", m_RawDataLen - rawDataLen);
			return false;
		}
	}

	m_pRawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);
	memcpy(m_pRawData, pRawData, m_RawDataLen);
	delete [] pRawData;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_FrameLength = frameLength;
	m_linkLayerType = layerType;

	return true;
}

void MBufRawPacket::clear()
{
	if (m_MBuf != NULL)
	{
		rte_pktmbuf_free(m_MBuf);
		m_MBuf = NULL;
	}

	m_pRawData = NULL;

	RawPacket::clear();
}

void MBufRawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return; //TODO: need to return false here or something
	}

	char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToAppendLen);
	if (startOfNewlyAppendedData == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to RawPacket - not enough room in mBuf", (int)dataToAppendLen);
		return; //TODO: need to return false here or something
	}

	RawPacket::appendData(dataToAppend, dataToAppendLen);

	LOG_DEBUG("Appended %d bytes to MBufRawPacket", (int)dataToAppendLen);
}

void MBufRawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return; //TODO: need to return false here or something
	}

	char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToInsertLen);
	if (startOfNewlyAppendedData == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to RawPacket - not enough room in mBuf", (int)dataToInsertLen);
		return; //TODO: need to return false here or something
	}

	RawPacket::insertData(atIndex, dataToInsert, dataToInsertLen);

	LOG_DEBUG("Inserted %d bytes to MBufRawPacket", (int)dataToInsertLen);
}

bool MBufRawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return false;
	}

	if (!RawPacket::removeData(atIndex, numOfBytesToRemove))
		return false;

	if (rte_pktmbuf_trim(m_MBuf, numOfBytesToRemove) != 0)
	{
		LOG_ERROR("Couldn't trim the mBuf");
		return false;
	}

	LOG_DEBUG("Trimmed %d bytes from MBufRawPacket", (int)numOfBytesToRemove);

	return true;
}

bool MBufRawPacket::reallocateData(size_t newBufferLength)
{
	if ((int)newBufferLength < m_RawDataLen)
	{
		LOG_ERROR("Cannot reallocate mBuf raw packet to a smaller size. Current data length: %d; requested length: %d", m_RawDataLen, (int)newBufferLength);
		return false;
	}

	if (newBufferLength > MBUF_DATA_SIZE)
	{
		LOG_ERROR("Cannot reallocate mBuf raw packet to a size larger than mBuf data. mBuf max length: %d; requested length: %d", MBUF_DATA_SIZE, (int)newBufferLength);
		return false;
	}

	// no need to do any memory allocation because mbuf is already allocated

	return true;
}

void MBufRawPacket::setMBuf(struct rte_mbuf* mBuf, timeval timestamp)
{
	if (m_MBuf != NULL)
		rte_pktmbuf_free(m_MBuf);

	if (mBuf == NULL)
	{
		LOG_ERROR("mbuf to set is NULL");
		return;
	}

	m_MBuf = mBuf;
	RawPacket::setRawData(rte_pktmbuf_mtod(mBuf, const uint8_t*), rte_pktmbuf_pkt_len(mBuf), timestamp, LINKTYPE_ETHERNET);
}




/**
 * ================
 * Class DpdkDevice
 * ================
 */

#define DPDK_COFIG_HEADER_SPLIT			0 /**< Header Split disabled */
#define DPDK_COFIG_SPLIT_HEADER_SIZE	0
#define DPDK_COFIG_HW_IP_CHECKSUM		0 /**< IP checksum offload disabled */
#define DPDK_COFIG_HW_VLAN_FILTER		0 /**< VLAN filtering disabled */
#define DPDK_COFIG_JUMBO_FRAME			0 /**< Jumbo Frame Support disabled */
#define DPDK_COFIG_HW_STRIP_CRC			0 /**< CRC stripped by hardware disabled */
#define DPDK_CONFIG_MQ_MODE				ETH_RSS

//RSS random key:
uint8_t DpdkDevice::m_RSSKey[40] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	};

DpdkDevice::DpdkDevice(int port, uint32_t mBufPoolSize)
	: m_Id(port), m_MacAddress(MacAddress::Zero)
{
	snprintf((char*)m_DeviceName, 30, "DPDK_%d", m_Id);

	struct ether_addr etherAddr;
	rte_eth_macaddr_get((uint8_t) m_Id, &etherAddr);
	m_MacAddress = MacAddress(etherAddr.addr_bytes[0], etherAddr.addr_bytes[1],
			etherAddr.addr_bytes[2], etherAddr.addr_bytes[3],
			etherAddr.addr_bytes[4], etherAddr.addr_bytes[5]);

	rte_eth_dev_get_mtu((uint8_t) m_Id, &m_DeviceMtu);

	char mBufMemPoolName[32];
	sprintf(mBufMemPoolName, "MBufMemPool%d", m_Id);
	if (!initMemPool(m_MBufMempool, mBufMemPoolName, mBufPoolSize))
	{
		LOG_ERROR("Could not initialize mBuf mempool. Device not initialized");
		return;
	}

	m_NumOfRxQueuesOpened = 0;
	m_NumOfTxQueuesOpened = 0;

	setDeviceInfo();

	memset(&m_PrevStats, 0 ,sizeof(m_PrevStats));

	m_TxBuffers = NULL;
	m_TxBufferLastDrainTsc = NULL;

	m_DeviceOpened = false;
	m_WasOpened = false;
	m_StopThread = true;
}

DpdkDevice::~DpdkDevice()
{
	if (m_TxBuffers != NULL)
		delete [] m_TxBuffers;

	if (m_TxBufferLastDrainTsc != NULL)
		delete [] m_TxBufferLastDrainTsc;
}

uint32_t DpdkDevice::getCurrentCoreId()
{
	return rte_lcore_id();
}

bool DpdkDevice::setMtu(uint16_t newMtu)
{
	int res = rte_eth_dev_set_mtu(m_Id, newMtu);
	if (res != 0)
	{
		LOG_ERROR("Couldn't set device MTU. DPDK error: %d", res);
		return false;
	}

	LOG_DEBUG("Managed to set MTU from %d to %d", m_DeviceMtu, newMtu);
	m_DeviceMtu = newMtu;
	return true;
}

bool DpdkDevice::openMultiQueues(uint16_t numOfRxQueuesToOpen, uint16_t numOfTxQueuesToOpen, const DpdkDeviceConfiguration& config)
{
	if (m_DeviceOpened)
	{
		LOG_ERROR("Device already opened");
		return false;
	}

	// There is a VMXNET3 limitation that when opening a device with a certain number of RX+TX queues
	// it's impossible to close it and open it again with a larger number of RX+TX queues. So for this
	// PMD I made a patch to open the device in the first time with maximum RX & TX queue, close it
	// immediately and open it again with number of queues the user wanted to
	if (!m_WasOpened && m_PMDType == PMD_VMXNET3)
	{
		m_WasOpened = true;
		openMultiQueues(getTotalNumOfRxQueues(), getTotalNumOfTxQueues(), config);
		close();
	}

	m_Config = config;

	if (!configurePort(numOfRxQueuesToOpen, numOfTxQueuesToOpen))
	{
		m_DeviceOpened = false;
		return false;
	}

	clearCoreConfiguration();

	if (!initQueues(numOfRxQueuesToOpen, numOfTxQueuesToOpen))
		return false;

	if (!startDevice())
	{
		LOG_ERROR("failed to start device %d\n", m_Id);
		m_DeviceOpened = false;
		return false;
	}

	m_NumOfRxQueuesOpened = numOfRxQueuesToOpen;
	m_NumOfTxQueuesOpened = numOfTxQueuesToOpen;

	rte_eth_stats_reset(m_Id);

	m_DeviceOpened = true;
	return m_DeviceOpened;
}


void DpdkDevice::close()
{
	if (!m_DeviceOpened)
	{
		LOG_DEBUG("Trying to close device [%s] but device is already closed", m_DeviceName);
		return;
	}
	stopCapture();
	clearCoreConfiguration();
	m_NumOfRxQueuesOpened = 0;
	m_NumOfTxQueuesOpened = 0;
	rte_eth_dev_stop(m_Id);
	LOG_DEBUG("Called rte_eth_dev_stop for device [%s]", m_DeviceName);
	m_DeviceOpened = false;
}


bool DpdkDevice::configurePort(uint8_t numOfRxQueues, uint8_t numOfTxQueues)
{
	if (numOfRxQueues > getTotalNumOfRxQueues())
	{
		LOG_ERROR("Could not open more than %d RX queues", getTotalNumOfRxQueues());
		return false;
	}

	if (numOfTxQueues > getTotalNumOfTxQueues())
	{
		LOG_ERROR("Could not open more than %d TX queues", getTotalNumOfTxQueues());
		return false;
	}

	// if PMD doesn't support RSS, set RSS HF to 0
	if (getSupportedRssHashFunctions() == 0 && m_Config.rssHashFunction != 0)
	{
		LOG_DEBUG("PMD '%s' doesn't support RSS, setting RSS hash functions to 0", m_PMDName.c_str());
		m_Config.rssHashFunction = 0;
	}

	if (!isDeviceSupportRssHashFunction(m_Config.rssHashFunction))
	{
		LOG_ERROR("PMD '%s' doesn't support the request RSS hash functions 0x%X", m_PMDName.c_str(), (uint32_t)m_Config.rssHashFunction);
		return false;
	}

	// verify num of RX queues is power of 2
	bool isRxQueuePowerOfTwo = !(numOfRxQueues == 0) && !(numOfRxQueues & (numOfRxQueues - 1));
	if (!isRxQueuePowerOfTwo)
	{
		LOG_ERROR("Num of RX queues must be power of 2 (because of DPDK limitation). Attempted to open device with %d RX queues", numOfRxQueues);
		return false;
	}

	struct rte_eth_conf portConf;
	memset(&portConf,0,sizeof(rte_eth_conf));
	portConf.rxmode.split_hdr_size = DPDK_COFIG_SPLIT_HEADER_SIZE;
	portConf.rxmode.header_split = DPDK_COFIG_HEADER_SPLIT;
	portConf.rxmode.hw_ip_checksum = DPDK_COFIG_HW_IP_CHECKSUM;
	portConf.rxmode.hw_vlan_filter = DPDK_COFIG_HW_VLAN_FILTER;
	portConf.rxmode.jumbo_frame = DPDK_COFIG_JUMBO_FRAME;
	portConf.rxmode.hw_strip_crc = DPDK_COFIG_HW_STRIP_CRC;
	portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_MODE;
	portConf.rx_adv_conf.rss_conf.rss_key = m_Config.rssKey;
	portConf.rx_adv_conf.rss_conf.rss_key_len = m_Config.rssKeyLength;
	portConf.rx_adv_conf.rss_conf.rss_hf = convertRssHfToDpdkRssHf(m_Config.rssHashFunction);

	int res = rte_eth_dev_configure((uint8_t) m_Id, numOfRxQueues, numOfTxQueues, &portConf);
	if (res < 0)
	{
		LOG_ERROR("Failed to configure device [%s]. error is: '%s' [Error code: %d]\n", m_DeviceName, rte_strerror(res), res);
		return false;
	}

	LOG_DEBUG("Successfully called rte_eth_dev_configure for device [%s] with %d RX queues and %d TX queues", m_DeviceName, numOfRxQueues, numOfTxQueues);

	return true;
}

bool DpdkDevice::initQueues(uint8_t numOfRxQueuesToInit, uint8_t numOfTxQueuesToInit)
{
	rte_eth_dev_info devInfo;
	rte_eth_dev_info_get(m_Id, &devInfo);
	if (numOfRxQueuesToInit > devInfo.max_rx_queues)
	{
		LOG_ERROR("Num of RX queues requested for open [%d] is larger than RX queues available in NIC [%d]", numOfRxQueuesToInit, devInfo.max_rx_queues);
		return false;
	}

	if (numOfTxQueuesToInit > devInfo.max_tx_queues)
	{
		LOG_ERROR("Num of TX queues requested for open [%d] is larger than TX queues available in NIC [%d]", numOfTxQueuesToInit, devInfo.max_tx_queues);
		return false;
	}

	for (uint8_t i = 0; i < numOfRxQueuesToInit; i++)
	{
		int ret = rte_eth_rx_queue_setup((uint8_t) m_Id, i,
				m_Config.receiveDescriptorsNumber, 0,
				NULL, m_MBufMempool);

		if (ret < 0)
		{
			LOG_ERROR("Failed to init RX queue for device [%s]. Error was: '%s' [Error code: %d]", m_DeviceName, rte_strerror(ret), ret);
			return false;
		}
	}

	LOG_DEBUG("Successfully initialized %d RX queues for device [%s]", numOfRxQueuesToInit, m_DeviceName);

	for (uint8_t i = 0; i < numOfTxQueuesToInit; i++)
	{
		int ret = rte_eth_tx_queue_setup((uint8_t) m_Id, i,
				m_Config.transmitDescriptorsNumber,
					0, NULL);
		if (ret < 0)
		{
			LOG_ERROR("Failed to init TX queue #%d for port %d. Error was: '%s' [Error code: %d]", i, m_Id, rte_strerror(ret), ret);
			return false;
		}
	}

	if (m_TxBuffers != NULL)
		delete [] m_TxBuffers;

	if (m_TxBufferLastDrainTsc != NULL)
		delete [] m_TxBufferLastDrainTsc;

	m_TxBuffers = new rte_eth_dev_tx_buffer*[numOfTxQueuesToInit];
	m_TxBufferLastDrainTsc = new uint64_t[numOfTxQueuesToInit];
	memset(m_TxBufferLastDrainTsc, 0, sizeof(uint64_t)*numOfTxQueuesToInit);

	for (uint8_t i = 0; i < numOfTxQueuesToInit; i++)
	{
		m_TxBuffers[i] = (rte_eth_dev_tx_buffer*)rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_BURST_SIZE), 0, rte_eth_dev_socket_id(m_Id));

		if (m_TxBuffers[i] == NULL)
		{
			LOG_ERROR("Failed to allocate TX buffer for port %d TX queue %d", m_Id, (int)i);
			return false;
		}

		int res = rte_eth_tx_buffer_init(m_TxBuffers[i], MAX_BURST_SIZE);

		if (res != 0)
		{
			LOG_ERROR("Failed to init TX buffer for port %d TX queue %d", m_Id, (int)i);
			return false;
		}
	}

	m_TxBufferDrainTsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * m_Config.flushTxBufferTimeout;

	memset(m_TxBufferLastDrainTsc, 0, sizeof(uint64_t)*numOfTxQueuesToInit);

	LOG_DEBUG("Successfully initialized %d TX queues for device [%s]", numOfTxQueuesToInit, m_DeviceName);

	return true;
}


bool DpdkDevice::initMemPool(struct rte_mempool*& memPool, const char* mempoolName, uint32_t mBufPoolSize)
{
    bool ret = false;

    // Create transmission memory pool
    memPool = rte_mempool_create(mempoolName, // The name of the mempool
    		mBufPoolSize, // The number of elements in the mempool
            MBUF_SIZE, // The size of each element
            32, // cache_size
            sizeof(struct rte_pktmbuf_pool_private),// The size of the private data appended after the mempool structure
            rte_pktmbuf_pool_init, // A function pointer that is called for initialization of the pool
            NULL, // An opaque pointer to data that can be used in the mempool
            rte_pktmbuf_init, // A function pointer that is called for each object at initialization of the pool
            NULL, // An opaque pointer to data that can be used as an argument
            0, // socket identifier in the case of NUMA
            MEMPOOL_F_SC_GET); // Flags

    if (memPool == NULL)
	{
		LOG_ERROR("Failed to create packets memory pool for port %d, pool name: %s", m_Id, mempoolName);
	}
	else
	{
		LOG_DEBUG("Successfully initialized packets pool of size [%d] for device [%s]", mBufPoolSize, m_DeviceName);
		ret = true;
	}
    return ret;
}

bool DpdkDevice::startDevice()
{
	int ret = rte_eth_dev_start((uint8_t) m_Id);
	if (ret < 0)
	{
	    LOG_ERROR("Failed to start device %d. Error is %d", m_Id, ret);
		return false;
	}

	LinkStatus status;
	getLinkStatus(status);
	LOG_DEBUG("Device [%s] : Link %s; Speed: %d Mbps; %s",
			m_DeviceName,
			(status.linkUp ? "up" : "down"),
			status.linkSpeedMbps,
			(status.linkDuplex == LinkStatus::FULL_DUPLEX ? "full-duplex" : "half-duplex"));


	rte_eth_promiscuous_enable((uint8_t) m_Id);
	LOG_DEBUG("Started device [%s]", m_DeviceName);

	return true;
}


void DpdkDevice::clearCoreConfiguration()
{
	for (int i = 0; i < MAX_NUM_OF_CORES; i++)
	{
		m_CoreConfiguration[i].IsCoreInUse = false;
	}
}

int DpdkDevice::getCoresInUseCount()
{
	int res = 0;
	for (int i = 0; i < MAX_NUM_OF_CORES; i++)
		if (m_CoreConfiguration[i].IsCoreInUse)
			res++;

	return res;
}

void DpdkDevice::setDeviceInfo()
{
	rte_eth_dev_info portInfo;
	rte_eth_dev_info_get(m_Id, &portInfo);
	m_PMDName = std::string(portInfo.driver_name);

	if (m_PMDName == "eth_bond")
		m_PMDType = PMD_BOND;
	else if (m_PMDName ==  "rte_em_pmd")
		m_PMDType = PMD_E1000EM;
	else if (m_PMDName ==  "rte_igb_pmd")
		m_PMDType = PMD_IGB;
	else if (m_PMDName ==  "rte_igbvf_pmd")
		m_PMDType = PMD_IGBVF;
	else if (m_PMDName ==  "rte_enic_pmd")
		m_PMDType = PMD_ENIC;
	else if (m_PMDName == "rte_pmd_fm10k")
		m_PMDType = PMD_FM10K;
	else if (m_PMDName == "rte_i40e_pmd")
		m_PMDType = PMD_I40E;
	else if (m_PMDName == "rte_i40evf_pmd")
		m_PMDType = PMD_I40EVF;
	else if (m_PMDName == "rte_ixgbe_pmd")
		m_PMDType = PMD_IXGBE;
	else if (m_PMDName == "rte_ixgbevf_pmd")
		m_PMDType = PMD_IXGBEVF;
	else if (m_PMDName == "librte_pmd_mlx4")
		m_PMDType = PMD_MLX4;
	else if (m_PMDName == "eth_null")
		m_PMDType = PMD_NULL;
	else if (m_PMDName == "eth_pcap")
		m_PMDType = PMD_PCAP;
	else if (m_PMDName == "eth_ring")
		m_PMDType = PMD_RING;
	else if (m_PMDName == "rte_virtio_pmd")
		m_PMDType = PMD_VIRTIO;
	else if (m_PMDName == "rte_vmxnet3_pmd")
		m_PMDType = PMD_VMXNET3;
	else if (m_PMDName == "eth_xenvirt")
		m_PMDType = PMD_XENVIRT;
	else
		m_PMDType = PMD_UNKNOWN;

	m_PciAddress = PciAddress(
			portInfo.pci_dev->addr.domain,
			portInfo.pci_dev->addr.bus,
			portInfo.pci_dev->addr.devid,
			portInfo.pci_dev->addr.function);


	LOG_DEBUG("Device [%s] has %d RX queues", m_DeviceName, portInfo.max_rx_queues);
	LOG_DEBUG("Device [%s] has %d TX queues", m_DeviceName, portInfo.max_tx_queues);

	m_TotalAvailableRxQueues = portInfo.max_rx_queues;
	m_TotalAvailableTxQueues = portInfo.max_tx_queues;
}


bool DpdkDevice::isVirtual()
{
	switch (m_PMDType)
	{
	case PMD_IGBVF:
	case PMD_I40EVF:
	case PMD_IXGBEVF:
	case PMD_PCAP:
	case PMD_RING:
	case PMD_VIRTIO:
	case PMD_VMXNET3:
	case PMD_XENVIRT:
		return true;
	default:
		return false;
	}
}


void DpdkDevice::getLinkStatus(LinkStatus& linkStatus)
{
	struct rte_eth_link link;
	rte_eth_link_get((uint8_t) m_Id, &link);
	linkStatus.linkUp = link.link_status;
	linkStatus.linkSpeedMbps = (unsigned) link.link_speed;
	linkStatus.linkDuplex = (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? LinkStatus::FULL_DUPLEX : LinkStatus::HALF_DUPLEX;
}


bool DpdkDevice::initCoreConfigurationByCoreMask(CoreMask coreMask)
{
	int i = 0;
	int numOfCores = getNumOfCores();
	clearCoreConfiguration();
	while ((coreMask != 0) && (i < numOfCores))
	{
		if (coreMask & 1)
		{
			if (i == DpdkDeviceList::getInstance().getDpdkMasterCore().Id)
			{
				LOG_ERROR("Core %d is the master core, you can't use it for capturing threads", i);
				clearCoreConfiguration();
				return false;
			}

			if (!rte_lcore_is_enabled(i))
			{
				LOG_ERROR("Trying to use core #%d which isn't initialized by DPDK", i);
				clearCoreConfiguration();
				return false;
			}
			m_CoreConfiguration[i].IsCoreInUse = true;
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


bool DpdkDevice::startCaptureSingleThread(OnDpdkPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie)
{
	if (!m_StopThread)
	{
		LOG_ERROR("Device already capturing. Cannot start 2 capture sessions at the same time");
		return false;
	}

	if (m_NumOfRxQueuesOpened != 1)
	{
		LOG_ERROR("Cannot start capturing on a single thread when more than 1 RX queue is opened");
		return false;
	}

	LOG_DEBUG("Trying to start capturing on a single thread for device [%s]", m_DeviceName);

	clearCoreConfiguration();

	m_OnPacketsArriveCallback = onPacketsArrive;
	m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

	m_StopThread = false;

	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
    	if (coreId == (int)rte_get_master_lcore() || !rte_lcore_is_enabled(coreId))
    		continue;

    	m_CoreConfiguration[coreId].IsCoreInUse = true;
    	m_CoreConfiguration[coreId].RxQueueId = 0;

    	LOG_DEBUG("Trying to start capturing on core %d", coreId);
    	int err = rte_eal_remote_launch(dpdkCaptureThreadMain, (void*)this, coreId);
    	if (err != 0)
    	{
    		LOG_ERROR("Cannot create capture thread for device '%s'", m_DeviceName);
        	m_CoreConfiguration[coreId].IsCoreInUse = false;
    		return false;
    	}

    	LOG_DEBUG("Capturing started for device [%s]", m_DeviceName);
    	return true;
	}

	LOG_ERROR("Could not find initialized core so capturing thread cannot be initialized");
	return false;
}

bool DpdkDevice::startCaptureMultiThreads(OnDpdkPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie, CoreMask coreMask)
{
	if (!m_DeviceOpened)
	{
		LOG_ERROR("Device not opened");
		return false;
	}

	if (!initCoreConfigurationByCoreMask(coreMask))
		return false;

	if (m_NumOfRxQueuesOpened != getCoresInUseCount())
	{
		LOG_ERROR("Cannot use a different number of queues and cores. Opened %d queues but set %d cores in core mask", m_NumOfRxQueuesOpened, getCoresInUseCount());
		clearCoreConfiguration();
		return false;
	}

	m_StopThread = false;
	int rxQueue = 0;
	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
		if (!m_CoreConfiguration[coreId].IsCoreInUse)
			continue;

		// create a new thread
		m_CoreConfiguration[coreId].RxQueueId = rxQueue++;
		int err = rte_eal_remote_launch(dpdkCaptureThreadMain, (void*)this, coreId);
		if (err != 0)
		{
			LOG_ERROR("Cannot create capture thread #%d for device '%s': [%s]", coreId, m_DeviceName, strerror(err));
			m_CoreConfiguration[coreId].clear();
			return false;
		}
	}

	m_OnPacketsArriveCallback = onPacketsArrive;
	m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

	return true;
}

void DpdkDevice::stopCapture()
{
	LOG_DEBUG("Trying to stop capturing on device [%s]", m_DeviceName);
	m_StopThread = true;
	for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
	{
		if (!m_CoreConfiguration[coreId].IsCoreInUse)
			continue;
		rte_eal_wait_lcore(coreId);
		LOG_DEBUG("Thread on core [%d] stopped", coreId);
	}

	LOG_DEBUG("All capturing threads stopped");
}


int DpdkDevice::dpdkCaptureThreadMain(void *ptr)
{
	DpdkDevice* pThis = (DpdkDevice*)ptr;

	if (pThis == NULL)
	{
		LOG_ERROR("Failed to retrieve DPDK device in capture thread main loop");
		return 1;
	}

	uint32_t coreId = pThis->getCurrentCoreId();
	LOG_DEBUG("Starting capture thread %d", coreId);

	int queueId = pThis->m_CoreConfiguration[coreId].RxQueueId;

	while (likely(!pThis->m_StopThread))
	{
		uint32_t numOfPktsReceived = rte_eth_rx_burst(pThis->m_Id, queueId, pThis->m_mBufArray, MAX_BURST_SIZE);

		if (unlikely(numOfPktsReceived == 0))
			continue;

		timeval time;
		gettimeofday(&time, NULL);

		if (likely(pThis->m_OnPacketsArriveCallback != NULL))
		{
			MBufRawPacket rawPackets[numOfPktsReceived];
			for (uint32_t index = 0; index < numOfPktsReceived; ++index)
			{
				struct rte_mbuf* mBuf = pThis->m_mBufArray[index];
				rawPackets[index].setMBuf(mBuf, time);
			}

			pThis->m_OnPacketsArriveCallback(rawPackets, numOfPktsReceived, coreId, pThis, pThis->m_OnPacketsArriveUserCookie);
		}
	}

	LOG_DEBUG("Exiting capture thread %d", coreId);

	return 0;
}

void DpdkDevice::getStatistics(pcap_stat& stats)
{
	LOG_ERROR("This method is deprecated. Please use DpdkDevice::getStatistics(DpdkDeviceStats& stats)");
//	struct rte_eth_stats rteStats;
//	rte_eth_stats_get(m_Id, &rteStats);
//	stats.ps_recv = rteStats.ipackets;
//	stats.ps_drop = rteStats.ierrors + rteStats.rx_nombuf;
//	stats.ps_ifdrop = rteStats.rx_nombuf;
}

#define nanosec_gap(begin, end) ((end.tv_sec - begin.tv_sec) * 1000000000.0 + (end.tv_nsec - begin.tv_nsec))

void DpdkDevice::getStatistics(DpdkDeviceStats& stats)
{
	timespec timestamp;
	clock_gettime(CLOCK_MONOTONIC, &timestamp);
	struct rte_eth_stats rteStats;
	rte_eth_stats_get(m_Id, &rteStats);

	double secsElapsed = (double)nanosec_gap(m_PrevStats.timestamp, timestamp) / 1000000000.0;

	stats.devId = m_Id;
	stats.timestamp = timestamp;
	stats.rxErroneousPackets = rteStats.ierrors;
	stats.rxMbufAlocFailed = rteStats.rx_nombuf;
	stats.rxPacketsDropeedByHW = rteStats.imissed;
	stats.aggregatedRxStats.packets = rteStats.ipackets;
	stats.aggregatedRxStats.bytes = rteStats.ibytes;
	stats.aggregatedRxStats.packetsPerSec = (stats.aggregatedRxStats.packets - m_PrevStats.aggregatedRxStats.packets) / secsElapsed;
	stats.aggregatedRxStats.bytesPerSec = (stats.aggregatedRxStats.bytes - m_PrevStats.aggregatedRxStats.bytes) / secsElapsed;
	stats.aggregatedTxStats.packets = rteStats.opackets;
	stats.aggregatedTxStats.bytes = rteStats.obytes;
	stats.aggregatedTxStats.packetsPerSec = (stats.aggregatedTxStats.packets - m_PrevStats.aggregatedTxStats.packets) / secsElapsed;
	stats.aggregatedTxStats.bytesPerSec = (stats.aggregatedTxStats.bytes - m_PrevStats.aggregatedTxStats.bytes) / secsElapsed;

	int numRxQs = std::min<int>(DPDK_MAX_RX_QUEUES, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	int numTxQs = std::min<int>(DPDK_MAX_TX_QUEUES, RTE_ETHDEV_QUEUE_STAT_CNTRS);

	for (int i = 0; i < numRxQs; i++)
	{
		stats.rxStats[i].packets = rteStats.q_ipackets[i];
		stats.rxStats[i].bytes = rteStats.q_ibytes[i];
		stats.rxStats[i].packetsPerSec = (stats.rxStats[i].packets - m_PrevStats.rxStats[i].packets) / secsElapsed;
		stats.rxStats[i].bytesPerSec = (stats.rxStats[i].bytes - m_PrevStats.rxStats[i].bytes) / secsElapsed;
	}

	for (int i = 0; i < numTxQs; i++)
	{
		stats.txStats[i].packets = rteStats.q_opackets[i];
		stats.txStats[i].bytes = rteStats.q_obytes[i];
		stats.txStats[i].packetsPerSec = (stats.txStats[i].packets - m_PrevStats.txStats[i].packets) / secsElapsed;
		stats.txStats[i].bytesPerSec = (stats.txStats[i].bytes - m_PrevStats.txStats[i].bytes) / secsElapsed;
	}

	//m_PrevStats = stats;
	memcpy(&m_PrevStats, &stats, sizeof(m_PrevStats));
}

void DpdkDevice::clearStatistics()
{
	rte_eth_stats_reset(m_Id);
	memset(&m_PrevStats, 0 ,sizeof(m_PrevStats));
}


bool DpdkDevice::setFilter(GeneralFilter& filter)
{
	//TODO: I think DPDK supports filters
	LOG_ERROR("Filters aren't supported in DPDK device");
	return false;
}

bool DpdkDevice::setFilter(std::string filterAsString)
{
	//TODO: I think DPDK supports filters
	LOG_ERROR("Filters aren't supported in DPDK device");
	return false;
}

uint16_t DpdkDevice::receivePackets(MBufRawPacketVector& rawPacketsArr, uint16_t rxQueueId)
{
	if (!m_DeviceOpened)
	{
		LOG_ERROR("Device not opened");
		return 0;
	}

	if (!m_StopThread)
	{
		LOG_ERROR("DpdkDevice capture mode is currently running. Cannot recieve packets in parallel");
		return 0;
	}

	if (rxQueueId >= m_TotalAvailableRxQueues)
	{
		LOG_ERROR("RX queue ID #%d not available for this device", rxQueueId);
		return 0;
	}

	struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
	uint32_t numOfPktsReceived  = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray, MAX_BURST_SIZE);

	//the following line trashes the log with many messages. Uncomment only if necessary
	//LOG_DEBUG("Captured %d packets", numOfPktsReceived);

	if (unlikely(numOfPktsReceived <= 0))
	{
		return 0;
	}

	timeval time;
	gettimeofday(&time, NULL);

	for (uint32_t index = 0; index < numOfPktsReceived; ++index)
	{
		struct rte_mbuf* mBuf = mBufArray[index];
		MBufRawPacket* newRawPacket = new MBufRawPacket();
		newRawPacket->setMBuf(mBuf, time);
		rawPacketsArr.pushBack(newRawPacket);
	}

	return numOfPktsReceived;
}

uint16_t DpdkDevice::receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength, uint16_t rxQueueId)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("Device not opened");
		return 0;
	}

	if (unlikely(!m_StopThread))
	{
		LOG_ERROR("DpdkDevice capture mode is currently running. Cannot receive packets in parallel");
		return 0;
	}

	if (unlikely(rxQueueId >= m_TotalAvailableRxQueues))
	{
		LOG_ERROR("RX queue ID #%d not available for this device", rxQueueId);
		return 0;
	}

	if (unlikely(rawPacketsArr == NULL))
	{
		LOG_ERROR("Provided address of array to store packets is NULL");
		return 0;
	}

	struct rte_mbuf* mBufArray[rawPacketArrLength];
	uint16_t packetsReceived = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray, rawPacketArrLength);
	//LOG_DEBUG("Captured %d packets", rawPacketArrLength);

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
			rawPacketsArr[index] = new MBufRawPacket();

		rawPacketsArr[index]->setMBuf(mBuf, time);
	}

	return packetsReceived;
}

uint16_t DpdkDevice::receivePackets(Packet** packetsArr, uint16_t packetsArrLength, uint16_t rxQueueId)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("Device not opened");
		return 0;
	}

	if (unlikely(!m_StopThread))
	{
		LOG_ERROR("DpdkDevice capture mode is currently running. Cannot recieve packets in parallel");
		return 0;
	}

	if (unlikely(rxQueueId >= m_TotalAvailableRxQueues))
	{
		LOG_ERROR("RX queue ID #%d not available for this device", rxQueueId);
		return 0;
	}

	struct rte_mbuf* mBufArray[packetsArrLength];
	uint16_t packetsReceived = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray, packetsArrLength);
	//LOG_DEBUG("Captured %d packets", packetsArrLength);

	if (unlikely(packetsReceived <= 0))
	{
		return 0;
	}

	timeval time;
	gettimeofday(&time, NULL);

	for (size_t index = 0; index < packetsReceived; ++index)
	{
		struct rte_mbuf* mBuf = mBufArray[index];
		MBufRawPacket* newRawPacket = new MBufRawPacket();
		newRawPacket->setMBuf(mBuf, time);
		if (packetsArr[index] == NULL)
			packetsArr[index] = new Packet();

		packetsArr[index]->setRawPacket(newRawPacket, true);
	}

	return packetsReceived;
}

uint16_t DpdkDevice::flushTxBuffer(bool flushOnlyIfTimeoutExpired, uint16_t txQueueId)
{
	bool flush = true;

	if (flushOnlyIfTimeoutExpired)
	{
		uint64_t curTsc = rte_rdtsc();

		if (curTsc - m_TxBufferLastDrainTsc[txQueueId] > m_TxBufferDrainTsc)
			m_TxBufferLastDrainTsc[txQueueId] = curTsc;
		else
			flush = false;
	}

	if (flush)
		return rte_eth_tx_buffer_flush(m_Id, txQueueId, m_TxBuffers[txQueueId]);

	return 0;
}

static rte_mbuf* getNextPacketFromMBufRawPacketArray(void* packetStorage, int index)
{
	MBufRawPacket** packetsArr = (MBufRawPacket**)packetStorage;
	return packetsArr[index]->getMBuf();
}

static rte_mbuf* getNextPacketFromMBufArray(void* packetStorage, int index)
{
	rte_mbuf** mbufArr = (rte_mbuf**)packetStorage;
	return mbufArr[index];
}

static rte_mbuf* getNextPacketFromMBufRawPacketVec(void* packetStorage, int index)
{
	MBufRawPacketVector* packetVec = (MBufRawPacketVector*)packetStorage;
	return packetVec->at(index)->getMBuf();
}

static rte_mbuf* getNextPacketFromMBufRawPacket(void* packetStorage, int index)
{
	MBufRawPacket* mbufRawPacket = (MBufRawPacket*)packetStorage;
	return mbufRawPacket->getMBuf();
}

uint16_t DpdkDevice::sendPacketsInner(uint16_t txQueueId, void* packetStorage, packetIterator iter, int arrLength, bool useTxBuffer)
{
	if (unlikely(!m_DeviceOpened))
	{
		LOG_ERROR("Device '%s' not opened!", m_DeviceName);
		return 0;
	}

	if (unlikely(txQueueId >= m_NumOfTxQueuesOpened))
	{
		LOG_ERROR("TX queue %d isn't opened in device", txQueueId);
		return 0;
	}

	rte_mbuf* mBufArr[MAX_BURST_SIZE];

	int packetIndex = 0;
	int mBufArrIndex = 0;
	uint16_t packetsSent = 0;
	int lastSleep = 0;

	#define PACKET_TRANSMITION_THRESHOLD 0.8
	int packetTxThreshold = m_Config.transmitDescriptorsNumber*PACKET_TRANSMITION_THRESHOLD;

	while (packetIndex < arrLength)
	{
		rte_mbuf* mBuf = iter(packetStorage, packetIndex);

		if (useTxBuffer)
		{
			packetsSent += rte_eth_tx_buffer(m_Id, txQueueId, m_TxBuffers[txQueueId], mBuf);
		}
		else
		{
			mBufArr[mBufArrIndex++] = mBuf;

			if (unlikely(mBufArrIndex == MAX_BURST_SIZE))
			{
				packetsSent += rte_eth_tx_burst(m_Id, txQueueId, mBufArr, MAX_BURST_SIZE);
				mBufArrIndex = 0;

				if (unlikely((packetsSent - lastSleep) >= packetTxThreshold))
				{
					LOG_DEBUG("Since NIC couldn't send all packet in this iteration, waiting for 0.2 second for H/W descriptors to get free");
					usleep(200000);
					lastSleep = packetsSent;
				}
			}
		}

		packetIndex++;
	}

	if (useTxBuffer)
	{
		packetsSent += flushTxBuffer(true, txQueueId);
	}
	else if (mBufArrIndex > 0)
	{
		packetsSent += rte_eth_tx_burst(m_Id, txQueueId, mBufArr, mBufArrIndex);
	}

	return packetsSent;
}


uint16_t DpdkDevice::sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength, uint16_t txQueueId, bool useTxBuffer)
{
	return sendPacketsInner(txQueueId, (void*)rawPacketsArr, getNextPacketFromMBufRawPacketArray, arrLength, useTxBuffer);
}

uint16_t DpdkDevice::sendPackets(Packet** packetsArr, uint16_t arrLength, uint16_t txQueueId, bool useTxBuffer)
{
	rte_mbuf* mBufArr[arrLength];
	MBufRawPacketVector mBufVec;

	for (size_t i = 0; i < arrLength; i++)
	{
		MBufRawPacket* rawPacket = NULL;

		if (packetsArr[i]->getRawPacketReadOnly()->getObjectType() != MBUFRAWPACKET_OBJECT_TYPE)
		{
			rawPacket = new MBufRawPacket();
			if (unlikely(!rawPacket->initFromRawPacket(packetsArr[i]->getRawPacketReadOnly(), this)))
			{
				delete rawPacket;
				return 0;
			}

			mBufVec.pushBack(rawPacket);
		}
		else
		{
			rawPacket = (MBufRawPacket*)packetsArr[i]->getRawPacketReadOnly();
		}

		mBufArr[i] = rawPacket->getMBuf();
	}

	return sendPacketsInner(txQueueId, (void*)mBufArr, getNextPacketFromMBufArray, arrLength, useTxBuffer);
}

uint16_t DpdkDevice::sendPackets(const RawPacketVector& rawPacketsVec, uint16_t txQueueId, bool useTxBuffer)
{
	rte_mbuf* mBufArr[rawPacketsVec.size()];
	MBufRawPacketVector mBufVec;
	int mBufIndex = 0;

	for (RawPacketVector::ConstVectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); iter++)
	{
		MBufRawPacket* rawPacket = NULL;

		if ((*iter)->getObjectType() != MBUFRAWPACKET_OBJECT_TYPE)
		{
			rawPacket = new MBufRawPacket();
			if (unlikely(!rawPacket->initFromRawPacket(*iter, this)))
			{
				delete rawPacket;
				return 0;
			}

			mBufVec.pushBack(rawPacket);
		}
		else
		{
			rawPacket = (MBufRawPacket*)(*iter);
		}

		mBufArr[mBufIndex++] = rawPacket->getMBuf();
	}

	return sendPacketsInner(txQueueId, (void*)mBufArr, getNextPacketFromMBufArray, rawPacketsVec.size(), useTxBuffer);
}

uint16_t DpdkDevice::sendPackets(const MBufRawPacketVector& rawPacketsVec, uint16_t txQueueId, bool useTxBuffer)
{
	return sendPacketsInner(txQueueId, (void*)(&rawPacketsVec), getNextPacketFromMBufRawPacketVec, rawPacketsVec.size(), useTxBuffer);
}

bool DpdkDevice::sendPacket(const RawPacket& rawPacket, uint16_t txQueueId, bool useTxBuffer)
{
	if (rawPacket.getObjectType() == MBUFRAWPACKET_OBJECT_TYPE)
		return (sendPacketsInner(txQueueId, (MBufRawPacket*)&rawPacket, getNextPacketFromMBufRawPacket, 1, useTxBuffer) == 1);

	MBufRawPacket mbufRawPacket;
	if (unlikely(!mbufRawPacket.initFromRawPacket(&rawPacket, this)))
		return false;

	return (sendPacketsInner(txQueueId, &mbufRawPacket, getNextPacketFromMBufRawPacket, 1, useTxBuffer) == 1);
}

bool DpdkDevice::sendPacket(const MBufRawPacket& rawPacket, uint16_t txQueueId, bool useTxBuffer)
{
	return (sendPacketsInner(txQueueId, (MBufRawPacket*)&rawPacket, getNextPacketFromMBufRawPacket, 1, useTxBuffer) == 1);
}

bool DpdkDevice::sendPacket(const Packet& packet, uint16_t txQueueId, bool useTxBuffer)
{
	return sendPacket(*(packet.getRawPacketReadOnly()), txQueueId);
}

int DpdkDevice::getAmountOfFreeMbufs()
{
	return (int)rte_mempool_avail_count(m_MBufMempool);
}

int DpdkDevice::getAmountOfMbufsInUse()
{
	return (int)rte_mempool_in_use_count(m_MBufMempool);
}

uint64_t DpdkDevice::convertRssHfToDpdkRssHf(uint64_t rssHF)
{
	if (rssHF == (uint64_t)-1)
	{
		rte_eth_dev_info devInfo;
		rte_eth_dev_info_get(m_Id, &devInfo);
		return devInfo.flow_type_rss_offloads;
	}

	uint64_t dpdkRssHF = 0;

	if ((rssHF & RSS_IPV4) != 0)
		dpdkRssHF |= ETH_RSS_IPV4;

	if ((rssHF & RSS_FRAG_IPV4) != 0)
		dpdkRssHF |= ETH_RSS_IPV4;

	if ((rssHF & RSS_NONFRAG_IPV4_TCP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV4_TCP;

	if ((rssHF & RSS_NONFRAG_IPV4_UDP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV4_UDP;

	if ((rssHF & RSS_NONFRAG_IPV4_SCTP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV4_SCTP;

	if ((rssHF & RSS_NONFRAG_IPV4_OTHER) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV4_OTHER;

	if ((rssHF & RSS_IPV6) != 0)
		dpdkRssHF |= ETH_RSS_IPV6;

	if ((rssHF & RSS_FRAG_IPV6) != 0)
		dpdkRssHF |= ETH_RSS_FRAG_IPV6;

	if ((rssHF & RSS_NONFRAG_IPV6_TCP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV6_TCP;

	if ((rssHF & RSS_NONFRAG_IPV6_UDP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV6_UDP;

	if ((rssHF & RSS_NONFRAG_IPV6_SCTP) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV6_SCTP;

	if ((rssHF & RSS_NONFRAG_IPV6_OTHER) != 0)
		dpdkRssHF |= ETH_RSS_NONFRAG_IPV6_OTHER;

	if ((rssHF & RSS_L2_PAYLOAD) != 0)
		dpdkRssHF |= ETH_RSS_L2_PAYLOAD;

	if ((rssHF & RSS_IPV6_EX) != 0)
		dpdkRssHF |= ETH_RSS_IPV6_EX;

	if ((rssHF & RSS_IPV6_TCP_EX) != 0)
		dpdkRssHF |= ETH_RSS_IPV6_TCP_EX;

	if ((rssHF & RSS_IPV6_UDP_EX) != 0)
		dpdkRssHF |= ETH_RSS_IPV6_UDP_EX;

	if ((rssHF & RSS_PORT) != 0)
		dpdkRssHF |= ETH_RSS_PORT;

	if ((rssHF & RSS_VXLAN) != 0)
		dpdkRssHF |= ETH_RSS_VXLAN;

	if ((rssHF & RSS_GENEVE) != 0)
		dpdkRssHF |= ETH_RSS_GENEVE;

	if ((rssHF & RSS_NVGRE) != 0)
		dpdkRssHF |= ETH_RSS_NVGRE;

	return dpdkRssHF;
}

uint64_t DpdkDevice::convertDpdkRssHfToRssHf(uint64_t dpdkRssHF)
{
	uint64_t rssHF = 0;

	if ((dpdkRssHF & ETH_RSS_IPV4) != 0)
		rssHF |= RSS_IPV4;

	if ((dpdkRssHF & ETH_RSS_FRAG_IPV4) != 0)
		rssHF |= RSS_IPV4;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV4_TCP) != 0)
		rssHF |= RSS_NONFRAG_IPV4_TCP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV4_UDP) != 0)
		rssHF |= RSS_NONFRAG_IPV4_UDP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV4_SCTP) != 0)
		rssHF |= RSS_NONFRAG_IPV4_SCTP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV4_OTHER) != 0)
		rssHF |= RSS_NONFRAG_IPV4_OTHER;

	if ((dpdkRssHF & ETH_RSS_IPV6) != 0)
		rssHF |= RSS_IPV6;

	if ((dpdkRssHF & ETH_RSS_FRAG_IPV6) != 0)
		rssHF |= RSS_FRAG_IPV6;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV6_TCP) != 0)
		rssHF |= RSS_NONFRAG_IPV6_TCP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV6_UDP) != 0)
		rssHF |= RSS_NONFRAG_IPV6_UDP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV6_SCTP) != 0)
		rssHF |= RSS_NONFRAG_IPV6_SCTP;

	if ((dpdkRssHF & ETH_RSS_NONFRAG_IPV6_OTHER) != 0)
		rssHF |= RSS_NONFRAG_IPV6_OTHER;

	if ((dpdkRssHF & ETH_RSS_L2_PAYLOAD) != 0)
		rssHF |= RSS_L2_PAYLOAD;

	if ((dpdkRssHF & ETH_RSS_IPV6_EX) != 0)
		rssHF |= RSS_IPV6_EX;

	if ((dpdkRssHF & ETH_RSS_IPV6_TCP_EX) != 0)
		rssHF |= RSS_IPV6_TCP_EX;

	if ((dpdkRssHF & ETH_RSS_IPV6_UDP_EX) != 0)
		rssHF |= RSS_IPV6_UDP_EX;

	if ((dpdkRssHF & ETH_RSS_PORT) != 0)
		rssHF |= RSS_PORT;

	if ((dpdkRssHF & ETH_RSS_VXLAN) != 0)
		rssHF |= RSS_VXLAN;

	if ((dpdkRssHF & ETH_RSS_GENEVE) != 0)
		rssHF |= RSS_GENEVE;

	if ((dpdkRssHF & ETH_RSS_NVGRE) != 0)
		rssHF |= RSS_NVGRE;

	return rssHF;
}

bool DpdkDevice::isDeviceSupportRssHashFunction(DpdkRssHashFunction rssHF)
{
	return isDeviceSupportRssHashFunction((uint64_t)rssHF);
}

bool DpdkDevice::isDeviceSupportRssHashFunction(uint64_t rssHFMask)
{
	uint64_t dpdkRssHF = convertRssHfToDpdkRssHf(rssHFMask);

	rte_eth_dev_info devInfo;
	rte_eth_dev_info_get(m_Id, &devInfo);

	return ((devInfo.flow_type_rss_offloads & dpdkRssHF) == dpdkRssHF);
}

uint64_t DpdkDevice::getSupportedRssHashFunctions()
{
	rte_eth_dev_info devInfo;
	rte_eth_dev_info_get(m_Id, &devInfo);

	return convertDpdkRssHfToRssHf(devInfo.flow_type_rss_offloads);
}


} // namespace pcpp

#endif /* USE_DPDK */
