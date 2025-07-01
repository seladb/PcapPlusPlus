// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModuleDpdkDevice

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "Logger.h"
#include "rte_version.h"
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
#	include "rte_bus_pci.h"
#endif
#include "rte_pci.h"
#include "rte_config.h"
#include "rte_ethdev.h"
#include "rte_errno.h"
#include "rte_malloc.h"
#include "rte_cycles.h"
#include <string>
#include <unistd.h>
#include <chrono>
#include <thread>

#define MAX_BURST_SIZE 64

#define MEMPOOL_CACHE_SIZE 256

#if (RTE_VER_YEAR < 21) || (RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11)
#	define GET_MASTER_CORE rte_get_master_lcore
#else
#	define GET_MASTER_CORE rte_get_main_lcore
#endif

namespace pcpp
{

	/// ================
	/// Class DpdkDevice
	/// ================

#define DPDK_CONFIG_HEADER_SPLIT 0  ///< Header Split disabled
#define DPDK_CONFIG_SPLIT_HEADER_SIZE 0
#define DPDK_CONFIG_HW_IP_CHECKSUM 0  ///< IP checksum offload disabled
#define DPDK_CONFIG_HW_VLAN_FILTER 0  ///< VLAN filtering disabled
#define DPDK_CONFIG_JUMBO_FRAME 0     ///< Jumbo Frame Support disabled
#define DPDK_CONFIG_HW_STRIP_CRC 0    ///< CRC stripped by hardware disabled
#if (RTE_VER_YEAR < 21) || (RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11)
#	define DPDK_CONFIG_ETH_LINK_FULL_DUPLEX ETH_LINK_FULL_DUPLEX
#	define DPDK_CONFIG_MQ_RSS ETH_RSS
#	define DPDK_CONFIG_MQ_NO_RSS ETH_MQ_RX_NONE
#else
#	define DPDK_CONFIG_ETH_LINK_FULL_DUPLEX RTE_ETH_LINK_FULL_DUPLEX
#	define DPDK_CONFIG_MQ_RSS RTE_ETH_MQ_RX_RSS
#	define DPDK_CONFIG_MQ_NO_RSS RTE_ETH_MQ_RX_NONE
#endif

#if (RTE_VER_YEAR < 22) || (RTE_VER_YEAR == 22 && RTE_VER_MONTH < 11)
#	define DPDK_CONFIG_ETH_RSS_IPV4 ETH_RSS_IPV4
#	define DPDK_CONFIG_ETH_RSS_FRAG_IPV4 ETH_RSS_FRAG_IPV4
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_TCP ETH_RSS_NONFRAG_IPV4_TCP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_UDP ETH_RSS_NONFRAG_IPV4_UDP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_SCTP ETH_RSS_NONFRAG_IPV4_SCTP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_OTHER ETH_RSS_NONFRAG_IPV4_OTHER
#	define DPDK_CONFIG_ETH_RSS_IPV6 ETH_RSS_IPV6
#	define DPDK_CONFIG_ETH_RSS_FRAG_IPV6 ETH_RSS_FRAG_IPV6
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_TCP ETH_RSS_NONFRAG_IPV6_TCP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_UDP ETH_RSS_NONFRAG_IPV6_UDP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_SCTP ETH_RSS_NONFRAG_IPV6_SCTP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_OTHER ETH_RSS_NONFRAG_IPV6_OTHER
#	define DPDK_CONFIG_ETH_RSS_L2_PAYLOAD ETH_RSS_L2_PAYLOAD
#	define DPDK_CONFIG_ETH_RSS_IPV6_EX ETH_RSS_IPV6_EX
#	define DPDK_CONFIG_ETH_RSS_IPV6_TCP_EX ETH_RSS_IPV6_TCP_EX
#	define DPDK_CONFIG_ETH_RSS_IPV6_UDP_EX ETH_RSS_IPV6_UDP_EX
#	define DPDK_CONFIG_ETH_RSS_PORT ETH_RSS_PORT
#	define DPDK_CONFIG_ETH_RSS_VXLAN ETH_RSS_VXLAN
#	define DPDK_CONFIG_ETH_RSS_GENEVE ETH_RSS_GENEVE
#	define DPDK_CONFIG_ETH_RSS_NVGRE ETH_RSS_NVGRE
#else
#	define DPDK_CONFIG_ETH_RSS_IPV4 RTE_ETH_RSS_IPV4
#	define DPDK_CONFIG_ETH_RSS_FRAG_IPV4 RTE_ETH_RSS_FRAG_IPV4
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_TCP RTE_ETH_RSS_NONFRAG_IPV4_TCP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_UDP RTE_ETH_RSS_NONFRAG_IPV4_UDP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_SCTP RTE_ETH_RSS_NONFRAG_IPV4_SCTP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_OTHER RTE_ETH_RSS_NONFRAG_IPV4_OTHER
#	define DPDK_CONFIG_ETH_RSS_IPV6 RTE_ETH_RSS_IPV6
#	define DPDK_CONFIG_ETH_RSS_FRAG_IPV6 RTE_ETH_RSS_FRAG_IPV6
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_TCP RTE_ETH_RSS_NONFRAG_IPV6_TCP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_UDP RTE_ETH_RSS_NONFRAG_IPV6_UDP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_SCTP RTE_ETH_RSS_NONFRAG_IPV6_SCTP
#	define DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_OTHER RTE_ETH_RSS_NONFRAG_IPV6_OTHER
#	define DPDK_CONFIG_ETH_RSS_L2_PAYLOAD RTE_ETH_RSS_L2_PAYLOAD
#	define DPDK_CONFIG_ETH_RSS_IPV6_EX RTE_ETH_RSS_IPV6_EX
#	define DPDK_CONFIG_ETH_RSS_IPV6_TCP_EX RTE_ETH_RSS_IPV6_TCP_EX
#	define DPDK_CONFIG_ETH_RSS_IPV6_UDP_EX RTE_ETH_RSS_IPV6_UDP_EX
#	define DPDK_CONFIG_ETH_RSS_PORT RTE_ETH_RSS_PORT
#	define DPDK_CONFIG_ETH_RSS_VXLAN RTE_ETH_RSS_VXLAN
#	define DPDK_CONFIG_ETH_RSS_GENEVE RTE_ETH_RSS_GENEVE
#	define DPDK_CONFIG_ETH_RSS_NVGRE RTE_ETH_RSS_NVGRE
#endif

	// RSS random key:
	uint8_t DpdkDevice::m_RSSKey[40] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	};

	static bool getDeviceInfo(uint16_t devId, rte_eth_dev_info& devInfo)
	{
		auto ret = rte_eth_dev_info_get(devId, &devInfo);
		if (ret < 0)
		{
			PCPP_LOG_ERROR("Couldn't get device info, error was: " << rte_strerror(ret) << " (" << ret << ")");
			return false;
		}

		return true;
	}

	DpdkDevice::DpdkDevice(int port, uint32_t mBufPoolSize, uint16_t mBufDataSize)
	    : m_Id(port), m_MacAddress(MacAddress::Zero),
	      m_MBufDataSize(mBufDataSize < 1 ? RTE_MBUF_DEFAULT_BUF_SIZE : mBufDataSize)
	{
		std::ostringstream deviceNameStream;
		deviceNameStream << "DPDK_" << m_Id;
		m_DeviceName = deviceNameStream.str();
		m_DeviceSocketId = rte_eth_dev_socket_id(m_Id);

#if (RTE_VER_YEAR > 19) || (RTE_VER_YEAR == 19 && RTE_VER_MONTH >= 8)
		struct rte_ether_addr etherAddr;
#else
		struct ether_addr etherAddr;
#endif
		rte_eth_macaddr_get((uint8_t)m_Id, &etherAddr);
		m_MacAddress = MacAddress(etherAddr.addr_bytes[0], etherAddr.addr_bytes[1], etherAddr.addr_bytes[2],
		                          etherAddr.addr_bytes[3], etherAddr.addr_bytes[4], etherAddr.addr_bytes[5]);

		rte_eth_dev_get_mtu((uint8_t)m_Id, &m_DeviceMtu);

		char mBufMemPoolName[32];
		sprintf(mBufMemPoolName, "MBufMemPool%d", m_Id);
		if (!initMemPool(m_MBufMempool, mBufMemPoolName, mBufPoolSize))
		{
			PCPP_LOG_ERROR("Could not initialize mBuf mempool. Device not initialized");
			return;
		}

		m_NumOfRxQueuesOpened = 0;
		m_NumOfTxQueuesOpened = 0;

		setDeviceInfo();

		memset(&m_PrevStats, 0, sizeof(m_PrevStats));

		m_TxBuffers = nullptr;
		m_TxBufferLastDrainTsc = nullptr;

		m_DeviceOpened = false;
		m_WasOpened = false;
		m_StopThread = true;
	}

	DpdkDevice::~DpdkDevice()
	{
		if (m_TxBuffers != nullptr)
			delete[] m_TxBuffers;

		if (m_TxBufferLastDrainTsc != nullptr)
			delete[] m_TxBufferLastDrainTsc;
	}

	uint32_t DpdkDevice::getCurrentCoreId() const
	{
		return rte_lcore_id();
	}

	bool DpdkDevice::setMtu(uint16_t newMtu)
	{
		int res = rte_eth_dev_set_mtu(m_Id, newMtu);
		if (res != 0)
		{
			PCPP_LOG_ERROR("Couldn't set device MTU. DPDK error: " << res);
			return false;
		}

		PCPP_LOG_DEBUG("Managed to set MTU from " << m_DeviceMtu << " to " << newMtu);
		m_DeviceMtu = newMtu;
		return true;
	}

	bool DpdkDevice::openMultiQueues(uint16_t numOfRxQueuesToOpen, uint16_t numOfTxQueuesToOpen,
	                                 const DpdkDeviceConfiguration& config)
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
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
			PCPP_LOG_ERROR("failed to start device " << m_Id);
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
			PCPP_LOG_DEBUG("Trying to close device [" << m_DeviceName << "] but device is already closed");
			return;
		}
		stopCapture();
		clearCoreConfiguration();
		m_NumOfRxQueuesOpened = 0;
		m_NumOfTxQueuesOpened = 0;
		rte_eth_dev_stop(m_Id);
		PCPP_LOG_DEBUG("Called rte_eth_dev_stop for device [" << m_DeviceName << "]");

		if (m_TxBuffers != nullptr)
		{
			delete[] m_TxBuffers;
			m_TxBuffers = nullptr;
		}

		if (m_TxBufferLastDrainTsc != nullptr)
		{
			delete[] m_TxBufferLastDrainTsc;
			m_TxBufferLastDrainTsc = nullptr;
		}

		m_DeviceOpened = false;
	}

	bool DpdkDevice::configurePort(uint8_t numOfRxQueues, uint8_t numOfTxQueues)
	{
		if (numOfRxQueues > getTotalNumOfRxQueues())
		{
			PCPP_LOG_ERROR("Could not open more than " << getTotalNumOfRxQueues() << " RX queues");
			return false;
		}

		if (numOfTxQueues > getTotalNumOfTxQueues())
		{
			PCPP_LOG_ERROR("Could not open more than " << getTotalNumOfTxQueues() << " TX queues");
			return false;
		}

		// if PMD doesn't support RSS, set RSS HF to 0
		if (getSupportedRssHashFunctions() == 0 && getConfiguredRssHashFunction() != 0)
		{
			PCPP_LOG_DEBUG("PMD '" << m_PMDName << "' doesn't support RSS, setting RSS hash functions to 0");
			m_Config.rssHashFunction = RSS_NONE;
			m_Config.rssKey = nullptr;
			m_Config.rssKeyLength = 0;
		}

		if (!isDeviceSupportRssHashFunction(getConfiguredRssHashFunction()))
		{
			PCPP_LOG_ERROR("PMD '" << m_PMDName << "' doesn't support the request RSS hash functions 0x" << std::hex
			                       << getConfiguredRssHashFunction());
			return false;
		}

		// verify num of RX queues is nonzero
		if (numOfRxQueues == 0)
		{
			PCPP_LOG_ERROR("Num of RX queues must be nonzero.");
			return false;
		}

		// verify num of RX queues is power of 2 for virtual devices
		if (isVirtual())
		{
			bool isRxQueuePowerOfTwo = !(numOfRxQueues & (numOfRxQueues - 1));
			if (!isRxQueuePowerOfTwo)
			{
				PCPP_LOG_ERROR(
				    "Num of RX queues must be power of 2 when device is virtual (because of DPDK limitation). Attempted to open device with "
				    << numOfRxQueues << " RX queues");
				return false;
			}
		}

		struct rte_eth_conf portConf;
		memset(&portConf, 0, sizeof(rte_eth_conf));
#if (RTE_VER_YEAR < 22) || (RTE_VER_YEAR == 22 && RTE_VER_MONTH < 11)
		portConf.rxmode.split_hdr_size = DPDK_CONFIG_SPLIT_HEADER_SIZE;
#endif
#if (RTE_VER_YEAR < 18) || (RTE_VER_YEAR == 18 && RTE_VER_MONTH < 8)
		portConf.rxmode.header_split = DPDK_CONFIG_HEADER_SPLIT;
		portConf.rxmode.hw_ip_checksum = DPDK_CONFIG_HW_IP_CHECKSUM;
		portConf.rxmode.hw_vlan_filter = DPDK_CONFIG_HW_VLAN_FILTER;
		portConf.rxmode.jumbo_frame = DPDK_CONFIG_JUMBO_FRAME;
		portConf.rxmode.hw_strip_crc = DPDK_CONFIG_HW_STRIP_CRC;
#endif
		// Enable RSS only if hardware supports it and the user wants to use it
		if (m_Config.rssHashFunction == RSS_NONE)
		{
			portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_NO_RSS;
		}
		else
		{
			portConf.rxmode.mq_mode = DPDK_CONFIG_MQ_RSS;
		}

		portConf.rx_adv_conf.rss_conf.rss_key = m_Config.rssKey;
		portConf.rx_adv_conf.rss_conf.rss_key_len = m_Config.rssKeyLength;
		portConf.rx_adv_conf.rss_conf.rss_hf = convertRssHfToDpdkRssHf(getConfiguredRssHashFunction());

		int res = rte_eth_dev_configure((uint8_t)m_Id, numOfRxQueues, numOfTxQueues, &portConf);
		if (res < 0)
		{
			PCPP_LOG_ERROR("Failed to configure device [" << m_DeviceName << "]. error is: '" << rte_strerror(res)
			                                              << "' [Error code: " << res << "]");
			return false;
		}

		PCPP_LOG_DEBUG("Successfully called rte_eth_dev_configure for device ["
		               << m_DeviceName << "] with " << numOfRxQueues << " RX queues and " << numOfTxQueues
		               << " TX queues");

		return true;
	}

	bool DpdkDevice::initQueues(uint8_t numOfRxQueuesToInit, uint8_t numOfTxQueuesToInit)
	{
		rte_eth_dev_info devInfo;
		if (!getDeviceInfo(m_Id, devInfo))
		{
			return false;
		}

		if (numOfRxQueuesToInit > devInfo.max_rx_queues)
		{
			PCPP_LOG_ERROR("Num of RX queues requested for open [" << numOfRxQueuesToInit
			                                                       << "] is larger than RX queues available in NIC ["
			                                                       << devInfo.max_rx_queues << "]");
			return false;
		}

		if (numOfTxQueuesToInit > devInfo.max_tx_queues)
		{
			PCPP_LOG_ERROR("Num of TX queues requested for open [" << numOfTxQueuesToInit
			                                                       << "] is larger than TX queues available in NIC ["
			                                                       << devInfo.max_tx_queues << "]");
			return false;
		}

		for (uint8_t i = 0; i < numOfRxQueuesToInit; i++)
		{
			int ret = rte_eth_rx_queue_setup((uint8_t)m_Id, i, m_Config.receiveDescriptorsNumber, m_DeviceSocketId,
			                                 nullptr, m_MBufMempool);

			if (ret < 0)
			{
				PCPP_LOG_ERROR("Failed to init RX queue for device [" << m_DeviceName << "]. Error was: '"
				                                                      << rte_strerror(ret) << "' [Error code: " << ret
				                                                      << "]");
				return false;
			}
		}

		PCPP_LOG_DEBUG("Successfully initialized " << numOfRxQueuesToInit << " RX queues for device [" << m_DeviceName
		                                           << "]");

		for (uint8_t i = 0; i < numOfTxQueuesToInit; i++)
		{
			int ret =
			    rte_eth_tx_queue_setup((uint8_t)m_Id, i, m_Config.transmitDescriptorsNumber, m_DeviceSocketId, nullptr);
			if (ret < 0)
			{
				PCPP_LOG_ERROR("Failed to init TX queue #" << i << " for port " << m_Id << ". Error was: '"
				                                           << rte_strerror(ret) << "' [Error code: " << ret << "]");
				return false;
			}
		}

		if (m_TxBuffers != nullptr)
			delete[] m_TxBuffers;

		if (m_TxBufferLastDrainTsc != nullptr)
			delete[] m_TxBufferLastDrainTsc;

		m_TxBuffers = new rte_eth_dev_tx_buffer*[numOfTxQueuesToInit];
		m_TxBufferLastDrainTsc = new uint64_t[numOfTxQueuesToInit];
		memset(m_TxBufferLastDrainTsc, 0, sizeof(uint64_t) * numOfTxQueuesToInit);

		for (uint8_t i = 0; i < numOfTxQueuesToInit; i++)
		{
			m_TxBuffers[i] = (rte_eth_dev_tx_buffer*)rte_zmalloc_socket(
			    "tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_BURST_SIZE), 0, m_DeviceSocketId);

			if (m_TxBuffers[i] == nullptr)
			{
				PCPP_LOG_ERROR("Failed to allocate TX buffer for port " << m_Id << " TX queue " << (int)i);
				return false;
			}

			int res = rte_eth_tx_buffer_init(m_TxBuffers[i], MAX_BURST_SIZE);

			if (res != 0)
			{
				PCPP_LOG_ERROR("Failed to init TX buffer for port " << m_Id << " TX queue " << (int)i);
				return false;
			}
		}

		m_TxBufferDrainTsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * m_Config.flushTxBufferTimeout;

		memset(m_TxBufferLastDrainTsc, 0, sizeof(uint64_t) * numOfTxQueuesToInit);

		PCPP_LOG_DEBUG("Successfully initialized " << numOfTxQueuesToInit << " TX queues for device [" << m_DeviceName
		                                           << "]");

		return true;
	}

	bool DpdkDevice::initMemPool(struct rte_mempool*& memPool, const char* mempoolName, uint32_t mBufPoolSize)
	{
		bool ret = false;

		// create mbuf pool
		memPool =
		    rte_pktmbuf_pool_create(mempoolName, mBufPoolSize, MEMPOOL_CACHE_SIZE, 0, m_MBufDataSize, m_DeviceSocketId);
		if (memPool == nullptr)
		{
			PCPP_LOG_ERROR("Failed to create packets memory pool for port "
			               << m_Id << ", pool name: " << mempoolName << ". Error was: '" << rte_strerror(rte_errno)
			               << "' [Error code: " << rte_errno << "]");
		}
		else
		{
			PCPP_LOG_DEBUG("Successfully initialized packets pool of size [" << mBufPoolSize << "] for device ["
			                                                                 << m_DeviceName << "]");
			ret = true;
		}
		return ret;
	}

	bool DpdkDevice::startDevice()
	{
		int ret = rte_eth_dev_start((uint8_t)m_Id);
		if (ret < 0)
		{
			PCPP_LOG_ERROR("Failed to start device " << m_Id << ". Error is " << ret);
			return false;
		}

		LinkStatus status;
		getLinkStatus(status);
		if (Logger::getInstance().isDebugEnabled(PcapLogModuleDpdkDevice))
		{
			std::string linkStatus = (status.linkUp ? "up" : "down");
			std::string linkDuplex = (status.linkDuplex == LinkStatus::FULL_DUPLEX ? "full-duplex" : "half-duplex");
			PCPP_LOG_DEBUG("Device [" << m_DeviceName << "] : Link " << linkStatus
			                          << "; Speed: " << status.linkSpeedMbps << " Mbps; " << linkDuplex);
		}

		rte_eth_promiscuous_enable((uint8_t)m_Id);
		PCPP_LOG_DEBUG("Started device [" << m_DeviceName << "]");

		return true;
	}

	void DpdkDevice::clearCoreConfiguration()
	{
		for (int i = 0; i < MAX_NUM_OF_CORES; i++)
		{
			m_CoreConfiguration[i].IsCoreInUse = false;
		}
	}

	int DpdkDevice::getCoresInUseCount() const
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
		if (!getDeviceInfo(m_Id, portInfo))
		{
			return;
		}

		m_PMDName = std::string(portInfo.driver_name);

		if (m_PMDName == "eth_bond")
			m_PMDType = PMD_BOND;
		else if (m_PMDName == "rte_em_pmd")
			m_PMDType = PMD_E1000EM;
		else if (m_PMDName == "rte_igb_pmd")
			m_PMDType = PMD_IGB;
		else if (m_PMDName == "rte_igbvf_pmd")
			m_PMDType = PMD_IGBVF;
		else if (m_PMDName == "rte_enic_pmd")
			m_PMDType = PMD_ENIC;
		else if (m_PMDName == "rte_pmd_fm10k")
			m_PMDType = PMD_FM10K;
		else if (m_PMDName == "rte_i40e_pmd" || m_PMDName == "net_i40e")
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

#if (RTE_VER_YEAR < 18) || (RTE_VER_YEAR == 18 && RTE_VER_MONTH < 5)  // before 18.05
		char pciName[30];
#	if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)  // 17.11 - 18.02
		rte_pci_device_name(&(portInfo.pci_dev->addr), pciName, 30);
#	else  // 16.11 - 17.11
		rte_eal_pci_device_name(&(portInfo.pci_dev->addr), pciName, 30);
#	endif
		m_PciAddress = std::string(pciName);
#elif (RTE_VER_YEAR < 22) || (RTE_VER_YEAR == 22 && RTE_VER_MONTH < 11)  // before 22.11
		m_PciAddress = std::string(portInfo.device->name);
#else                                                                    // 22.11 forward
		m_PciAddress = std::string(rte_dev_name(portInfo.device));
#endif

		PCPP_LOG_DEBUG("Device [" << m_DeviceName << "] has " << portInfo.max_rx_queues << " RX queues");
		PCPP_LOG_DEBUG("Device [" << m_DeviceName << "] has " << portInfo.max_tx_queues << " TX queues");

		m_TotalAvailableRxQueues = portInfo.max_rx_queues;
		m_TotalAvailableTxQueues = portInfo.max_tx_queues;
	}

	bool DpdkDevice::isVirtual() const
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

	bool DpdkDevice::getLinkStatus(LinkStatus& linkStatus) const
	{
		struct rte_eth_link link;
		auto ret = rte_eth_link_get((uint8_t)m_Id, &link);
		if (ret < 0)
		{
			PCPP_LOG_ERROR("Couldn't get link info, error was: " << rte_strerror(ret) << " (" << ret << ")");
			return false;
		}

		linkStatus.linkUp = link.link_status;
		linkStatus.linkSpeedMbps = (unsigned)link.link_speed;
		linkStatus.linkDuplex =
		    (link.link_duplex == DPDK_CONFIG_ETH_LINK_FULL_DUPLEX) ? LinkStatus::FULL_DUPLEX : LinkStatus::HALF_DUPLEX;

		return true;
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
					PCPP_LOG_ERROR("Core " << i << " is the master core, you can't use it for capturing threads");
					clearCoreConfiguration();
					return false;
				}

				if (!rte_lcore_is_enabled(i))
				{
					PCPP_LOG_ERROR("Trying to use core #" << i << " which isn't initialized by DPDK");
					clearCoreConfiguration();
					return false;
				}
				m_CoreConfiguration[i].IsCoreInUse = true;
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

	bool DpdkDevice::startCaptureSingleThread(OnDpdkPacketsArriveCallback onPacketsArrive,
	                                          void* onPacketsArriveUserCookie)
	{
		if (!m_StopThread)
		{
			PCPP_LOG_ERROR("Device already capturing. Cannot start 2 capture sessions at the same time");
			return false;
		}

		if (m_NumOfRxQueuesOpened != 1)
		{
			PCPP_LOG_ERROR("Cannot start capturing on a single thread when more than 1 RX queue is opened");
			return false;
		}

		PCPP_LOG_DEBUG("Trying to start capturing on a single thread for device [" << m_DeviceName << "]");

		clearCoreConfiguration();

		m_OnPacketsArriveCallback = onPacketsArrive;
		m_OnPacketsArriveUserCookie = onPacketsArriveUserCookie;

		m_StopThread = false;

		for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
		{
			if (coreId == (int)GET_MASTER_CORE() || !rte_lcore_is_enabled(coreId))
				continue;

			m_CoreConfiguration[coreId].IsCoreInUse = true;
			m_CoreConfiguration[coreId].RxQueueId = 0;

			PCPP_LOG_DEBUG("Trying to start capturing on core " << coreId);
			int err = rte_eal_remote_launch(dpdkCaptureThreadMain, (void*)this, coreId);
			if (err != 0)
			{
				PCPP_LOG_ERROR("Cannot create capture thread for device '" << m_DeviceName << "'");
				m_CoreConfiguration[coreId].IsCoreInUse = false;
				return false;
			}

			PCPP_LOG_DEBUG("Capturing started for device [" << m_DeviceName << "]");
			return true;
		}

		PCPP_LOG_ERROR("Could not find initialized core so capturing thread cannot be initialized");
		return false;
	}

	bool DpdkDevice::startCaptureMultiThreads(OnDpdkPacketsArriveCallback onPacketsArrive,
	                                          void* onPacketsArriveUserCookie, CoreMask coreMask)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device not opened");
			return false;
		}

		if (!initCoreConfigurationByCoreMask(coreMask))
			return false;

		if (m_NumOfRxQueuesOpened != getCoresInUseCount())
		{
			PCPP_LOG_ERROR("Cannot use a different number of queues and cores. Opened "
			               << m_NumOfRxQueuesOpened << " queues but set " << getCoresInUseCount()
			               << " cores in core mask");
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
				PCPP_LOG_ERROR("Cannot create capture thread #" << coreId << " for device '" << m_DeviceName << "': ["
				                                                << strerror(err) << "]");
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
		PCPP_LOG_DEBUG("Trying to stop capturing on device [" << m_DeviceName << "]");
		m_StopThread = true;
		for (int coreId = 0; coreId < MAX_NUM_OF_CORES; coreId++)
		{
			if (!m_CoreConfiguration[coreId].IsCoreInUse)
				continue;
			rte_eal_wait_lcore(coreId);
			PCPP_LOG_DEBUG("Thread on core [" << coreId << "] stopped");
		}

		PCPP_LOG_DEBUG("All capturing threads stopped");
	}

	int DpdkDevice::dpdkCaptureThreadMain(void* ptr)
	{
		DpdkDevice* pThis = (DpdkDevice*)ptr;
		struct rte_mbuf* mBufArray[MAX_BURST_SIZE];

		if (pThis == nullptr)
		{
			PCPP_LOG_ERROR("Failed to retrieve DPDK device in capture thread main loop");
			return 1;
		}

		uint32_t coreId = pThis->getCurrentCoreId();
		PCPP_LOG_DEBUG("Starting capture thread " << coreId);

		int queueId = pThis->m_CoreConfiguration[coreId].RxQueueId;

		while (likely(!pThis->m_StopThread))
		{
			uint32_t numOfPktsReceived = rte_eth_rx_burst(pThis->m_Id, queueId, mBufArray, MAX_BURST_SIZE);

			if (unlikely(numOfPktsReceived == 0))
				continue;

			timespec time;
			clock_gettime(CLOCK_REALTIME, &time);

			if (likely(pThis->m_OnPacketsArriveCallback != nullptr))
			{
				MBufRawPacket rawPackets[MAX_BURST_SIZE];
				for (uint32_t index = 0; index < numOfPktsReceived; ++index)
				{
					rawPackets[index].setMBuf(mBufArray[index], time);
				}

				pThis->m_OnPacketsArriveCallback(rawPackets, numOfPktsReceived, coreId, pThis,
				                                 pThis->m_OnPacketsArriveUserCookie);
			}
		}

		PCPP_LOG_DEBUG("Exiting capture thread " << coreId);

		return 0;
	}

#define nanosec_gap(begin, end) ((end.tv_sec - begin.tv_sec) * 1000000000.0 + (end.tv_nsec - begin.tv_nsec))

	void DpdkDevice::getStatistics(DpdkDeviceStats& stats) const
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
		stats.rxPacketsDroppedByHW = rteStats.imissed;
		stats.aggregatedRxStats.packets = rteStats.ipackets;
		stats.aggregatedRxStats.bytes = rteStats.ibytes;
		stats.aggregatedRxStats.packetsPerSec =
		    (stats.aggregatedRxStats.packets - m_PrevStats.aggregatedRxStats.packets) / secsElapsed;
		stats.aggregatedRxStats.bytesPerSec =
		    (stats.aggregatedRxStats.bytes - m_PrevStats.aggregatedRxStats.bytes) / secsElapsed;
		stats.aggregatedTxStats.packets = rteStats.opackets;
		stats.aggregatedTxStats.bytes = rteStats.obytes;
		stats.aggregatedTxStats.packetsPerSec =
		    (stats.aggregatedTxStats.packets - m_PrevStats.aggregatedTxStats.packets) / secsElapsed;
		stats.aggregatedTxStats.bytesPerSec =
		    (stats.aggregatedTxStats.bytes - m_PrevStats.aggregatedTxStats.bytes) / secsElapsed;

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

		// m_PrevStats = stats;
		memcpy(&m_PrevStats, &stats, sizeof(m_PrevStats));
	}

	void DpdkDevice::clearStatistics()
	{
		rte_eth_stats_reset(m_Id);
		memset(&m_PrevStats, 0, sizeof(m_PrevStats));
	}

	bool DpdkDevice::setFilter(GeneralFilter& filter)
	{
		// TODO: I think DPDK supports filters
		PCPP_LOG_ERROR("Filters aren't supported in DPDK device");
		return false;
	}

	bool DpdkDevice::setFilter(std::string filterAsString)
	{
		// TODO: I think DPDK supports filters
		PCPP_LOG_ERROR("Filters aren't supported in DPDK device");
		return false;
	}

	uint16_t DpdkDevice::receivePackets(MBufRawPacketVector& rawPacketsArr, uint16_t rxQueueId) const
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device not opened");
			return 0;
		}

		if (!m_StopThread)
		{
			PCPP_LOG_ERROR("DpdkDevice capture mode is currently running. Cannot receive packets in parallel");
			return 0;
		}

		if (rxQueueId >= m_TotalAvailableRxQueues)
		{
			PCPP_LOG_ERROR("RX queue ID #" << rxQueueId << " not available for this device");
			return 0;
		}

		struct rte_mbuf* mBufArray[MAX_BURST_SIZE];
		uint32_t numOfPktsReceived = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray, MAX_BURST_SIZE);

		// the following line trashes the log with many messages. Uncomment only if necessary
		// PCPP_LOG_DEBUG("Captured %d packets", numOfPktsReceived);

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

	uint16_t DpdkDevice::receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength,
	                                    uint16_t rxQueueId) const
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("Device not opened");
			return 0;
		}

		if (unlikely(!m_StopThread))
		{
			PCPP_LOG_ERROR("DpdkDevice capture mode is currently running. Cannot receive packets in parallel");
			return 0;
		}

		if (unlikely(rxQueueId >= m_TotalAvailableRxQueues))
		{
			PCPP_LOG_ERROR("RX queue ID #" << rxQueueId << " not available for this device");
			return 0;
		}

		if (unlikely(rawPacketsArr == nullptr))
		{
			PCPP_LOG_ERROR("Provided address of array to store packets is nullptr");
			return 0;
		}

		std::vector<struct rte_mbuf*> mBufArray(rawPacketArrLength);
		uint16_t packetsReceived = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray.data(), rawPacketArrLength);

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

	uint16_t DpdkDevice::receivePackets(Packet** packetsArr, uint16_t packetsArrLength, uint16_t rxQueueId) const
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("Device not opened");
			return 0;
		}

		if (unlikely(!m_StopThread))
		{
			PCPP_LOG_ERROR("DpdkDevice capture mode is currently running. Cannot receive packets in parallel");
			return 0;
		}

		if (unlikely(rxQueueId >= m_TotalAvailableRxQueues))
		{
			PCPP_LOG_ERROR("RX queue ID #" << rxQueueId << " not available for this device");
			return 0;
		}

		std::vector<struct rte_mbuf*> mBufArray(packetsArrLength);
		uint16_t packetsReceived = rte_eth_rx_burst(m_Id, rxQueueId, mBufArray.data(), packetsArrLength);

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

	uint16_t DpdkDevice::sendPacketsInner(uint16_t txQueueId, void* packetStorage, PacketIterator iter, int arrLength,
	                                      bool useTxBuffer)
	{
		if (unlikely(!m_DeviceOpened))
		{
			PCPP_LOG_ERROR("Device '" << m_DeviceName << "' not opened!");
			return 0;
		}

		if (unlikely(txQueueId >= m_NumOfTxQueuesOpened))
		{
			PCPP_LOG_ERROR("TX queue " << txQueueId << " isn't opened in device");
			return 0;
		}

		rte_mbuf* mBufArr[MAX_BURST_SIZE] = {};

		int packetIndex = 0;
		int mBufArrIndex = 0;
		uint16_t packetsSent = 0;
		int lastSleep = 0;

#define PACKET_TRANSMISSION_THRESHOLD 0.8
		int packetTxThreshold = m_Config.transmitDescriptorsNumber * PACKET_TRANSMISSION_THRESHOLD;

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
						PCPP_LOG_DEBUG(
						    "Since NIC couldn't send all packet in this iteration, waiting for 0.2 second for H/W descriptors to get free");
						std::this_thread::sleep_for(std::chrono::microseconds(200000));
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

	uint16_t DpdkDevice::sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength, uint16_t txQueueId,
	                                 bool useTxBuffer)
	{
		uint16_t packetsSent = sendPacketsInner(txQueueId, (void*)rawPacketsArr, getNextPacketFromMBufRawPacketArray,
		                                        arrLength, useTxBuffer);

		bool needToFreeMbuf = false;
		int applyForMBufs = arrLength;

		if (unlikely(!useTxBuffer && (packetsSent != arrLength)))
		{
			applyForMBufs = packetsSent;
		}

		for (int index = 0; index < applyForMBufs; index++)
			rawPacketsArr[index]->setFreeMbuf(needToFreeMbuf);

		for (int index = applyForMBufs; index < arrLength; index++)
			rawPacketsArr[index]->setFreeMbuf(!needToFreeMbuf);

		return packetsSent;
	}

	uint16_t DpdkDevice::sendPackets(Packet** packetsArr, uint16_t arrLength, uint16_t txQueueId, bool useTxBuffer)
	{
		std::vector<rte_mbuf*> mBufArr(arrLength);
		MBufRawPacketVector mBufVec;
		std::vector<MBufRawPacket*> mBufRawPacketArr(arrLength);

		for (size_t i = 0; i < arrLength; i++)
		{
			MBufRawPacket* rawPacket = nullptr;
			uint8_t rawPacketType = packetsArr[i]->getRawPacketReadOnly()->getObjectType();
			if (rawPacketType != MBUFRAWPACKET_OBJECT_TYPE)
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
			mBufRawPacketArr[i] = rawPacket;
		}

		uint16_t packetsSent =
		    sendPacketsInner(txQueueId, (void*)mBufArr.data(), getNextPacketFromMBufArray, arrLength, useTxBuffer);

		bool needToFreeMbuf = (!useTxBuffer && (packetsSent != arrLength));
		for (int index = 0; index < arrLength; index++)
			mBufRawPacketArr[index]->setFreeMbuf(needToFreeMbuf);

		return packetsSent;
	}

	uint16_t DpdkDevice::sendPackets(RawPacketVector& rawPacketsVec, uint16_t txQueueId, bool useTxBuffer)
	{
		size_t vecSize = rawPacketsVec.size();
		std::vector<rte_mbuf*> mBufArr(vecSize);
		std::vector<MBufRawPacket*> mBufRawPacketArr(vecSize);
		MBufRawPacketVector mBufVec;
		int mBufIndex = 0;

		for (RawPacketVector::ConstVectorIterator iter = rawPacketsVec.begin(); iter != rawPacketsVec.end(); iter++)
		{
			MBufRawPacket* rawPacket = nullptr;
			uint8_t rawPacketType = (*iter)->getObjectType();
			if (rawPacketType != MBUFRAWPACKET_OBJECT_TYPE)
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

			mBufRawPacketArr[mBufIndex] = rawPacket;
			mBufArr[mBufIndex++] = rawPacket->getMBuf();
		}

		uint16_t packetsSent =
		    sendPacketsInner(txQueueId, (void*)mBufArr.data(), getNextPacketFromMBufArray, vecSize, useTxBuffer);

		bool needToFreeMbuf = (!useTxBuffer && (packetsSent != vecSize));
		for (size_t index = 0; index < rawPacketsVec.size(); index++)
			mBufRawPacketArr[index]->setFreeMbuf(needToFreeMbuf);

		return packetsSent;
	}

	uint16_t DpdkDevice::sendPackets(MBufRawPacketVector& rawPacketsVec, uint16_t txQueueId, bool useTxBuffer)
	{
		size_t vecSize = rawPacketsVec.size();
		uint16_t packetsSent = sendPacketsInner(txQueueId, (void*)(&rawPacketsVec), getNextPacketFromMBufRawPacketVec,
		                                        vecSize, useTxBuffer);

		bool needToFreeMbuf = (!useTxBuffer && (packetsSent != vecSize));

		for (size_t index = 0; index < vecSize; index++)
			rawPacketsVec.at(index)->setFreeMbuf(needToFreeMbuf);

		return packetsSent;
	}

	bool DpdkDevice::sendPacket(RawPacket& rawPacket, uint16_t txQueueId, bool useTxBuffer)
	{
		uint8_t rawPacketType = rawPacket.getObjectType();
		if (rawPacketType == MBUFRAWPACKET_OBJECT_TYPE)
		{
			bool packetSent = (sendPacketsInner(txQueueId, (MBufRawPacket*)&rawPacket, getNextPacketFromMBufRawPacket,
			                                    1, useTxBuffer) == 1);
			bool needToFreeMbuf = (!useTxBuffer && !packetSent);
			((MBufRawPacket*)&rawPacket)->setFreeMbuf(needToFreeMbuf);
			return packetSent;
		}

		MBufRawPacket mbufRawPacket;
		if (unlikely(!mbufRawPacket.initFromRawPacket(&rawPacket, this)))
			return false;

		bool packetSent =
		    (sendPacketsInner(txQueueId, &mbufRawPacket, getNextPacketFromMBufRawPacket, 1, useTxBuffer) == 1);
		bool needToFreeMbuf = (!useTxBuffer && !packetSent);
		mbufRawPacket.setFreeMbuf(needToFreeMbuf);

		return packetSent;
	}

	bool DpdkDevice::sendPacket(MBufRawPacket& rawPacket, uint16_t txQueueId, bool useTxBuffer)
	{
		bool packetSent =
		    (sendPacketsInner(txQueueId, &rawPacket, getNextPacketFromMBufRawPacket, 1, useTxBuffer) == 1);
		bool needToFreeMbuf = (!useTxBuffer && !packetSent);
		rawPacket.setFreeMbuf(needToFreeMbuf);
		return packetSent;
	}

	bool DpdkDevice::sendPacket(Packet& packet, uint16_t txQueueId, bool useTxBuffer)
	{
		return sendPacket(*(packet.getRawPacket()), txQueueId);
	}

	int DpdkDevice::getAmountOfFreeMbufs() const
	{
		return (int)rte_mempool_avail_count(m_MBufMempool);
	}

	int DpdkDevice::getAmountOfMbufsInUse() const
	{
		return (int)rte_mempool_in_use_count(m_MBufMempool);
	}

	uint64_t DpdkDevice::convertRssHfToDpdkRssHf(uint64_t rssHF) const
	{
		if (rssHF == (uint64_t)-1)
		{
			rte_eth_dev_info devInfo;
			if (!getDeviceInfo(m_Id, devInfo))
			{
				return 0;
			}

			return devInfo.flow_type_rss_offloads;
		}

		uint64_t dpdkRssHF = 0;

		if ((rssHF & RSS_IPV4) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_IPV4;

		if ((rssHF & RSS_FRAG_IPV4) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_FRAG_IPV4;

		if ((rssHF & RSS_NONFRAG_IPV4_TCP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_TCP;

		if ((rssHF & RSS_NONFRAG_IPV4_UDP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_UDP;

		if ((rssHF & RSS_NONFRAG_IPV4_SCTP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_SCTP;

		if ((rssHF & RSS_NONFRAG_IPV4_OTHER) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_OTHER;

		if ((rssHF & RSS_IPV6) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_IPV6;

		if ((rssHF & RSS_FRAG_IPV6) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_FRAG_IPV6;

		if ((rssHF & RSS_NONFRAG_IPV6_TCP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_TCP;

		if ((rssHF & RSS_NONFRAG_IPV6_UDP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_UDP;

		if ((rssHF & RSS_NONFRAG_IPV6_SCTP) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_SCTP;

		if ((rssHF & RSS_NONFRAG_IPV6_OTHER) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_OTHER;

		if ((rssHF & RSS_L2_PAYLOAD) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_L2_PAYLOAD;

		if ((rssHF & RSS_IPV6_EX) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_IPV6_EX;

		if ((rssHF & RSS_IPV6_TCP_EX) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_IPV6_TCP_EX;

		if ((rssHF & RSS_IPV6_UDP_EX) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_IPV6_UDP_EX;

		if ((rssHF & RSS_PORT) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_PORT;

		if ((rssHF & RSS_VXLAN) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_VXLAN;

		if ((rssHF & RSS_GENEVE) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_GENEVE;

		if ((rssHF & RSS_NVGRE) != 0)
			dpdkRssHF |= DPDK_CONFIG_ETH_RSS_NVGRE;

		return dpdkRssHF;
	}

	uint64_t DpdkDevice::convertDpdkRssHfToRssHf(uint64_t dpdkRssHF) const
	{
		uint64_t rssHF = 0;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_IPV4) != 0)
			rssHF |= RSS_IPV4;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_FRAG_IPV4) != 0)
			rssHF |= RSS_FRAG_IPV4;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_TCP) != 0)
			rssHF |= RSS_NONFRAG_IPV4_TCP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_UDP) != 0)
			rssHF |= RSS_NONFRAG_IPV4_UDP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_SCTP) != 0)
			rssHF |= RSS_NONFRAG_IPV4_SCTP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV4_OTHER) != 0)
			rssHF |= RSS_NONFRAG_IPV4_OTHER;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_IPV6) != 0)
			rssHF |= RSS_IPV6;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_FRAG_IPV6) != 0)
			rssHF |= RSS_FRAG_IPV6;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_TCP) != 0)
			rssHF |= RSS_NONFRAG_IPV6_TCP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_UDP) != 0)
			rssHF |= RSS_NONFRAG_IPV6_UDP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_SCTP) != 0)
			rssHF |= RSS_NONFRAG_IPV6_SCTP;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NONFRAG_IPV6_OTHER) != 0)
			rssHF |= RSS_NONFRAG_IPV6_OTHER;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_L2_PAYLOAD) != 0)
			rssHF |= RSS_L2_PAYLOAD;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_IPV6_EX) != 0)
			rssHF |= RSS_IPV6_EX;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_IPV6_TCP_EX) != 0)
			rssHF |= RSS_IPV6_TCP_EX;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_IPV6_UDP_EX) != 0)
			rssHF |= RSS_IPV6_UDP_EX;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_PORT) != 0)
			rssHF |= RSS_PORT;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_VXLAN) != 0)
			rssHF |= RSS_VXLAN;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_GENEVE) != 0)
			rssHF |= RSS_GENEVE;

		if ((dpdkRssHF & DPDK_CONFIG_ETH_RSS_NVGRE) != 0)
			rssHF |= RSS_NVGRE;

		return rssHF;
	}

	bool DpdkDevice::isDeviceSupportRssHashFunction(DpdkRssHashFunction rssHF) const
	{
		return isDeviceSupportRssHashFunction((uint64_t)rssHF);
	}

	bool DpdkDevice::isDeviceSupportRssHashFunction(uint64_t rssHFMask) const
	{
		uint64_t dpdkRssHF = convertRssHfToDpdkRssHf(rssHFMask);

		rte_eth_dev_info devInfo;
		if (!getDeviceInfo(m_Id, devInfo))
		{
			return false;
		}

		return ((devInfo.flow_type_rss_offloads & dpdkRssHF) == dpdkRssHF);
	}

	uint64_t DpdkDevice::getSupportedRssHashFunctions() const
	{
		rte_eth_dev_info devInfo;
		if (!getDeviceInfo(m_Id, devInfo))
		{
			return 0;
		}

		return convertDpdkRssHfToRssHf(devInfo.flow_type_rss_offloads);
	}

	uint64_t DpdkDevice::getConfiguredRssHashFunction() const
	{
		if (m_Config.rssHashFunction == static_cast<uint64_t>(RSS_DEFAULT))
		{
			if (m_PMDType == PMD_I40E || m_PMDType == PMD_I40EVF)
			{
				return RSS_NONFRAG_IPV4_TCP | RSS_NONFRAG_IPV4_UDP | RSS_NONFRAG_IPV4_OTHER | RSS_FRAG_IPV4 |
				       RSS_NONFRAG_IPV6_TCP | RSS_NONFRAG_IPV6_UDP | RSS_NONFRAG_IPV6_OTHER | RSS_FRAG_IPV6;
			}
			else
			{
				return RSS_IPV4 | RSS_IPV6;
			}
		}

		if (m_Config.rssHashFunction == static_cast<uint64_t>(RSS_ALL_SUPPORTED))
		{
			return getSupportedRssHashFunctions();
		}

		return m_Config.rssHashFunction;
	}

	std::vector<std::string> DpdkDevice::rssHashFunctionMaskToString(uint64_t rssHFMask) const
	{
		std::vector<std::string> result = std::vector<std::string>();

		if (rssHFMask == RSS_NONE)
		{
			result.push_back("RSS_NONE");
			return result;
		}

		if ((rssHFMask & RSS_IPV4) != 0)
			result.push_back("RSS_IPV4");

		if ((rssHFMask & RSS_FRAG_IPV4) != 0)
			result.push_back("RSS_FRAG_IPV4");

		if ((rssHFMask & RSS_NONFRAG_IPV4_TCP) != 0)
			result.push_back("RSS_NONFRAG_IPV4_TCP");

		if ((rssHFMask & RSS_NONFRAG_IPV4_UDP) != 0)
			result.push_back("RSS_NONFRAG_IPV4_UDP");

		if ((rssHFMask & RSS_NONFRAG_IPV4_SCTP) != 0)
			result.push_back("RSS_NONFRAG_IPV4_SCTP");

		if ((rssHFMask & RSS_NONFRAG_IPV4_OTHER) != 0)
			result.push_back("RSS_NONFRAG_IPV4_OTHER");

		if ((rssHFMask & RSS_IPV6) != 0)
			result.push_back("RSS_IPV6");

		if ((rssHFMask & RSS_FRAG_IPV6) != 0)
			result.push_back("RSS_FRAG_IPV6");

		if ((rssHFMask & RSS_NONFRAG_IPV6_TCP) != 0)
			result.push_back("RSS_NONFRAG_IPV6_TCP");

		if ((rssHFMask & RSS_NONFRAG_IPV6_UDP) != 0)
			result.push_back("RSS_NONFRAG_IPV6_UDP");

		if ((rssHFMask & RSS_NONFRAG_IPV6_SCTP) != 0)
			result.push_back("RSS_NONFRAG_IPV6_SCTP");

		if ((rssHFMask & RSS_NONFRAG_IPV6_OTHER) != 0)
			result.push_back("RSS_NONFRAG_IPV6_OTHER");

		if ((rssHFMask & RSS_L2_PAYLOAD) != 0)
			result.push_back("RSS_L2_PAYLOAD");

		if ((rssHFMask & RSS_IPV6_EX) != 0)
			result.push_back("RSS_IPV6_EX");

		if ((rssHFMask & RSS_IPV6_TCP_EX) != 0)
			result.push_back("RSS_IPV6_TCP_EX");

		if ((rssHFMask & RSS_IPV6_UDP_EX) != 0)
			result.push_back("RSS_IPV6_UDP_EX");

		if ((rssHFMask & RSS_PORT) != 0)
			result.push_back("RSS_PORT");

		if ((rssHFMask & RSS_VXLAN) != 0)
			result.push_back("RSS_VXLAN");

		if ((rssHFMask & RSS_GENEVE) != 0)
			result.push_back("RSS_GENEVE");

		if ((rssHFMask & RSS_NVGRE) != 0)
			result.push_back("RSS_NVGRE");

		return result;
	}

}  // namespace pcpp

// GCOVR_EXCL_STOP
