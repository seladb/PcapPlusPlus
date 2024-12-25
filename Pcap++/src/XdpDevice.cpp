#define LOG_MODULE PcapLogModuleXdpDevice

#include "XdpDevice.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include "Packet.h"
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <functional>
#include <algorithm>
#include <poll.h>

namespace pcpp
{

	struct xsk_umem_info
	{
		struct xsk_ring_prod fq;
		struct xsk_ring_cons cq;
		struct xsk_umem* umem;
	};

	struct xsk_socket_info
	{
		struct xsk_ring_cons rx;
		struct xsk_ring_prod tx;
		struct xsk_socket* xsk;
	};

#define DEFAULT_UMEM_NUM_FRAMES (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define DEFAULT_FILL_RING_SIZE (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define DEFAULT_COMPLETION_RING_SIZE XSK_RING_PROD__DEFAULT_NUM_DESCS
#define DEFAULT_BATCH_SIZE 64
#define IS_POWER_OF_TWO(num) (num && ((num & (num - 1)) == 0))

	XdpDevice::XdpUmem::XdpUmem(uint16_t numFrames, uint16_t frameSize, uint32_t fillRingSize,
	                            uint32_t completionRingSize)
	{
		size_t bufferSize = numFrames * frameSize;

		if (posix_memalign(&m_Buffer, getpagesize(), bufferSize))
		{
			throw std::runtime_error("Could not allocate buffer memory for UMEM");
		}

		struct xsk_umem_config cfg = { .fill_size = fillRingSize,
			                           .comp_size = completionRingSize,
			                           .frame_size = frameSize,
			                           .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
			                           .flags = 0 };

		struct xsk_umem_info* umem = new xsk_umem_info;
		memset(umem, 0, sizeof(xsk_umem_info));

		int ret = xsk_umem__create(&umem->umem, m_Buffer, bufferSize, &umem->fq, &umem->cq, &cfg);
		if (ret)
		{
			throw std::runtime_error("Could not allocate UMEM - xsk_umem__create() returned " + std::to_string(ret));
		}

		m_UmemInfo = umem;

		for (uint16_t i = 0; i < numFrames; i++)
		{
			m_FreeFrames.push_back(i * frameSize);
		}

		m_FrameSize = frameSize;
		m_FrameCount = numFrames;
	}

	XdpDevice::XdpUmem::~XdpUmem()
	{
		xsk_umem__delete(static_cast<xsk_umem_info*>(m_UmemInfo)->umem);
		free(m_Buffer);
	}

	const uint8_t* XdpDevice::XdpUmem::getDataPtr(uint64_t addr) const
	{
		return static_cast<const uint8_t*>(xsk_umem__get_data(m_Buffer, addr));
	}

	void XdpDevice::XdpUmem::setData(uint64_t addr, const uint8_t* data, size_t dataLen)
	{
		auto dataPtr = static_cast<uint8_t*>(xsk_umem__get_data(m_Buffer, addr));
		memcpy(dataPtr, data, dataLen);
	}

	std::pair<bool, std::vector<uint64_t>> XdpDevice::XdpUmem::allocateFrames(uint32_t count)
	{
		if (m_FreeFrames.size() < count)
		{
			PCPP_LOG_ERROR("Not enough frames to allocate. Requested: " << count
			                                                            << ", available: " << m_FreeFrames.size());
			return { false, {} };
		}

		std::vector<uint64_t> result;
		for (uint32_t i = 0; i < count; i++)
		{
			result.push_back(m_FreeFrames.back());
			m_FreeFrames.pop_back();
		}

		return { true, result };
	}

	void XdpDevice::XdpUmem::freeFrame(uint64_t addr)
	{
		auto frame = (uint64_t)((addr / m_FrameSize) * m_FrameSize);
		m_FreeFrames.push_back(frame);
	}

	XdpDevice::XdpDevice(std::string interfaceName)
	    : m_InterfaceName(std::move(interfaceName)), m_Config(nullptr), m_ReceivingPackets(false), m_Umem(nullptr),
	      m_SocketInfo(nullptr)
	{
		memset(&m_Stats, 0, sizeof(m_Stats));
		memset(&m_PrevStats, 0, sizeof(m_PrevStats));
	}

	XdpDevice::~XdpDevice()
	{
		close();
	}

	bool XdpDevice::receivePackets(OnPacketsArrive onPacketsArrive, void* onPacketsArriveUserCookie, int timeoutMS)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device is not open");
			return false;
		}

		auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);

		m_ReceivingPackets = true;
		uint32_t rxId = 0;

		pollfd pollFds[1];
		pollFds[0] = { .fd = xsk_socket__fd(socketInfo->xsk), .events = POLLIN };

		std::vector<RawPacket> receiveBuffer;
		while (m_ReceivingPackets)
		{
			checkCompletionRing();

			auto pollResult = poll(pollFds, 1, timeoutMS);
			if (pollResult == 0 && timeoutMS != 0)
			{
				m_Stats.rxPollTimeout++;
				m_ReceivingPackets = false;
				return true;
			}
			if (pollResult < 0)
			{
				m_ReceivingPackets = false;
				if (errno != EINTR)
				{
					PCPP_LOG_ERROR("poll() returned an error: " << errno);
					return false;
				}

				return true;
			}

			uint32_t receivedPacketsCount = xsk_ring_cons__peek(&socketInfo->rx, m_Config->rxTxBatchSize, &rxId);

			if (receivedPacketsCount == 0)
			{
				continue;
			}

			m_Stats.rxPackets += receivedPacketsCount;

			// Reserves at least enough memory to hold all the received packets. No-op if capacity is enough.
			// May hold more memory than needed if a previous cycle has reserved more already.
			receiveBuffer.reserve(receivedPacketsCount);

			for (uint32_t i = 0; i < receivedPacketsCount; i++)
			{
				uint64_t addr = xsk_ring_cons__rx_desc(&socketInfo->rx, rxId + i)->addr;
				uint32_t len = xsk_ring_cons__rx_desc(&socketInfo->rx, rxId + i)->len;

				auto data = m_Umem->getDataPtr(addr);
				timespec ts;
				clock_gettime(CLOCK_REALTIME, &ts);
				// Initializes the RawPacket directly into the buffer.
				receiveBuffer.emplace_back(data, static_cast<int>(len), ts, false);

				m_Stats.rxBytes += len;

				m_Umem->freeFrame(addr);
			}

			onPacketsArrive(receiveBuffer.data(), receiveBuffer.size(), this, onPacketsArriveUserCookie);

			xsk_ring_cons__release(&socketInfo->rx, receivedPacketsCount);
			m_Stats.rxRingId = rxId + receivedPacketsCount;

			if (!populateFillRing(receivedPacketsCount, rxId))
			{
				m_ReceivingPackets = false;
			}

			// Clears the receive buffer.
			receiveBuffer.clear();
		}

		return true;
	}

	void XdpDevice::stopReceivePackets()
	{
		m_ReceivingPackets = false;
	}

	bool XdpDevice::sendPackets(const std::function<RawPacket(uint32_t)>& getPacketAt,
	                            const std::function<uint32_t()>& getPacketCount, bool waitForTxCompletion,
	                            int waitForTxCompletionTimeoutMS)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device is not open");
			return false;
		}

		auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);

		checkCompletionRing();

		uint32_t txId = 0;
		uint32_t packetCount = getPacketCount();

		auto frameResponse = m_Umem->allocateFrames(packetCount);
		if (!frameResponse.first)
		{
			return false;
		}

		if (xsk_ring_prod__reserve(&socketInfo->tx, packetCount, &txId) < packetCount)
		{
			for (auto frame : frameResponse.second)
			{
				m_Umem->freeFrame(frame);
			}
			PCPP_LOG_ERROR("Cannot reserve " << packetCount << " tx slots");
			return false;
		}

		for (uint32_t i = 0; i < packetCount; i++)
		{
			if (getPacketAt(i).getRawDataLen() > m_Umem->getFrameSize())
			{
				PCPP_LOG_ERROR("Cannot send packets with data length (" << getPacketAt(i).getRawDataLen()
				                                                        << ") greater than UMEM frame size ("
				                                                        << m_Umem->getFrameSize() << ")");
				return false;
			}
		}

		uint64_t sentBytes = 0;
		for (uint32_t i = 0; i < packetCount; i++)
		{
			uint64_t frame = frameResponse.second[i];
			m_Umem->setData(frame, getPacketAt(i).getRawData(), getPacketAt(i).getRawDataLen());

			struct xdp_desc* txDesc = xsk_ring_prod__tx_desc(&socketInfo->tx, txId + i);
			txDesc->addr = frame;
			txDesc->len = getPacketAt(i).getRawDataLen();

			sentBytes += txDesc->len;
		}

		xsk_ring_prod__submit(&socketInfo->tx, packetCount);
		m_Stats.txSentPackets += packetCount;
		m_Stats.txSentBytes += sentBytes;
		m_Stats.txRingId = txId + packetCount;

		if (waitForTxCompletion)
		{
			uint32_t completedPackets = checkCompletionRing();

			pollfd pollFds[1];
			pollFds[0] = { .fd = xsk_socket__fd(socketInfo->xsk), .events = POLLOUT };

			while (completedPackets < packetCount)
			{
				auto pollResult = poll(pollFds, 1, waitForTxCompletionTimeoutMS);
				if (pollResult == 0 && waitForTxCompletionTimeoutMS != 0)
				{
					PCPP_LOG_ERROR("Wait for TX completion timed out");
					return false;
				}
				if (pollResult < 0)
				{
					PCPP_LOG_ERROR("poll() returned an error: " << errno);
					return false;
				}

				completedPackets += checkCompletionRing();
			}
		}

		return true;
	}

	bool XdpDevice::sendPackets(const RawPacketVector& packets, bool waitForTxCompletion,
	                            int waitForTxCompletionTimeoutMS)
	{
		return sendPackets([&](uint32_t i) { return *packets.at(static_cast<int>(i)); },
		                   [&]() { return packets.size(); }, waitForTxCompletion, waitForTxCompletionTimeoutMS);
	}

	bool XdpDevice::sendPackets(RawPacket packets[], size_t packetCount, bool waitForTxCompletion,
	                            int waitForTxCompletionTimeoutMS)
	{
		return sendPackets([&](uint32_t i) { return packets[i]; }, [&]() { return static_cast<uint32_t>(packetCount); },
		                   waitForTxCompletion, waitForTxCompletionTimeoutMS);
	}

	bool XdpDevice::populateFillRing(uint32_t count, uint32_t rxId)
	{
		auto frameResponse = m_Umem->allocateFrames(count);
		if (!frameResponse.first)
		{
			return false;
		}

		bool result = populateFillRing(frameResponse.second, rxId);
		if (!result)
		{
			for (auto frame : frameResponse.second)
			{
				m_Umem->freeFrame(frame);
			}
		}

		return result;
	}

	bool XdpDevice::populateFillRing(const std::vector<uint64_t>& addresses, uint32_t rxId)
	{
		auto umem = static_cast<xsk_umem_info*>(m_Umem->getInfo());
		auto count = static_cast<uint32_t>(addresses.size());

		uint32_t ret = xsk_ring_prod__reserve(&umem->fq, count, &rxId);
		if (ret != count)
		{
			PCPP_LOG_ERROR("xsk_ring_prod__reserve returned: " << ret << "; expected: " << count);
			return false;
		}

		for (uint32_t i = 0; i < count; i++)
		{
			*xsk_ring_prod__fill_addr(&umem->fq, rxId + i) = addresses[i];
		}

		xsk_ring_prod__submit(&umem->fq, count);
		m_Stats.fqRingId = rxId + count;

		return true;
	}

	uint32_t XdpDevice::checkCompletionRing()
	{
		uint32_t cqId = 0;
		auto umemInfo = static_cast<xsk_umem_info*>(m_Umem->getInfo());

		auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);
		if (xsk_ring_prod__needs_wakeup(&socketInfo->tx))
		{
			sendto(xsk_socket__fd(socketInfo->xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
		}

		uint32_t completedCount = xsk_ring_cons__peek(&umemInfo->cq, m_Config->rxTxBatchSize, &cqId);

		if (completedCount)
		{
			for (uint32_t i = 0; i < completedCount; i++)
			{
				uint64_t addr = *xsk_ring_cons__comp_addr(&umemInfo->cq, cqId + i);
				m_Umem->freeFrame(addr);
			}

			xsk_ring_cons__release(&umemInfo->cq, completedCount);
			m_Stats.cqRingId = cqId + completedCount;
		}

		m_Stats.txCompletedPackets += completedCount;
		return completedCount;
	}

	bool XdpDevice::configureSocket()
	{
		auto socketInfo = new xsk_socket_info();

		auto umemInfo = static_cast<xsk_umem_info*>(m_Umem->getInfo());

		struct xsk_socket_config xskConfig;
		xskConfig.rx_size = m_Config->txSize;
		xskConfig.tx_size = m_Config->rxSize;
		xskConfig.libbpf_flags = 0;
		xskConfig.xdp_flags = 0;
		xskConfig.bind_flags = 0;
		if (m_Config->attachMode == XdpDeviceConfiguration::SkbMode)
		{
			xskConfig.xdp_flags = XDP_FLAGS_SKB_MODE;
			xskConfig.bind_flags &= ~XDP_ZEROCOPY;
			xskConfig.bind_flags |= XDP_COPY;
		}
		else if (m_Config->attachMode == XdpDeviceConfiguration::DriverMode)
		{
			xskConfig.xdp_flags = XDP_FLAGS_DRV_MODE;
		}

		int ret = xsk_socket__create(&socketInfo->xsk, m_InterfaceName.c_str(), 0, umemInfo->umem, &socketInfo->rx,
		                             &socketInfo->tx, &xskConfig);
		if (ret)
		{
			PCPP_LOG_ERROR("xsk_socket__create returned an error: " << ret);
			delete socketInfo;
			return false;
		}

		m_SocketInfo = socketInfo;
		return true;
	}

	bool XdpDevice::initUmem()
	{
		m_Umem = new XdpUmem(m_Config->umemNumFrames, m_Config->umemFrameSize, m_Config->fillRingSize,
		                     m_Config->completionRingSize);
		return true;
	}

	bool XdpDevice::initConfig()
	{
		if (!m_Config)
		{
			m_Config = new XdpDeviceConfiguration();
		}

		uint16_t numFrames = m_Config->umemNumFrames ? m_Config->umemNumFrames : DEFAULT_UMEM_NUM_FRAMES;
		uint16_t frameSize = m_Config->umemFrameSize ? m_Config->umemFrameSize : getpagesize();
		uint32_t fillRingSize = m_Config->fillRingSize ? m_Config->fillRingSize : DEFAULT_FILL_RING_SIZE;
		uint32_t completionRingSize =
		    m_Config->completionRingSize ? m_Config->completionRingSize : DEFAULT_COMPLETION_RING_SIZE;
		uint32_t rxSize = m_Config->rxSize ? m_Config->rxSize : XSK_RING_CONS__DEFAULT_NUM_DESCS;
		uint32_t txSize = m_Config->txSize ? m_Config->txSize : XSK_RING_PROD__DEFAULT_NUM_DESCS;
		uint32_t batchSize = m_Config->rxTxBatchSize ? m_Config->rxTxBatchSize : DEFAULT_BATCH_SIZE;

		if (frameSize != getpagesize())
		{
			PCPP_LOG_ERROR("UMEM frame size must match the memory page size (" << getpagesize() << ")");
			return false;
		}

		if (!(IS_POWER_OF_TWO(fillRingSize) && IS_POWER_OF_TWO(completionRingSize) && IS_POWER_OF_TWO(rxSize) &&
		      IS_POWER_OF_TWO(txSize)))
		{
			PCPP_LOG_ERROR("All ring sizes (fill ring, completion ring, rx ring, tx ring) should be a power of two");
			return false;
		}

		if (fillRingSize > numFrames)
		{
			PCPP_LOG_ERROR("Fill ring size (" << fillRingSize
			                                  << ") must be lower or equal to the total number of UMEM frames ("
			                                  << numFrames << ")");
			return false;
		}

		if (completionRingSize > numFrames)
		{
			PCPP_LOG_ERROR("Completion ring size (" << completionRingSize
			                                        << ") must be lower or equal to the total number of UMEM frames ("
			                                        << numFrames << ")");
			return false;
		}

		if (rxSize > numFrames)
		{
			PCPP_LOG_ERROR("RX size (" << rxSize << ") must be lower or equal to the total number of UMEM frames ("
			                           << numFrames << ")");
			return false;
		}

		if (txSize > numFrames)
		{
			PCPP_LOG_ERROR("TX size (" << txSize << ") must be lower or equal to the total number of UMEM frames ("
			                           << numFrames << ")");
			return false;
		}

		if (batchSize > rxSize || batchSize > txSize)
		{
			PCPP_LOG_ERROR("RX/TX batch size (" << batchSize << ") must be lower or equal to RX/TX ring size");
			return false;
		}

		m_Config->umemNumFrames = numFrames;
		m_Config->umemFrameSize = frameSize;
		m_Config->fillRingSize = fillRingSize;
		m_Config->completionRingSize = completionRingSize;
		m_Config->rxSize = rxSize;
		m_Config->txSize = txSize;
		m_Config->rxTxBatchSize = batchSize;

		return true;
	}

	bool XdpDevice::open()
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device already opened");
			return false;
		}

		if (!(initConfig() && initUmem() &&
		      populateFillRing(std::min(m_Config->fillRingSize, static_cast<uint32_t>(m_Config->umemNumFrames / 2))) &&
		      configureSocket()))
		{
			if (m_Umem)
			{
				delete m_Umem;
				m_Umem = nullptr;
			}
			if (m_Config)
			{
				delete m_Config;
				m_Config = nullptr;
			}
			return false;
		}

		memset(&m_Stats, 0, sizeof(m_Stats));
		memset(&m_PrevStats, 0, sizeof(m_PrevStats));

		m_DeviceOpened = true;
		return m_DeviceOpened;
	}

	bool XdpDevice::open(const XdpDeviceConfiguration& config)
	{
		m_Config = new XdpDeviceConfiguration(config);
		return open();
	}

	void XdpDevice::close()
	{
		if (m_DeviceOpened)
		{
			auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);
			xsk_socket__delete(socketInfo->xsk);
			m_DeviceOpened = false;
			delete m_Umem;
			delete m_Config;
			m_Config = nullptr;
			m_Umem = nullptr;
		}
	}

	bool XdpDevice::getSocketStats()
	{
		auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);
		int fd = xsk_socket__fd(socketInfo->xsk);

		struct xdp_statistics socketStats;
		socklen_t optlen = sizeof(socketStats);

		int err = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &socketStats, &optlen);
		if (err)
		{
			PCPP_LOG_ERROR("Error getting stats from socket, return error: " << err);
			return false;
		}

		if (optlen != sizeof(struct xdp_statistics))
		{
			PCPP_LOG_ERROR("Error getting stats from socket: optlen (" << optlen << ") != expected size ("
			                                                           << sizeof(struct xdp_statistics) << ")");
			return false;
		}

		m_Stats.rxDroppedInvalidPackets = socketStats.rx_invalid_descs;
		m_Stats.rxDroppedRxRingFullPackets = socketStats.rx_ring_full;
		m_Stats.rxDroppedFillRingPackets = socketStats.rx_fill_ring_empty_descs;
		m_Stats.rxDroppedTotalPackets = m_Stats.rxDroppedFillRingPackets + m_Stats.rxDroppedRxRingFullPackets +
		                                m_Stats.rxDroppedInvalidPackets + socketStats.rx_dropped;
		m_Stats.txDroppedInvalidPackets = socketStats.tx_invalid_descs;

		return true;
	}

#define nanosec_gap(begin, end) ((end.tv_sec - begin.tv_sec) * 1000000000.0 + (end.tv_nsec - begin.tv_nsec))

	XdpDevice::XdpDeviceStats XdpDevice::getStatistics()
	{
		timespec timestamp;
		clock_gettime(CLOCK_MONOTONIC, &timestamp);

		m_Stats.timestamp = timestamp;

		if (m_DeviceOpened)
		{
			getSocketStats();
			m_Stats.umemFreeFrames = m_Umem->getFreeFrameCount();
			m_Stats.umemAllocatedFrames = m_Umem->getFrameCount() - m_Stats.umemFreeFrames;
		}
		else
		{
			m_Stats.umemFreeFrames = 0;
			m_Stats.umemAllocatedFrames = 0;
		}

		double secsElapsed = (double)nanosec_gap(m_PrevStats.timestamp, timestamp) / 1000000000.0;
		m_Stats.rxPacketsPerSec = static_cast<uint64_t>((m_Stats.rxPackets - m_PrevStats.rxPackets) / secsElapsed);
		m_Stats.rxBytesPerSec = static_cast<uint64_t>((m_Stats.rxBytes - m_PrevStats.rxBytes) / secsElapsed);
		m_Stats.txSentPacketsPerSec =
		    static_cast<uint64_t>((m_Stats.txSentPackets - m_PrevStats.txSentPackets) / secsElapsed);
		m_Stats.txSentBytesPerSec =
		    static_cast<uint64_t>((m_Stats.txSentBytes - m_PrevStats.txSentBytes) / secsElapsed);
		m_Stats.txCompletedPacketsPerSec =
		    static_cast<uint64_t>((m_Stats.txCompletedPackets - m_PrevStats.txCompletedPackets) / secsElapsed);

		m_PrevStats.timestamp = timestamp;
		m_PrevStats.rxPackets = m_Stats.rxPackets;
		m_PrevStats.rxBytes = m_Stats.rxBytes;
		m_PrevStats.txSentPackets = m_Stats.txSentPackets;
		m_PrevStats.txSentBytes = m_Stats.txSentBytes;
		m_PrevStats.txCompletedPackets = m_Stats.txCompletedPackets;

		return m_Stats;
	}

}  // namespace pcpp
