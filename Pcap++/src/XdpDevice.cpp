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
//#include <xdp/libxdp.h>
#include <functional>
#include <poll.h>

namespace pcpp
{

	//TODO: add stats

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
};

struct xsk_socket_info
{
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_socket *xsk;
};

#define DEFAULT_UMEM_NUM_FRAMES      (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define MINIMUM_UMEM_FRAME_SIZE      2048
#define DEFAULT_FILL_RING_SIZE       (XSK_RING_PROD__DEFAULT_NUM_DESCS *2)
#define DEFAULT_COMPLETION_RING_SIZE XSK_RING_PROD__DEFAULT_NUM_DESCS
#define DEFAULT_BATCH_SIZE           64


XdpDevice::XdpUmem::XdpUmem(uint16_t numFrames, uint16_t frameSize, uint32_t fillRingSize, uint32_t completionRingSize)
{
	size_t bufferSize = numFrames * frameSize;

	if (posix_memalign(&m_Buffer, getpagesize(), bufferSize))
	{
		throw std::runtime_error("Could not allocate buffer memory for UMEM");
	}

	struct xsk_umem_config cfg = {
		.fill_size = fillRingSize,
		.comp_size = completionRingSize,
		.frame_size = frameSize,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0
	};

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
	//TODO: return true if memcpy succeeds
	memcpy(dataPtr, data, dataLen);
}

std::pair<bool, std::vector<uint64_t>> XdpDevice::XdpUmem::allocateFrames(uint32_t count)
{
	if (m_FreeFrames.size() < count)
	{
		PCPP_LOG_ERROR("Not enough frames to allocate. Requested: " << count << ", available: " << m_FreeFrames.size());
		return {false, {} };
	}

	std::vector<uint64_t> result;
	for (uint32_t i = 0; i < count; i++)
	{
		result.push_back(m_FreeFrames.back());
		m_FreeFrames.pop_back();
	}

//	std::cout << "allocating frame " << std::hex << frame << std::dec << std::endl;
//	std::cout << "remaining frames: " << m_FreeFrames.size() << std::endl << std::endl;
	return {true, result};
}

void XdpDevice::XdpUmem::freeFrame(uint64_t addr)
{
	auto frame = (uint64_t )((addr / m_FrameSize) * m_FrameSize);
	m_FreeFrames.push_back(frame);

//	std::cout << "free frame " << std::hex << frame << std::dec << std::endl;
//	std::cout << "remaining frames: " << m_FreeFrames.size() << std::endl << std::endl;
}

//bool XdpDevice::loadProgram(const std::string& filename)
//{
//	char errmsg[1024];
//	int err;
////	bool opt_frags = false;
//
//	auto xdp_prog = xdp_program__open_file(filename.c_str(), NULL, NULL);
//	err = libxdp_get_error(xdp_prog);
//	if (err) {
//		libxdp_strerror(err, errmsg, sizeof(errmsg));
//		fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
//		return false;
//	}
//
////	err = xdp_program__set_xdp_frags_support(xdp_prog, opt_frags);
////	if (err) {
////		libxdp_strerror(err, errmsg, sizeof(errmsg));
////		fprintf(stderr, "ERROR: Enable frags support failed: %s\n", errmsg);
////		return false;
////	}
//
//	auto opt_ifindex = if_nametoindex(m_InterfaceName.c_str());
//	xdp_attach_mode attachMode = XDP_MODE_SKB;
//	err = xdp_program__attach(xdp_prog, opt_ifindex, attachMode, 0);
//	if (err) {
//		libxdp_strerror(err, errmsg, sizeof(errmsg));
//		fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
//		return false;
//	}
//
//
//	m_Prog = xdp_prog;
//
//	return true;
//}

XdpDevice::~XdpDevice()
{
	close();
}

void XdpDevice::startCapture(OnPacketsArrive onPacketsArrive, void* onPacketsArriveUserCookie, int timeoutMS)
{
	if (!m_SocketInfo)
	{
		PCPP_LOG_ERROR("XDP socket is not open");
		return;
	}

	auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);

	m_Capturing = true;
	uint32_t rxId = 0;

	pollfd pollFds[1];
	pollFds[0] = {
		.fd = xsk_socket__fd(socketInfo->xsk),
		.events = POLLIN
	};

	while (m_Capturing)
	{
		checkCompletionRing();

		auto pollResult = poll(pollFds, 1, timeoutMS);
		if (pollResult == 0 && timeoutMS != 0)
		{
			return;
		}
		if (pollResult < 0)
		{
			PCPP_LOG_ERROR("poll() returned an error: " << errno);
			return;
		}

		uint32_t receivedPacketsCount = xsk_ring_cons__peek(&socketInfo->rx, m_Config->rxTxBatchSize, &rxId);

		if (!receivedPacketsCount)
		{
			continue;
		}

		printf("rxId = %d\n", rxId);
		RawPacket rawPacketsArr[receivedPacketsCount];

		for (uint32_t i = 0; i < receivedPacketsCount; i++)
		{
			uint64_t addr = xsk_ring_cons__rx_desc(&socketInfo->rx, rxId + i)->addr;
			uint32_t len = xsk_ring_cons__rx_desc(&socketInfo->rx, rxId + i)->len;

			auto data = m_Umem->getDataPtr(addr);
			timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			rawPacketsArr[i].initWithRawData(data, static_cast<int>(len), ts);

			m_Umem->freeFrame(addr);
		}

		onPacketsArrive(rawPacketsArr, receivedPacketsCount, this, onPacketsArriveUserCookie);

		xsk_ring_cons__release(&socketInfo->rx, receivedPacketsCount);

		if (!populateFillRing(receivedPacketsCount, rxId))
		{
			m_Capturing = false;
		}
	}
}

void XdpDevice::stopCapture()
{
	m_Capturing = false;
}

void XdpDevice::sendPackets(const std::function<RawPacket(uint32_t)>& getPacketAt, const std::function<uint32_t()>& getPacketCount, bool waitForTxCompletion, int waitForTxCompletionTimeoutMS)
{
	if (!m_SocketInfo)
	{
		PCPP_LOG_ERROR("XDP socket is not open");
		return;
	}

	auto socketInfo = static_cast<xsk_socket_info *>(m_SocketInfo);

	checkCompletionRing();

	uint32_t txId = 0;
	uint32_t packetCount = getPacketCount();

	auto frameResponse = m_Umem->allocateFrames(packetCount);
	if (!frameResponse.first)
	{
		return;
	}

	if (xsk_ring_prod__reserve(&socketInfo->tx, packetCount, &txId) < packetCount)
	{
		for (auto frame : frameResponse.second)
		{
			m_Umem->freeFrame(frame);
		}
		PCPP_LOG_ERROR("Cannot reserve " << packetCount << " tx slots");
		return;
	}

	for (uint32_t i = 0; i < packetCount; i++)
	{
		if (getPacketAt(i).getRawDataLen() > m_Umem->getFrameSize())
		{
			PCPP_LOG_ERROR("Cannot send packets with data length (" << getPacketAt(i).getRawDataLen() << ") greater than UMEM frame size (" << m_Umem->getFrameSize() << ")");
			return;
		}
	}

	for (uint32_t i = 0; i < packetCount; i++)
	{
		uint64_t frame = frameResponse.second[i];
		m_Umem->setData(frame, getPacketAt(i).getRawData(), getPacketAt(i).getRawDataLen());

		printf("txId = %d\n", txId+i);
		struct xdp_desc* txDesc = xsk_ring_prod__tx_desc(&socketInfo->tx, txId + i);
		txDesc->addr = frame;
		txDesc->len = getPacketAt(i).getRawDataLen();
	}

	xsk_ring_prod__submit(&socketInfo->tx, packetCount);
	std::cout << "submitted " << packetCount << " packets to tx" << std::endl;

	if (waitForTxCompletion)
	{
		uint32_t completedPackets = checkCompletionRing();

		pollfd pollFds[1];
		pollFds[0] = {
			.fd = xsk_socket__fd(socketInfo->xsk),
			.events = POLLOUT
		};

		while (completedPackets < packetCount)
		{
			auto pollResult = poll(pollFds, 1, waitForTxCompletionTimeoutMS);
			if (pollResult == 0 && waitForTxCompletionTimeoutMS != 0)
			{
				PCPP_LOG_ERROR("Wait for TX completion timed out");
				return;
			}
			if (pollResult < 0)
			{
				PCPP_LOG_ERROR("poll() returned an error: " << errno);
				return;
			}

			completedPackets += checkCompletionRing();
		}
	}
}

void XdpDevice::sendPackets(const RawPacketVector& packets, bool waitForTxCompletion, int waitForTxCompletionTimeoutMS)
{
	sendPackets([&](uint32_t i) { return *packets.at(static_cast<int>(i)); }, [&]() { return packets.size(); }, waitForTxCompletion, waitForTxCompletionTimeoutMS);
}

void XdpDevice::sendPackets(RawPacket packets[], size_t packetCount, bool waitForTxCompletion, int waitForTxCompletionTimeoutMS)
{
	sendPackets([&](uint32_t i) { return packets[i]; }, [&]() { return static_cast<uint32_t>(packetCount); }, waitForTxCompletion, waitForTxCompletionTimeoutMS);
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
	auto umem = static_cast<xsk_umem_info *>(m_Umem->getInfo());
	auto count = static_cast<uint32_t>(addresses.size());

	uint32_t ret = xsk_ring_prod__reserve(&umem->fq,count, &rxId);
	if (ret != count)
	{
		PCPP_LOG_ERROR("xsk_ring_prod__reserve returned: " << ret << "; expected: " << count);
		return false;
	}

	for (uint32_t i = 0; i < count; i++)
	{
		*xsk_ring_prod__fill_addr(&umem->fq, rxId++) = addresses[i];
	}

	xsk_ring_prod__submit(&umem->fq, count);

	return true;
}

uint32_t XdpDevice::checkCompletionRing()
{
	uint32_t cqId = 0;
	auto umemInfo = static_cast<xsk_umem_info*>(m_Umem->getInfo());

	auto socketInfo = static_cast<xsk_socket_info*>(m_SocketInfo);
	if (xsk_ring_prod__needs_wakeup(&socketInfo->tx))
	{
		sendto(xsk_socket__fd(socketInfo->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	}

	uint32_t completedCount = xsk_ring_cons__peek(&umemInfo->cq, m_Config->rxTxBatchSize, &cqId);

	if (completedCount)
	{
		printf("completed tx of %d packets\n", completedCount);
		for (uint32_t i = 0; i < completedCount; i++)
		{
			uint64_t addr = *xsk_ring_cons__comp_addr(&umemInfo->cq, cqId + i);
			m_Umem->freeFrame(addr);
		}

		xsk_ring_cons__release(&umemInfo->cq, completedCount);
	}

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

	int ret = xsk_socket__create(&socketInfo->xsk, m_InterfaceName.c_str(), 0, umemInfo->umem,
								 &socketInfo->rx, &socketInfo->tx, &xskConfig);
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
	if (m_Umem)
	{
		return true;
	}

	if (m_Config->umemFrameSize < MINIMUM_UMEM_FRAME_SIZE)
	{
		PCPP_LOG_ERROR("UMEM frame size has to be larger than " << MINIMUM_UMEM_FRAME_SIZE);
		return false;
	}

	m_Umem = new XdpUmem(m_Config->umemNumFrames, m_Config->umemFrameSize, m_Config->fillRingSize, m_Config->completionRingSize);
	return true;
}

bool XdpDevice::initConfig()
{
	if (!m_Config)
	{
		m_Config = new XdpDeviceConfiguration();
	}

	uint16_t numFrames = m_Config->umemNumFrames ? m_Config->umemNumFrames : DEFAULT_UMEM_NUM_FRAMES;
	uint32_t fillRingSize = m_Config->fillRingSize ? m_Config->fillRingSize : DEFAULT_FILL_RING_SIZE;
	uint32_t completionRingSize = m_Config->completionRingSize ? m_Config->completionRingSize : DEFAULT_COMPLETION_RING_SIZE;
	uint32_t rxSize = m_Config->rxSize ? m_Config->rxSize : XSK_RING_CONS__DEFAULT_NUM_DESCS;
	uint32_t txSize = m_Config->txSize ? m_Config->txSize : XSK_RING_PROD__DEFAULT_NUM_DESCS;
	uint32_t batchSize = m_Config->rxTxBatchSize ? m_Config->rxTxBatchSize : DEFAULT_BATCH_SIZE;

	if (fillRingSize > numFrames)
	{
		PCPP_LOG_ERROR("Fill ring size (" << fillRingSize << ") must be lower or equal to the total number of UMEM frames (" << numFrames << ")");
		return false;
	}

	if (completionRingSize > numFrames)
	{
		PCPP_LOG_ERROR("Completion ring size (" << completionRingSize << ") must be lower or equal to the total number of UMEM frames (" << numFrames << ")");
		return false;
	}

	if (rxSize > numFrames)
	{
		PCPP_LOG_ERROR("RX size (" << rxSize << ") must be lower or equal to the total number of UMEM frames (" << numFrames << ")");
		return false;
	}

	if (txSize > numFrames)
	{
		PCPP_LOG_ERROR("TX size (" << txSize << ") must be lower or equal to the total number of UMEM frames (" << numFrames << ")");
		return false;
	}

	if (batchSize > rxSize || batchSize > txSize)
	{
		PCPP_LOG_ERROR("RX/TX batch size (" << batchSize << ") must be lower or equal to RX/TX ring size");
		return false;
	}

	m_Config->umemNumFrames = numFrames;
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

	if (!initConfig())
	{
		return false;
	}

	if (!initUmem())
	{
		return false;
	}

	if (!populateFillRing(m_Umem->getFrameCount() / 2))
	{
		return false;
	}

	if (!configureSocket())
	{
		return false;
	}

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

}
