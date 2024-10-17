#define LOG_MODULE PcapLogModuleLiveDevice

#include "IpUtils.h"
#include "DeviceUtils.h"
#include "PcapUtils.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "Packet.h"
#ifndef _MSC_VER
#	include <unistd.h>
#endif  // ! _MSC_VER
#include "pcap.h"
#include <thread>
#include "Logger.h"
#include "SystemUtils.h"
#include <cstring>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sstream>
#include <vector>
#include <array>
#if defined(_WIN32)
// The definition of BPF_MAJOR_VERSION is required to support Npcap. In Npcap there are
// compilation errors due to struct redefinition when including both Packet32.h and pcap.h
// This define statement eliminates these errors
#	ifndef BPF_MAJOR_VERSION
#		define BPF_MAJOR_VERSION 1
#	endif  // BPF_MAJOR_VERSION
#	include <ws2tcpip.h>
#	include <Packet32.h>
#	include <ntddndis.h>
#	include <iphlpapi.h>
#else
#	include <arpa/inet.h>
#	include <sys/ioctl.h>
#	include <net/if.h>
#	include <poll.h>
#	include <pcap/pcap.h>
#endif  // if defined(_WIN32)
#if defined(__APPLE__)
#	include <net/if_dl.h>
#	include <sys/sysctl.h>
#	include <net/route.h>
#endif

#if defined(__FreeBSD__)
#	include <sys/sysctl.h>
#	include <net/if_dl.h>
#endif

// TODO: FIX FreeBSD
// On Mac OS X and FreeBSD timeout of -1 causes pcap_open_live to fail.
// A value of 1ms first solve the issue but since Jan. 2024 an issue
// seems to make pcap_breakloop() to not properly break pcap_dispatch()
// After multiple test a 10ms is the minimum to fix pcap_breakloop().
// On Linux and Windows this is not the case so we keep the -1 value
#if defined(__FreeBSD__)
#	define LIBPCAP_OPEN_LIVE_TIMEOUT 10
#elif defined(__APPLE__)
#	define LIBPCAP_OPEN_LIVE_TIMEOUT 1
#else
#	define LIBPCAP_OPEN_LIVE_TIMEOUT -1
#endif

static const char* NFLOG_IFACE = "nflog";
static const int DEFAULT_SNAPLEN = 9000;

namespace pcpp
{

#ifdef HAS_SET_DIRECTION_ENABLED
	static pcap_direction_t directionTypeMap(PcapLiveDevice::PcapDirection direction)
	{
		switch (direction)
		{
		case PcapLiveDevice::PCPP_IN:
			return PCAP_D_IN;
		case PcapLiveDevice::PCPP_OUT:
			return PCAP_D_OUT;
		case PcapLiveDevice::PCPP_INOUT:
			return PCAP_D_INOUT;
		}
	}
#endif

	PcapLiveDevice::DeviceInterfaceDetails::DeviceInterfaceDetails(pcap_if_t* pInterface)
	    : name(pInterface->name), isLoopback(pInterface->flags & PCAP_IF_LOOPBACK)
	{
		if (pInterface->description != nullptr)
			description = pInterface->description;
		for (pcap_addr* current = pInterface->addresses; current != nullptr; current = current->next)
		{
			in_addr* ipv4Addr = internal::try_sockaddr2in_addr(current->addr);
			if (ipv4Addr != nullptr)
			{
				addresses.push_back(IPv4Address(ipv4Addr->s_addr));
				continue;
			}
			in6_addr* ipv6Addr = internal::try_sockaddr2in6_addr(current->addr);
			if (ipv6Addr != nullptr)
			{
				addresses.push_back(IPv6Address(ipv6Addr->s6_addr));
				continue;
			}
		}
	}

	PcapLiveDevice::PcapLiveDevice(DeviceInterfaceDetails interfaceDetails, bool calculateMTU, bool calculateMacAddress,
	                               bool calculateDefaultGateway)
	    : IPcapDevice(), m_PcapSendDescriptor(nullptr), m_PcapSelectableFd(-1),
	      m_InterfaceDetails(std::move(interfaceDetails)), m_DefaultGateway(IPv4Address::Zero), m_UsePoll(false)
	{
		m_DeviceMtu = 0;
		m_LinkType = LINKTYPE_ETHERNET;

		if (Logger::getInstance().isDebugEnabled(PcapLogModuleLiveDevice))
		{
			PCPP_LOG_DEBUG("Added live device: name=" << m_InterfaceDetails.name
			                                          << "; desc=" << m_InterfaceDetails.description);
			PCPP_LOG_DEBUG("   Addresses:");
			for (auto const& address : m_InterfaceDetails.addresses)
			{
				PCPP_LOG_DEBUG("      " << address.toString());
			}
		}

		if (calculateMTU)
		{
			setDeviceMtu();
			PCPP_LOG_DEBUG("   MTU: " << m_DeviceMtu);
		}

		if (calculateDefaultGateway)
		{
			setDefaultGateway();
			PCPP_LOG_DEBUG("   Default Gateway: " << m_DefaultGateway);
		}

		// init all other members
		m_CaptureThreadStarted = false;
		m_StatsThreadStarted = false;
		m_StopThread = false;
		m_CaptureThread = {};
		m_StatsThread = {};
		m_cbOnPacketArrives = nullptr;
		m_cbOnStatsUpdate = nullptr;
		m_cbOnPacketArrivesBlockingMode = nullptr;
		m_cbOnPacketArrivesBlockingModeUserCookie = nullptr;
		m_IntervalToUpdateStats = 0;
		m_cbOnPacketArrivesUserCookie = nullptr;
		m_cbOnStatsUpdateUserCookie = nullptr;
		m_CaptureCallbackMode = true;
		m_CapturedPackets = nullptr;
		if (calculateMacAddress)
		{
			setDeviceMacAddress();
			PCPP_LOG_DEBUG("   MAC addr: " << m_MacAddress);
		}
	}

	void PcapLiveDevice::onPacketArrives(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet)
	{
		PcapLiveDevice* pThis = reinterpret_cast<PcapLiveDevice*>(user);
		if (pThis == nullptr)
		{
			PCPP_LOG_ERROR("Unable to extract PcapLiveDevice instance");
			return;
		}

		RawPacket rawPacket(packet, pkthdr->caplen, pkthdr->ts, false, pThis->getLinkType());

		if (pThis->m_cbOnPacketArrives != nullptr)
			pThis->m_cbOnPacketArrives(&rawPacket, pThis, pThis->m_cbOnPacketArrivesUserCookie);
	}

	void PcapLiveDevice::onPacketArrivesNoCallback(uint8_t* user, const struct pcap_pkthdr* pkthdr,
	                                               const uint8_t* packet)
	{
		PcapLiveDevice* pThis = reinterpret_cast<PcapLiveDevice*>(user);
		if (pThis == nullptr)
		{
			PCPP_LOG_ERROR("Unable to extract PcapLiveDevice instance");
			return;
		}

		uint8_t* packetData = new uint8_t[pkthdr->caplen];
		memcpy(packetData, packet, pkthdr->caplen);
		RawPacket* rawPacketPtr = new RawPacket(packetData, pkthdr->caplen, pkthdr->ts, true, pThis->getLinkType());
		pThis->m_CapturedPackets->pushBack(rawPacketPtr);
	}

	void PcapLiveDevice::onPacketArrivesBlockingMode(uint8_t* user, const struct pcap_pkthdr* pkthdr,
	                                                 const uint8_t* packet)
	{
		PcapLiveDevice* pThis = reinterpret_cast<PcapLiveDevice*>(user);
		if (pThis == nullptr)
		{
			PCPP_LOG_ERROR("Unable to extract PcapLiveDevice instance");
			return;
		}

		RawPacket rawPacket(packet, pkthdr->caplen, pkthdr->ts, false, pThis->getLinkType());

		if (pThis->m_cbOnPacketArrivesBlockingMode != nullptr)
			if (pThis->m_cbOnPacketArrivesBlockingMode(&rawPacket, pThis,
			                                           pThis->m_cbOnPacketArrivesBlockingModeUserCookie))
				pThis->m_StopThread = true;
	}

	void PcapLiveDevice::captureThreadMain()
	{
		PCPP_LOG_DEBUG("Started capture thread for device '" << m_InterfaceDetails.name << "'");
		m_CaptureThreadStarted = true;

		if (m_CaptureCallbackMode)
		{
			while (!m_StopThread)
			{
				if (pcap_dispatch(m_PcapDescriptor.get(), -1, onPacketArrives, reinterpret_cast<uint8_t*>(this)) == -1)
				{
					PCPP_LOG_ERROR("pcap_dispatch returned an error: " << m_PcapDescriptor.getLastError());
					m_StopThread = true;
				}
			}
		}
		else
		{
			while (!m_StopThread)
			{
				if (pcap_dispatch(m_PcapDescriptor.get(), 100, onPacketArrivesNoCallback,
				                  reinterpret_cast<uint8_t*>(this)) == -1)
				{
					PCPP_LOG_ERROR("pcap_dispatch returned an error: " << m_PcapDescriptor.getLastError());
					m_StopThread = true;
				}
			}
		}
		PCPP_LOG_DEBUG("Ended capture thread for device '" << m_InterfaceDetails.name << "'");
	}

	void PcapLiveDevice::statsThreadMain()
	{
		PCPP_LOG_DEBUG("Started stats thread for device '" << m_InterfaceDetails.name << "'");
		while (!m_StopThread)
		{
			PcapStats stats;
			getStatistics(stats);
			m_cbOnStatsUpdate(stats, m_cbOnStatsUpdateUserCookie);
			multiPlatformSleep(m_IntervalToUpdateStats);
		}
		PCPP_LOG_DEBUG("Ended stats thread for device '" << m_InterfaceDetails.name << "'");
	}

	pcap_t* PcapLiveDevice::doOpen(const DeviceConfiguration& config)
	{
		char errbuf[PCAP_ERRBUF_SIZE] = { '\0' };
		std::string device_name = m_InterfaceDetails.name;

		if (device_name == NFLOG_IFACE)
		{
			device_name += ":" + std::to_string(config.nflogGroup & 0xffff);
		}

		pcap_t* pcap = pcap_create(device_name.c_str(), errbuf);
		if (!pcap)
		{
			PCPP_LOG_ERROR(errbuf);
			return pcap;
		}
		int ret = pcap_set_snaplen(pcap, config.snapshotLength <= 0 ? DEFAULT_SNAPLEN : config.snapshotLength);
		if (ret != 0)
		{
			PCPP_LOG_ERROR(pcap_geterr(pcap));
		}
		ret = pcap_set_promisc(pcap, config.mode);
		if (ret != 0)
		{
			PCPP_LOG_ERROR(pcap_geterr(pcap));
		}

		int timeout = (config.packetBufferTimeoutMs <= 0 ? LIBPCAP_OPEN_LIVE_TIMEOUT : config.packetBufferTimeoutMs);
		ret = pcap_set_timeout(pcap, timeout);
		if (ret != 0)
		{
			PCPP_LOG_ERROR(pcap_geterr(pcap));
		}

		if (config.packetBufferSize >= 100)
		{
			ret = pcap_set_buffer_size(pcap, config.packetBufferSize);
			if (ret != 0)
			{
				PCPP_LOG_ERROR(pcap_geterr(pcap));
			}
		}

#ifdef HAS_PCAP_IMMEDIATE_MODE
		ret = pcap_set_immediate_mode(pcap, 1);
		if (ret == 0)
		{
			PCPP_LOG_DEBUG("Immediate mode is activated");
		}
		else
		{
			PCPP_LOG_ERROR("Failed to activate immediate mode, error code: '" << ret << "', error message: '"
			                                                                  << pcap_geterr(pcap) << "'");
		}
#endif

		ret = pcap_activate(pcap);
		if (ret != 0)
		{
			PCPP_LOG_ERROR(pcap_geterr(pcap));
			pcap_close(pcap);
			return nullptr;
		}

#ifdef HAS_SET_DIRECTION_ENABLED
		pcap_direction_t directionToSet = directionTypeMap(config.direction);
		ret = pcap_setdirection(pcap, directionToSet);
		if (ret == 0)
		{
			if (config.direction == PCPP_IN)
			{
				PCPP_LOG_DEBUG("Only incoming traffics will be captured");
			}
			else if (config.direction == PCPP_OUT)
			{
				PCPP_LOG_DEBUG("Only outgoing traffics will be captured");
			}
			else
			{
				PCPP_LOG_DEBUG("Both incoming and outgoing traffics will be captured");
			}
		}
		else
		{
			PCPP_LOG_ERROR("Failed to set direction for capturing packets, error code: '"
			               << ret << "', error message: '" << pcap_geterr(pcap) << "'");
		}
#endif

		if (pcap)
		{
			int dlt = pcap_datalink(pcap);
			const char* dlt_name = pcap_datalink_val_to_name(dlt);
			if (dlt_name)
			{
				PCPP_LOG_DEBUG("link-type " << dlt << ": " << dlt_name << " (" << pcap_datalink_val_to_description(dlt)
				                            << ")");
			}
			else
			{
				PCPP_LOG_DEBUG("link-type " << dlt);
			}

			m_LinkType = static_cast<LinkLayerType>(dlt);
		}
		return pcap;
	}

	bool PcapLiveDevice::open(const DeviceConfiguration& config)
	{
		if (m_DeviceOpened)
		{
			PCPP_LOG_DEBUG("Device '" << m_InterfaceDetails.name << "' already opened");
			return true;
		}

		auto pcapDescriptor = internal::PcapHandle(doOpen(config));
		internal::PcapHandle pcapSendDescriptor;

		// It's not possible to have two open instances of the same NFLOG device:group
		if (m_InterfaceDetails.name == NFLOG_IFACE)
		{
			pcapSendDescriptor = nullptr;
		}
		else
		{
			pcapSendDescriptor = internal::PcapHandle(doOpen(config));
		}

		if (pcapDescriptor == nullptr || (m_InterfaceDetails.name != NFLOG_IFACE && pcapSendDescriptor == nullptr))
		{
			m_DeviceOpened = false;
			return false;
		}

		PCPP_LOG_DEBUG("Device '" << m_InterfaceDetails.name << "' opened");
		m_PcapDescriptor = std::move(pcapDescriptor);
		// The send descriptor is held as a raw pointer as it can sometimes be the same as the receive descriptor
		m_PcapSendDescriptor = pcapSendDescriptor.release();
		m_DeviceOpened = true;

		if (!config.usePoll)
		{
			m_UsePoll = false;
			m_PcapSelectableFd = -1;
		}
		else
		{
#if !defined(_WIN32)
			m_UsePoll = true;
			m_PcapSelectableFd = pcap_get_selectable_fd(m_PcapSendDescriptor);
#else
			PCPP_LOG_ERROR("Windows doesn't support poll(), ignoring the `usePoll` parameter");
#endif
		}

		return true;
	}

	bool PcapLiveDevice::open()
	{
		DeviceConfiguration defaultConfig;
		return open(defaultConfig);
	}

	void PcapLiveDevice::close()
	{
		if (m_PcapDescriptor == nullptr && m_PcapSendDescriptor == nullptr)
		{
			PCPP_LOG_DEBUG("Device '" << m_InterfaceDetails.name << "' already closed");
			return;
		}

		bool sameDescriptor = (m_PcapDescriptor.get() == m_PcapSendDescriptor);
		m_PcapDescriptor.reset();
		PCPP_LOG_DEBUG("Receive pcap descriptor closed");
		if (!sameDescriptor)
		{
			pcap_close(m_PcapSendDescriptor);
			PCPP_LOG_DEBUG("Send pcap descriptor closed");
		}

		m_DeviceOpened = false;
		PCPP_LOG_DEBUG("Device '" << m_InterfaceDetails.name << "' closed");
	}

	PcapLiveDevice* PcapLiveDevice::clone() const
	{
		return new PcapLiveDevice(m_InterfaceDetails, true, true, true);
	}

	bool PcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie)
	{
		return startCapture(std::move(onPacketArrives), onPacketArrivesUserCookie, 0, nullptr, nullptr);
	}

	bool PcapLiveDevice::startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
	                                  void* onStatsUpdateUserCookie)
	{
		return startCapture(nullptr, nullptr, intervalInSecondsToUpdateStats, std::move(onStatsUpdate),
		                    onStatsUpdateUserCookie);
	}

	bool PcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie,
	                                  int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
	                                  void* onStatsUpdateUserCookie)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return false;
		}

		if (m_CaptureThreadStarted)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' already capturing traffic");
			return false;
		}

		m_IntervalToUpdateStats = intervalInSecondsToUpdateStats;

		m_CaptureCallbackMode = true;
		m_cbOnPacketArrives = std::move(onPacketArrives);
		m_cbOnPacketArrivesUserCookie = onPacketArrivesUserCookie;

		m_CaptureThread = std::thread(&pcpp::PcapLiveDevice::captureThreadMain, this);

		// Wait thread to be start
		// C++20 = m_CaptureThreadStarted.wait(true);
		while (m_CaptureThreadStarted != true)
		{
			std::this_thread::yield();
		}
		PCPP_LOG_DEBUG("Successfully created capture thread for device '"
		               << m_InterfaceDetails.name << "'. Thread id: " << m_CaptureThread.get_id());

		if (onStatsUpdate != nullptr && intervalInSecondsToUpdateStats > 0)
		{
			m_cbOnStatsUpdate = std::move(onStatsUpdate);
			m_cbOnStatsUpdateUserCookie = onStatsUpdateUserCookie;
			m_StatsThread = std::thread(&pcpp::PcapLiveDevice::statsThreadMain, this);
			m_StatsThreadStarted = true;
			PCPP_LOG_DEBUG("Successfully created stats thread for device '"
			               << m_InterfaceDetails.name << "'. Thread id: " << m_StatsThread.get_id());
		}

		return true;
	}

	bool PcapLiveDevice::startCapture(RawPacketVector& capturedPacketsVector)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return false;
		}

		if (captureActive())
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' already capturing traffic");
			return false;
		}

		m_CapturedPackets = &capturedPacketsVector;
		m_CapturedPackets->clear();

		m_CaptureCallbackMode = false;
		m_CaptureThread = std::thread(&pcpp::PcapLiveDevice::captureThreadMain, this);
		// Wait thread to be start
		// C++20 = m_CaptureThreadStarted.wait(true);
		while (m_CaptureThreadStarted != true)
		{
			std::this_thread::yield();
		}

		PCPP_LOG_DEBUG("Successfully created capture thread for device '"
		               << m_InterfaceDetails.name << "'. Thread id: " << m_CaptureThread.get_id());

		return true;
	}

	int PcapLiveDevice::startCaptureBlockingMode(OnPacketArrivesStopBlocking onPacketArrives, void* userCookie,
	                                             const double timeout)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return 0;
		}

		if (captureActive())
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' already capturing traffic");
			return 0;
		}

		m_cbOnPacketArrives = nullptr;
		m_cbOnStatsUpdate = nullptr;
		m_cbOnPacketArrivesUserCookie = nullptr;
		m_cbOnStatsUpdateUserCookie = nullptr;

		m_cbOnPacketArrivesBlockingMode = std::move(onPacketArrives);
		m_cbOnPacketArrivesBlockingModeUserCookie = userCookie;

		m_CaptureThreadStarted = true;
		m_StopThread = false;

		const int64_t timeoutMs = timeout * 1000;  // timeout unit is seconds, let's change it to milliseconds
		auto startTime = std::chrono::steady_clock::now();
		auto currentTime = startTime;

#if !defined(_WIN32)
		struct pollfd pcapPollFd;
		memset(&pcapPollFd, 0, sizeof(pcapPollFd));
		pcapPollFd.fd = m_PcapSelectableFd;
		pcapPollFd.events = POLLIN;
#endif

		bool shouldReturnError = false;

		if (timeoutMs <= 0)
		{
			while (!m_StopThread)
			{
				if (pcap_dispatch(m_PcapDescriptor.get(), -1, onPacketArrivesBlockingMode,
				                  reinterpret_cast<uint8_t*>(this)) == -1)
				{
					PCPP_LOG_ERROR("pcap_dispatch returned an error: " << m_PcapDescriptor.getLastError());
					shouldReturnError = true;
					m_StopThread = true;
				}
			}
		}
		else
		{
			while (!m_StopThread &&
			       std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count() < timeoutMs)
			{
				if (m_UsePoll)
				{
#if !defined(_WIN32)
					int64_t pollTimeoutMs =
					    timeoutMs -
					    std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
					// poll will be in blocking mode if negative value
					pollTimeoutMs = std::max(pollTimeoutMs, static_cast<int64_t>(0));

					int ready = poll(&pcapPollFd, 1, pollTimeoutMs);  // wait the packets until timeout

					if (ready > 0)
					{
						if (pcap_dispatch(m_PcapDescriptor.get(), -1, onPacketArrivesBlockingMode,
						                  reinterpret_cast<uint8_t*>(this)) == -1)
						{
							PCPP_LOG_ERROR("pcap_dispatch returned an error: " << m_PcapDescriptor.getLastError());
							shouldReturnError = true;
							m_StopThread = true;
						}
					}
					else if (ready < 0)
					{
						PCPP_LOG_ERROR("poll() got error '" << strerror(errno) << "'");
						shouldReturnError = true;
						m_StopThread = true;
					}
#else
					PCPP_LOG_ERROR("Windows doesn't support poll()");
					shouldReturnError = true;
					m_StopThread = true;
#endif
				}
				else
				{
					if (pcap_dispatch(m_PcapDescriptor.get(), -1, onPacketArrivesBlockingMode,
					                  reinterpret_cast<uint8_t*>(this)) == -1)
					{
						PCPP_LOG_ERROR("pcap_dispatch returned an error: " << m_PcapDescriptor.getLastError());
						shouldReturnError = true;
						m_StopThread = true;
					}
				}
				currentTime = std::chrono::steady_clock::now();
			}
		}

		m_CaptureThreadStarted = false;
		m_StopThread = false;
		m_cbOnPacketArrivesBlockingMode = nullptr;
		m_cbOnPacketArrivesBlockingModeUserCookie = nullptr;

		if (shouldReturnError)
		{
			return 0;
		}

		if (std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count() >= timeoutMs)
		{
			return -1;
		}
		return 1;
	}

	void PcapLiveDevice::stopCapture()
	{
		// in blocking mode stop capture isn't relevant
		if (m_cbOnPacketArrivesBlockingMode != nullptr)
			return;

		m_StopThread = true;
		if (m_CaptureThreadStarted)
		{
			pcap_breakloop(m_PcapDescriptor.get());
			PCPP_LOG_DEBUG("Stopping capture thread, waiting for it to join...");
			m_CaptureThread.join();
			m_CaptureThreadStarted = false;
			PCPP_LOG_DEBUG("Capture thread stopped for device '" << m_InterfaceDetails.name << "'");
		}
		PCPP_LOG_DEBUG("Capture thread stopped for device '" << m_InterfaceDetails.name << "'");
		if (m_StatsThreadStarted)
		{
			PCPP_LOG_DEBUG("Stopping stats thread, waiting for it to join...");
			m_StatsThread.join();
			m_StatsThreadStarted = false;
			PCPP_LOG_DEBUG("Stats thread stopped for device '" << m_InterfaceDetails.name << "'");
		}

		m_StopThread = false;
	}

	bool PcapLiveDevice::captureActive()
	{
		return m_CaptureThreadStarted;
	}

	void PcapLiveDevice::getStatistics(PcapStats& stats) const
	{
		pcap_stat pcapStats;
		if (pcap_stats(m_PcapDescriptor.get(), &pcapStats) < 0)
		{
			PCPP_LOG_ERROR("Error getting statistics from live device '" << m_InterfaceDetails.name << "'");
		}

		stats.packetsRecv = pcapStats.ps_recv;
		stats.packetsDrop = pcapStats.ps_drop;
		stats.packetsDropByInterface = pcapStats.ps_ifdrop;
	}

	bool PcapLiveDevice::doMtuCheck(int packetPayloadLength) const
	{
		if (packetPayloadLength > static_cast<int>(m_DeviceMtu))
		{
			PCPP_LOG_ERROR("Payload length [" << packetPayloadLength << "] is larger than device MTU [" << m_DeviceMtu
			                                  << "]");
			return false;
		}
		return true;
	}

	bool PcapLiveDevice::sendPacket(RawPacket const& rawPacket, bool checkMtu)
	{
		if (checkMtu)
		{
			RawPacket* rPacket = const_cast<RawPacket*>(&rawPacket);
			Packet parsedPacket = Packet(rPacket, OsiModelDataLinkLayer);
			return sendPacket(&parsedPacket, true);
		}
		// Send packet without Mtu check
		return sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen());
	}

	bool PcapLiveDevice::sendPacket(const uint8_t* packetData, int packetDataLength, int packetPayloadLength)
	{
		return doMtuCheck(packetPayloadLength) && sendPacket(packetData, packetDataLength);
	}

	bool PcapLiveDevice::sendPacket(const uint8_t* packetData, int packetDataLength, bool checkMtu,
	                                pcpp::LinkLayerType linkType)
	{
		if (checkMtu)
		{
			timeval time;
			gettimeofday(&time, nullptr);
			pcpp::RawPacket rawPacket(packetData, packetDataLength, time, false, linkType);
			Packet parsedPacket = Packet(&rawPacket, pcpp::OsiModelDataLinkLayer);
			return sendPacket(&parsedPacket, true);
		}

		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened!");
			return false;
		}

		if (packetDataLength == 0)
		{
			PCPP_LOG_ERROR("Trying to send a packet with length 0");
			return false;
		}

		if (pcap_sendpacket(m_PcapSendDescriptor, packetData, packetDataLength) == -1)
		{
			PCPP_LOG_ERROR("Error sending packet: " << pcap_geterr(m_PcapSendDescriptor));
			return false;
		}

		PCPP_LOG_DEBUG("Packet sent successfully. Packet length: " << packetDataLength);
		return true;
	}

	bool PcapLiveDevice::sendPacket(Packet* packet, bool checkMtu)
	{
		RawPacket* rawPacket = packet->getRawPacket();
		if (checkMtu)
		{
			int packetPayloadLength = 0;
			switch (packet->getFirstLayer()->getOsiModelLayer())
			{
			case (pcpp::OsiModelDataLinkLayer):
				packetPayloadLength = static_cast<int>(packet->getFirstLayer()->getLayerPayloadSize());
				break;
			case (pcpp::OsiModelNetworkLayer):
				packetPayloadLength = static_cast<int>(packet->getFirstLayer()->getDataLen());
				break;
			default:
				// if packet layer is not known, do not perform MTU check.
				return sendPacket(*rawPacket, false);
			}
			return doMtuCheck(packetPayloadLength) && sendPacket(*rawPacket, false);
		}
		return sendPacket(*rawPacket, false);
	}

	int PcapLiveDevice::sendPackets(RawPacket* rawPacketsArr, int arrLength, bool checkMtu)
	{
		int packetsSent = 0;
		for (int i = 0; i < arrLength; i++)
		{
			if (sendPacket(rawPacketsArr[i], checkMtu))
				packetsSent++;
		}

		PCPP_LOG_DEBUG(packetsSent << " packets sent successfully. " << arrLength - packetsSent << " packets not sent");
		return packetsSent;
	}

	int PcapLiveDevice::sendPackets(Packet** packetsArr, int arrLength, bool checkMtu)
	{
		int packetsSent = 0;
		for (int i = 0; i < arrLength; i++)
		{
			if (sendPacket(packetsArr[i], checkMtu))
				packetsSent++;
		}

		PCPP_LOG_DEBUG(packetsSent << " packets sent successfully. " << arrLength - packetsSent << " packets not sent");
		return packetsSent;
	}

	int PcapLiveDevice::sendPackets(const RawPacketVector& rawPackets, bool checkMtu)
	{
		int packetsSent = 0;
		for (RawPacketVector::ConstVectorIterator iter = rawPackets.begin(); iter != rawPackets.end(); iter++)
		{
			if (sendPacket(**iter, checkMtu))
				packetsSent++;
		}

		PCPP_LOG_DEBUG(packetsSent << " packets sent successfully. " << (rawPackets.size() - packetsSent)
		                           << " packets not sent");
		return packetsSent;
	}

	void PcapLiveDevice::setDeviceMtu()
	{
#if defined(_WIN32)

		if (m_InterfaceDetails.isLoopback)
		{
			PCPP_LOG_DEBUG("Npcap Loopback Adapter - MTU is insignificant, setting MTU to max value (0xffffffff)");
			m_DeviceMtu = 0xffffffff;
			return;
		}

		uint32_t mtuValue = 0;
		LPADAPTER adapter = PacketOpenAdapter(const_cast<char*>(m_InterfaceDetails.name.c_str()));
		if (adapter == nullptr)
		{
			PCPP_LOG_ERROR("Error in retrieving MTU: Adapter is nullptr");
			return;
		}

		uint8_t buffer[512];
		PACKET_OID_DATA* oidData = reinterpret_cast<PACKET_OID_DATA*>(buffer);
		oidData->Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;
		oidData->Length = sizeof(uint32_t);
		memcpy(oidData->Data, &mtuValue, sizeof(uint32_t));
		if (PacketRequest(adapter, false, oidData))
		{
			if (oidData->Length <= sizeof(uint32_t))
			{
				/* copy value from driver */
				memcpy(&mtuValue, oidData->Data, oidData->Length);
				// Sometimes the query gives a wrong number that includes the link header size
				// A very common value is 1514 - if identify this value just reduce to 1500.
				// TODO: think of a better way to always get the right value
				if (mtuValue == 1514)
				{
					mtuValue = 1500;
				}
				m_DeviceMtu = mtuValue;
			}
			else
			{
				/* the driver returned a value that is longer than expected (and longer than the given buffer) */
				PCPP_LOG_ERROR(
				    "Error in retrieving MTU: Size of Oid larger than uint32_t, OidLen: " << oidData->Length);
				return;
			}
		}
		else
		{
			PCPP_LOG_ERROR("Error in retrieving MTU: PacketRequest failed");
		}

#else
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, m_InterfaceDetails.name.c_str(), sizeof(ifr.ifr_name) - 1);

		int socketfd = -1;
		try
		{
			socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
			if (ioctl(socketfd, SIOCGIFMTU, &ifr) == -1)
			{
				PCPP_LOG_DEBUG("Error in retrieving MTU: ioctl() returned -1");
				m_DeviceMtu = 0;
				return;
			}
			m_DeviceMtu = ifr.ifr_mtu;
		}
		catch (const std::exception& e)
		{
			PCPP_LOG_ERROR("Error in retrieving MTU: " << e.what());
			m_DeviceMtu = 0;
		}

		if (socketfd != -1)
		{
			::close(socketfd);
		}
#endif
	}

	void PcapLiveDevice::setDeviceMacAddress()
	{
#if defined(_WIN32)

		LPADAPTER adapter = PacketOpenAdapter(const_cast<char*>(m_InterfaceDetails.name.c_str()));
		if (adapter == nullptr)
		{
			PCPP_LOG_ERROR("Error in retrieving MAC address: Adapter is nullptr");
			return;
		}

		uint8_t buffer[512];
		PACKET_OID_DATA* oidData = reinterpret_cast<PACKET_OID_DATA*>(buffer);
		oidData->Oid = OID_802_3_CURRENT_ADDRESS;
		oidData->Length = 6;
		oidData->Data[0] = 0;
		if (PacketRequest(adapter, false, oidData))
		{
			if (oidData->Length == 6)
			{
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Warray-bounds"
				/* copy value from driver */
				m_MacAddress = MacAddress(oidData->Data[0], oidData->Data[1], oidData->Data[2], oidData->Data[3],
				                          oidData->Data[4], oidData->Data[5]);
#	pragma GCC diagnostic pop
				PCPP_LOG_DEBUG("   MAC address: " << m_MacAddress);
			}
			else
			{
				/* the driver returned a value that is longer than expected (and longer than the given buffer) */
				PCPP_LOG_DEBUG(
				    "Error in retrieving MAC address: Size of Oid larger than 6, OidLen: " << oidData->Length);
				return;
			}
		}
		else
		{
			PCPP_LOG_DEBUG("Error in retrieving MAC address: PacketRequest failed");
		}
#elif defined(__linux__)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, m_InterfaceDetails.name.c_str(), sizeof(ifr.ifr_name) - 1);

		int socketfd = -1;
		try
		{
			socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
			if (ioctl(socketfd, SIOCGIFHWADDR, &ifr) == -1)
			{
				PCPP_LOG_DEBUG("Error in retrieving MAC address: ioctl() returned -1");
				return;
			}

			m_MacAddress = MacAddress(ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1], ifr.ifr_hwaddr.sa_data[2],
			                          ifr.ifr_hwaddr.sa_data[3], ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
		}
		catch (const std::exception& e)
		{
			PCPP_LOG_ERROR("Error in retrieving MAC address: " << e.what());
		}

		if (socketfd != -1)
		{
			::close(socketfd);
		}
#elif defined(__APPLE__) || defined(__FreeBSD__)
		int mib[6];
		size_t len;

		mib[0] = CTL_NET;
		mib[1] = AF_ROUTE;
		mib[2] = 0;
		mib[3] = AF_LINK;
		mib[4] = NET_RT_IFLIST;
		mib[5] = if_nametoindex(m_InterfaceDetails.name.c_str());

		if (mib[5] == 0)
		{
			PCPP_LOG_DEBUG("Error in retrieving MAC address: if_nametoindex error");
			return;
		}

		if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0)
		{
			PCPP_LOG_DEBUG("Error in retrieving MAC address: sysctl 1 error");
			return;
		}

		std::vector<uint8_t> buf(len);

		if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) < 0)
		{
			PCPP_LOG_DEBUG("Error in retrieving MAC address: sysctl 2 error");
			return;
		}

		struct if_msghdr* ifm = (struct if_msghdr*)buf.data();
		struct sockaddr_dl* sdl = (struct sockaddr_dl*)(ifm + 1);
		uint8_t* ptr = (uint8_t*)LLADDR(sdl);
		m_MacAddress = MacAddress(ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#endif
	}

	void PcapLiveDevice::setDefaultGateway()
	{
#if defined(_WIN32)
		ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
		std::vector<uint8_t> buffer(outBufLen);
		PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
		DWORD retVal = 0;

		retVal = GetAdaptersInfo(adapterInfo, &outBufLen);
		if (retVal == ERROR_BUFFER_OVERFLOW)
		{
			buffer.resize(outBufLen);
			// Repins the adapter info pointer to the vector data pointer as the vector might be reallocated during the
			// resize.
			adapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
			retVal = GetAdaptersInfo(adapterInfo, &outBufLen);
		}

		if (retVal == NO_ERROR)
		{
			PIP_ADAPTER_INFO curAdapterInfo = adapterInfo;
			while (curAdapterInfo != nullptr)
			{
				if (m_InterfaceDetails.name.find(curAdapterInfo->AdapterName) != std::string::npos)
				{
					try
					{
						m_DefaultGateway = IPv4Address(curAdapterInfo->GatewayList.IpAddress.String);
					}
					catch (const std::exception& e)
					{
						PCPP_LOG_ERROR("Error retrieving default gateway address: " << e.what());
					}
					break;
				}

				curAdapterInfo = curAdapterInfo->Next;
			}
		}
		else
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address");
		}
#elif defined(__linux__)
		std::ifstream routeFile("/proc/net/route");
		std::string line;
		while (std::getline(routeFile, line))
		{
			std::stringstream lineStream(line);
			std::string interfaceName;
			std::getline(lineStream, interfaceName, '\t');
			if (interfaceName != m_InterfaceDetails.name)
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
			try
			{
				m_DefaultGateway = IPv4Address(interfaceGatewayIPInt);
			}
			catch (const std::exception& e)
			{
				PCPP_LOG_ERROR("Error retrieving default gateway address: " << e.what());
			}
		}
#elif defined(__APPLE__)

		// route message struct for communication in APPLE device
		struct BSDRoutingMessage
		{
			struct rt_msghdr header;
			char messageSpace[512];
		};

		struct BSDRoutingMessage routingMessage;
		// It creates a raw socket that can be used for routing-related operations
		int sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
		if (sockfd < 0)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: couldn't get open routing socket");
			return;
		}
		memset(reinterpret_cast<char*>(&routingMessage), 0, sizeof(routingMessage));
		routingMessage.header.rtm_msglen = sizeof(struct rt_msghdr);
		routingMessage.header.rtm_version = RTM_VERSION;
		routingMessage.header.rtm_type = RTM_GET;
		routingMessage.header.rtm_addrs = RTA_DST | RTA_NETMASK;
		routingMessage.header.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
		routingMessage.header.rtm_msglen += 2 * sizeof(sockaddr_in);

		if (write(sockfd, reinterpret_cast<char*>(&routingMessage), routingMessage.header.rtm_msglen) < 0)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: couldn't write into the routing socket");
			return;
		}

		// Read the response from the route socket
		if (read(sockfd, reinterpret_cast<char*>(&routingMessage), sizeof(routingMessage)) < 0)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: couldn't read from the routing socket");
			return;
		}

		struct in_addr* gateAddr = nullptr;
		struct sockaddr* sa = nullptr;
		char* spacePtr = (reinterpret_cast<char*>(&routingMessage.header + 1));
		auto rtmAddrs = routingMessage.header.rtm_addrs;
		int index = 1;
		auto roundUpClosestMultiple = [](int multiple, int num) {
			return ((num + multiple - 1) / multiple) * multiple;
		};
		while (rtmAddrs)
		{
			if (rtmAddrs & 1)
			{
				sa = reinterpret_cast<sockaddr*>(spacePtr);
				if (index == RTA_GATEWAY)
				{
					gateAddr = internal::sockaddr2in_addr(sa);
					break;
				}
				spacePtr += sa->sa_len > 0 ? roundUpClosestMultiple(sizeof(uint32_t), sa->sa_len) : sizeof(uint32_t);
			}
			index++;
			rtmAddrs >>= 1;
		}

		if (gateAddr == nullptr)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: Empty Message related to gate");
			return;
		}
		try
		{
			m_DefaultGateway = IPv4Address(gateAddr->s_addr);
		}
		catch (const std::exception& e)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: " << inet_ntoa(*gateAddr) << ": " << e.what());
		}
#elif defined(__FreeBSD__)
		std::string command = "netstat -nr | grep default | grep " + m_InterfaceDetails.name;
		std::string ifaceInfo = executeShellCommand(command);
		if (ifaceInfo == "")
		{
			PCPP_LOG_DEBUG("Error retrieving default gateway address: couldn't get netstat output");
			return;
		}

		// remove the word "default"
		ifaceInfo.erase(0, 7);

		// remove spaces
		while (ifaceInfo.at(0) == ' ')
			ifaceInfo.erase(0, 1);

		// erase string after gateway IP address
		ifaceInfo.resize(ifaceInfo.find(' ', 0));

		try
		{
			m_DefaultGateway = IPv4Address(ifaceInfo);
		}
		catch (const std::exception& e)
		{
			PCPP_LOG_ERROR("Error retrieving default gateway address: " << ifaceInfo << ": " << e.what());
		}
#endif
	}

	IPv4Address PcapLiveDevice::getIPv4Address() const
	{
		auto const& addresses = m_InterfaceDetails.addresses;
		auto it = std::find_if(addresses.begin(), addresses.end(), [](const IPAddress& addr) { return addr.isIPv4(); });
		return it != addresses.end() ? it->getIPv4() : IPv4Address::Zero;
	}

	IPv6Address PcapLiveDevice::getIPv6Address() const
	{
		auto const& addresses = m_InterfaceDetails.addresses;
		auto it = std::find_if(addresses.begin(), addresses.end(), [](const IPAddress& addr) { return addr.isIPv6(); });
		return it != addresses.end() ? it->getIPv6() : IPv6Address::Zero;
	}

	IPv4Address PcapLiveDevice::getDefaultGateway() const
	{
		return m_DefaultGateway;
	}

	const std::vector<IPv4Address>& PcapLiveDevice::getDnsServers() const
	{
		return PcapLiveDeviceList::getInstance().getDnsServers();
	}

	PcapLiveDevice::~PcapLiveDevice()
	{}

}  // namespace pcpp
