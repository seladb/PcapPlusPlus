#define LOG_MODULE PcapLogModuleWinPcapLiveDevice

#include "WinPcapLiveDevice.h"
#include "Logger.h"
#include "TimespecTimeval.h"
#include "pcap.h"

#include <memory>
#include <vector>

namespace pcpp
{

	WinPcapLiveDevice::WinPcapLiveDevice(DeviceInterfaceDetails interfaceDetails, bool calculateMTU,
	                                     bool calculateMacAddress, bool calculateDefaultGateway)
	    : PcapLiveDevice(std::move(interfaceDetails), calculateMTU, calculateMacAddress, calculateDefaultGateway)
	{
		m_MinAmountOfDataToCopyFromKernelToApplication = 16000;
	}

	bool WinPcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie,
	                                     int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
	                                     void* onStatsUpdateUserCookie)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return false;
		}

		// Put the interface in capture mode
		if (pcap_setmode(m_PcapDescriptor.get(), MODE_CAPT) < 0)
		{
			PCPP_LOG_ERROR("Error setting the capture mode for device '" << m_InterfaceDetails.name << "'");
			return false;
		}

		return PcapLiveDevice::startCapture(onPacketArrives, onPacketArrivesUserCookie, intervalInSecondsToUpdateStats,
		                                    onStatsUpdate, onStatsUpdateUserCookie);
	}

	bool WinPcapLiveDevice::startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
	                                     void* onStatsUpdateUserCookie)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return false;
		}

		// Put the interface in statistics mode
		if (pcap_setmode(m_PcapDescriptor.get(), MODE_STAT) < 0)
		{
			PCPP_LOG_ERROR("Error setting the statistics mode for device '" << m_InterfaceDetails.name << "'");
			return false;
		}

		return PcapLiveDevice::startCapture(intervalInSecondsToUpdateStats, onStatsUpdate, onStatsUpdateUserCookie);
	}

	int WinPcapLiveDevice::sendPackets(RawPacket* rawPacketsArr, int arrLength)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return 0;
		}

		int dataSize = 0;
		int packetsSent = 0;
		for (int i = 0; i < arrLength; i++)
			dataSize += rawPacketsArr[i].getRawDataLen();

		struct PcapSendQueueDeleter
		{
			void operator()(pcap_send_queue* ptr) const noexcept
			{
				pcap_sendqueue_destroy(ptr);
			}
		};

		auto sendQueue = std::unique_ptr<pcap_send_queue, PcapSendQueueDeleter>(
		    pcap_sendqueue_alloc(dataSize + arrLength * sizeof(pcap_pkthdr)));
		PCPP_LOG_DEBUG("Allocated send queue of size " << (dataSize + arrLength * sizeof(pcap_pkthdr)));

		std::vector<pcap_pkthdr> packetHeader(arrLength);
		for (int i = 0; i < arrLength; i++)
		{
			packetHeader[i].caplen = rawPacketsArr[i].getRawDataLen();
			packetHeader[i].len = rawPacketsArr[i].getRawDataLen();
			timespec packet_time = rawPacketsArr[i].getPacketTimeStamp();
			TIMESPEC_TO_TIMEVAL(&packetHeader[i].ts, &packet_time);
			if (pcap_sendqueue_queue(sendQueue.get(), &packetHeader[i], rawPacketsArr[i].getRawData()) == -1)
			{
				PCPP_LOG_ERROR("pcap_send_queue is too small for all packets. Sending only " << i << " packets");
				break;
			}
			packetsSent++;
		}

		PCPP_LOG_DEBUG(packetsSent << " packets were queued successfully");

		int res = pcap_sendqueue_transmit(m_PcapDescriptor.get(), sendQueue.get(), 0);
		if (res < static_cast<int>(sendQueue->len))
		{
			PCPP_LOG_ERROR("An error occurred sending the packets: " << m_PcapDescriptor.getLastError() << ". Only "
			                                                         << res << " bytes were sent");
			packetsSent = 0;
			dataSize = 0;
			for (int i = 0; i < arrLength; i++)
			{
				dataSize += rawPacketsArr[i].getRawDataLen();
				if (dataSize > res)
				{
					return packetsSent;
				}
				packetsSent++;
			}
			return packetsSent;
		}
		PCPP_LOG_DEBUG("Packets were sent successfully");

		return packetsSent;
	}

	bool WinPcapLiveDevice::setMinAmountOfDataToCopyFromKernelToApplication(int size)
	{
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device not opened");
			return false;
		}

		if (pcap_setmintocopy(m_PcapDescriptor.get(), size) != 0)
		{
			PCPP_LOG_ERROR("pcap_setmintocopy failed");
			return false;
		}
		m_MinAmountOfDataToCopyFromKernelToApplication = size;
		return true;
	}

	WinPcapLiveDevice* WinPcapLiveDevice::clone() const
	{
		return new WinPcapLiveDevice(m_InterfaceDetails, true, true, true);
	}

}  // namespace pcpp
