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

	void WinPcapLiveDevice::prepareCapture(bool asyncCapture, bool captureStats)
	{

		int mode = captureStats ? MODE_STAT : MODE_CAPT;
		int res = pcap_setmode(m_PcapDescriptor.get(), mode);
		if (res < 0)
		{
			throw std::runtime_error("Error setting the mode for device '" + m_InterfaceDetails.name +
			                         "': " + m_PcapDescriptor.getLastError());
		}
	}

	namespace
	{
		struct PcapSendQueueDeleter
		{
			void operator()(pcap_send_queue* ptr) const noexcept
			{
				pcap_sendqueue_destroy(ptr);
			}
		};

		class PcapSendQueue
		{
		public:
			explicit PcapSendQueue(std::uint32_t maxBuffer) : m_Queue(pcap_sendqueue_alloc(maxBuffer))
			{}

			int pushPacket(RawPacket const& packet)
			{
				pcap_pkthdr header;
				header.caplen = packet.getRawDataLen();
				header.len = packet.getRawDataLen();
				header.ts = internal::toTimeval(packet.getPacketTimeStamp());
				int res = pcap_sendqueue_queue(m_Queue.get(), &header, packet.getRawData());
				return res;
			}

			/// @brief Transmits the packets in the send queue through the specified pcap handle.
			/// @param handle The pcap handle to use for transmission.
			/// @return The number of bytes transmitted.
			size_t transmit(pcap_t* handle)
			{
				return pcap_sendqueue_transmit(handle, m_Queue.get(), 0);
			}

			size_t maxSizeBytes() const
			{
				return m_Queue->maxlen;
			}

			size_t sizeBytes() const
			{
				return m_Queue->len;
			}

		private:
			std::unique_ptr<pcap_send_queue, PcapSendQueueDeleter> m_Queue;
		};

		RawPacket const& deref(RawPacket const& p)
		{
			return p;
		}
		RawPacket const& deref(RawPacket const* p)
		{
			return *p;
		}

		template <typename PacketElem>
		int sendPacketBatchByQueue(PacketElem const* packetsArr, int arrLength, internal::PcapHandle& sendHandle)
		{
			if(arrLength <= 0)
			{
				PCPP_LOG_DEBUG("Empty array. No packets to send");
				return 0;
			}

			int dataSize = 0;
			int packetsSent = 0;
			for(int i = 0; i < arrLength; i++)
			{
				dataSize += deref(packetsArr[i]).getRawDataLen();
			}

			auto sendQueue = PcapSendQueue(dataSize + arrLength * sizeof(pcap_pkthdr));
			PCPP_LOG_DEBUG("Allocated send queue of size " << sendQueue.maxSizeBytes());

			for (int i = 0; i < arrLength; i++)
			{
				if (sendQueue.pushPacket(deref(packetsArr[i])) == -1)
				{
					PCPP_LOG_ERROR("pcap_send_queue is too small for all packets. Sending only " << i << " packets");
					break;
				}
				packetsSent++;
			}

			PCPP_LOG_DEBUG(packetsSent << " packets were queued successfully");

			size_t res = sendQueue.transmit(sendHandle.get());
			if (res < sendQueue.sizeBytes())
			{
				PCPP_LOG_ERROR("An error occurred sending the packets: " << sendHandle.getLastError() << ". Only "
				                                                         << res << " bytes were sent");
				packetsSent = 0;
				dataSize = 0;
				for (int i = 0; i < arrLength; i++)
				{
					dataSize += deref(packetsArr[i]).getRawDataLen();
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
	}  // namespace

	int WinPcapLiveDevice::sendPacketBatchUnchecked(RawPacket const* rawPacketsArr, int arrLength)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return 0;
		}

		return sendPacketBatchByQueue(rawPacketsArr, arrLength, m_PcapDescriptor);
	}

	int WinPcapLiveDevice::sendPacketBatchUncheckedIndirect(RawPacket const* const* rawPacketsArr, int arrLength)
	{
		if (!m_DeviceOpened || m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Device '" << m_InterfaceDetails.name << "' not opened");
			return 0;
		}

		return sendPacketBatchByQueue(rawPacketsArr, arrLength, m_PcapDescriptor);
	}

}  // namespace pcpp
