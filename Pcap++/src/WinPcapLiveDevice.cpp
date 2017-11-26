#if defined(WIN32) || defined(WINx64)

#define LOG_MODULE PcapLogModuleWinPcapLiveDevice

#include "WinPcapLiveDevice.h"
#include "Logger.h"

namespace pcpp
{

WinPcapLiveDevice::WinPcapLiveDevice(pcap_if_t* iface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway) : PcapLiveDevice(iface, calculateMTU, calculateMacAddress, calculateDefaultGateway)
{
	m_MinAmountOfDataToCopyFromKernelToApplication = 16000;
}

bool WinPcapLiveDevice::startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUsrrCookie)
{
    //Put the interface in capture mode
    if (pcap_setmode(m_PcapDescriptor, MODE_CAPT) < 0)
    {
        LOG_ERROR("Error setting the capture mode for device '%s'", m_Name);
        return false;
    }

    return PcapLiveDevice::startCapture(onPacketArrives, onPacketArrivesUserCookie, intervalInSecondsToUpdateStats, onStatsUpdate, onStatsUpdateUsrrCookie);
}

bool WinPcapLiveDevice::startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie)
{
    //Put the interface in statistics mode
    if (pcap_setmode(m_PcapDescriptor, MODE_STAT) < 0)
    {
        LOG_ERROR("Error setting the statistics mode for device '%s'", m_Name);
        return false;
    }

    return PcapLiveDevice::startCapture(intervalInSecondsToUpdateStats, onStatsUpdate, onStatsUpdateUserCookie);
}

int WinPcapLiveDevice::sendPackets(RawPacket* rawPacketsArr, int arrLength)
{
	int dataSize = 0;
	int packetsSent = 0;
	for (int i = 0; i < arrLength; i++)
		dataSize += rawPacketsArr[i].getRawDataLen();

	pcap_send_queue* sendQueue = pcap_sendqueue_alloc(dataSize + arrLength*sizeof(pcap_pkthdr));
	LOG_DEBUG("Allocated send queue of size %d", dataSize + arrLength*sizeof(pcap_pkthdr));
	struct pcap_pkthdr* packetHeader = new struct pcap_pkthdr[arrLength];
	for (int i = 0; i < arrLength; i++)
	{
		packetHeader[i].caplen = rawPacketsArr[i].getRawDataLen();
		packetHeader[i].len = rawPacketsArr[i].getRawDataLen();
		packetHeader[i].ts = rawPacketsArr[i].getPacketTimeStamp();
		if (pcap_sendqueue_queue(sendQueue, &packetHeader[i], rawPacketsArr[i].getRawData()) == -1)
		{
			LOG_ERROR("pcap_send_queue is too small for all packets. Sending only %d packets", i);
			break;
		}
		packetsSent++;
	}
	
	LOG_DEBUG("%d packets were queued successfully", packetsSent);

	int res;
	if ((res = pcap_sendqueue_transmit(m_PcapDescriptor, sendQueue, 0)) < (int)(sendQueue->len))
    {
        LOG_ERROR("An error occurred sending the packets: %s. Only %d bytes were sent\n", pcap_geterr(m_PcapDescriptor), res);
        packetsSent = 0;
        dataSize = 0;
    	for (int i = 0; i < arrLength; i++)
    	{
    		dataSize += rawPacketsArr[i].getRawDataLen();
    		//printf("dataSize = %d\n", dataSize);
    		if (dataSize > res)
    		{
    			return packetsSent;
    		}
    		packetsSent++;
    	}
    	return packetsSent;
    }
	LOG_DEBUG("Packets were sent successfully");

	pcap_sendqueue_destroy(sendQueue);
	LOG_DEBUG("Send queue destroyed");

	delete[] packetHeader;
	return packetsSent;
}

bool WinPcapLiveDevice::setMinAmountOfDataToCopyFromKernelToApplication(int size)
{
	if (!m_DeviceOpened)
	{
		LOG_ERROR("Device not opened");
		return false;
	}

	if (pcap_setmintocopy(m_PcapDescriptor, size) != 0)
	{
		LOG_ERROR("pcap_setmintocopy failed");
		return false;
	}
	m_MinAmountOfDataToCopyFromKernelToApplication = size;
	return true;
}

} // namespace pcpp

#endif // WIN32 || WINx64
