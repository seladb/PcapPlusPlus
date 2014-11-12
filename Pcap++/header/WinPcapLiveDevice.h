#ifndef PCAPP_WINPCAP_LIVE_DEVICE
#define PCAPP_WINPCAP_LIVE_DEVICE

#ifdef WIN32

#include <PcapLiveDevice.h>

class WinPcapLiveDevice : public PcapLiveDevice
{
	friend class PcapLiveDeviceList;
protected:
	int m_MinAmountOfDataToCopyFromKernelToApplication;
	//WinPcapLiveDevice();
	WinPcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU);
public:
	virtual LiveDeviceType getDeviceType() { return WinPcapDevice; }

	bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUsrrCookie);
	bool startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);
	bool startCapture(RawPacketVector& rCapturedPacketsVector) { return PcapLiveDevice::startCapture(rCapturedPacketsVector); }

	virtual int sendPackets(RawPacket* rawPacketsArr, int arrLength);

	bool setMinAmountOfDataToCopyFromKernelToApplication(int size);
	int getMinAmountOfDataToCopyFromKernelToApplication() { return m_MinAmountOfDataToCopyFromKernelToApplication; }
};

#endif // WIN32

#endif /* PCAPP_WINPCAP_LIVE_DEVICE */
