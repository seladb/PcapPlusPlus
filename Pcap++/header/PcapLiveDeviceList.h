#ifndef PCAPPP_LIVE_DEVICE_LIST
#define PCAPPP_LIVE_DEVICE_LIST

#include <IpAddress.h>
#include <PcapLiveDevice.h>
#include <WinPcapLiveDevice.h>
#include <vector>

using namespace std;

class PcapLiveDeviceList
{
private:
	static bool m_IsInitialized;
	static vector<PcapLiveDevice*> m_xLiveDeviceList;
public:
	static const vector<PcapLiveDevice*>& getPcapLiveDevicesList();
	static PcapLiveDevice* getPcapLiveDeviceByIp(IPAddress* pIPAddr);
	static PcapLiveDevice* getPcapLiveDeviceByIp(IPv4Address ipAddr);
	static PcapLiveDevice* getPcapLiveDeviceByIp(IPv6Address ip6Addr);
	static PcapLiveDevice* getPcapLiveDeviceByIp(const char* ipAddrAsString);
};

#endif
