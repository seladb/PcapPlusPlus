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
	vector<PcapLiveDevice*> m_xLiveDeviceList;
	PcapLiveDeviceList();
	~PcapLiveDeviceList();
public:
	static inline PcapLiveDeviceList& getInstance()
	{
		static PcapLiveDeviceList instance;
		return instance;
	}

	inline const vector<PcapLiveDevice*>& getPcapLiveDevicesList() { return m_xLiveDeviceList; }
	PcapLiveDevice* getPcapLiveDeviceByIp(IPAddress* pIPAddr);
	PcapLiveDevice* getPcapLiveDeviceByIp(IPv4Address ipAddr);
	PcapLiveDevice* getPcapLiveDeviceByIp(IPv6Address ip6Addr);
	PcapLiveDevice* getPcapLiveDeviceByIp(const char* ipAddrAsString);
};

#endif
