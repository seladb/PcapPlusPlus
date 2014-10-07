#ifndef PCAPPP_DEVICE
#define PCAPPP_DEVICE

#include <RawPacket.h>
#include <PcapFilter.h>
#include <pcap.h>

class IPcapDevice
{
protected:
	pcap_t* m_pPcapDescriptor;
	bool m_DeviceOpened;
public:
	IPcapDevice() { m_DeviceOpened = false; m_pPcapDescriptor = NULL; }
	virtual ~IPcapDevice();
	virtual bool open() = 0;
	virtual void close() = 0;
	virtual void getStatistics(pcap_stat& stats) = 0;
	bool setFilter(GeneralFilter& filter);
	bool setFilter(string filterAsString);
};

#endif
