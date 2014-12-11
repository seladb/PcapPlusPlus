#ifndef PCAPPP_DEVICE
#define PCAPPP_DEVICE

#include <RawPacket.h>
#include <PcapFilter.h>
#include <PointerVector.h>
#include <pcap.h>


typedef PointerVector<RawPacket> RawPacketVector;

class IPcapDevice
{
protected:
	pcap_t* m_PcapDescriptor;
	bool m_DeviceOpened;
public:
	IPcapDevice() { m_DeviceOpened = false; m_PcapDescriptor = NULL; }
	virtual ~IPcapDevice();
	virtual bool open() = 0;
	virtual void close() = 0;
	virtual void getStatistics(pcap_stat& stats) = 0;
	bool setFilter(GeneralFilter& filter);
	bool setFilter(string filterAsString);
};

#endif
