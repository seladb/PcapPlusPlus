#ifndef PCAPP_PCAP_REMOTE_DEVICE_LIST
#define PCAPP_PCAP_REMOTE_DEVICE_LIST

#ifdef WIN32

#include <IpAddress.h>
#include <PcapRemoteDevice.h>

class PcapRemoteDeviceList : public vector<PcapRemoteDevice*>
{
private:
	string m_RemoteMachineIpAddress;
	uint16_t m_RemoteMachinePort;
	pcap_rmtauth* m_RemoteAuthentication;
public:
	~PcapRemoteDeviceList();

	static const bool getRemoteDeviceList(string ipAddress, uint16_t port, PcapRemoteDeviceList& resultList);
	static const bool getRemoteDeviceList(string ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth, PcapRemoteDeviceList& resultList);

	string getRemoteMachineIpAddress() { return m_RemoteMachineIpAddress; }
	uint16_t getRemoteMachinePort() { return m_RemoteMachinePort; }

	PcapRemoteDevice* getRemoteDeviceByIP(IPv4Address ip4Addr);
	PcapRemoteDevice* getRemoteDeviceByIP(IPv6Address ip6Addr);
	PcapRemoteDevice* getRemoteDeviceByIP(IPAddress* ipAddr);
	PcapRemoteDevice* getRemoteDeviceByIP(const char* ipAddrAsString);
};

#endif // WIN32

#endif /* PCAPP_PCAP_REMOTE_DEVICE_LIST */
