#ifndef PCAPPP_PCAP_REMOTE_DEVICE
#define PCAPPP_PCAP_REMOTE_DEVICE

#ifdef WIN32

#include <vector>
#include <PcapLiveDevice.h>

using namespace std;

struct pcap_rmtauth;

struct PcapRemoteAuthentication
{
	PcapRemoteAuthentication(const char* username, const char* passwd) { userName = (char*)username; password = (char*)passwd; }
	char* userName;
	char* password;
};

class PcapRemoteDevice : public PcapLiveDevice
{
	friend class PcapRemoteDeviceList;
private:
	string m_RemoteMachineIpAddress;
	uint16_t m_RemoteMachinePort;
	pcap_rmtauth* m_RemoteAuthentication;

	// c'tor is not public, there should be only one for every remote interface (created by PcapRemoteDeviceList)
	PcapRemoteDevice(pcap_if_t* iface, pcap_rmtauth* remoteAuthentication);
	// copy c'tor is not public
	PcapRemoteDevice( const PcapRemoteDevice& other );
	PcapRemoteDevice& operator=(const PcapRemoteDevice& other);


	static void* remoteDeviceCaptureThreadMain(void *ptr);

	//overridden methods
	ThreadStart getCaptureThreadStart();
public:
	virtual ~PcapRemoteDevice();

	string getRemoteMachineIpAddress() { return m_RemoteMachineIpAddress; }
	uint16_t getRemoteMachinePort() { return m_RemoteMachinePort; }

	//overridden methods
	virtual bool open();
	void getStatistics(pcap_stat& stats);
};

#endif // WIN32

#endif /* PCAPPP_PCAP_REMOTE_DEVICE */
