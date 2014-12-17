//TODO: replace all these defines with #pragma once
#ifndef PCAPPP_LIVE_DEVICE
#define PCAPPP_LIVE_DEVICE

#include <PcapDevice.h>
#include <vector>
#include <string.h>
#include "IpAddress.h"
#include <Packet.h>

using namespace std;

class PcapLiveDevice;

typedef void (*OnPacketArrivesCallback)(RawPacket* pPacket, PcapLiveDevice* pDevice, void* userCookie);
typedef void (*OnStatsUpdateCallback)(pcap_stat& stats, void* userCookie);

typedef void* (*ThreadStart)(void*);

struct PcapThread;

class PcapLiveDevice : public IPcapDevice
{
	friend class PcapLiveDeviceList;
protected:
	// This is a second descriptor for the same device. It is needed because of a bug
	// that occurs in libpcap on Linux (on Windows using WinPcap it works well):
	// It's impossible to capture packets sent by the same descriptor
	pcap_t* m_PcapSendDescriptor;
	const char* m_Name;
	const char* m_Description;
	bool m_IsLoopback;
	uint16_t m_DeviceMtu;
	vector<pcap_addr_t> m_Addresses;
	MacAddress m_MacAddress;
	PcapThread* m_CaptureThread;
	bool m_CaptureThreadStarted;
	PcapThread* m_StatsThread;
	bool m_StatsThreadStarted;
	bool m_StopThread;
	OnPacketArrivesCallback m_cbOnPacketArrives;
	void* m_cbOnPacketArrivesUserCookie;
	OnStatsUpdateCallback m_cbOnStatsUpdate;
	void* m_cbOnStatsUpdateUserCookie;
	int m_IntervalToUpdateStats;
	RawPacketVector* m_CapturedPackets;
	bool m_CaptureCallbackMode;

	// c'tor is not public, there should be only one for every interface (created by PcapLiveDeviceList)
	PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU);
	// copy c'tor is not public
	PcapLiveDevice( const PcapLiveDevice& other );
	PcapLiveDevice& operator=(const PcapLiveDevice& other);

	void setDeviceMtu();
	void setDeviceMacAddress();
	static void* captureThreadMain(void *ptr);
	static void* statsThreadMain(void *ptr);
	static void onPacketArrives(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
	static void onPacketArrivesNoCallback(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
	string printThreadId(PcapThread* id);
	virtual ThreadStart getCaptureThreadStart();
public:
	enum LiveDeviceType {
		LibPcapDevice,
		WinPcapDevice
	};

	enum DeviceMode {
		Normal = 0,
		Promiscuous = 1
	};

	~PcapLiveDevice();

	virtual LiveDeviceType getDeviceType() { return LibPcapDevice; }
	inline const char* getName() { return m_Name; }
	inline const char* getDesc() { return m_Description; }
	inline bool getLoopback() { return m_IsLoopback; }
	inline uint16_t getMtu() { return m_DeviceMtu; }
	inline vector<pcap_addr_t>& getAddresses() { return m_Addresses; }
	inline MacAddress getMacAddress() { return m_MacAddress; }
	IPv4Address getIPv4Address();

	virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie);
	virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);
	virtual bool startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);
	virtual bool startCapture(RawPacketVector& capturedPacketsVector);
	void stopCapture();
	bool sendPacket(RawPacket const& rawPacket);
	bool sendPacket(const uint8_t* packetData, int packetDataLength);
	bool sendPacket(Packet* packet);
	virtual int sendPackets(RawPacket* rawPacketsArr, int arrLength);
	virtual int sendPackets(Packet** packetsArr, int arrLength);
	virtual int sendPackets(const RawPacketVector& rawPackets);

	//override methods

	bool open();
	void close();
	virtual void getStatistics(pcap_stat& stats);

	bool open(DeviceMode mode);
};

#endif
