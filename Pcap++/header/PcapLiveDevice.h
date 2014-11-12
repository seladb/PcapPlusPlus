//TODO: replace all these defines with #pragma once
#ifndef PCAPPP_LIVE_DEVICE
#define PCAPPP_LIVE_DEVICE

#include <PcapDevice.h>
#include <vector>
#include <string.h>
#include "IpAddress.h"
#include <Packet.h>
#include "PointerVector.h"

using namespace std;

class PcapLiveDevice;

typedef void (*OnPacketArrivesCallback)(RawPacket* pPacket, PcapLiveDevice* pDevice, void* userCookie);
typedef void (*OnStatsUpdateCallback)(pcap_stat& stats, void* userCookie);

typedef void* (*ThreadStart)(void*);

typedef PointerVector<RawPacket> RawPacketVector;

struct PcapThread;

class PcapLiveDevice : public IPcapDevice
{
	friend class PcapLiveDeviceList;
protected:
	const char* m_pName;
	const char* m_pDescription;
	bool m_IsLoopback;
	uint16_t m_DeviceMtu;
	vector<pcap_addr_t> m_xAddresses;
	MacAddress m_xMacAddress;
	PcapThread* m_pCaptureThread;
	bool m_CaptureThreadStarted;
	PcapThread* m_pStatsThread;
	bool m_StatsThreadStarted;
	bool m_StopThread;
	OnPacketArrivesCallback m_cbOnPacketArrives;
	void* m_cbOnPacketArrivesUserCookie;
	OnStatsUpdateCallback m_cbOnStatsUpdate;
	void* m_cbOnStatsUpdateUserCookie;
	int m_IntervalToUpdateStats;
	RawPacketVector* m_pCapturedPackets;
	bool m_CaptureCallbackMode;

	PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU);
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
	inline const char* getName() { return m_pName; }
	inline const char* getDesc() { return m_pDescription; }
	inline bool getLoopback() { return m_IsLoopback; }
	inline uint16_t getMtu() { return m_DeviceMtu; }
	inline vector<pcap_addr_t>& getAddresses() { return m_xAddresses; }
	inline MacAddress getMacAddress() { return m_xMacAddress; }
	IPv4Address getIPv4Address();

	virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie);
	virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);
	virtual bool startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);
	virtual bool startCapture(RawPacketVector& rCpapturedPacketsVector);
	void stopCapture();
	bool sendPacket(RawPacket const& rawPacket);
	bool sendPacket(const uint8_t* packetData, int packetDataLength);
	bool sendPacket(Packet* packet);
	virtual int sendPackets(RawPacket* rawPacketsArr, int arrLength);
	virtual int sendPackets(Packet** packetsArr, int arrLength);

	//override methods

	bool open();
	void close();
	virtual void getStatistics(pcap_stat& stats);

	bool open(DeviceMode mode);
};

#endif
