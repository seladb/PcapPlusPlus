//TODO: replace all these defines with #pragma once
#ifndef PCAPPP_LIVE_DEVICE
#define PCAPPP_LIVE_DEVICE

#include "PcapDevice.h"
#include <vector>
#include <string.h>
#include "IpAddress.h"
#include "Packet.h"


/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	class PcapLiveDevice;

	/**
	 * @typedef OnPacketArrivesCallback
	 * A callback that is called when a packet is captured by PcapLiveDevice
	 * @param[in] pPacket A pointer to the raw packet
	 * @param[in] pDevice A pointer to the PcapLiveDevice instance
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 */
	typedef void (*OnPacketArrivesCallback)(RawPacket* pPacket, PcapLiveDevice* pDevice, void* userCookie);

	/**
	 * @typedef OnPacketArrivesStopBlocking
	 * A callback that is called when a packet is captured by PcapLiveDevice
	 * @param[in] pPacket A pointer to the raw packet
	 * @param[in] pDevice A pointer to the PcapLiveDevice instance
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 * @return True when main thread should stop blocking or false otherwise
	 */
	typedef bool (*OnPacketArrivesStopBlocking)(RawPacket* pPacket, PcapLiveDevice* pDevice, void* userData);


	/**
	 * @typedef OnStatsUpdateCallback
	 * A callback that is called periodically for stats collection if user asked to start packet capturing with periodic stats collection
	 * @param[in] stats A reference to the most updated stats
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 */
	typedef void (*OnStatsUpdateCallback)(pcap_stat& stats, void* userCookie);

	// for internal use only
	typedef void* (*ThreadStart)(void*);

	struct PcapThread;

	/**
	 * @class PcapLiveDevice
	 * A class that wraps a network interface (each of the interfaces listed in ifconfig/ipconfig).
	 * This class wraps the libpcap capabilities of capturing packets from the network, filtering packets and sending packets back to the network.
	 * This class is relevant for Linux applications only. On Windows the WinPcapLiveDevice (which inherits this class) is used. Both classes are
	 * almost similar in capabilities, the main difference between them is adapting some capabilities to the specific OS.
	 * This class cannot be instantiated by the user (it has a private constructor), as network interfaces aren't dynamic. Instances of
	 * this class (one instance per network interface) are created by PcapLiveDeviceList singleton on application startup and the user can get
	 * access to them by using PcapLiveDeviceList public methods such as PcapLiveDeviceList#getPcapLiveDeviceByIp()<BR>
	 * Main capabilities of this class:
	 * - Get all available information for this network interfaces such as name, IP addresses, MAC address, MTU, etc. This information is taken
	 * from both libpcap and the OS
	 * - Capture packets from the network. Capturing is always conducted on a different thread. PcapPlusPlus creates this
	 * thread when capturing starts and kills it when capturing ends. This prevents the application from being stuck while waiting for packets or
	 * processing them. Currently only one capturing thread is allowed, so when the interface is in capture mode, no further capturing is allowed.
	 * In addition to capturing the user can get stats on packets that were received by the application, dropped by the NIC (due to full
	 * NIC buffers), etc. Stats collection can be initiated by the user by calling getStatistics() or be pushed to the user periodically by
	 * supplying a callback and a timeout to startCapture()
	 * - Send packets back to the network. Sending the packets is done on the caller thread. No additional threads are created for this task
	 */
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
		std::vector<pcap_addr_t> m_Addresses;
		MacAddress m_MacAddress;
		IPv4Address m_DefaultGateway;
		PcapThread* m_CaptureThread;
		bool m_CaptureThreadStarted;
		PcapThread* m_StatsThread;
		bool m_StatsThreadStarted;
		bool m_StopThread;
		OnPacketArrivesCallback m_cbOnPacketArrives;
		void* m_cbOnPacketArrivesUserCookie;
		OnStatsUpdateCallback m_cbOnStatsUpdate;
		void* m_cbOnStatsUpdateUserCookie;
		OnPacketArrivesStopBlocking m_cbOnPacketArrivesBlockingMode;
		void* m_cbOnPacketArrivesBlockingModeUserCookie;
		int m_IntervalToUpdateStats;
		RawPacketVector* m_CapturedPackets;
		bool m_CaptureCallbackMode;

		// c'tor is not public, there should be only one for every interface (created by PcapLiveDeviceList)
		PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway);
		// copy c'tor is not public
		PcapLiveDevice( const PcapLiveDevice& other );
		PcapLiveDevice& operator=(const PcapLiveDevice& other);

		void setDeviceMtu();
		void setDeviceMacAddress();
		void setDefaultGateway();
		static void* captureThreadMain(void *ptr);
		static void* statsThreadMain(void *ptr);
		static void onPacketArrives(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
		static void onPacketArrivesNoCallback(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
		static void onPacketArrivesBlockingMode(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
		std::string printThreadId(PcapThread* id);
		virtual ThreadStart getCaptureThreadStart();
	public:
		/**
		 * The type of the live device
		 */
		enum LiveDeviceType {
			/** libPcap live device */
			LibPcapDevice,
			/** WinPcap live device */
			WinPcapDevice,
			/** WinPcap Remote Capture device */
			RemoteDevice
		};

		/**
		 * Device capturing mode
		 */
		enum DeviceMode {
			/** Only packets that their destination is this NIC are captured */
			Normal = 0,
			/** All packets that arrive to the NIC are captured, even packets that their destination isn't this NIC */
			Promiscuous = 1
		};

		/**
		 * A destructor for this class
		 */
		virtual ~PcapLiveDevice();

		/**
		 * @return The type of the device (libPcap, WinPcap or a remote device)
		 */
		virtual LiveDeviceType getDeviceType() { return LibPcapDevice; }

		/**
		 * @return The name of the device (e.g eth0), taken from pcap_if_t->name
		 */
		inline const char* getName() { return m_Name; }

		/**
		 * @return A human-readable description of the device, taken from pcap_if_t->description. May be NULL in some interfaces
		 */
		inline const char* getDesc() { return m_Description; }

		/**
		 * @return True if this interface is a loopback interface, false otherwise
		 */
		inline bool getLoopback() { return m_IsLoopback; }

		/**
		 * @return The device's maximum transmission unit (MTU) in bytes
		 */
		virtual inline uint16_t getMtu() { return m_DeviceMtu; }

		/**
		 * @return A vector containing all addresses defined for this interface, each in pcap_addr_t struct
		 */
		inline std::vector<pcap_addr_t>& getAddresses() { return m_Addresses; }

		/**
		 * @return The MAC address for this interface
		 */
		virtual inline MacAddress getMacAddress() { return m_MacAddress; }

		/**
		 * @return The IPv4 address for this interface. If multiple IPv4 addresses are defined for this interface, the first will be picked.
		 * If no IPv4 addresses are defined, a zeroed IPv4 address (IPv4Address#Zero) will be returned
		 */
		IPv4Address getIPv4Address();

		/**
		 * @return The default gateway defined for this interface. If no default gateway is defined, if it's not IPv4 or if couldn't extract
		 * default gateway IPv4Address#Zero will be returned. If multiple gateways were defined the first one will be returned
		 */
		IPv4Address getDefaultGateway();

		/**
		 * @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers were defined or they
		 * couldn't be extracted from some reason. This list is created in PcapLiveDeviceList class and can be also retrieved from there.
		 * This method exists for convenience - so it'll be possible to get this list from PcapLiveDevice as well
		 */
		std::vector<IPv4Address>& getDnsServers();

		/**
		 * Start capturing packets on this network interface (device). Each time a packet is captured the onPacketArrives callback is called.
		 * The capture is done on a new thread created by this method, meaning all callback calls are done in a thread other than the
		 * caller thread. Capture process will stop and this capture thread will be terminated when calling stopCapture(). This method must be
		 * called after the device is opened (i.e the open() method was called), otherwise an error will be returned.
		 * @param[in] onPacketArrives A callback that is called each time a packet is captured
		 * @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to the onPacketArrives callback
		 * each time it is called. This cookie is very useful for transferring objects that give context to the capture callback, for example:
		 * objects that counts packets, manages flow state or manages the application state according to the packet that was captured
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 */
		virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie);

		/**
		 * Start capturing packets on this network interface (device) with periodic stats collection. Each time a packet is captured the onPacketArrives
		 * callback is called. In addition, each intervalInSecondsToUpdateStats seconds stats are collected from the device and the onStatsUpdate
		 * callback is called. Both the capture and periodic stats collection are done on new threads created by this method, each on a different thread,
		 * meaning all callback calls are done in threads other than the caller thread. Capture process and stats collection will stop and threads will be
		 * terminated when calling stopCapture(). This method must be called after the device is opened (i.e the open() method was called), otherwise an
		 * error will be returned.
		 * @param[in] onPacketArrives A callback that is called each time a packet is captured
		 * @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to the onPacketArrives callback
		 * each time it is called. This cookie is very useful for transferring objects that give context to the capture callback, for example:
		 * objects that counts packets, manages flow state or manages the application state according to the packet that was captured
		 * @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		 * @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and stats are collected. This
		 * callback will contain the collected stats
		 * @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to the onStatsUpdate callback
		 * each time it is called
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 * - Stats collection thread could not be created
		 */
		virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie, int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);

		/**
		 * Start capturing packets on this network interface (device) with periodic stats collection only. This means that packets arriving to the
		 * network interface aren't delivered to the user but only counted. Each intervalInSecondsToUpdateStats seconds stats are collected from the
		 * device and the onStatsUpdate callback is called with the updated counters. The periodic stats collection is done on a new thread created
		 * by this method, meaning all callback calls are done in threads other than the caller thread. Stats collection will stop and threads will
		 * be terminated when calling stopCapture(). This method must be called after the device is opened (i.e the open() method was called),
		 * otherwise an error will be returned.
		 * @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		 * @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and stats are collected. This
		 * callback will contain the collected stats
		 * @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to the onStatsUpdate callback
		 * each time it is called
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Stats collection thread could not be created
		 */
		virtual bool startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate, void* onStatsUpdateUserCookie);

		/**
		 * Start capturing packets on this network interface (device). All captured packets are added to capturedPacketsVector, so at the end of
		 * the capture (when calling stopCapture()) this vector contains pointers to all captured packets in the form of RawPacket. The capture
		 * is done on a new thread created by this method, meaning capturedPacketsVector is updated from another thread other than the caller
		 * thread (so user should avoid changing or iterating this vector while capture is on). Capture process will stop and this capture thread
		 * will be terminated when calling stopCapture(). This method must be called after the device is opened (i.e the open() method was called),
		 * otherwise an error will be returned.
		 * @param[in] capturedPacketsVector A reference to a RawPacketVector, meaning a vector of pointer to RawPacket objects
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 */
		virtual bool startCapture(RawPacketVector& capturedPacketsVector);

		/**
		 * Start capturing packets on this network interface (device) in blocking mode, meaning this method blocks and won't return until
		 * the user frees the blocking (via onPacketArrives callback) or until a user defined timeout expires.
		 * Whenever a packets is captured the onPacketArrives callback is called and lets the user handle the packet. In each callback call
		 * the user should return true if he wants to release the block or false if it wants it to keep blocking. Regardless of this callback
		 * a timeout is defined when start capturing. When this timeout expires the method will return.<BR>
		 * Please notice that stopCapture() isn't needed here because when the method returns (after timeout or per user decision) capturing
		 * on the device is stopped
		 * @param[in] onPacketArrives A callback given by the user for handling incoming packets. After handling each packet the user needs to
		 * return a boolean value. True value indicates stop capturing and stop blocking and false value indicates continue capturing and blocking
		 * @param[in] userCookie A pointer to a user provided object. This object will be transferred to the onPacketArrives callback
		 * each time it is called. This cookie is very useful for transferring objects that give context to the capture callback, for example:
		 * objects that counts packets, manages flow state or manages the application state according to the packet that was captured
		 * @param[in] timeout A timeout in seconds for the blocking to stop even if the user didn't return "true" in the onPacketArrives callback
		 * If this timeout is set to 0 or less the timeout will be ignored, meaning the method will keep blocking until the user frees it via
		 * the onPacketArrives callback
		 * @return -1 if timeout expired, 1 if blocking was stopped via onPacketArrives callback or 0 if an error occurred (such as device
		 * not open etc.). When returning 0 an appropriate error message is printed to log
		 */
		virtual int startCaptureBlockingMode(OnPacketArrivesStopBlocking onPacketArrives, void* userCookie, int timeout);

		/**
		 * Stop a currently running packet capture. This method terminates gracefully both packet capture thread and periodic stats collection
		 * thread (both if exist)
		 */
		void stopCapture();

		/**
		 * Send a RawPacket to the network
		 * @param[in] rawPacket A reference to the raw packet to send. This method treats the raw packet as read-only, it doesn't change anything
		 * in it
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		bool sendPacket(RawPacket const& rawPacket);

		/**
		 * Send a buffer containing packet raw data (including all layers) to the network
		 * @param[in] packetData The buffer containing the packet raw data
		 * @param[in] packetDataLength The length of the buffer
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		bool sendPacket(const uint8_t* packetData, int packetDataLength);

		/**
		 * Send a parsed Packet to the network
		 * @param[in] packet A pointer to the packet to send. This method treats the packet as read-only, it doesn't change anything in it
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		bool sendPacket(Packet* packet);

		/**
		 * Send an array of RawPacket objects to the network
		 * @param[in] rawPacketsArr The array of RawPacket objects to send. This method treats all packets as read-only, it doesn't change anything
		 * in them
		 * @param[in] arrLength The length of the array
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		virtual int sendPackets(RawPacket* rawPacketsArr, int arrLength);

		/**
		 * Send an array of pointers to Packet objects to the network
		 * @param[in] packetsArr The array of pointers to Packet objects to send. This method treats all packets as read-only, it doesn't change
		 * anything in them
		 * @param[in] arrLength The length of the array
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		virtual int sendPackets(Packet** packetsArr, int arrLength);

		/**
		 * Send a vector of pointers to RawPacket objects to the network
		 * @param[in] rawPackets The array of pointers to RawPacket objects to send. This method treats all packets as read-only, it doesn't change
		 * anything in them
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap
		 */
		virtual int sendPackets(const RawPacketVector& rawPackets);

		//override methods

		/**
		 * Open the device using libpcap pcap_open_live. Opening the device only makes the device ready for use, it doesn't start packet capturing.
		 * For packet capturing the user should call startCapture(). This implies that calling this method is a must before calling startCapture()
		 * (otherwise startCapture() will fail with a "device not open" error). The device is opened in promiscuous mode
		 * @return True if the device was opened successfully, false otherwise. When opening the device fails an error will be printed to log
		 * as well
		 */
		bool open();

		void close();

		virtual void getStatistics(pcap_stat& stats);

		/**
		 * Same as open(), but enables to open the device in normal or promiscuous mode
		 * @param[in] mode Normal or promiscuous mode
		 * @return Same as open()
		 */
		bool open(DeviceMode mode);
	protected:
		pcap_t* doOpen(DeviceMode mode);
	};

} // namespace pcpp

#endif
