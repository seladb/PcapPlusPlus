#pragma once

#include <atomic>
#include <vector>
#include <thread>
#include <functional>

#include "IpAddress.h"
#include "PcapDevice.h"

// forward declarations for structs and typedefs that are defined in pcap.h
struct pcap_if;
typedef pcap_if pcap_if_t;
struct pcap_addr;
typedef struct pcap_addr pcap_addr_t;

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class PcapLiveDevice;

	/// A callback that is called when a packet is captured by PcapLiveDevice
	/// @param[in] packet A pointer to the raw packet
	/// @param[in] device A pointer to the PcapLiveDevice instance
	/// @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	using OnPacketArrivesCallback = std::function<void(RawPacket*, PcapLiveDevice*, void*)>;

	/// A callback that is called when a packet is captured by PcapLiveDevice
	/// @param[in] packet A pointer to the raw packet
	/// @param[in] device A pointer to the PcapLiveDevice instance
	/// @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	/// @return True when main thread should stop blocking or false otherwise
	using OnPacketArrivesStopBlocking = std::function<bool(RawPacket*, PcapLiveDevice*, void*)>;

	/// A callback that is called periodically for stats collection if user asked to start packet capturing with
	/// periodic stats collection
	/// @param[in] stats A reference to the most updated stats
	/// @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	using OnStatsUpdateCallback = std::function<void(IPcapDevice::PcapStats&, void*)>;

	/// @class PcapLiveDevice
	/// A class that wraps a network interface (each of the interfaces listed in ifconfig/ipconfig).
	/// This class wraps the libpcap capabilities of capturing packets from the network, filtering packets and sending
	/// packets back to the network. This class is relevant for Linux applications only. On Windows the
	/// WinPcapLiveDevice (which inherits this class) is used. Both classes are almost similar in capabilities, the main
	/// difference between them is adapting some capabilities to the specific OS. This class cannot be instantiated by
	/// the user (it has a private constructor), as network interfaces aren't dynamic. Instances of this class (one
	/// instance per network interface) are created by PcapLiveDeviceList singleton on application startup and the user
	/// can get access to them by using PcapLiveDeviceList public methods such as
	/// PcapLiveDeviceList#getPcapLiveDeviceByIp()<BR> Main capabilities of this class:
	/// - Get all available information for this network interfaces such as name, IP addresses, MAC address, MTU, etc.
	///   This information is taken from both libpcap and the OS
	/// - Capture packets from the network. Capturing is always conducted on a different thread. PcapPlusPlus creates
	///   this thread when capturing starts and kills it when capturing ends. This prevents the application from being
	///   stuck while waiting for packets or processing them. Currently only one capturing thread is allowed, so when
	///   the interface is in capture mode, no further capturing is allowed. In addition to capturing the user can get
	///   stats on packets that were received by the application, dropped by the NIC (due to full NIC buffers), etc.
	///   Stats collection can be initiated by the user by calling getStatistics() or be pushed to the user periodically
	///   by supplying a callback and a timeout to startCapture()
	/// - Send packets back to the network. Sending the packets is done on the caller thread. No additional threads are
	///   created for this task
	class PcapLiveDevice : public IPcapDevice
	{
		friend class PcapLiveDeviceList;

	protected:
		/// @struct DeviceInterfaceDetails
		/// @brief A struct that contains all details of a network interface.
		struct DeviceInterfaceDetails
		{
			explicit DeviceInterfaceDetails(pcap_if_t* pInterface);
			/// @brief Name of the device.
			std::string name;
			/// @brief Description of the device.
			std::string description;
			/// @brief IP addresses associated with the device.
			std::vector<IPAddress> addresses;
			/// @brief Flag to indicate if the device is a loopback device.
			bool isLoopback;
		};

		// This is a second descriptor for the same device. It is needed because of a bug
		// that occurs in libpcap on Linux (on Windows using WinPcap/Npcap it works well):
		// It's impossible to capture packets sent by the same descriptor
		pcap_t* m_PcapSendDescriptor;
		int m_PcapSelectableFd;
		DeviceInterfaceDetails m_InterfaceDetails;
		// NOTE@Dimi: Possibly pull mtu, mac address and default gateway in the interface details.
		// They only appear to be set in the constructor and not modified afterwards.
		uint32_t m_DeviceMtu;
		MacAddress m_MacAddress;
		IPv4Address m_DefaultGateway;
		std::thread m_CaptureThread;
		std::thread m_StatsThread;
		bool m_StatsThreadStarted;

		// Should be set to true by the Caller for the Callee
		std::atomic<bool> m_StopThread;
		// Should be set to true by the Callee for the Caller
		std::atomic<bool> m_CaptureThreadStarted;

		OnPacketArrivesCallback m_cbOnPacketArrives;
		void* m_cbOnPacketArrivesUserCookie;
		OnStatsUpdateCallback m_cbOnStatsUpdate;
		void* m_cbOnStatsUpdateUserCookie;
		OnPacketArrivesStopBlocking m_cbOnPacketArrivesBlockingMode;
		void* m_cbOnPacketArrivesBlockingModeUserCookie;
		int m_IntervalToUpdateStats;
		RawPacketVector* m_CapturedPackets;
		bool m_CaptureCallbackMode;
		LinkLayerType m_LinkType;
		bool m_UsePoll;

		// c'tor is not public, there should be only one for every interface (created by PcapLiveDeviceList)
		PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway)
		    : PcapLiveDevice(DeviceInterfaceDetails(pInterface), calculateMTU, calculateMacAddress,
		                     calculateDefaultGateway)
		{}
		PcapLiveDevice(DeviceInterfaceDetails interfaceDetails, bool calculateMTU, bool calculateMacAddress,
		               bool calculateDefaultGateway);

		void setDeviceMtu();
		void setDeviceMacAddress();
		void setDefaultGateway();

		// threads
		void captureThreadMain();
		void statsThreadMain();

		static void onPacketArrives(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);
		static void onPacketArrivesNoCallback(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);
		static void onPacketArrivesBlockingMode(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);

	public:
		/// The type of the live device
		enum LiveDeviceType
		{
			/// libPcap live device
			LibPcapDevice,
			/// WinPcap/Npcap live device
			WinPcapDevice,
			/// WinPcap/Npcap Remote Capture device
			RemoteDevice
		};

		/// Device capturing mode
		enum DeviceMode
		{
			/// Only packets that their destination is this NIC are captured
			Normal = 0,
			/// All packets that arrive to the NIC are captured, even packets that their destination isn't this NIC
			Promiscuous = 1
		};

		/// Set direction for capturing packets (you can read more here:
		/// <https://www.tcpdump.org/manpages/pcap.3pcap.html#lbAI>)
		enum PcapDirection
		{
			/// Capture traffics both incoming and outgoing
			PCPP_INOUT = 0,
			/// Only capture incoming traffics
			PCPP_IN,
			/// Only capture outgoing traffics
			PCPP_OUT
		};

		/// Set which source provides timestamps associated to each captured packet
		/// (you can read more here: <https://www.tcpdump.org/manpages/pcap-tstamp.7.html>)
		enum class TimestampProvider
		{
			/// host-provided, unknown characteristics, default
			Host = 0,
			/// host-provided, low precision, synced with the system clock
			HostLowPrecision,
			/// host-provided, high precision, synced with the system clock
			HostHighPrecision,
			/// device-provided, synced with the system clock
			Adapter,
			/// device-provided, not synced with the system clock
			AdapterUnsynced,
			/// host-provided, high precision, not synced with the system clock
			HostHighPrecisionUnsynced
		};

		/// Set the precision of timestamps associated to each captured packet
		/// (you can read more here: <https://www.tcpdump.org/manpages/pcap-tstamp.7.html>)
		enum class TimestampPrecision
		{
			/// use timestamps with microsecond precision, default
			Microseconds = 0,
			/// use timestamps with nanosecond precision
			Nanoseconds,
		};

		/// @struct DeviceConfiguration
		/// A struct that contains user configurable parameters for opening a device. All parameters have default values
		/// so the user isn't expected to set all parameters or understand exactly how they work
		struct DeviceConfiguration
		{
			/// Indicates whether to open the device in promiscuous or normal mode
			DeviceMode mode;

			/// Set the packet buffer timeout in milliseconds. You can read more here:
			/// https://www.tcpdump.org/manpages/pcap.3pcap.html .
			/// Any value above 0 is considered legal, otherwise a value of 1 or -1 is used (depends on the platform)
			int packetBufferTimeoutMs;

			/// Set the packet buffer size. You can read more about the packet buffer here:
			/// https://www.tcpdump.org/manpages/pcap.3pcap.html .
			/// Any value of 100 or above is considered valid, otherwise the default value is used (which varies between
			/// different OS's). However, please notice that setting values which are too low or two high may result in
			/// failure to open the device. These too low or too high thresholds may vary between OS's, as an example
			/// please refer to this thread: https://stackoverflow.com/questions/11397367/issue-in-pcap-set-buffer-size
			int packetBufferSize;

			/// Set the direction for capturing packets. You can read more here:
			/// <https://www.tcpdump.org/manpages/pcap.3pcap.html#lbAI>.
			PcapDirection direction;

			/// Set the snapshot length. Snapshot length is the amount of data for each frame that is actually captured.
			/// Note that taking larger snapshots both increases the amount of time it takes to process packets and,
			/// effectively, decreases the amount of packet buffering. This may cause packets to be lost. Note also that
			/// taking smaller snapshots will discard data from protocols above the transport layer, which loses
			/// information that may be important. You can read more here: https://wiki.wireshark.org/SnapLen
			int snapshotLength;

			/// Set NFLOG group. Which NFLOG group to be listened to when connecting to NFLOG device. If device is not
			/// of type NFLOG this attribute is ignored.
			unsigned int nflogGroup;

			/// In Unix-like system, use poll() for blocking mode.
			bool usePoll;

			/// Set which timestamp provider is used.
			/// Depending on the capture device and the software on the host, different types of time stamp can be used
			TimestampProvider timestampProvider;

			/// Set which timestamp precision is used.
			/// Depending on the capture device and the software on the host, different precision can be used
			TimestampPrecision timestampPrecision;

			/// A c'tor for this struct
			/// @param[in] mode The mode to open the device: promiscuous or non-promiscuous. Default value is
			/// promiscuous
			/// @param[in] packetBufferTimeoutMs Buffer timeout in millisecond. Default value is 0 which means set
			/// timeout of 1 or -1 (depends on the platform)
			/// @param[in] packetBufferSize The packet buffer size. Default value is 0 which means use the default value
			/// (varies between different OS's)
			/// @param[in] direction Direction for capturing packets. Default value is INOUT which means capture both
			/// incoming and outgoing packets (not all platforms support this)
			/// @param[in] snapshotLength Snapshot length for capturing packets. Default value is 0 which means use the
			/// default value. A snapshot length of 262144 should be big enough for maximum-size Linux loopback packets
			/// (65549) and some USB packets captured with USBPcap (> 131072, < 262144). A snapshot length of 65535
			/// should be sufficient, on most if not all networks, to capture all the data available from the packet.
			/// @param[in] nflogGroup NFLOG group for NFLOG devices. Default value is 0.
			/// @param[in] usePoll use `poll()` when capturing packets in blocking more (`startCaptureBlockingMode()`)
			/// on Unix-like system. Default value is false.
			/// @param[in] timestampProvider The source (host or hardware adapter) that provides the timestamp
			/// for each packet (not all platforms support this). Default provider is Host.
			/// @param[in] timestampPrecision The timestamp precision (not all platforms support this).
			/// Default precision is Microseconds.
			explicit DeviceConfiguration(DeviceMode mode = Promiscuous, int packetBufferTimeoutMs = 0,
			                             int packetBufferSize = 0, PcapDirection direction = PCPP_INOUT,
			                             int snapshotLength = 0, unsigned int nflogGroup = 0, bool usePoll = false,
			                             TimestampProvider timestampProvider = TimestampProvider::Host,
			                             TimestampPrecision timestampPrecision = TimestampPrecision::Microseconds)
			{
				this->mode = mode;
				this->packetBufferTimeoutMs = packetBufferTimeoutMs;
				this->packetBufferSize = packetBufferSize;
				this->direction = direction;
				this->snapshotLength = snapshotLength;
				this->nflogGroup = nflogGroup;
				this->usePoll = usePoll;
				this->timestampProvider = timestampProvider;
				this->timestampPrecision = timestampPrecision;
			}
		};

		PcapLiveDevice(const PcapLiveDevice& other) = delete;
		PcapLiveDevice& operator=(const PcapLiveDevice& other) = delete;
		/// A destructor for this class
		~PcapLiveDevice() override;

		/// @return The type of the device (libPcap, WinPcap/Npcap or a remote device)
		virtual LiveDeviceType getDeviceType() const
		{
			return LibPcapDevice;
		}

		/// @return The name of the device (e.g eth0), taken from pcap_if_t->name
		std::string getName() const
		{
			return m_InterfaceDetails.name;
		}

		/// @return A human-readable description of the device, taken from pcap_if_t->description. May be empty string
		/// in some interfaces
		std::string getDesc() const
		{
			return m_InterfaceDetails.description;
		}

		/// @return True if this interface is a loopback interface, false otherwise
		bool getLoopback() const
		{
			return m_InterfaceDetails.isLoopback;
		}

		/// @return The device's maximum transmission unit (MTU) in bytes
		virtual uint32_t getMtu() const
		{
			return m_DeviceMtu;
		}

		/// @return The device's link layer type
		virtual LinkLayerType getLinkType() const
		{
			return m_LinkType;
		}

		/// @return A vector containing all IP addresses defined for this interface.
		std::vector<IPAddress> getIPAddresses() const
		{
			return m_InterfaceDetails.addresses;
		}

		/// @return The MAC address for this interface
		virtual MacAddress getMacAddress() const
		{
			return m_MacAddress;
		}

		/// @return The IPv4 address for this interface. If multiple IPv4 addresses are defined for this interface, the
		/// first will be picked. If no IPv4 addresses are defined, a zeroed IPv4 address (IPv4Address#Zero) will be
		/// returned
		IPv4Address getIPv4Address() const;

		/// @return The IPv6 address for this interface. If multiple IPv6 addresses are defined for this interface, the
		/// first will be picked. If no IPv6 addresses are defined, a zeroed IPv6 address (IPv6Address#Zero) will be
		/// returned
		IPv6Address getIPv6Address() const;

		/// @return The default gateway defined for this interface. If no default gateway is defined, if it's not IPv4
		/// or if couldn't extract default gateway IPv4Address#Zero will be returned. If multiple gateways were defined
		/// the first one will be returned
		IPv4Address getDefaultGateway() const;

		/// @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers
		/// were defined or they couldn't be extracted from some reason. This list is created in PcapLiveDeviceList
		/// class and can be also retrieved from there. This method exists for convenience - so it'll be possible to get
		/// this list from PcapLiveDevice as well
		const std::vector<IPv4Address>& getDnsServers() const;

		/// Start capturing packets on this network interface (device). Each time a packet is captured the
		/// onPacketArrives callback is called. The capture is done on a new thread created by this method, meaning all
		/// callback calls are done in a thread other than the caller thread. Capture process will stop and this capture
		/// thread will be terminated when calling stopCapture(). This method must be called after the device is opened
		/// (i.e the open() method was called), otherwise an error will be returned.
		/// @param[in] onPacketArrives A callback that is called each time a packet is captured
		/// @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onPacketArrives callback each time it is called. This cookie is very useful for transferring objects
		/// that give context to the capture callback, for example: objects that counts packets, manages flow state or
		/// manages the application state according to the packet that was captured
		/// @return True if capture started successfully, false if (relevant log error is printed in any case):
		/// - Capture is already running
		/// - Device is not opened
		/// - Capture thread could not be created
		virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie);

		/// Start capturing packets on this network interface (device) with periodic stats collection. Each time a
		/// packet is captured the onPacketArrives callback is called. In addition, each intervalInSecondsToUpdateStats
		/// seconds stats are collected from the device and the onStatsUpdate callback is called. Both the capture and
		/// periodic stats collection are done on new threads created by this method, each on a different thread,
		/// meaning all callback calls are done in threads other than the caller thread. Capture process and stats
		/// collection will stop and threads will be terminated when calling stopCapture(). This method must be called
		/// after the device is opened (i.e the open() method was called), otherwise an error will be returned.
		/// @param[in] onPacketArrives A callback that is called each time a packet is captured
		/// @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onPacketArrives callback each time it is called. This cookie is very useful for transferring objects
		/// that give context to the capture callback, for example: objects that counts packets, manages flow state or
		/// manages the application state according to the packet that was captured
		/// @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		/// @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and
		/// stats are collected. This callback will contain the collected stats
		/// @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onStatsUpdate callback each time it is called
		/// @return True if capture started successfully, false if (relevant log error is printed in any case):
		/// - Capture is already running
		/// - Device is not opened
		/// - Capture thread could not be created
		/// - Stats collection thread could not be created
		virtual bool startCapture(OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie,
		                          int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                          void* onStatsUpdateUserCookie);

		/// Start capturing packets on this network interface (device) with periodic stats collection only. This means
		/// that packets arriving to the network interface aren't delivered to the user but only counted. Each
		/// intervalInSecondsToUpdateStats seconds stats are collected from the device and the onStatsUpdate callback is
		/// called with the updated counters. The periodic stats collection is done on a new thread created by this
		/// method, meaning all callback calls are done in threads other than the caller thread. Stats collection will
		/// stop and threads will be terminated when calling stopCapture(). This method must be called after the device
		/// is opened (i.e the open() method was called), otherwise an error will be returned.
		/// @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		/// @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and
		/// stats are collected. This callback will contain the collected stats
		/// @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onStatsUpdate callback each time it is called
		/// @return True if capture started successfully, false if (relevant log error is printed in any case):
		/// - Capture is already running
		/// - Device is not opened
		/// - Stats collection thread could not be created
		virtual bool startCapture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                          void* onStatsUpdateUserCookie);

		/// Start capturing packets on this network interface (device). All captured packets are added to
		/// capturedPacketsVector, so at the end of the capture (when calling stopCapture()) this vector contains
		/// pointers to all captured packets in the form of RawPacket. The capture is done on a new thread created by
		/// this method, meaning capturedPacketsVector is updated from another thread other than the caller thread (so
		/// user should avoid changing or iterating this vector while capture is on). Capture process will stop and this
		/// capture thread will be terminated when calling stopCapture(). This method must be called after the device is
		/// opened (i.e the open() method was called), otherwise an error will be returned.
		/// @param[in] capturedPacketsVector A reference to a RawPacketVector, meaning a vector of pointer to RawPacket
		/// objects
		/// @return True if capture started successfully, false if (relevant log error is printed in any case):
		/// - Capture is already running
		/// - Device is not opened
		/// - Capture thread could not be created
		virtual bool startCapture(RawPacketVector& capturedPacketsVector);

		/// Start capturing packets on this network interface (device) in blocking mode, meaning this method blocks and
		/// won't return until the user frees the blocking (via onPacketArrives callback) or until a user defined
		/// timeout expires. Whenever a packets is captured the onPacketArrives callback is called and lets the user
		/// handle the packet. In each callback call the user should return true if he wants to release the block or
		/// false if it wants it to keep blocking. Regardless of this callback a timeout is defined when start
		/// capturing. When this timeout expires the method will return.<BR> Please notice that stopCapture() isn't
		/// needed here because when the method returns (after timeout or per user decision) capturing on the device is
		/// stopped
		/// @param[in] onPacketArrives A callback given by the user for handling incoming packets. After handling each
		/// packet the user needs to return a boolean value. True value indicates stop capturing and stop blocking and
		/// false value indicates continue capturing and blocking
		/// @param[in] userCookie A pointer to a user provided object. This object will be transferred to the
		/// onPacketArrives callback each time it is called. This cookie is very useful for transferring objects that
		/// give context to the capture callback, for example: objects that counts packets, manages flow state or
		/// manages the application state according to the packet that was captured
		/// @param[in] timeout A timeout in seconds for the blocking to stop even if the user didn't return "true" in
		/// the onPacketArrives callback. The precision of `timeout` is millisecond, e.g. 2.345 seconds means 2345
		/// milliseconds. If this timeout is set to 0 or less the timeout will be ignored, meaning the method will keep
		/// handling packets until the `onPacketArrives` callback returns `true`.
		/// @return -1 if timeout expired, 1 if blocking was stopped via onPacketArrives callback or 0 if an error
		/// occurred (such as device not open etc.). When returning 0 an appropriate error message is printed to log
		/// @note On Unix-like systems, enabling the `usePoll` option in `DeviceConfiguration` prevents the method from
		/// blocking indefinitely when no packets are available, even if a timeout is set.
		virtual int startCaptureBlockingMode(OnPacketArrivesStopBlocking onPacketArrives, void* userCookie,
		                                     const double timeout);

		/// Stop a currently running packet capture. This method terminates gracefully both packet capture thread and
		/// periodic stats collection thread (both if exist)
		void stopCapture();

		/// Check if a capture thread is running
		/// @return True if a capture thread is currently running
		bool captureActive();

		/// Checks whether the packetPayloadLength is larger than the device MTU. Logs an error if check fails
		/// @param[in] packetPayloadLength The length of the IP layer of the packet
		/// @return True if the packetPayloadLength is less than or equal to the device MTU
		bool doMtuCheck(int packetPayloadLength) const;

		/// Send a RawPacket to the network
		/// @param[in] rawPacket A reference to the raw packet to send. This method treats the raw packet as read-only,
		/// it doesn't change anything in it
		/// @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. If enabled
		/// this comes with a small performance penalty. Default value is false to avoid performance overhead. Set to
		/// true if you don't know whether packets fit the live device's MTU and you can afford the overhead.
		/// @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		/// error is printed in any case):
		/// - Device is not opened
		/// - Packet length is 0
		/// - Packet length is larger than device MTU
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		bool sendPacket(RawPacket const& rawPacket, bool checkMtu = false);

		/// Send a buffer containing packet raw data (including all layers) to the network.
		/// This particular version of the sendPacket method should only be used if you already have access to the size
		/// of the network layer of the packet, since it allows you to check the payload size (see packetPayloadLength
		/// parameter) MTU of the live device without incurring a parsing overhead. If the packetPayloadLength is
		/// unknown, please use a different implementation of the sendPacket method.
		/// @param[in] packetData The buffer containing the packet raw data
		/// @param[in] packetDataLength The length of the buffer (this is the entire packet, including link layer)
		/// @param[in] packetPayloadLength The length of the payload for the data link layer. This includes all data
		/// apart from the header for the data link layer.
		/// @return True if the packet was sent successfully. False will be returned in the following cases (relevant
		/// log error is printed in any case):
		/// - Device is not opened
		/// - Packet data length is 0
		/// - Packet payload length is larger than device MTU
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		bool sendPacket(const uint8_t* packetData, int packetDataLength, int packetPayloadLength);

		/// Send a buffer containing packet raw data (including all layers) to the network
		/// @param[in] packetData The buffer containing the packet raw data
		/// @param[in] packetDataLength The length of the buffer
		/// @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. If enabled
		/// this comes with a small performance penalty. Default value is false to avoid performance overhead. Set to
		/// true if you don't know whether packets fit the live device's MTU and you can afford the overhead.
		/// @param[in] linkType Only used if checkMtu is true. Defines the layer type for parsing the first layer of the
		/// packet. Used for parsing the packet to perform the MTU check. Default value is pcpp::LINKTYPE_ETHERNET.
		/// Ensure this parameter matches the linktype of the packet if checkMtu is true.
		/// @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		/// error is printed in any case):
		/// - Device is not opened
		/// - Packet length is 0
		/// - Packet length is larger than device MTU and checkMtu is true
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		bool sendPacket(const uint8_t* packetData, int packetDataLength, bool checkMtu = false,
		                pcpp::LinkLayerType linkType = pcpp::LINKTYPE_ETHERNET);

		/// Send a parsed Packet to the network
		/// @param[in] packet A pointer to the packet to send. This method treats the packet as read-only, it doesn't
		/// change anything in it
		/// @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. Default
		/// value is true, since the packet being passed in has already been parsed, so checking the MTU does not incur
		/// significant processing overhead.
		/// @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		/// error is printed in any case):
		/// - Device is not opened
		/// - Packet length is 0
		/// - Packet length is larger than device MTU and checkMtu is true
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		bool sendPacket(Packet* packet, bool checkMtu = true);

		/// Send an array of RawPacket objects to the network
		/// @param[in] rawPacketsArr The array of RawPacket objects to send. This method treats all packets as
		/// read-only, it doesn't change anything in them
		/// @param[in] arrLength The length of the array
		/// @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Incurs a parsing
		/// overhead. Default value is false to avoid performance overhead. Set to true if you don't know whether
		/// packets fit the live device's MTU and you can afford the overhead.
		/// @return The number of packets sent successfully. Sending a packet can fail if:
		/// - Device is not opened. In this case no packets will be sent, return value will be 0
		/// - Packet length is 0
		/// - Packet length is larger than device MTU and checkMtu is true
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		virtual int sendPackets(RawPacket* rawPacketsArr, int arrLength, bool checkMtu = false);

		/// Send an array of pointers to Packet objects to the network
		/// @param[in] packetsArr The array of pointers to Packet objects to send. This method treats all packets as
		/// read-only, it doesn't change anything in them
		/// @param[in] arrLength The length of the array
		/// @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Default value is true,
		/// since the packets being passed in has already been parsed, so checking the MTU does not incur significant
		/// processing overhead.
		/// @return The number of packets sent successfully. Sending a packet can fail if:
		/// - Device is not opened. In this case no packets will be sent, return value will be 0
		/// - Packet length is 0
		/// - Packet length is larger than device MTU and checkMtu is true
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		virtual int sendPackets(Packet** packetsArr, int arrLength, bool checkMtu = true);

		/// Send a vector of pointers to RawPacket objects to the network
		/// @param[in] rawPackets The array of pointers to RawPacket objects to send. This method treats all packets as
		/// read-only, it doesn't change anything in them
		/// @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Incurs a parsing
		/// overhead. Default value is false to avoid performance overhead. Set to true if you don't know whether
		/// packets fit the live device's MTU and you can afford the overhead.
		/// @return The number of packets sent successfully. Sending a packet can fail if:
		/// - Device is not opened. In this case no packets will be sent, return value will be 0
		/// - Packet length is 0
		/// - Packet length is larger than device MTU and checkMtu is true
		/// - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		virtual int sendPackets(const RawPacketVector& rawPackets, bool checkMtu = false);

		// implement abstract methods

		/// Open the device using libpcap pcap_open_live. Opening the device only makes the device ready for use, it
		/// doesn't start packet capturing. For packet capturing the user should call startCapture(). This implies that
		/// calling this method is a must before calling startCapture() (otherwise startCapture() will fail with a
		/// "device not open" error). The device is opened in promiscuous mode
		/// @return True if the device was opened successfully, false otherwise. When opening the device fails an error
		/// will be printed to log as well
		bool open() override;

		/// Enables to open a device in a non-default configuration. Configuration has parameters like packet buffer
		/// timeout & size, open in promiscuous/non-promiscuous mode, etc. Please check DeviceConfiguration for more
		/// details
		/// @param[in] config The requested configuration
		/// @return Same as open()
		bool open(const DeviceConfiguration& config);

		void close() override;

		/// Clones the current device class
		/// @return Pointer to the copied class
		virtual PcapLiveDevice* clone() const;

		void getStatistics(IPcapDevice::PcapStats& stats) const override;

	protected:
		internal::PcapHandle doOpen(const DeviceConfiguration& config);

	private:
		bool isNflogDevice() const;
	};
}  // namespace pcpp
