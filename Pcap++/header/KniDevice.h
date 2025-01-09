#pragma once

// GCOVR_EXCL_START

#include <string>
#include <atomic>

#include "Device.h"
#include "MacAddress.h"
#include "MBufRawPacket.h"
#include "LinuxNicInformationSocket.h"

/// @file
/// @brief This file and KniDeviceList.h provide PcapPlusPlus C++ wrapper
/// for DPDK KNI (Kernel Network Interface) library (librte_kni).
/// The main propose of the rte_kni library is to provide a way to forward
/// packets received by DPDK application to Linux kernel (a.e. to processes that
/// have opened some kind of a net socket) for further processing and to obtain
/// packets from Linux kernel. The KNI device is the bridge that accomplish the
/// translation between DPDK packets (mbuf) and Linux kernel/socket packets
/// (skbuf). Currently KNI devices report speeds up to 10 GBit/s.<BR>
/// KNI device is a virtual network interface so it can be created and destroyed
/// programmatically at will. As a real network interface KNI deivice must
/// be managed appropriately like other interfaces. To start operate it MUST be
/// given an IP address for example by the means of <B>ip a</B> command and
/// MUST be put up for example by <B>ip l set [interface] up</B>.<BR>
/// Additionally KNI interfaces support 4 other settings (depends on DPDK
/// version used):
///  - change link state: <B>ip l set [interface] up/down</B>
///  - change MTU: <B>ip l set dev [interface] mtu [mtu_count]</B>
///  - change MAC address: <B>ip l set [interface] address [new_mac]</B>
///  - change promiscuous mode: <B>ip l set [interface] promisc on/off</B>
///
/// Changes of each of this settings generates an event/request that must be
/// handled by an application that have created the KNI device in 3 second
/// period or it will be rejected and Linux kernel will not apply the change.
/// The way that this requests MUST be handled is defined by DPDK and so for
/// each type of request the application that creates the KNI device must provide
/// the callback function to call. This callbacks are set in time of KNI device
/// creation via KniIoctlCallbacks or KniOldIoctlCallbacks structures (the
/// structure used is dependent on DPDK version).<BR>
/// There is a way to enable <B>ethtool</B> on KNI devices that include
/// recompilation of DPDK and strict correspondence between KNI port id and DPDK
/// port id, but it is not currently supported by PcapPlusPlus.<BR>
///
/// Known issues:
///  - KNI device may not be able to set/update it's link status up
///    (LINK_ERROR returned):
///    The problem is laying in DPDK in rte_kni_update_link function
///    (it is DPDK BUG if rte_kni_update_link is __rte_experimental).
///    It is recommended to load rte_kni.ko module with "carrier=on" DPDK
///    default is "carrier=off", provided setup_dpdk.py by default loads with
///    "carrier=on" if Your DPDK version supports it. The good indication of
///    this issue are "DPDK KNI Failed to update links state for device"
///    messages when Pcap++Test application is being run.
///  - Packets may not be seen by applications that have open sockets on KNI
///    device:
///    Check your <B>iptables</B> settings and other packet filters - KNI device
///    is traditional network device so all caveats apply;
///  - I see a lot of unknown traffic - what is it?
///    This must be Linux kernel trying to communicate with other devices from
///    KNI device and it will do so as long as You give the KNI device any IP
///    address via ip command or by record in /etc/networking/interfaces;
///  - On old versions of DPDK only 4 KNI devices may be created:
///    Yep this is a limitation. You can change MAX_KNI_DEVICES constant in
///    KniDeviceList.cpp to unlock this limit;
///  - Any set* method never succeeds:
///    You may forgot that they generate KNI requests that Your application MUST
///    handle. Just use KniDevice#startRequestHandlerThread to handle all
///    requests automatically. Or user running the application don't have
///    suitable access rights (must have CAP_NET_ADMIN).
///
/// Useful links:
///  - <a href="https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html">KNI interface concept DPDK
///    documentation</a>
///  - <a href="https://doc.dpdk.org/guides/nics/kni.html">KNI PMD</a>
///  - <a href="https://doc.dpdk.org/guides/sample_app_ug/kernel_nic_interface.html">KNI DPDK sample application</a>
///  - <a href="https://doc.dpdk.org/dts/test_plans/kni_test_plan.html">KNI DPDK test plan</a>
struct rte_kni;

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class KniDevice;
	class KniDeviceList;

	/// Defines the signature callback used by capturing API on KNI device
	typedef bool (*OnKniPacketArriveCallback)(MBufRawPacket* packets, uint32_t numOfPackets, KniDevice* device,
	                                          void* userCookie);

	/// @class KniDevice
	/// This class represents special kind of DPDK devices called KNI - Kernel Network Interface
	/// that are used to exchange DPDK mbuf packets with Linux kernel network stack.
	/// This devices have only one RX and one TX queue so MT receiving or MT sending is not
	/// safe but simultaneous receiving and sending packets is MT safe.
	/// The RX queue of KNI device is pointed from kernel to application and TX queue is
	/// pointed in opposite direction - from application to kernel. So receive* methods will
	/// obtain packets from kernel and send* methods will send them to kernel.<BR>
	/// The lifecycle of the KNI device is as follows:
	///  - KniDeviceConfiguration structure is created by user and filled with device settings;
	///  - The KniDeviceList#getInstance method is called to initialize the KNI module and
	///    obtain the KniDeviceList singleton;
	///  - KniDeviceList#createDevice method of the singleton is called to allocate new KNI device;
	///  - Device then must be opened by calling KniDevice#open;
	///  - During lifetime the application must handle the requests from kernel either by calling
	///    KniDevice#handleRequests to handle them synchronously or by starting separate thread
	///    to do this by calling KniDevice#startRequestHandlerThread;
	///  - During lifetime the packets may be send to/received from KNI device via
	///    calls to synchronous API (send/receive methods) or asynchronously by
	///    running capturing thread using KniDevice#startCapture;
	///  - KNI device will be destroyed or implicitly on application exit. User must assure
	///    that NO OTHER linux application is using KNI device when and after it is being
	///    destroyed otherwise Linux kernel may crush dramatically.
	class KniDevice : public IDevice
	{
		friend class KniDeviceList;
		friend class MBufRawPacket;

	public:
		/// Various link related constants for KNI device
		enum KniLinkState
		{
			/// Returned by KNI functions if DPDK version used don't support link setup capability
			LINK_NOT_SUPPORTED = -2,
			/// Returned by KNI functions if link changing function meets an error
			LINK_ERROR = -1,
			/// Used to put link status on KNI device DOWN
			LINK_DOWN = 0,
			/// Used to put link status on KNI device UP
			LINK_UP = 1
		};
		/// Various information related constants for KNI device
		enum KniInfoState
		{
			/// Used to identify intent to obtain cached version of KNI device information
			INFO_CACHED = 0,
			/// Used to identify intent to renew/update KNI device information
			INFO_RENEW = 1
		};
		/// Promiscuous mode related constants for KNI device
		enum KniPromiscuousMode
		{
			/// Used to DISABLE promiscuous mode on KNI device
			PROMISC_DISABLE = 0,
			/// Used to ENABLE promiscuous mode on KNI device
			PROMISC_ENABLE = 1
		};

		/// @brief New callbacks for KNI device events.
		/// This structure MUST be used ONLY when KniDeviceList#callbackVersion returns
		/// KniDeviceList#KniCallbackVersion#CALLBACKS_NEW.
		/// Or if You are sure that DPDK version used is 17.11 or higher.
		/// If some callback is not provided (nullptr) the request will always succeeds
		/// if other is not specified in callback description.
		/// @note This callbacks are direct copy of one defined in rte_kni_ops. Future
		/// maintainers of KNI device feature MUST refer to rte_kni_ops structure in
		/// rte_kni.h header file of DPDK to track the difference in signatures
		struct KniIoctlCallbacks
		{
			/// Pointer to function of changing MTU.
			/// Must return 0 in case of success or negative error code
			int (*change_mtu)(uint16_t port_id, unsigned int new_mtu);
			/// Pointer to function of configuring network interface.
			/// Must return 0 in case of success or negative error code
			int (*config_network_if)(uint16_t port_id, uint8_t if_up);
			/// Pointer to function of configuring mac address.
			/// If callback is not provided and port_id of KNI device is not UINT16_MAX
			/// then DPDK will use predefined callback witch sets MAC address of
			/// DPDK port port_id via rte_eth_dev_default_mac_addr_set.
			/// Must return 0 in case of success or negative error code
			int (*config_mac_address)(uint16_t port_id, uint8_t mac_addr[]);
			/// Pointer to function of configuring promiscuous mode.
			/// If callback is not provided and port_id of KNI device is not UINT16_MAX
			/// then DPDK will use predefined callback witch sets promiscuous mode of
			/// DPDK port port_id via rte_eth_promiscuous_enable/rte_eth_promiscuous_disable.
			/// Must return 0 in case of success or negative error code
			int (*config_promiscusity)(uint16_t port_id, uint8_t to_on);
		};

		/// @brief Old callbacks for KNI device events.
		/// This structure MUST be used ONLY when KniDeviceList#callbackVersion returns
		/// KniDeviceList#KniCallbackVersion#CALLBACKS_OLD.
		/// Or if You are sure that DPDK version used is lower than 17.11.
		/// If some callback is not provided (nullptr) the request will always succeeds.
		struct KniOldIoctlCallbacks
		{
			/// Pointer to function of changing MTU.
			/// Must return 0 in case of success or negative error code
			int (*change_mtu)(uint8_t port_id, unsigned int new_mtu);
			/// Pointer to function of configuring network interface.
			/// Must return 0 in case of success or negative error code
			int (*config_network_if)(uint8_t port_id, uint8_t if_up);
		};

		/// @brief KNI device initialization data.
		/// Used to create new KNI device.
		/// Usage of callbacks member or oldCallbacks member is defined by
		/// result of KniDeviceList#callbackVersion
		struct KniDeviceConfiguration
		{
			/// Name used to display device in system.
			/// Must not interfere with already existing network interfaces.
			/// Must be less than or equal to IFNAMSIZ (16 chars including \0 on most systems)
			std::string name;
			union {
				KniIoctlCallbacks* callbacks;
				KniOldIoctlCallbacks* oldCallbacks;
			};
			/// MAC (ETHERNET) address of new KNI device.
			/// If MacAddress::Zero is provided then
			/// some valid address will be automatically generated.
			/// If provided (not MacAddress::Zero) will be cached by new KNI device info structure.
			MacAddress mac;
			/// Used in same way as DPDK port id.
			/// If some new callbacks are omitted then have separate meaning
			/// (see KniIoctlCallbacks#config_mac_address and KniIoctlCallbacks#config_promiscusity).
			/// Can be set to UINT16_MAX.
			uint16_t portId;
			/// MTU of new KNI device. Will be cached by new KNI device info structure
			uint16_t mtu;
			/// If set forces to bind KNI Linux kernel thread (NOT userspace thread) to specific core.
			/// If rte_kni kernel module is loaded with "kthread_mode=single" then -
			/// rebinds kernel thread used for all KNI devices to specified core.
			/// If rte_kni kernel module is loaded with "kthread_mode=multiple" then -
			/// binds new kernel thread for this device to specified core.
			bool bindKthread;
			/// ID of core to bind Linux kernel thread to (same as DPDK cores IDs)
			uint32_t kthreadCoreId;
		};

	private:
		/// All instances of this class MUST be produced by KniDeviceList class
		KniDevice(const KniDeviceConfiguration& conf, size_t mempoolSize, int unique);
		/// This class is not copyable
		KniDevice(const KniDevice&);
		/// This class is not copyable
		KniDevice& operator=(const KniDevice&);
		/// All instances of this class MUST be destroyed by KniDeviceList class
		~KniDevice();

	public:
		/// Indicates whether the KNI device was initialized successfully
		inline bool isInitialized() const
		{
			return !(m_Device == nullptr || m_MBufMempool == nullptr);
		}
		/// Obtains name of KNI device in form of C++ string
		inline std::string getName() const
		{
			return std::string(m_DeviceInfo.name);
		}
		/// Obtains port ID of KNI device
		inline uint16_t getPort() const
		{
			return m_DeviceInfo.portId;
		}
		/// @brief Obtains link status of KNI device.
		/// If called with INFO_CACHED - returns cached data about link state (SUPER FAST may be INACCURATE).
		/// If called with INFO_RENEW - makes system call to Linux to obtain
		/// link information and caches it (VERY SLOW but ACCURATE).
		/// @param[in] state Defines information relevance level
		/// @return LINK_UP, LINK_DOWN, LINK_NOT_SUPPORTED if device is not initialized, some times LINK_ERROR
		KniLinkState getLinkState(KniInfoState state = INFO_CACHED);
		/// @brief Obtains MAC address of KNI device.
		/// If called with INFO_CACHED - returns cached data about MAC address (SUPER FAST may be INACCURATE).
		/// If called with INFO_RENEW - makes system call to Linux to obtain
		/// MAC address and caches it (VERY SLOW but ACCURATE).
		/// @param[in] state Defines information relevance level
		/// @return Known MAC address of KNI interface
		MacAddress getMacAddress(KniInfoState state = INFO_CACHED);
		/// @brief Obtains MTU of KNI device.
		/// If called with INFO_CACHED - returns cached data about MTU (SUPER FAST may be INACCURATE).
		/// If called with INFO_RENEW - makes system call to Linux to obtain
		/// MTU and caches it (VERY SLOW but ACCURATE).
		/// @param[in] state Defines information relevance level
		/// @return Known MTU of KNI interface
		uint16_t getMtu(KniInfoState state = INFO_CACHED);
		/// @brief Obtains information about promiscuous mode of KNI device.
		/// If called with INFO_CACHED - returns cached data about promiscuous mode (SUPER FAST may be INACCURATE).
		/// If called with INFO_RENEW - makes system call to Linux to obtain
		/// promiscuous mode and caches it (VERY SLOW but ACCURATE).
		/// @param[in] state Defines information relevance level
		/// @return Known promiscuous mode of KNI interface
		KniPromiscuousMode getPromiscuous(KniInfoState state = INFO_CACHED);

		/// @brief Sets link state of KNI device.
		/// Firstly the link information is updated as by call to getLinkState(INFO_RENEW).
		/// Then link state is set only if obtained state differs from provided.
		/// New link state of KNI device is cached.
		/// @note You must be using sudo or be root or have CAP_NET_ADMIN capability to use this function
		/// @note Generates change link state request
		/// @param[in] state Must be LINK_UP or LINK_DOWN
		/// @return true if desired link state of KNI device is set (was as provided or set successfully),
		///    false if some error occurred (debug info is printed)
		bool setLinkState(KniLinkState state);
		/// @brief Sets MAC address of KNI device.
		/// Unconditionally changes MAC of KNI device.
		/// If MAC is updated successfully then it is cached.
		/// @note You must be using sudo or be root or have CAP_NET_ADMIN capability to use this function
		/// @note Generates change mac request
		/// @param[in] mac New MAC address of KNI device
		/// @return true if desired MAC address is set, false if not and some error occurred (debug info is printed)
		bool setMacAddress(const MacAddress& mac);
		/// @brief Sets MTU of KNI device.
		/// Unconditionally changes MTU of KNI device.
		/// If MTU is updated successfully then it is cached.
		/// @note You must be using sudo or be root or have CAP_NET_ADMIN capability to use this function
		/// @note Generates change mtu request
		/// @warning Low MTU values may crush Linux kernel. Follow Your kernel version documentation for details
		/// @param[in] mtu New MTU address of KNI device
		/// @return true if desired MTU is set, false if not and some error occurred (debug info is printed)
		bool setMtu(uint16_t mtu);
		/// @brief Sets promiscuous mode of KNI device.
		/// Firstly the promiscuous mode information is updated as by call to getPromiscuous(INFO_RENEW).
		/// Then promiscuous mode is set only if obtained mode differs from provided.
		/// New promiscuous mode of KNI device is cached.
		/// @note You must be using sudo or be root or have CAP_NET_ADMIN capability to use this function
		/// @note Generates promiscuous mode request
		/// @param[in] mode Must be PROMISC_DISABLE or PROMISC_ENABLE
		/// @return true if desired promiscuous mode of KNI device is set (was as provided or set successfully),
		///    false if some error occurred (debug info is printed)
		bool setPromiscuous(KniPromiscuousMode mode);
		/// @brief Updates link state of KNI device.
		/// Unconditionally updates link state of KNI device via call to DPDK librte_kni API.
		/// FASTER THAN setLinkState(state) but may not be supported or may fail.
		/// If link state is updated successfully then it is cached.
		/// @param[in] state New link state of KNI device
		/// @return LINK_NOT_SUPPORTED if this capability is not supported by DPDK version used (DPDK ver < 18.11),
		///    LINK_ERROR if attempt to set link state failed (may always fail on some systems see class description)
		///    LINK_DOWN - previous link state was DOWN, state is successfully updated to provided one
		///    LINK_UP - previous link state was UP, state is successfully updated to provided one
		KniLinkState updateLinkState(KniLinkState state);

		/// @brief Handle requests from Linux kernel synchronously in calling thread.
		/// When one of events which is needed application attention occurres it must be handled by calling this
		/// function (or by running RequestHandlerThread for this device).
		/// Until the request is handled the Linux kernel thread that manages this KNI is blocked.
		/// If it is not handled by application in 3 seconds the request is reported to kernel as failed one.
		/// Current known requests are:
		///  - change link state: ip l set [interface] up/down
		///  - change mtu: ip l set dev [interface] mtu [mtu_count]
		///  - change mac: ip l set [interface] address [new_mac]
		///  - change promiscuous mode: ip l set [interface] promisc on/off
		/// @warning Functions setLinkState, setMacAddress, setMtu and setPromiscuous will generate this requests.
		/// @note Callbacks provided for this KNI device will be called synchronously in calling thread during execution
		/// of this function
		/// @return true if no error happened during request handling false otherwise
		bool handleRequests();
		/// @brief Starts new thread (using pthread) to asynchronously handle KNI device requests.
		/// See description of handleRequests() about requests.
		/// New thread is detached using pthread_detach.
		/// This thread can be stopped explicitly by calling stopRequestHandlerThread() or
		/// implicitly on KNI device destruction.
		/// Linux <a href="http://man7.org/linux/man-pages/man2/nanosleep.2.html">nanosleep()</a> function is used for
		/// sleeping.
		/// @note Callbacks provided for this KNI device will be called asynchronously in new thread
		/// @param[in] sleepSeconds Sleeping time in seconds
		/// @param[in] sleepNanoSeconds Sleeping time in nanoseconds
		/// @return true if new thread is started successfully false otherwise
		bool startRequestHandlerThread(long sleepSeconds, long sleepNanoSeconds = 0);
		/// @brief Explicitly stops request thread for this device if it was running.
		/// See description of handleRequests() about requests.
		/// @warning There may be a rare error when request thread handles requests on already
		/// destroyed device. It occurres only because request thread is detached one but it is really really rare.
		/// In case of this error occurring (must be SIGSEGV) change type of created thread in startRequestHandlerThread
		/// function from DETACHED to JOINABLE.
		void stopRequestHandlerThread();

		/// @brief Receive raw packets from kernel.
		/// @param[out] rawPacketsArr A vector where all received packets will be written into
		/// @return The number of packets received. If an error occurred 0 will be returned and the error will be
		/// printed to log
		uint16_t receivePackets(MBufRawPacketVector& rawPacketsArr);
		/// @brief Receive raw packets from kernel.
		/// Please notice that in terms of performance, this is the best method to use
		/// for receiving packets because out of all receivePackets overloads this method requires the least overhead
		/// and is almost as efficient as receiving packets directly through DPDK. So if performance is a critical
		/// factor in your application, please use this method
		/// @param[out] rawPacketsArr A pointer to an array of MBufRawPacket pointers where all received packets will be
		/// written into. The array is expected to be allocated by the user and its length should be provided in
		/// rawPacketArrLength. Number of packets received will be returned. Notice it's the user responsibility to free
		/// the array and its content when done using it
		/// @param[out] rawPacketArrLength The length of MBufRawPacket pointers array
		/// @return The number of packets received. If an error occurred 0 will be returned and the error will be
		/// printed to log
		uint16_t receivePackets(MBufRawPacket** rawPacketsArr, uint16_t rawPacketArrLength);
		/// @brief Receive parsed packets from kernel.
		/// @param[out] packetsArr A pointer to an allocated array of Packet pointers where all received packets will be
		/// written into. The array is expected to be allocated by the user and its length should be provided in
		/// packetsArrLength. Number of packets received will be returned. Notice it's the user responsibility to free
		/// the array and its content when done using it
		/// @param[out] packetsArrLength The length of Packet pointers array
		/// @return The number of packets received. If an error occurred 0 will be returned and the error will be
		/// printed to log
		uint16_t receivePackets(Packet** packetsArr, uint16_t packetsArrLength);

		/// @brief Send an array of MBufRawPacket to kernel.
		/// Please notice the following:<BR>
		/// - In terms of performance, this is the best method to use for sending packets because out of all sendPackets
		///   overloads this method requires the least overhead and is almost as efficient as sending the packets
		///   directly through DPDK. So if performance is a critical factor in your application, please use this method
		/// - If the number of packets to send is higher than 64 this method will run multiple iterations of sending
		///   packets to DPDK, each iteration of 64 packets
		/// - The mbufs used in this method aren't freed by this method, they will be transparently freed by DPDK
		///   <BR><BR>
		/// @param[in] rawPacketsArr A pointer to an array of MBufRawPacket
		/// @param[in] arrLength The length of the array
		/// @return The number of packets actually and successfully sent
		uint16_t sendPackets(MBufRawPacket** rawPacketsArr, uint16_t arrLength);
		/// @brief Send an array of parsed packets to kernel.
		/// Please notice the following:<BR>
		/// - If some or all of the packets contain raw packets which aren't of type MBufRawPacket, a new temp
		///   MBufRawPacket instances will be created and packet data will be copied to them. This is necessary to
		///   allocate mbufs which will store the data to be sent. If performance is a critical factor please make sure
		///   you send parsed packets that contain only raw packets of type MBufRawPacket
		/// - If the number of packets to send is higher than 64 this method will run multiple iterations of sending
		///   packets to DPDK, each iteration of 64 packets
		/// - The mbufs used or allocated in this method aren't freed by this method, they will be transparently freed
		///   by DPDK <BR><BR>
		/// @param[in] packetsArr A pointer to an array of parsed packet pointers
		/// @param[in] arrLength The length of the array
		/// @return The number of packets actually and successfully sent
		uint16_t sendPackets(Packet** packetsArr, uint16_t arrLength);
		/// @brief Send a vector of MBufRawPacket pointers to kernel.
		/// Please notice the following:<BR>
		/// - If the number of packets to send is higher than 64 this method will run multiple iterations of sending
		///   packets to DPDK, each iteration of 64 packets
		/// - The mbufs used in this method aren't freed by this method, they will be transparently freed by DPDK
		///   <BR><BR>
		/// @param[in] rawPacketsVec The vector of raw packet
		/// @return The number of packets actually and successfully sent
		uint16_t sendPackets(MBufRawPacketVector& rawPacketsVec);
		/// @brief Send a vector of RawPacket pointers to kernel.
		/// Please notice the following:<BR>
		/// - If some or all of the raw packets aren't of type MBufRawPacket, a new temp MBufRawPacket instances will be
		///   created and packet data will be copied to them. This is necessary to allocate mbufs which will store the
		///   data to be sent. If performance is a critical factor please make sure you send only raw packets of type
		///   MBufRawPacket (or use the sendPackets overload that sends MBufRawPacketVector)
		/// - If the number of packets to send is higher than 64 this method will run multiple iterations of sending
		///   packets to DPDK, each iteration of 64 packets
		/// - The mbufs used or allocated in this method aren't freed by this method, they will be transparently freed
		///   by DPDK <BR><BR>
		/// @param[in] rawPacketsVec The vector of raw packet
		/// @return The number of packets actually and successfully sent
		uint16_t sendPackets(RawPacketVector& rawPacketsVec);
		/// @brief Send a raw packet to kernel.
		/// Please notice that if the raw packet isn't of type MBufRawPacket, a new temp MBufRawPacket
		/// will be created and the data will be copied to it. This is necessary to allocate an mbuf which will store
		/// the data to be sent. If performance is a critical factor please make sure you send a raw packet of type
		/// MBufRawPacket. Please also notice that the mbuf used or allocated in this method isn't freed by this method,
		/// it will be transparently freed by DPDK
		/// @param[in] rawPacket The raw packet to send
		/// @return True if packet was sent successfully or false if the packet wasn't sent for any other reason
		bool sendPacket(RawPacket& rawPacket);
		/// @brief Send a MBufRawPacket to kernel.
		/// Please notice that the mbuf used in this method isn't freed by this method, it will be transparently freed
		/// by DPDK
		/// @param[in] rawPacket The MBufRawPacket to send
		/// @return True if packet was sent successfully or false if device is not opened or if the packet wasn't sent
		/// for any other reason
		bool sendPacket(MBufRawPacket& rawPacket);
		/// @brief Send a parsed packet to kernel.
		/// Please notice that the mbuf used or allocated in this method isn't freed by this method, it will be
		/// transparently freed by DPDK
		/// @param[in] packet The parsed packet to send. Please notice that if the packet contains a raw packet which
		/// isn't of type MBufRawPacket, a new temp MBufRawPacket will be created and the data will be copied to it.
		/// This is necessary to allocate an mbuf which will store the data to be sent. If performance is a critical
		/// factor please make sure you send a parsed packet that contains a raw packet of type MBufRawPacket
		/// @return True if packet was sent successfully or false if device is not opened or if the packet wasn't sent
		/// for any other reason
		bool sendPacket(Packet& packet);

		/// @brief Start capturing packets asynchronously on this KNI interface.
		/// Each time a burst of packets is captured the onPacketArrives callback is called.
		/// The capture is done on a new thread created by this method, meaning all callback
		/// calls are done in a thread other than the caller thread.
		/// Capture process will stop and this capture thread will be terminated when calling stopCapture().
		/// This method must be called after the device is opened (i.e the open() method was called), otherwise an error
		/// will be returned. Capturing thread will be terminated automatically on KNI device destruction or when
		/// close() is called.
		/// @param[in] onPacketArrives A callback that is called each time a burst of packets is captured
		/// @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onPacketArrives callback each time it is called. This cookie is very useful for transferring objects
		/// that give context to the capture callback, for example: objects that counts packets, manages flow state or
		/// manages the application state according to the packet that was captured
		/// @return True if capture started successfully, false if (relevant log error is printed in any case):
		/// - Capture is already running
		/// - Device is not opened
		/// - Capture thread could not be created
		bool startCapture(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie);
		/// @brief Start capturing packets synchronously on this KNI interface in blocking mode.
		/// Blocking mode means that this method block and won't return until the user frees the blocking
		/// (via onPacketArrives callback) or until a user defined timeout expires.
		/// Whenever a burst of packets is captured the onPacketArrives callback is called and lets the user handle the
		/// packet. In each callback call the user should return true if he wants to release the block or false if it
		/// wants it to keep blocking. Regardless of this callback a timeout is defined when stop capturing. When this
		/// timeout expires the method will return.<BR> Please notice that stopCapture() isn't needed here because when
		/// the method returns (after timeout or per user decision) capturing on the device is stopped.
		/// @param[in] onPacketArrives A callback given by the user for handling incoming packets. After handling each
		/// burst of packets the user needs to return a boolean value. True value indicates stop capturing and stop
		/// blocking and false value indicates continue capturing and blocking
		/// @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		/// the onPacketArrives callback each time it is called. This cookie is very useful for transferring objects
		/// that give context to the capture callback, for example: objects that counts packets, manages flow state or
		/// manages the application state according to the packet that was captured
		/// @param[in] timeout A timeout in seconds for the blocking to stop even if the user didn't return "true" in
		/// the onPacketArrives callback If this timeout is set to 0 or less the timeout will be ignored, meaning the
		/// method will keep blocking until the user frees it via the onPacketArrives callback
		/// @return -1 if timeout expired, 1 if blocking was stopped via onPacketArrives callback or 0 if an error
		/// occurred (such as device not open etc.). When returning 0 an appropriate error message is printed to log

		int startCaptureBlockingMode(OnKniPacketArriveCallback onPacketArrives, void* onPacketArrivesUserCookie,
		                             int timeout);
		/// Stop a currently running asynchronous packet capture.
		void stopCapture();

		/// Takes appropriate actions for opening KNI device.
		/// @return true if the device was opened successfully, false if device is already opened,
		/// or KNI device configuration and startup failed
		bool open();
		/// @brief Close the KNI device.
		/// When device is closed it's not possible to work with it.
		/// Stops asynchronous packet capture if it is running.
		void close();

	private:
		struct rte_kni* m_Device;
		struct rte_mempool* m_MBufMempool;
		struct KniDeviceInfo
		{
			LinuxNicInformationSocket soc;
			KniLinkState link;
			KniPromiscuousMode promisc;
			uint16_t portId;
			uint16_t mtu;
			MacAddress mac;
			std::string name;

			bool init(const KniDeviceConfiguration& conf);
		} m_DeviceInfo;
		struct KniThread;
		struct KniCapturing
		{
			OnKniPacketArriveCallback callback;
			void* userCookie;
			KniThread* thread;

			static void runCapture(void* devicePointer, std::atomic<bool>& stopThread);
			inline bool isRunning() const
			{
				return thread != nullptr;
			}
			void cleanup();
		} m_Capturing;
		struct KniRequests
		{
			long sleepS;
			long sleepNs;
			KniThread* thread;

			static void runRequests(void* devicePointer, std::atomic<bool>& stopThread);
			void cleanup();
		} m_Requests;
	};

}  // namespace pcpp

// GCOVR_EXCL_STOP
