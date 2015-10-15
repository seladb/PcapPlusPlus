#ifndef PCAPPP_DPDK_DEVICE
#define PCAPPP_DPDK_DEVICE

#ifdef USE_DPDK

#include <pthread.h>
#include <MacAddress.h>
#include <SystemUtils.h>
#include <RawPacket.h>
#include <PcapLiveDevice.h>

/// @file

class DpdkDeviceList;
class DpdkDevice;

/**
 * An enum describing all PMD (poll mode driver) type supported by DPDK
 */
enum DpdkPMDType {
	/** Unknown PMD type */
	PMD_UNKNOWN,
	/** Link Bonding for 1GbE and 10GbE ports to allow the aggregation of multiple (slave) NICs into a single logical interface*/
	PMD_BOND,
	/** Intel E1000 PMD */
	PMD_E1000EM,
	/** Intel 1GbE PMD */
	PMD_IGB,
	/** Intel 1GbE virtual function PMD */
	PMD_IGBVF,
	/** Cisco enic (UCS Virtual Interface Card) PMD */
	PMD_ENIC,
	/** Intel fm10k PMD */
	PMD_FM10K,
	/** Intel 40GbE PMD */
	PMD_I40E,
	/** Intel 40GbE virtual function PMD */
	PMD_I40EVF,
	/** Intel 10GbE PMD */
	PMD_IXGBE,
	/** Intel 10GbE virtual function PMD */
	PMD_IXGBEVF,
	/** Mellanox ConnectX-3, ConnectX-3 Pro PMD */
	PMD_MLX4,
	/** Null PMD */
	PMD_NULL,
	/** pcap file PMD */
	PMD_PCAP,
	/** ring-based (memory) PMD */
	PMD_RING,
	/** VirtIO PMD */
	PMD_VIRTIO,
	/** VMWare VMXNET3 PMD */
	PMD_VMXNET3,
	/** Xen Project PMD */
	PMD_XENVIRT,
	/** AF_PACKET PMD */
	PMD_AF_PACKET
};

struct rte_mbuf;
struct rte_mempool;
struct rte_eth_conf;

class DpdkDevice;

/**
 * @class MBufRawPacket
 * A class that inherits RawPacket and wraps DPDK's mbuf object (which wraps a network raw packet) and still is compatible with
 * PcapPlusPlus framework. Using MBufRawPacket is be almost similar as using RawPacket, the implementation differences are
 * encapsulated in class implementation. For example: user can create and manipulate a Packet object from MBufRawPacket the
 * same way it is done with RawPacket; User can use PcapFileWriterDevice to save MBufRawPacket to pcap the same way it's used with
 * RawPacket; etc.
 * The main difference is that RawPacket contains a pointer to the data itself and MBufRawPacket is holding a pointer to an mbuf
 * object that contains a pointer to the data. This implies that MBufRawPacket without an mbuf allocated to it is worthless.
 * Getting instances of MBufRawPacket can be done in one to two ways:
 * - Receiving packets with DpdkDevice. In this case DpdkDevice takes care of getting the mbuf from DPDK and wrapping it with
 * MBufRawPacket
 * - Creating MBufRawPacket from scratch (in order to send it with DpdkDevice, for example). In this case the user should call
 * the init() method after constructing the object in order to allocate a new mbuf from DPDK (using the mbuf pool inside a certain
 * DpdkDevice)
 */
class MBufRawPacket : public RawPacket
{
	friend class DpdkDevice;

private:
	struct rte_mbuf* m_MBuf;
	DpdkDevice* m_Device;

	void setMBuf(struct rte_mbuf* mBuf, timeval timestamp);
public:

	/**
	 * A default c'tor for this class. Initializes an instance of this class without an mbuf attached to it. In order to allocate
	 * an mbuf the user should call the init() method. Without calling init() the instance of this class is worthless.
	 * This c'tor can be used for initializing an array of MBufRawPacket (which requires an empty c'tor)
	 */
	MBufRawPacket() : RawPacket(), m_MBuf(NULL), m_Device(NULL) { m_DeleteRawDataAtDestructor = false; }

	/**
	 * A d'tor for this class. Once called it frees the mbuf attached to it (returning it back to the mbuf pool it was allocated from)
	 */
	virtual ~MBufRawPacket();

	/**
	 * A copy c'tor for this class. The copy c'tor allocates a new mbuf from the same pool the original mbuf was
	 * allocated from, attaches the new mbuf to this instance of MBufRawPacket and copies the data from the original mbuf
	 * to the new mbuf
	 * @param[in] other The MBufRawPacket instance to copy from
	 */
	MBufRawPacket(const MBufRawPacket& other);

	/**
	 * Initialize an instance of this class. Initialization includes allocating an mbuf from the pool resides in the DpdkDevice.
	 * The user should call this method only once per instance. Calling it more than once will result with an error
	 * @param[in] device The DpdkDevice which has the pool to allocate the mbuf from
	 * @return True if initialization succeeded and false if this method was already called for this instance (and an mbuf is
	 * already attched) or if allocating an mbuf from the pool failed for some reason
	 */
	bool init(DpdkDevice* device);

	// overridden methods

	/**
	 * An assignment operator for this class. Copies the data from the mbuf attached to the other MBufRawPacket to the mbuf
	 * attached to this instance. If instance is not initialized (meaning no mbuf is attached) nothing will be copied and
	 * instance will remain uninitialized (also, an error will be printed)
	 * @param[in] other The MBufRawPacket to assign data from
	 */
	MBufRawPacket& operator=(const MBufRawPacket& other);

	/**
	 * Set raw data to the mbuf by copying the data to it. In order to stay compatible with the ancestor method
	 * which takes control of the data pointer and frees it when RawPacket is destroyed, this method frees this pointer right away after
	 * data is copied to the mbuf. So when using this method please notice that after it's called pRawData memory is free, don't
	 * use this pointer again. In addition, if raw packet isn't initialized (mbuf is NULL), this method will call the init() method
	 * @param[in] pRawData A pointer to the new raw data
	 * @param[in] rawDataLen The new raw data length in bytes
	 * @param[in] timestamp The timestamp packet was received by the NIC
	 * @return True if raw data was copied to the mbuf successfully, false if rawDataLen is larger than mbuf max size, if initialization
	 * failed or if copying the data to the mbuf failed. In all of these cases an error will be printed to log
	 */
	bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp);

	/**
	 * Clears the object and frees the mbuf
	 */
	void clear();

	/**
	 * Append data to the end of current data. This method uses the same mbuf already allocated and tries to append more space and
	 * then copy the data to it. If MBufRawPacket is not initialize (mbuf is NULL) or mbuf append failed an error is printed to log
	 * @param[in] dataToAppend A pointer to the data to append to current raw data
	 * @param[in] dataToAppendLen Length in bytes of dataToAppend
	 */
	void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

	/**
	 * Insert new data at some index of the current data and shift the remaining old data to the end. This method uses the
	 * same mbuf already allocated and tries to append more space to it. Then it just copies dataToAppend at the relevant index and shifts
	 * the remaining data to the end. If MBufRawPacket is not initialize (mbuf is NULL) or mbuf append failed an error is printed to log
	 * @param[in] atIndex The index to insert the new data to
	 * @param[in] dataToInsert A pointer to the new data to insert
	 * @param[in] dataToInsertLen Length in bytes of dataToInsert
	 */
	void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

	/**
	 * Remove certain number of bytes from current raw data buffer. All data after the removed bytes will be shifted back. This method
	 * uses the mbuf already allocated and tries to trim space from it
	 * @param[in] atIndex The index to start removing bytes from
	 * @param[in] numOfBytesToRemove Number of bytes to remove
	 * @return True if all bytes were removed successfully, or false if MBufRawPacket is not initialize (mbuf is NULL), mbuf trim
	 * failed or logatIndex+numOfBytesToRemove is out-of-bounds of the raw data buffer. In all of these cases an error is printed to log
	 */
	bool removeData(int atIndex, size_t numOfBytesToRemove);

	/**
	 * This overridden method,in contrast to its ancestor RawPacket#reallocateData() doesn't need to do anything because mbuf is already
	 * allocated to its maximum extent. So it only performs a check to verify the size after re-allocation doesn't exceed mbuf max size
	 * @param[in] newBufferLength The new buffer length as required by the user
	 * @return True if new size is larger than current size but smaller than mbuf max size, false otherwise
	 */
	bool reallocateData(size_t newBufferLength);
};

/**
 * @typedef OnDpdkPacketsArriveCallback
 * A callback that is called when a burst of packets are captured by DpdkDevice
 * @param[in] packets A pointer to an array of MBufRawPacket
 * @param[in] numOfPackets The length of the array
 * @param[in] threadId The thread/core ID who captured the packets
 * @param[in] device A pointer to the DpdkDevice who captured the packets
 * @param[in] userCookie The user cookie assigned by the user in DpdkDevice#startCaptureSingleThread() or DpdkDevice#startCaptureMultiThreads
 */
typedef void (*OnDpdkPacketsArriveCallback)(MBufRawPacket* packets, uint32_t numOfPackets, uint8_t threadId, DpdkDevice* device, void* userCookie);

/**
 * @class PciAddress
 * A class representing a PCI address
 */
class PciAddress
{
public:
	/**
	 * Default c'tor that initializes all PCI address fields to 0 (until set otherwise, address will look like: 0000:00:00.0)
	 */
	PciAddress() { domain = 0; bus = 0; devid = 0; function = 0; }

	/**
	 * A c'tor that initialized all PCI address fields
	 * @param[in] domain Device domain
	 * @param[in] bus Device bus id
	 * @param[in] devid Device ID
	 * @param[in] function Device function
	 */
	PciAddress(uint16_t domain, uint8_t bus, uint8_t devid, uint8_t function)
	{
		this->domain = domain;
		this->bus = bus;
		this->devid = devid;
		this->function = function;
	}

	/** Device domain */
	uint16_t domain;
	/** Device bus id */
	uint8_t bus;
	/** Device ID */
	uint8_t devid;
	/** Device function */
	uint8_t function;

	/**
	 * @return The string format of the PCI address (xxxx:xx:xx.x)
	 */
	string toString()
	{
		char pciString[15];
		snprintf(pciString, 15, "%04x:%02x:%02x.%x", domain, bus, devid, function);
		return string(pciString);
	}

	/**
	 * Comparison operator overload. Two PCI addresses are equal if all of their members (domain, bus, devid, function) are equal
	 */
	bool operator==(const PciAddress &other) const
	{
		return (domain == other.domain && bus == other.bus && devid == other.devid && function == other.function);
	}
};


/**
 * @class DpdkDevice
 * TODO
 */
class DpdkDevice : public IPcapDevice
{
	friend class DpdkDeviceList;
	friend class MBufRawPacket;
public:

	/**
	 * @struct DpdkDeviceConfiguration
	 * A struct that contains the user configurable parameters for a DpdkDevice. If the user wants the default parameters, they exist in the c'tor
	 */
	struct DpdkDeviceConfiguration
	{
		/**
		 * When configuring a DPDK RX queue, DPDK creates descriptors it will be using for receiving packets from the network to this RX queue.
		 * This parameter enables to configure the number of descriptors that will be created for each RX queue
		 */
		uint16_t receiveDescriptorsNumber;

		/**
		 * When configuring a DPDK TX queue, DPDK creates descriptors it will be using for transmitting packets to the network through this TX queue.
		 * This parameter enables to configure the number of descriptors that will be created for each TX queue
		 */
		uint16_t transmitDescriptorsNumber;

		/**
		 * The c'tor for this strcut
		 * @param[in] receiveDescriptorsNumber An optional parameter for defining the number of RX descriptors that will be allocated for each RX queue.
		 * Default value is 128
		 * @param[in] transmitDescriptorsNumber An optional parameter for defining the number of TX descriptors that will be allocated for each TX queue.
		 * Default value is 512
		 */
		DpdkDeviceConfiguration(uint16_t receiveDescriptorsNumber = 128, uint16_t transmitDescriptorsNumber = 512)
		{
			this->receiveDescriptorsNumber = receiveDescriptorsNumber;
			this->transmitDescriptorsNumber = transmitDescriptorsNumber;
		}
	};

	/**
	 * @struct LinkStatus
	 * A struct that contains the link status of a DpdkDevice (DPDK port). Should be used with DpdkDevice#getLinkStatus()
	 */
	struct LinkStatus
	{
		/** Enum for describing link duplex */
		enum LinkDuplex { FULL_DUPLEX, HALF_DUPLEX };

		/** Link up or down */
		bool linkUp;
		/** Link speed in Mbps (for example: 10Gbe will show 10000 */
		int linkSpeedMbps;
		/** Link duplex (half/full duplex) */
		LinkDuplex linkDuplex;
	};

	virtual ~DpdkDevice() {}

	/**
	 * @return The device (DPDK port) ID
	 */
	inline int getDeviceId() { return m_Id; }
	/**
	 * @return The device name which is in the format of 'DPDK_[PORT-ID]'
	 */
	inline string getDeviceName() { return string(m_DeviceName); }

	/**
	 * @return The MAC address of the device (DPDK port)
	 */
	inline MacAddress getMacAddress() { return m_MacAddress; }

	/**
	 * @return The name of the PMD (poll mode driver) DPDK is using for this device (DPDK port). You can read about PMDs in the DPDK documentation:
	 * http://dpdk.org/doc/guides/prog_guide/poll_mode_drv.html
	 */
	inline string getPMDName() { return m_PMDName; }

	/**
	 * @return The enum type of the PMD (poll mode driver) DPDK is using for this device (DPDK port). You can read about PMDs in the DPDK documentation:
	 * http://dpdk.org/doc/guides/prog_guide/poll_mode_drv.html
	 */
	inline DpdkPMDType getPMDType() { return m_PMDType; }

	/**
	 * @return The PCI address of this device
	 */
	inline PciAddress getPciAddress() { return m_PciAddress; }

	/**
	 * @return The device's maximum transmission unit (MTU) in bytes
	 */
	inline uint16_t getMtu() { return m_DeviceMtu; }

	/**
	 * Set a new maximum transmission unit (MTU) for this device
	 * @param[in] newMtu The new MTU in bytes
	 * @return True if MTU was set successfully, false otherwise with appropriate error
	 */
	bool setMtu(uint16_t newMtu);

	/**
	 * @return True if this device is a virtual interface (such as VMXNET3, 1G/10G virtual function, etc.), false otherwise
	 */
	bool isVirtual();

	/**
	 * Get the link status (link up/down, link speed and link duplex)
	 * @param[out] linkStatus The object the result shall be written into
	 */
	void getLinkStatus(LinkStatus& linkStatus);

	/**
	 * @return The core ID used in this context
	 */
	uint32_t getCurrentCoreId();

	/**
	 * @return The number of RX queues currently opened for this device (were configured in openMultiQueues() )
	 */
	uint16_t getNumOfOpenedRxQueues() { return m_NumOfRxQueuesOpened; }

	/**
	 * @return The number of TX queues currently opened for this device (were configured in openMultiQueues() )
	 */
	uint16_t getNumOfOpenedTxQueues() { return m_NumOfTxQueuesOpened; }

	/**
	 * @return The total number of RX queues available for this device
	 */
	uint16_t getTotalNumOfRxQueues() { return m_TotalAvailableRxQueues; }

	/**
	 * @return The total number of TX queues available for this device
	 */
	uint16_t getTotalNumOfTxQueues() { return m_TotalAvailableTxQueues; }


	/**
	 * Receive packets from the network
	 * @param[out] rawPacketsArr A vector where all received packets will be written into
	 * @param[in] rxQueueId The RX queue to receive packets from
	 * @return True if packets were received and no error occurred or false if device isn't opened, or if device is currently capturing
	 * (using startCaptureSingleThread() or startCaptureMultiThreads(), or if rxQueueId doesn't exist on device, or DPDK receive packets method returned
	 * an error
	 */
	bool receivePackets(RawPacketVector& rawPacketsArr, uint16_t rxQueueId);

	/**
	 * Receive packets from the network as raw packets
	 * @param[out] rawPacketsArr An array of MBufRawPacket pointers where all received packets will be written into
	 * @param[out] rawPacketArrLength A variable where MBufRawPacket pointers array length will be written into
	 * @param[in] rxQueueId The RX queue to receive packets from
	 * @return True if packets were received and no error occurred or false if device isn't opened, or if device is currently capturing
	 * (using startCaptureSingleThread() or startCaptureMultiThreads(), or if rxQueueId doesn't exist on device, or DPDK receive packets method returned
	 * an error
	 */
	bool receivePackets(MBufRawPacket** rawPacketsArr, int& rawPacketArrLength, uint16_t rxQueueId);

	/**
	 * Receive packets from the network as parsed packets
	 * @param[out] packetsArr An array of Packet pointers where all received packets will be written into
	 * @param[out] packetsArrLength A variable where Packet pointers array length will be written into
	 * @param[in] rxQueueId The RX queue to receive packets from
	 * @return True if packets were received and no error occurred or false if device isn't opened, or if device is currently capturing
	 * (using startCaptureSingleThread() or startCaptureMultiThreads(), or if rxQueueId doesn't exist on device, or DPDK receive packets method returned
	 * an error
	 */
	bool receivePackets(Packet** packetsArr, int& packetsArrLength, uint16_t rxQueueId);

	/**
	 * Send an array of raw packets to the network.<BR><BR>
	 * The sending algorithm works as follows: the algorithm tries to allocate a
	 * group of mbufs from the device's pool. For each mbuf allocated a raw packet data is copied to the mbuf. The algorithm will
	 * continue allocating mbufs until: no more raw packets to send OR cannot allocate mbufs because pool is empty OR number
	 * of allocated mbuf is higher than 80% of TX descriptors. When one of these happen the algorithm will try to send the mbufs
	 * through DPDK API. DPDK will free the allocated mbufs. Then the algorithm will try to allocate mbufs again and send them
	 * again until no more raw packets to send or it failed to allocated an mbuf 3 times in a raw. Raw packets that are bigger
	 * than the size of an mbuf or with length 0 will be skipped. Same goes for raw packets that their data could not be copied
	 * to the allocated mbuf for some reason. An error will be printed to each such packet
	 * @param[in] rawPacketsArr A pointer to an array of raw packets
	 * @param[in] arrLength The length of the array
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packets will be sent on. The default is
	 * TX queue 0
	 * @return The number of packets successfully sent. If device is not opened or TX queue isn't open, 0 will be returned
	 */
	int sendPackets(const RawPacket* rawPacketsArr, int arrLength, uint16_t txQueueId = 0);

	/**
	 * Send an array of parsed packets to the network. For the send packets algorithm see sendPackets()
	 * @param[in] packetsArr A pointer to an array of parsed packet pointers
	 * @param[in] arrLength The length of the array
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packets will be sent on. The default is
	 * TX queue 0
	 * @return The number of packets successfully sent. If device is not opened or TX queue isn't open, 0 will be returned
	 */
	int sendPackets(const Packet** packetsArr, int arrLength, uint16_t txQueueId = 0);

	/**
	 * Send a vector of raw packets to the network. For the send packets algorithm see sendPackets()
	 * @param[in] rawPacketsVec The vector of raw packet
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packets will be sent on. The default is
	 * TX queue 0
	 * @return The number of packets successfully sent. If device is not opened or TX queue isn't open, 0 will be returned
	 */
	int sendPackets(const RawPacketVector& rawPacketsVec, uint16_t txQueueId = 0);

	/**
	 * Send packet raw data to the network. For the send packets algorithm see sendPackets(), but keep in mind this method send
	 * only 1 packet
	 * @param[in] packetData The packet raw data to send
	 * @param[in] packetDataLength The length of the raw data
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packet will be sent on. The default is
	 * TX queue 0
	 * @return True if packet was sent successfully or false if device is not opened, TX queue isn't open or the sending algorithm
	 * failed (for example: couldn't allocate an mbuf or DPDK returned an error)
	 */
	bool sendPacket(const uint8_t* packetData, int packetDataLength, uint16_t txQueueId = 0);

	/**
	 * Send a raw packet to the network. For the send packets algorithm see sendPackets(), but keep in mind this method send
	 * only 1 packet
	 * @param[in] rawPacket The raw packet to send
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packet will be sent on. The default is
	 * TX queue 0
	 * @return True if packet was sent successfully or false if device is not opened, TX queue isn't open or the sending algorithm
	 * failed (for example: couldn't allocate an mbuf or DPDK returned an error)
	 */
	bool sendPacket(const RawPacket& rawPacket, uint16_t txQueueId = 0);

	/**
	 * Send a parsed packet to the network. For the send packets algorithm see sendPackets(), but keep in mind this method send
	 * only 1 packet
	 * @param[in] packet The packet to send
	 * @param[in] txQueueId An optional parameter which indicate to which TX queue the packet will be sent on. The default is
	 * TX queue 0
	 * @return True if packet was sent successfully or false if device is not opened, TX queue isn't open or the sending algorithm
	 * failed (for example: couldn't allocate an mbuf or DPDK returned an error)
	 */
	bool sendPacket(const Packet& packet, uint16_t txQueueId = 0);

	/**
	 * Overridden method from IPcapDevice, working with filters is currently not implemented for DpdkDevice
	 * @return Always false with a "Filters aren't supported in DPDK device" error message
	 */
	bool setFilter(GeneralFilter& filter);

	/**
	 * Overridden method from IPcapDevice, working with filters is currently not implemented for DpdkDevice
	 * @return Always false with a "Filters aren't supported in DPDK device" error message
	 */
	bool setFilter(string filterAsString);

	/**
	 * Open the DPDK device. Notice opening the device only makes the device ready for use, it doesn't start packet capturing.
	 * The device is opened in promiscuous mode
	 * @param[in] numOfRxQueuesToOpen Number of RX queues to setup. This number must be smaller or equal to the return value of getTotalNumOfRxQueues()
	 * @param[in] numOfTxQueuesToOpen Number of TX queues to setup. This number must be smaller or equal to the return value of getTotalNumOfTxQueues()
	 * @param[in] config Optional param for defining special port configuration parameters such as number of receive/transmit descriptors. If not set the default
	 * parameters will be set (see DpdkDeviceConfiguration)
	 * @return True if the device was opened successfully, false if device is already opened, if RX/TX queues configuration failed or of DPDK port
	 * configuration and startup failed
	 */
	bool openMultiQueues(uint16_t numOfRxQueuesToOpen, uint16_t numOfTxQueuesToOpen, const DpdkDeviceConfiguration& config = DpdkDeviceConfiguration());

	/**
	 * There are two ways to capture packets using DpdkDevice: one of them is using worker threads (@see DpdkDeviceList#startDpdkWorkerThreads() ) and
	 * the other way is using a callback which is invoked on each a burst of packets are captured. This method implements the second way.
	 * After invoking this method the DpdkDevice enters capture mode and starts capturing packets.
	 * This method assumes there is only 1 RX queue opened for this device, otherwise an error is returned. It then allocates a core and creates 1 thread
	 * that runs in an endless loop and tries to capture packets using DPDK. Each time a burst of packets is captured a user callback is invoked with the user
	 * cookie as a parameter. This loop continue until stopCapture() is called. Notice: since the callback is invoked for packet burst captured
	 * using this method to can be slower than using worker threads. On the other hand, it's a simpler way comparing to worker threads
	 * @param[in] onPacketsArrive The user callback which will be invoked each time packet burst is captured by the device
	 * @param[in] onPacketsArriveUserCookie The user callback is invoked with this cookie as a parameter. It can be used to pass
	 * information from the user application to the callback
	 * @return True if capture thread started successfully or false if device is already in capture mode, number of opened RX queues isn't equal
	 * to 1, if the method couldn't find an available core to allocate for the capture thread, or if thread invocation failed. In
	 * all of these cases an appropriate error message will be printed
	 */
	bool startCaptureSingleThread(OnDpdkPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie);

	/**
	 * This method does exactly what @see startCaptureSingleThread() does, but with more than one RX queue / capturing thread. It's called
	 * with a core mask as a parameter and creates a packet capture thread on every core. Each thread is assigned with a specific
	 * RX queue. This method assumes all cores in the core-mask are available and there are enough opened RX queues to match for each thread.
	 * If these assumptions are not true an error is returned. After invoking all threads, all of them run in an endless loop
	 * and try to capture packets from their designated RX queues. Each time a burst of packets is captured the callback is invoked with the user
	 * cookie and the thread ID that captured the packets
	 * @param[in] onPacketsArrive The user callback which will be invoked each time a burst of packets is captured by the device
	 * @param[in] onPacketsArriveUserCookie The user callback is invoked with this cookie as a parameter. It can be used to pass
	 * information from the user application to the callback
	 * @param coreMask The core-mask for creating the cpature threads
	 * @return True if all capture threads started successfully or false if device is already in capture mode, not all cores in the core-mask are
	 * available to DPDK, there are not enough opened RX queues to match all cores in the core-mask, or if thread invocation failed. In
	 * all of these cases an appropriate error message will be printed
	 */
	bool startCaptureMultiThreads(OnDpdkPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie, CoreMask coreMask);

	/**
	 * If device is in capture mode started by invoking startCaptureSingleThread() or startCaptureMultiThreads(), this method
	 * will stop all capturing threads and turn the device to non-capturing mode
	 */
	void stopCapture();

	//overridden methods

	/**
	 * Overridden method from IPcapDevice. It calls openMultiQueues() with 1 RX queue and 1 TX queue
	 * Notice opening the device only makes the device ready for use, it doesn't start packet capturing. The device is opened in promiscuous mode
	 * @return True if the device was opened successfully, false if device is already opened, if RX/TX queues configuration failed or of DPDK port
	 * configuration and startup failed
	 */
	bool open() { return openMultiQueues(1, 1); };

	/**
	 * Close the DpdkDevice. When device is closed it's not possible to do any work with it
	 */
	void close();

	/**
	 * Receive statistics from device
	 * @todo pcap_stat is poor struct that doesn't contain all the information DPDK can provide. Consider using a more extensive struct
	 */
	void getStatistics(pcap_stat& stats);

private:

	struct DpdkCoreConfiguration
	{
		int RxQueueId;
		bool IsCoreInUse;

		void clear() { RxQueueId = -1; IsCoreInUse = false; }

		DpdkCoreConfiguration() : RxQueueId(-1), IsCoreInUse(false) {}
	};

	DpdkDevice(int port, uint32_t mBufPoolSize);
	bool initMemPool(struct rte_mempool*& memPool, const char* mempoolName, uint32_t mBufPoolSize);

	bool configurePort(uint8_t numOfRxQueues, uint8_t numOfTxQueues);
	bool initQueues(uint8_t numOfRxQueuesToInit, uint8_t numOfTxQueuesToInit);
	bool startDevice();

	static int dpdkCaptureThreadMain(void *ptr);

	void clearCoreConfiguration();
	bool initCoreConfigurationByCoreMask(CoreMask coreMask);
	int getCoresInUseCount();

	void setDeviceInfo();

	typedef RawPacket* (*packetIterator)(void* packetStorage, int index);
	int sendPacketsInner(uint16_t txQueueId, void* packetStorage, packetIterator iter, int arrLength);

	char m_DeviceName[30];
	DpdkPMDType m_PMDType;
	string m_PMDName;
	PciAddress m_PciAddress;

	DpdkDeviceConfiguration m_Config;

	int m_Id;
	MacAddress m_MacAddress;
	uint16_t m_DeviceMtu;
	struct rte_mempool* m_MBufMempool;
	struct rte_mbuf* m_mBufArray[256];
	DpdkCoreConfiguration m_CoreConfiguration[MAX_NUM_OF_CORES];
	uint16_t m_TotalAvailableRxQueues;
	uint16_t m_TotalAvailableTxQueues;
	uint16_t m_NumOfRxQueuesOpened;
	uint16_t m_NumOfTxQueuesOpened;
	OnDpdkPacketsArriveCallback m_OnPacketsArriveCallback;
	void* m_OnPacketsArriveUserCookie;
	bool m_StopThread;

	 // RSS key used by the NIC for load balancing the packets between cores
	static uint8_t m_RSSKey[40];
};

#endif /* USE_DPDK */

#endif /* PCAPPP_DPDK_DEVICE */
