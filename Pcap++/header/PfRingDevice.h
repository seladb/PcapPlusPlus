#ifndef PCAPPP_PF_RING_DEVICE
#define PCAPPP_PF_RING_DEVICE

#include "PcapDevice.h"
#include "PcapFilter.h"
#include "MacAddress.h"
#include "SystemUtils.h"
#include "RawPacket.h"
#include "Packet.h"
#include <pthread.h>

/// @file

// forward declaration of PF_RING structs
struct __pfring;
typedef struct __pfring pfring;

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	class PfRingDevice;

	typedef void (*OnPfRingPacketsArriveCallback)(RawPacket* packets, uint32_t numOfPackets, uint8_t threadId, PfRingDevice* device, void* userCookie);


	/**
	 * @class PfRingDevice
	 * A class representing a PF_RING port
	 */
	class PfRingDevice : public IPcapDevice
	{
		friend class PfRingDeviceList;
	private:

		struct CoreConfiguration
		{
			pthread_t RxThread;
			pfring* Channel;
			bool IsInUse;
			bool IsAffinitySet;

			CoreConfiguration();
			void clear();
		};

		pfring** m_PfRingDescriptors;
		uint8_t m_NumOfOpenedRxChannels;
		char m_DeviceName[30];
		int m_InterfaceIndex;
		MacAddress m_MacAddress;
		int m_DeviceMTU;
		CoreConfiguration m_CoreConfiguration[MAX_NUM_OF_CORES];
		bool m_StopThread;
		OnPfRingPacketsArriveCallback m_OnPacketsArriveCallback;
		void* m_OnPacketsArriveUserCookie;
		bool m_ReentrantMode;
		bool m_HwClockEnabled;
		bool m_IsFilterCurrentlySet;

		PfRingDevice(const char* deviceName);

		bool initCoreConfigurationByCoreMask(CoreMask coreMask);
		static void* captureThreadMain(void *ptr);

		int openSingleRxChannel(const char* deviceName, pfring** ring);

		inline bool getIsHwClockEnable() { setPfRingDeviceAttributes(); return m_HwClockEnabled; }
		bool setPfRingDeviceClock(pfring* ring);

		void clearCoreConfiguration();
		int getCoresInUseCount();

		void setPfRingDeviceAttributes();

		bool sendData(const uint8_t* packetData, int packetDataLength, bool flushTxQueues);
	public:

		/**
		 * An enum representing the type of packet distribution between different RX channels
		 */
		enum ChannelDistribution
		{
			/**
			 * Packets are distributed between channels in a round-robin manner
			 */
			RoundRobin,
			/**
			 * Packets are distributed between channels per flow (each flow goes for different channel)
			 */
			PerFlow
		};

		/**
		 * A destructor for PfRingDevice class
		 */
		~PfRingDevice();

		/**
		 * Get the MAC address of the current device
		 * @return The MAC address of the current device
		 */
		MacAddress getMacAddress() { setPfRingDeviceAttributes(); return m_MacAddress; }

		/**
		 * Get PF_RING interface index of the current device
		 * @return PF_RING interface index of the current device
		 */
		int getInterfaceIndex() { setPfRingDeviceAttributes(); return m_InterfaceIndex; }

		/**
		 * Get MTU of the current device
		 * @return Upon success return the device MTU, 0 otherwise
		 */
		int getMtu() { setPfRingDeviceAttributes(); return m_DeviceMTU; }

		/**
		 * Return true if device supports hardware timestamping. If it does, this feature will be automatically set
		 * for this device. You can read more about this in PF_RING documentation
		 * @return True if device supports hardware timestamping, false otherwise
		 */
		bool isHwClockEnabledForDevice() { setPfRingDeviceAttributes(); return m_HwClockEnabled; }

		/**
		 * Gets the interface name (e.g eth0, eth1, etc.)
		 * @return The interface name
		 */
		inline std::string getDeviceName() { return std::string(m_DeviceName); }


		/**
		 * Start single-threaded capturing with callback. Works with open() or openSingleRxChannel().
		 * @param[in] onPacketsArrive A callback to call whenever a packet arrives
		 * @param[in] onPacketsArriveUserCookie A cookie that will be delivered to onPacketsArrive callback on every packet
		 * @return True if this action succeeds, false otherwise
		 */
		bool startCaptureSingleThread(OnPfRingPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie);

		/**
		 * Start multi-threaded (multi-core) capturing with callback. Works with openMultiRxChannels().
		 * This method will return an error if the number of opened channels is different than the number of threads/cores
		 * requested
		 * @param[in] onPacketsArrive A callback to call whenever a packet arrives
		 * @param[in] onPacketsArriveUserCookie A cookie that will be delivered to onPacketsArrive callback on every packet
		 * @param[in] coreMask The cores to be used as mask. For example:
		 * @return True if this action succeeds, false otherwise
		 */
		bool startCaptureMultiThread(OnPfRingPacketsArriveCallback onPacketsArrive, void* onPacketsArriveUserCookie, CoreMask coreMask);

		/**
		 * Stops capturing packets (works will all type of startCapture*)
		 */
		void stopCapture();


		/**
		 * Opens a single RX channel (=RX queue) on this interface. All packets will be received on a single thread
		 * without core affinity. If the channel ID requested doesn't exist on this interface, the method will fail
		 * (return false)
		 * @param[in] channelId The requested channel ID
		 * @return True if this action succeeds, false otherwise
		 */
		bool openSingleRxChannel(uint8_t channelId);

		/**
		 * Opens a set of RX channels (=RX queues) on this interface, identified by their IDs. All packets will be received on a single thread
		 * without core affinity. If one of the channel IDs requested doesn't exist on this interface, the method will fail
		 * (return false)
		 * @param[in] channelIds An array of channel IDs
		 * @param[in] numOfChannelIds The channel ID array size
		 * @return True if this action succeeds, false otherwise
		 */
		bool openMultiRxChannels(const uint8_t* channelIds, int numOfChannelIds);

		/**
		 * Opens numOfRxChannelsToOpen RX channels. If numOfRxChannelsToOpen is larger than available RX queues for this
		 * interface than a number of RX channels will be opened on each RX queue. For example: if the user asks for 10
		 * RX channels but the interface has only 4 RX queues, then 3 RX channels will be opened for RX-queue0 and RX-queue2,
		 * and 2 RX channels will be opened for RX-queue2 and RX-queue3.
		 * Packets will be distributed between different RX queues on per-flow manner, but within multiple RX channels in
		 * the same RX queue packet will be distributed according to distribution requested by "dist"
		 * @param[in] numOfRxChannelsToOpen Number of RX channels to open
		 * @param[in] dist Distribution method
		 * @return True if this action succeeds, false otherwise
		 */
		bool openMultiRxChannels(uint8_t numOfRxChannelsToOpen, ChannelDistribution dist);

		/**
		 * Gets the number of RX channels currently open. RX channels aren't necessary interface's RX queues
		 * because in some cases the user asks to open several channels on the same queue. For example: if the user uses
		 * openMultiRxChannels() and asks to open 8 channels but interface has only 4 RX queues, 2 channels will be
		 * opened for each RX queue
		 * @return Number of opened RX channels
		 */
		inline uint8_t getNumOfOpenedRxChannels() { return m_NumOfOpenedRxChannels; }

		/**
		 * Gets the total number of RX channels (RX queues) this interface has
		 * @return The number of RX channels (queues) for this interface
		 */
		uint8_t getTotalNumOfRxChannels();

		/**
		 * Gets the core used in the current thread context
		 * @return The system core used in the current thread context
		 */
		SystemCore getCurrentCoreId();

		/**
		 * Get the statistics of a specific thread/core (=RX channel)
		 * @param[in] core The requested core
		 * @param[out] stats A reference for the stats object where the stats are written. Current values will be overriden
		 */
		void getThreadStatistics(SystemCore core, pcap_stat& stats);

		/**
		 * Get the statistics of the current thread/core (=RX channel)
		 * @param[out] stats A reference for the stats object where the stats are written. Current values will be overriden
		 */
		void getCurrentThreadStatistics(pcap_stat& stats);



		// implement abstract methods


		/**
		 * Opens the entire device (including all RX channels/queues on this interface). All packets will be received
		 * on a single thread without core affinity
		 * @return True if this action succeeds, false otherwise
		 */
		bool open();

		/**
		 * Closes all RX channels currently opened in device
		 */
		void close();

		/**
		 * Get the statistics for the entire device. If more than 1 RX channel is opened, this method aggregates the stats
		 * of all channels
		 * @param[out] stats A reference for the stats object where the stats are written. Current values will be overriden
		 */
		void getStatistics(pcap_stat& stats);


		/**
		 * Sets a filter to the device
		 * @param[in] filter The filter to set
		 */
		bool setFilter(GeneralFilter& filter);

		/**
		 * Sets a BPF filter to the device
		 * @param[in] filterAsString The BPF filter in string format
		 */
		bool setFilter(std::string filterAsString);

		/**
		 * Remove a filter if currently set
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		bool removeFilter();

		/**
		 * Return true if filter is currently set
		 * @return True if filter is currently set, false otherwise
		 */
		bool isFilterCurrentlySet();


		/**
		 * Send a raw packet. This packet must be fully specified (the MAC address up)
		 * and it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the data in any way (hence the "const" declaration).
		 * Note this method flushes the TX queues after the data is sent. So if you want to send several packets
		 * In the burst please use sendPackets()
		 * @param[in] rawPacket The raw packet to send
		 * @return True if raw packet was sent completely, false otherwise
		 */
		bool sendPacket(const RawPacket& rawPacket);

		/**
		 * Send raw data. This data must be a valid and fully specified packet (the MAC address up);
		 * it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the data in any way (hence the "const" declaration).
		 * Note this method flushes the TX queues after the data is sent. So if you want to send several packets
		 * in the burst please use sendPackets()
		 * @param[in] packetData The raw data to send
		 * @param[in] packetDataLength the length of packetData
		 * @return True if raw packet was sent completely, false otherwise
		 *
		 */
		bool sendPacket(const uint8_t* packetData, int packetDataLength);

		/**
		 * Send a packet. This packet must be fully specified (the MAC address up)
		 * and it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the data in any way (hence the "const" declaration).
		 * Note this method flushes the TX queues after the data is sent. So if you want to send several packets
		 * In the burst please use sendPackets()
		 * @param[in] packet The packet to send
		 * @return True if raw packet was sent completely, false otherwise
		 */
		bool sendPacket(const Packet& packet);

		/**
		 * Send raw packets. All raw packets must be fully specified (the MAC address up)
		 * and it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the raw packets data in any way (hence the "const" declaration).
		 * This method flushes the TX queues only when the last packet is sent
		 * @param[in] rawPacketsArr The RawPacket array
		 * @param[in] arrLength RawPacket array length
		 * @return Number of packets that were sent completely
		 */
		int sendPackets(const RawPacket* rawPacketsArr, int arrLength);

		/**
		 * Send packets. All packets must be fully specified (the MAC address up)
		 * and it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the packets data in any way (hence the "const" declaration).
		 * This method flushes the TX queues only when the last packet is sent
		 * @param[in] packetsArr An array of pointers to Packet objects
		 * @param[in] arrLength Packet pointers array length
		 * @return Number of packets that were sent completely
		 */
		int sendPackets(const Packet** packetsArr, int arrLength);

		/**
		 * Send all raw packets pointed by the RawPacketVector. All packets must be fully specified (the MAC address up)
		 * and it will be transmitted as-is without any further manipulation.
		 * This method doesn't change or manipulate the packets data in any way (hence the "const" declaration).
		 * This method flushes the TX queues only when the last packet is sent
		 * @param[in] rawPackets The raw packet vector
		 * @return Number of raw packets that were sent completely
		 */
		int sendPackets(const RawPacketVector& rawPackets);
	};

} // namespace pcpp

#endif /* PCAPPP_PF_RING_DEVICE */
