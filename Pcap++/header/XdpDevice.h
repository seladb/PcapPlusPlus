#pragma once

/// @file

#include "Device.h"
#include <utility>
#include <functional>

/// @namespace pcpp
/// @
namespace pcpp
{
	/// @class XdpDevice
	/// A class wrapping the main functionality of using AF_XDP (XSK) sockets
	/// which are optimized for high performance packet processing.
	///
	/// It provides methods for configuring and initializing an AF_XDP socket, and then send and receive packets through
	/// it. It also provides a method for gathering statistics from the socket.
	class XdpDevice : public IDevice
	{
	public:
		/// @typedef OnPacketsArrive
		/// The callback that is called whenever packets are received on the socket
		/// @param[in] packets An array of the raw packets received
		/// @param[in] packetCount The number of packets received
		/// @param[in] device The XdpDevice packets are received from (represents the AF_XDP socket)
		/// @param[in] userCookie A pointer to an object set by the user when receivePackets() started
		typedef void (*OnPacketsArrive)(RawPacket packets[], uint32_t packetCount, XdpDevice* device, void* userCookie);

		/// @struct XdpDeviceConfiguration
		/// A struct containing the configuration parameters available for opening an XDP device
		struct XdpDeviceConfiguration
		{
			/// @enum AttachMode
			/// AF_XDP operation mode
			enum AttachMode
			{
				/// A fallback mode that works for any network device. Use it if the network driver doesn't have support
				/// for XDP
				SkbMode = 1,
				/// Use this mode if the network driver has support for XDP
				DriverMode = 2,
				/// Automatically detect whether driver mode is supported, otherwise fallback to SKB mode
				AutoMode = 3
			};

			/// AF_XDP operation mode
			AttachMode attachMode;

			/// UMEM is a region of virtual contiguous memory, divided into equal-sized frames.
			/// This parameter determines the number of frames that will be allocated as pert of the UMEM.
			uint16_t umemNumFrames;

			/// UMEM is a region of virtual contiguous memory, divided into equal-sized frames.
			/// This parameter determines the frame size that will be allocated.
			/// NOTE: the frame size should be equal to the memory page size (use getpagesize() to determine this size)
			uint16_t umemFrameSize;

			/// The size of the fill ring used by the AF_XDP socket. This size should be a power of two
			/// and less or equal to the total number of UMEM frames
			uint32_t fillRingSize;

			/// The size of the completion ring used by the AF_XDP socket. This size should be a power of two
			/// and less or equal to the total number of UMEM frames
			uint32_t completionRingSize;

			/// The size of the RX ring used by the AF_XDP socket. This size should be a power of two
			/// and less or equal to the total number of UMEM frames
			uint32_t rxSize;

			/// The size of the TX ring used by the AF_XDP socket. This size should be a power of two
			/// and less or equal to the total number of UMEM frames
			uint32_t txSize;

			/// The max number of packets to be received or sent in one batch
			uint16_t rxTxBatchSize;

			/// A c'tor for this struct. Each parameter has a default value described below.
			/// @param[in] attachMode AF_XDP operation mode. The default value is auto mode
			/// @param[in] umemNumFrames Number of UMEM frames to allocate. The default value is 4096
			/// @param[in] umemFrameSize The size of each UMEM frame. The default value is equal to getpagesize()
			/// @param[in] fillRingSize The size of the fill ring used by the AF_XDP socket. The default value is 4096
			/// @param[in] completionRingSize The size of the completion ring used by the AF_XDP socket. The default
			/// value is 2048
			/// @param[in] rxSize The size of the RX ring used by the AF_XDP socket. The default value is 2048
			/// @param[in] txSize The size of the TX ring used by the AF_XDP socket. The default value is 2048
			/// @param[in] rxTxBatchSize The max number of packets to be received or sent in one batch. The default
			/// value is 64
			explicit XdpDeviceConfiguration(AttachMode attachMode = AutoMode, uint16_t umemNumFrames = 0,
			                                uint16_t umemFrameSize = 0, uint32_t fillRingSize = 0,
			                                uint32_t completionRingSize = 0, uint32_t rxSize = 0, uint32_t txSize = 0,
			                                uint16_t rxTxBatchSize = 0)
			{
				this->attachMode = attachMode;
				this->umemNumFrames = umemNumFrames;
				this->umemFrameSize = umemFrameSize;
				this->fillRingSize = fillRingSize;
				this->completionRingSize = completionRingSize;
				this->rxSize = rxSize;
				this->txSize = txSize;
				this->rxTxBatchSize = rxTxBatchSize;
			}
		};

		/// @struct XdpDeviceStats
		/// A container for XDP device statistics
		struct XdpDeviceStats
		{
			/// The timestamp when the stats were collected
			timespec timestamp;
			/// Number of packets received
			uint64_t rxPackets;
			/// Packets received per second. Measured from to the previous time stats were collected
			uint64_t rxPacketsPerSec;
			/// Number of bytes received
			uint64_t rxBytes;
			/// Bytes per second received. Measured from to the previous time stats were collected
			uint64_t rxBytesPerSec;
			/// Total number of dropped RX packets
			uint64_t rxDroppedTotalPackets;
			/// RX packets dropped due to invalid descriptor
			uint64_t rxDroppedInvalidPackets;
			/// RX packets dropped due to RX ring being full
			uint64_t rxDroppedRxRingFullPackets;
			/// Failed RX packets to retrieve item from fill ring
			uint64_t rxDroppedFillRingPackets;
			/// Number of poll() timeouts
			uint64_t rxPollTimeout;
			/// Number of packets sent from the application
			uint64_t txSentPackets;
			/// Packets sent from the app per second. Measured from to the previous time stats were collected
			uint64_t txSentPacketsPerSec;
			/// Number of bytes sent from the application
			uint64_t txSentBytes;
			/// Bytes per second sent from the app. Measured from to the previous time stats were collected
			uint64_t txSentBytesPerSec;
			/// Number of completed sent packets, meaning packets that were confirmed as sent by the kernel
			uint64_t txCompletedPackets;
			/// Completed sent packets per second. Measured from to the previous time stats were collected
			uint64_t txCompletedPacketsPerSec;
			/// TX packets dropped due to invalid descriptor
			uint64_t txDroppedInvalidPackets;
			/// Current RX ring ID
			uint64_t rxRingId;
			/// Current TX ring ID
			uint64_t txRingId;
			/// Current fill ring ID
			uint64_t fqRingId;
			/// Current completion ring ID
			uint64_t cqRingId;
			/// Number of UMEM frames that are currently in-use (allocated)
			uint64_t umemAllocatedFrames;
			/// Number of UMEM frames that are currently free (not allocated)
			uint64_t umemFreeFrames;
		};

		/// A c'tor for this class. Please note that calling this c'tor doesn't initialize the AF_XDP socket. In order
		/// to set up the socket call open().
		/// @param[in] interfaceName The interface name to open the AF_XDP socket on
		explicit XdpDevice(std::string interfaceName);

		/// A d'tor for this class. It closes the device if it's open.
		~XdpDevice() override;

		/// Open the device with default configuration. Call getConfig() after opening the device to get the
		/// current configuration.
		/// This method initializes the UMEM, and then creates and configures the AF_XDP socket. If it succeeds the
		/// socket is ready to receive and send packets.
		/// @return True if device was opened successfully, false otherwise
		bool open() override;

		/// Open the device with custom configuration set by the user.
		/// This method initializes the UMEM, and then creates and configures the AF_XDP socket. If it succeeds the
		/// socket is ready to receive and send packets.
		/// @param[in] config The configuration to use for opening the device
		/// @return True if device was opened successfully, false otherwise
		bool open(const XdpDeviceConfiguration& config);

		/// Close the device. This method closes the AF_XDP socket and frees the UMEM that was allocated for it.
		void close() override;

		/// Start receiving packets. In order to use this method the device should be open. Note that this method is
		/// blocking and will return if:
		/// - stopReceivePackets() was called from within the user callback
		/// - timeoutMS passed without receiving any packets
		/// - Some error occurred (an error log will be printed)
		/// @param[in] onPacketsArrive A callback to be called when packets are received
		/// @param[in] onPacketsArriveUserCookie The callback is invoked with this cookie as a parameter. It can be used
		/// to pass information from the user application to the callback
		/// @param[in] timeoutMS Timeout in milliseconds to stop if no packets are received. The default value is 5000
		/// ms
		/// @return True if stopped receiving packets because stopReceivePackets() was called or because timeoutMS
		/// passed, or false if an error occurred.
		bool receivePackets(OnPacketsArrive onPacketsArrive, void* onPacketsArriveUserCookie, int timeoutMS = 5000);

		/// Stop receiving packets. Call this method from within the callback passed to receivePackets() whenever you
		/// want to stop receiving packets.
		void stopReceivePackets();

		/// Send a vector of packet pointers.
		/// @param[in] packets A vector of packet pointers to send
		/// @param[in] waitForTxCompletion Wait for confirmation from the kernel that packets were sent. If set to true
		/// this method will wait until the number of packets in the completion ring is equal or greater to the number
		/// of packets that were sent. The default value is false
		/// @param[in] waitForTxCompletionTimeoutMS If waitForTxCompletion is set to true, poll the completion ring with
		/// this timeout. The default value is 5000 ms
		/// @return True if all packets were sent, or if waitForTxCompletion is true - all sent packets were confirmed.
		/// Returns false if an error occurred or if poll timed out.
		bool sendPackets(const RawPacketVector& packets, bool waitForTxCompletion = false,
		                 int waitForTxCompletionTimeoutMS = 5000);

		/// Send an array of packets.
		/// @param[in] packets An array of raw packets to send
		/// @param[in] packetCount The length of the packet array
		/// @param[in] waitForTxCompletion Wait for confirmation from the kernel that packets were sent. If set to true
		/// this method will wait until the number of packets in the completion ring is equal or greater to the number
		/// of packets sent. The default value is false
		/// @param[in] waitForTxCompletionTimeoutMS If waitForTxCompletion is set to true, poll the completion ring with
		/// this timeout. The default value is 5000 ms
		/// @return True if all packets were sent, or if waitForTxCompletion is true - all sent packets were confirmed.
		/// Returns false if an error occurred or if poll timed out.
		bool sendPackets(RawPacket packets[], size_t packetCount, bool waitForTxCompletion = false,
		                 int waitForTxCompletionTimeoutMS = 5000);

		/// @return A pointer to the current device configuration. If the device is not open this method returns nullptr
		XdpDeviceConfiguration* getConfig() const
		{
			return m_Config;
		}

		/// @return Current device statistics
		XdpDeviceStats getStatistics();

	private:
		class XdpUmem
		{
		public:
			explicit XdpUmem(uint16_t numFrames, uint16_t frameSize, uint32_t fillRingSize,
			                 uint32_t completionRingSize);

			virtual ~XdpUmem();

			inline uint16_t getFrameSize() const
			{
				return m_FrameSize;
			}
			inline uint16_t getFrameCount() const
			{
				return m_FrameCount;
			}

			std::pair<bool, std::vector<uint64_t>> allocateFrames(uint32_t count);

			void freeFrame(uint64_t addr);

			const uint8_t* getDataPtr(uint64_t addr) const;

			void setData(uint64_t addr, const uint8_t* data, size_t dataLen);

			inline size_t getFreeFrameCount()
			{
				return m_FreeFrames.size();
			}

			inline void* getInfo()
			{
				return m_UmemInfo;
			}

		private:
			void* m_UmemInfo;
			void* m_Buffer;
			uint16_t m_FrameSize;
			uint16_t m_FrameCount;
			std::vector<uint64_t> m_FreeFrames;
		};

		struct XdpPrevDeviceStats
		{
			timespec timestamp;
			uint64_t rxPackets;
			uint64_t rxBytes;
			uint64_t txSentPackets;
			uint64_t txSentBytes;
			uint64_t txCompletedPackets;
		};

		std::string m_InterfaceName;
		XdpDeviceConfiguration* m_Config;
		bool m_ReceivingPackets;
		XdpUmem* m_Umem;
		void* m_SocketInfo;
		XdpDeviceStats m_Stats;
		XdpPrevDeviceStats m_PrevStats;

		bool sendPackets(const std::function<RawPacket(uint32_t)>& getPacketAt,
		                 const std::function<uint32_t()>& getPacketCount, bool waitForTxCompletion = false,
		                 int waitForTxCompletionTimeoutMS = 5000);
		bool populateFillRing(uint32_t count, uint32_t rxId = 0);
		bool populateFillRing(const std::vector<uint64_t>& addresses, uint32_t rxId);
		uint32_t checkCompletionRing();
		bool configureSocket();
		bool initUmem();
		bool initConfig();
		bool getSocketStats();
	};
}  // namespace pcpp
