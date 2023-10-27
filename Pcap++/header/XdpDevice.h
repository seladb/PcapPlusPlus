#ifndef PCAPPP_XDP_DEVICE
#define PCAPPP_XDP_DEVICE

#include "Device.h"

#include <utility>
#include <functional>

namespace pcpp
{
	class XdpDevice : public IDevice
	{
	public:
		typedef void (*OnPacketsArrive)(RawPacket packets[], uint32_t packetCount, XdpDevice* device, void* userCookie);

		struct XdpDeviceConfiguration
		{
			enum AttachMode
			{
				SkbMode = 1,
				DriverMode = 2,
				AutoMode = 3
			};

			AttachMode attachMode;
			uint16_t umemNumFrames;
			uint16_t umemFrameSize;
			uint32_t fillRingSize;
			uint32_t completionRingSize;
			uint32_t rxSize;
			uint32_t txSize;
			uint16_t rxTxBatchSize;

			explicit XdpDeviceConfiguration(AttachMode attachMode = AutoMode,
											uint16_t umemNumFrames = 0,
											uint16_t umemFrameSize = 1 << 12,
								   			uint32_t fillRingSize = 0,
											uint32_t completionRingSize = 0,
											uint32_t rxSize = 0,
											uint32_t txSize = 0,
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

		struct XdpDeviceStats
		{
			timespec timestamp;
			uint64_t rxPackets;
			uint64_t rxPacketsPerSec;
			uint64_t rxBytes;
			uint64_t rxBytesPerSec;
			uint64_t rxDroppedTotalPackets;
			uint64_t rxDroppedInvalidPackets;
			uint64_t rxDroppedRxRingFullPackets;
			uint64_t rxDroppedFillRingPackets;
			uint64_t rxPollTimeout;
			uint64_t txSentPackets;
			uint64_t txSentPacketsPerSec;
			uint64_t txSentBytes;
			uint64_t txSentBytesPerSec;
			uint64_t txCompletedPackets;
			uint64_t txCompletedPacketsPerSec;
			uint64_t txDroppedInvalidPackets;
			uint64_t rxRingId;
			uint64_t txRingId;
			uint64_t fqRingId;
			uint64_t cqRingId;
			uint64_t umemAllocatedFrames;
			uint64_t umemFreeFrames;
		};

		explicit XdpDevice(std::string interfaceName);

		~XdpDevice() override;

		/**
		 * Open the device
		 * @return True if device was opened successfully, false otherwise
		 */
		bool open() override;
		bool open(const XdpDeviceConfiguration& config);

		/**
		 * Close the device
		 */
		void close() override;

		bool startCapture(OnPacketsArrive onPacketsArrive, void* onPacketsArriveUserCookie, int timeoutMS = 5000);

		void stopCapture();

		bool sendPackets(const RawPacketVector& packets, bool waitForTxCompletion = false, int waitForTxCompletionTimeoutMS = 5000);
		bool sendPackets(RawPacket packets[], size_t packetCount, bool waitForTxCompletion = false, int waitForTxCompletionTimeoutMS = 5000);

		XdpDeviceConfiguration* getConfig() const { return m_Config; }

		XdpDeviceStats getStatistics();

	private:
		class XdpUmem
		{
		public:
			explicit XdpUmem(uint16_t numFrames, uint16_t frameSize, uint32_t fillRingSize, uint32_t completionRingSize);

			virtual ~XdpUmem();

			inline uint16_t getFrameSize() const { return m_FrameSize; }
			inline uint16_t getFrameCount() const { return m_FrameCount; }

			std::pair<bool, std::vector<uint64_t>> allocateFrames(uint32_t count);

			void freeFrame(uint64_t addr);

			const uint8_t* getDataPtr(uint64_t addr) const;

			void setData(uint64_t addr, const uint8_t* data, size_t dataLen);

			inline size_t getFreeFrameCount() { return m_FreeFrames.size(); }

			inline void* getInfo() { return m_UmemInfo; }

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
		bool m_Capturing;
  		XdpUmem* m_Umem;
		void* m_SocketInfo;
		XdpDeviceStats m_Stats;
		XdpPrevDeviceStats m_PrevStats;

		bool sendPackets(const std::function<RawPacket(uint32_t)>& getPacketAt, const std::function<uint32_t()>& getPacketCount, bool waitForTxCompletion = false, int waitForTxCompletionTimeoutMS = 5000);
		bool populateFillRing(uint32_t count, uint32_t rxId = 0);
		bool populateFillRing(const std::vector<uint64_t>& addresses, uint32_t rxId);
		uint32_t checkCompletionRing();
		bool configureSocket();
		bool initUmem();
		bool initConfig();
		bool getSocketStats();
	};
}

#endif // PCAPPP_XDP_DEVICE
