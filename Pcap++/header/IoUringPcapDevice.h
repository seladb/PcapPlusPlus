#pragma once

#if defined(__linux__) && defined(PCPP_HAS_IO_URING_SUPPORT)

#	include "Device.h"
#	include "PcapDevice.h"
#	include "PcapFileDevice.h"
#	include "RawPacket.h"

#	include <liburing.h>
#	include <sys/uio.h>
#	include <string>
#	include <vector>
#	include <memory>
/// @file
/// @brief Linux io_uring asynchronous PCAP file reader device

namespace pcpp
{
	/// @struct IoUringReaderOptions
	/// @brief Configuration parameters for IoUringPcapReaderDevice
	struct IoUringReaderOptions
	{
		/// @brief Size of each chunk buffer in bytes. Must be at least 4096 bytes (1 page). Default is 4MB.
		size_t bufferSize = 4 * 1024 * 1024;

		/// @brief Number of circular prefetch buffers maintained in the ring pipeline. Must be at least 2. Default
		/// is 3.
		size_t numBuffers = 3;
	};

	/// @enum IoUringReaderStatus
	/// @brief Status indicator for IoUringPcapReaderDevice operations
	enum class IoUringReaderStatus
	{
		/// @brief Operation completed successfully
		Ok,
		/// @brief Clean end of file reached
		EndOfFile,
		/// @brief Storage or kernel I/O error occurred
		IoError,
		/// @brief PCAP file format or corruption error encountered
		FormatError
	};

	/// @class IoUringPcapReaderDevice
	/// @brief An offline PCAP file reader for Linux that leverages asynchronous io_uring for high-throughput ingestion.
	///
	/// IoUringPcapReaderDevice bypasses synchronous libpcap file operations, maintaining a circular ring
	/// of asynchronous storage buffers to saturate NVMe queues and prefetch chunks in the background while
	/// the CPU decodes headers in userspace.
	class IoUringPcapReaderDevice : public IFileReaderDevice
	{
	public:
		/// @brief A constructor for this class
		/// @param[in] fileName The path to the PCAP file to read
		/// @param[in] options Configuration options controlling buffer size and count
		explicit IoUringPcapReaderDevice(const std::string& fileName,
		                                 const IoUringReaderOptions& options = IoUringReaderOptions());

		/// @brief A destructor for this class
		~IoUringPcapReaderDevice() override;

		IoUringPcapReaderDevice(const IoUringPcapReaderDevice&) = delete;
		IoUringPcapReaderDevice& operator=(const IoUringPcapReaderDevice&) = delete;

		/// @brief Get the link layer type of the capture
		/// @return Link layer type
		LinkLayerType getLinkLayerType() const
		{
			return m_PcapLinkLayerType;
		}

		/// @brief Get the timestamp precision of the capture
		/// @return FileTimestampPrecision (Microseconds or Nanoseconds)
		FileTimestampPrecision getTimestampPrecision() const
		{
			return m_Precision;
		}

		/// @brief Get the snapshot length (snaplen) from the PCAP global header
		/// @return Snapshot length in bytes
		uint32_t getSnapshotLength() const
		{
			return m_SnapshotLength;
		}

		/// @brief Get the configured reader options
		/// @return Const reference to IoUringReaderOptions
		const IoUringReaderOptions& getOptions() const
		{
			return m_Options;
		}

		/// @brief Get the current operational status of the reader
		/// @return IoUringReaderStatus enum value
		IoUringReaderStatus getStatus() const
		{
			return m_Status;
		}

		/// @brief Open the PCAP file and initialize the io_uring submission/completion queue ring
		/// @return True if the file and ring initialized successfully, false otherwise
		bool open() override;

		/// @brief Close the file, drain and exit the io_uring ring, and release all buffer memory
		void close() override;

		/// @brief Check if the device is opened
		/// @return True if opened, false otherwise
		bool isOpened() const override
		{
			return m_IsOpened;
		}

		/// @brief Read the next packet from file by copying data into @p rawPacket (safe owning copy)
		///
		/// Allocates a new buffer in @p rawPacket with takeOwnership = true. The packet data is safe
		/// to retain across subsequent reads, push into containers, or send across threads.
		/// @param[out] rawPacket RawPacket object to receive the packet data
		/// @return True if a packet was successfully read, false on EOF or error
		bool getNextPacket(RawPacket& rawPacket) override;

		/**
		 * @brief Read the next packet using a non-owning zero-copy view.
		 *
		 * The raw data pointer in @p rawPacket points directly into the reader's circular
		 * prefetch buffer chunks (or internal staging buffer for boundary-split packets).
		 *
		 * LIFETIME AND SAFETY CONTRACT:
		 * The returned raw data pointer is valid ONLY until the next packet retrieval call
		 * (getNextPacket, getNextPacketView, forEachPacketView) or until close() is called.
		 * Callers MUST NOT retain the raw data pointer across iterations or store @p rawPacket
		 * in persistent STL containers without cloning. For safe multi-packet persistence,
		 * use getNextPacket().
		 *
		 * @param[out] rawPacket RawPacket object populated with a non-owning view of packet data.
		 * @return True if a packet was successfully read, false on EOF or error.
		 */
		bool getNextPacketView(RawPacket& rawPacket);

		/**
		 * @brief Zero-copy iteration over all packets in the capture.
		 *
		 * Passes a non-owning RawPacket view to @p callback for each packet. The packet
		 * view is valid for the duration of the callback invocation.
		 *
		 * @tparam Callback Callable with signature void(RawPacket&) or void(const RawPacket&)
		 * @param callback Callback invoked for each packet.
		 * @return Total number of packets processed.
		 */
		template <typename Callback> size_t forEachPacketView(Callback&& callback)
		{
			RawPacket rawPacket;
			size_t count = 0;
			while (getNextPacketView(rawPacket))
			{
				count++;
				callback(rawPacket);
			}
			return count;
		}

	private:
		enum class BufferState
		{
			Idle,
			InKernel,
			Ready
		};

		struct ChunkBuffer
		{
			uint8_t* data = nullptr;
			uint64_t fileOffset = 0;
			size_t bytesRequested = 0;
			ssize_t bytesRead = 0;
			BufferState state = BufferState::Idle;
			struct iovec iov{};
		};

		IoUringReaderOptions m_Options;
		int m_Fd = -1;
		bool m_IsOpened = false;
		struct io_uring m_Ring{};
		bool m_RingInitialized = false;
		bool m_UseReadOp = true;

		FileTimestampPrecision m_Precision = FileTimestampPrecision::Unknown;
		LinkLayerType m_PcapLinkLayerType = LINKTYPE_ETHERNET;
		uint32_t m_SnapshotLength = 0;
		bool m_NeedsSwap = false;
		uint64_t m_FileSize = 0;
		uint64_t m_NextFileOffsetToRead = 0;
		uint64_t m_TotalBytesConsumed = 0;

		std::vector<ChunkBuffer> m_Buffers;
		size_t m_CurrentBufferIdx = 0;
		size_t m_ChunkOffset = 0;
		size_t m_InKernelCount = 0;

		IoUringReaderStatus m_Status = IoUringReaderStatus::Ok;
		std::vector<uint8_t> m_StagingBuffer;

		bool submitRead(size_t bufferIdx, uint64_t fileOffset);
		bool waitForBuffer(size_t bufferIdx);
		bool advanceToNextChunk();
		bool readBytes(void* destination, size_t numBytes);
		bool readNextPacketInternal(timespec& packetTimestamp, const uint8_t*& packetData, uint32_t& capturedLength,
		                            uint32_t& frameLength);
		void drainInFlightRequests();
	};
}  // namespace pcpp

#endif  // __linux__ && PCPP_HAS_IO_URING_SUPPORT
