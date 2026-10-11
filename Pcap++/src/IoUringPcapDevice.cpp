#if defined(__linux__) && defined(PCPP_HAS_IO_URING_SUPPORT)

#	include "IoUringPcapDevice.h"
#	define LOG_MODULE PcapLogModuleFileDevice

#	include "Logger.h"
#	include <fcntl.h>
#	include <unistd.h>
#	include <sys/stat.h>
#	include <cstring>
#	include <cerrno>
#	include <cstdlib>
#	include <algorithm>

namespace pcpp
{
	namespace
	{
		inline uint16_t swap16(uint16_t value)
		{
			return static_cast<uint16_t>((value >> 8) | (value << 8));
		}

		inline uint32_t swap32(uint32_t value)
		{
			return __builtin_bswap32(value);
		}

		constexpr uint32_t TCPDUMP_MAGIC = 0xa1b2c3d4;
		constexpr uint32_t TCPDUMP_MAGIC_SWAPPED = 0xd4c3b2a1;
		constexpr uint32_t KUZNETZOV_MAGIC = 0xa1b2cd34;
		constexpr uint32_t KUZNETZOV_MAGIC_SWAPPED = 0x34cdb2a1;
		constexpr uint32_t NSEC_TCPDUMP_MAGIC = 0xa1b23c4d;
		constexpr uint32_t NSEC_TCPDUMP_MAGIC_SWAPPED = 0x4d3cb2a1;

		constexpr uint32_t MAX_SNAPLEN = 1024 * 1024;
		constexpr uint32_t MAX_PACKET_SIZE = 1024 * 1024;

#	pragma pack(push, 1)
		struct pcap_file_header
		{
			uint32_t magic;
			uint16_t version_major;
			uint16_t version_minor;
			int32_t thiszone;
			uint32_t sigfigs;
			uint32_t snaplen;
			uint32_t linktype;
		};
		static_assert(sizeof(pcap_file_header) == 24, "pcap_file_header must be 24 bytes");

		struct packet_header
		{
			uint32_t tv_sec;
			uint32_t tv_usec;
			uint32_t caplen;
			uint32_t len;
		};
		static_assert(sizeof(packet_header) == 16, "packet_header must be 16 bytes");
#	pragma pack(pop)
	}  // namespace

	IoUringPcapReaderDevice::IoUringPcapReaderDevice(const std::string& fileName, const IoUringReaderOptions& options)
	    : IFileReaderDevice(fileName), m_Options(options)
	{
		constexpr size_t MIN_BUFFER_SIZE = 4096;
		constexpr size_t MAX_BUFFER_SIZE = 128 * 1024 * 1024;

		if (m_Options.bufferSize < MIN_BUFFER_SIZE)
		{
			m_Options.bufferSize = MIN_BUFFER_SIZE;
		}
		else if (m_Options.bufferSize > MAX_BUFFER_SIZE)
		{
			m_Options.bufferSize = MAX_BUFFER_SIZE;
		}

		if (m_Options.bufferSize <= SIZE_MAX - 4095)
		{
			m_Options.bufferSize = (m_Options.bufferSize + 4095) & ~static_cast<size_t>(4095);
		}

		if (m_Options.numBuffers < 2)
		{
			m_Options.numBuffers = 2;
		}
		else if (m_Options.numBuffers > 64)
		{
			m_Options.numBuffers = 64;
		}
	}

	IoUringPcapReaderDevice::~IoUringPcapReaderDevice()
	{
		close();
	}

	bool IoUringPcapReaderDevice::open()
	{
		if (m_IsOpened)
		{
			return true;
		}

		resetStatisticCounters();
		m_CurrentBufferIdx = 0;
		m_ChunkOffset = 0;
		m_Status = IoUringReaderStatus::Ok;
		m_NextFileOffsetToRead = 0;
		m_TotalBytesConsumed = 0;
		m_InKernelCount = 0;

		m_Fd = ::open(m_FileName.c_str(), O_RDONLY);
		if (m_Fd < 0)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Failed to open file '" << m_FileName << "': " << strerror(errno));
			m_Status = IoUringReaderStatus::IoError;
			return false;
		}

		struct stat st{};
		if (fstat(m_Fd, &st) < 0)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: fstat failed: " << strerror(errno));
			m_Status = IoUringReaderStatus::IoError;
			close();
			return false;
		}

		m_FileSize = static_cast<uint64_t>(st.st_size);
		if (m_FileSize < sizeof(pcap_file_header))
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: File too small for PCAP header (" << m_FileSize << " bytes)");
			m_Status = IoUringReaderStatus::FormatError;
			close();
			return false;
		}

		unsigned queueEntries = static_cast<unsigned>(m_Options.numBuffers * 2);
		int ret = io_uring_queue_init(queueEntries, &m_Ring, 0);
		if (ret < 0)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: io_uring_queue_init failed: " << strerror(-ret));
			m_Status = IoUringReaderStatus::IoError;
			close();
			return false;
		}
		m_RingInitialized = true;

		struct io_uring_probe* probe = io_uring_get_probe_ring(&m_Ring);
		if (probe != nullptr)
		{
			m_UseReadOp = (io_uring_opcode_supported(probe, IORING_OP_READ) != 0);
			io_uring_free_probe(probe);
		}
		else
		{
			m_UseReadOp = false;
		}

		m_Buffers.resize(m_Options.numBuffers);
		for (size_t i = 0; i < m_Options.numBuffers; ++i)
		{
			void* mem = nullptr;
			if (posix_memalign(&mem, 4096, m_Options.bufferSize) != 0)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: posix_memalign failed for buffer " << i);
				m_Status = IoUringReaderStatus::IoError;
				close();
				return false;
			}
			m_Buffers[i].data = static_cast<uint8_t*>(mem);
			m_Buffers[i].fileOffset = 0;
			m_Buffers[i].bytesRequested = 0;
			m_Buffers[i].bytesRead = 0;
			m_Buffers[i].state = BufferState::Idle;
		}

		for (size_t i = 0; i < m_Options.numBuffers; ++i)
		{
			if (m_NextFileOffsetToRead < m_FileSize)
			{
				uint64_t submitOffset = m_NextFileOffsetToRead;
				m_NextFileOffsetToRead += m_Options.bufferSize;
				if (!submitRead(i, submitOffset))
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Failed to submit initial read for buffer " << i);
					close();
					return false;
				}
			}
		}

		if (!waitForBuffer(0) || m_Buffers[0].bytesRead < static_cast<ssize_t>(sizeof(pcap_file_header)))
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Failed to read PCAP global header from initial chunk");
			if (m_Status == IoUringReaderStatus::Ok)
			{
				m_Status = IoUringReaderStatus::FormatError;
			}
			close();
			return false;
		}

		pcap_file_header header{};
		std::memcpy(&header, m_Buffers[0].data, sizeof(pcap_file_header));

		if (header.magic == TCPDUMP_MAGIC)
		{
			m_Precision = FileTimestampPrecision::Microseconds;
			m_NeedsSwap = false;
		}
		else if (header.magic == TCPDUMP_MAGIC_SWAPPED)
		{
			m_Precision = FileTimestampPrecision::Microseconds;
			m_NeedsSwap = true;
		}
		else if (header.magic == NSEC_TCPDUMP_MAGIC)
		{
			m_Precision = FileTimestampPrecision::Nanoseconds;
			m_NeedsSwap = false;
		}
		else if (header.magic == NSEC_TCPDUMP_MAGIC_SWAPPED)
		{
			m_Precision = FileTimestampPrecision::Nanoseconds;
			m_NeedsSwap = true;
		}
		else if (header.magic == KUZNETZOV_MAGIC || header.magic == KUZNETZOV_MAGIC_SWAPPED)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Kuznetsov modified PCAP format (magic 0x"
			               << std::hex << header.magic << ") is unsupported.");
			m_Status = IoUringReaderStatus::FormatError;
			close();
			return false;
		}
		else
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Unsupported magic number: 0x" << std::hex << header.magic);
			m_Status = IoUringReaderStatus::FormatError;
			close();
			return false;
		}

		if (m_NeedsSwap)
		{
			header.version_major = swap16(header.version_major);
			header.version_minor = swap16(header.version_minor);
			header.snaplen = swap32(header.snaplen);
			header.linktype = swap32(header.linktype);
		}

		if (header.version_major != 2 || header.version_minor != 4)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Unsupported PCAP version " << header.version_major << "."
			                                                                    << header.version_minor);
			m_Status = IoUringReaderStatus::FormatError;
			close();
			return false;
		}

		if (header.snaplen == 0 || header.snaplen > MAX_SNAPLEN)
		{
			PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid snaplen: " << header.snaplen);
			m_Status = IoUringReaderStatus::FormatError;
			close();
			return false;
		}

		m_SnapshotLength = header.snaplen;
		m_PcapLinkLayerType = static_cast<LinkLayerType>(header.linktype);

		m_ChunkOffset = sizeof(pcap_file_header);
		m_TotalBytesConsumed = sizeof(pcap_file_header);
		m_IsOpened = true;
		return true;
	}

	void IoUringPcapReaderDevice::drainInFlightRequests()
	{
		if (!m_RingInitialized)
		{
			return;
		}

		for (size_t i = 0; i < m_Buffers.size(); ++i)
		{
			if (m_Buffers[i].state == BufferState::InKernel)
			{
				struct io_uring_sqe* cancelSqe = io_uring_get_sqe(&m_Ring);
				if (cancelSqe)
				{
					io_uring_prep_cancel64(cancelSqe, i, 0);
					io_uring_sqe_set_data64(cancelSqe, UINT64_MAX);
				}
			}
		}
		io_uring_submit(&m_Ring);

		struct __kernel_timespec ts{};
		ts.tv_sec = 1;
		ts.tv_nsec = 0;

		int waitFailures = 0;
		while (m_InKernelCount > 0 && waitFailures < 10)
		{
			struct io_uring_cqe* cqe = nullptr;
			int ret = io_uring_wait_cqe_timeout(&m_Ring, &cqe, &ts);
			if (ret < 0)
			{
				if (ret == -EINTR)
				{
					continue;
				}
				waitFailures++;
				continue;
			}

			uint64_t completedIdx = io_uring_cqe_get_data64(cqe);
			if (completedIdx < m_Buffers.size() && m_Buffers[completedIdx].state == BufferState::InKernel)
			{
				m_Buffers[completedIdx].state = BufferState::Ready;
				m_InKernelCount--;
			}
			io_uring_cqe_seen(&m_Ring, cqe);
		}
	}

	void IoUringPcapReaderDevice::close()
	{
		drainInFlightRequests();

		if (m_RingInitialized)
		{
			io_uring_queue_exit(&m_Ring);
			m_RingInitialized = false;
		}

		for (auto& buf : m_Buffers)
		{
			if (buf.data != nullptr)
			{
				std::free(buf.data);
				buf.data = nullptr;
			}
			buf.bytesRead = 0;
			buf.bytesRequested = 0;
			buf.state = BufferState::Idle;
		}
		m_Buffers.clear();

		if (m_Fd >= 0)
		{
			::close(m_Fd);
			m_Fd = -1;
		}

		m_IsOpened = false;
		m_CurrentBufferIdx = 0;
		m_ChunkOffset = 0;
		m_NextFileOffsetToRead = 0;
		m_TotalBytesConsumed = 0;
		m_InKernelCount = 0;
	}

	bool IoUringPcapReaderDevice::submitRead(size_t bufferIdx, uint64_t fileOffset)
	{
		if (fileOffset >= m_FileSize)
		{
			m_Buffers[bufferIdx].bytesRead = 0;
			m_Buffers[bufferIdx].bytesRequested = 0;
			m_Buffers[bufferIdx].state = BufferState::Idle;
			return false;
		}

		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_Ring);
		if (!sqe)
		{
			int flushRet = io_uring_submit(&m_Ring);
			if (flushRet < 0)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: io_uring_submit flush failed: " << strerror(-flushRet));
				m_Status = IoUringReaderStatus::IoError;
				m_Buffers[bufferIdx].state = BufferState::Idle;
				return false;
			}
			sqe = io_uring_get_sqe(&m_Ring);
			if (!sqe)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: Failed to obtain SQE from ring");
				m_Status = IoUringReaderStatus::IoError;
				m_Buffers[bufferIdx].state = BufferState::Idle;
				return false;
			}
		}

		size_t bytesToRead = std::min<uint64_t>(m_Options.bufferSize, m_FileSize - fileOffset);
		m_Buffers[bufferIdx].iov.iov_base = m_Buffers[bufferIdx].data;
		m_Buffers[bufferIdx].iov.iov_len = bytesToRead;
		if (m_UseReadOp)
		{
			io_uring_prep_read(sqe, m_Fd, m_Buffers[bufferIdx].data, bytesToRead, fileOffset);
		}
		else
		{
			io_uring_prep_readv(sqe, m_Fd, &m_Buffers[bufferIdx].iov, 1, fileOffset);
		}
		io_uring_sqe_set_data64(sqe, bufferIdx);

		m_Buffers[bufferIdx].fileOffset = fileOffset;
		m_Buffers[bufferIdx].bytesRequested = bytesToRead;
		m_Buffers[bufferIdx].bytesRead = -1;

		int retries = 0;
		while (io_uring_sq_ready(&m_Ring) > 0)
		{
			int submitRet = io_uring_submit(&m_Ring);
			if (submitRet > 0)
			{
				retries = 0;
				continue;
			}
			if (submitRet < 0)
			{
				if (submitRet == -EINTR)
				{
					continue;
				}
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: io_uring_submit failed: " << strerror(-submitRet));
				io_uring_prep_nop(sqe);
				io_uring_sqe_set_data64(sqe, UINT64_MAX);
				m_Buffers[bufferIdx].state = BufferState::Idle;
				m_Status = IoUringReaderStatus::IoError;
				return false;
			}

			retries++;
			if (retries > 5)
			{
				PCPP_LOG_ERROR(
				    "IoUringPcapReaderDevice: io_uring_submit repeatedly returned zero with pending entries");
				io_uring_prep_nop(sqe);
				io_uring_sqe_set_data64(sqe, UINT64_MAX);
				m_Buffers[bufferIdx].state = BufferState::Idle;
				m_Status = IoUringReaderStatus::IoError;
				return false;
			}
		}

		m_Buffers[bufferIdx].state = BufferState::InKernel;
		m_InKernelCount++;
		return true;
	}

	bool IoUringPcapReaderDevice::waitForBuffer(size_t bufferIdx)
	{
		if (m_Buffers[bufferIdx].state == BufferState::Ready)
		{
			return (m_Buffers[bufferIdx].bytesRead > 0);
		}

		if (m_Buffers[bufferIdx].state == BufferState::Idle)
		{
			return false;
		}

		while (m_Buffers[bufferIdx].state == BufferState::InKernel)
		{
			struct io_uring_cqe* cqe = nullptr;
			int ret = io_uring_wait_cqe(&m_Ring, &cqe);
			if (ret < 0)
			{
				if (ret == -EINTR)
				{
					continue;
				}
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: io_uring_wait_cqe failed: " << strerror(-ret));
				m_Status = IoUringReaderStatus::IoError;
				return false;
			}

			uint64_t completedIdx = io_uring_cqe_get_data64(cqe);
			int res = cqe->res;
			io_uring_cqe_seen(&m_Ring, cqe);

			if (completedIdx < m_Buffers.size() && m_Buffers[completedIdx].state == BufferState::InKernel)
			{
				m_Buffers[completedIdx].state = BufferState::Ready;
				if (m_InKernelCount > 0)
				{
					m_InKernelCount--;
				}

				if (res < 0)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: read error on buffer " << completedIdx << ": "
					                                                                << strerror(-res));
					m_Buffers[completedIdx].bytesRead = 0;
					m_Status = IoUringReaderStatus::IoError;
					return false;
				}
				else
				{
					m_Buffers[completedIdx].bytesRead = res;
					if (static_cast<size_t>(res) < m_Buffers[completedIdx].bytesRequested &&
					    m_Buffers[completedIdx].fileOffset + static_cast<uint64_t>(res) < m_FileSize)
					{
						PCPP_LOG_ERROR("IoUringPcapReaderDevice: Unexpected short read at offset "
						               << m_Buffers[completedIdx].fileOffset << " (" << res << " of "
						               << m_Buffers[completedIdx].bytesRequested << " bytes)");
						m_Status = IoUringReaderStatus::IoError;
						return false;
					}
				}
			}
		}

		return (m_Status != IoUringReaderStatus::IoError && m_Buffers[bufferIdx].bytesRead > 0);
	}

	bool IoUringPcapReaderDevice::advanceToNextChunk()
	{
		size_t oldIdx = m_CurrentBufferIdx;
		if (m_NextFileOffsetToRead < m_FileSize)
		{
			uint64_t submitOffset = m_NextFileOffsetToRead;
			m_NextFileOffsetToRead += m_Options.bufferSize;
			if (!submitRead(oldIdx, submitOffset))
			{
				return false;
			}
		}
		else
		{
			m_Buffers[oldIdx].state = BufferState::Idle;
			m_Buffers[oldIdx].bytesRead = 0;
		}

		m_CurrentBufferIdx = (m_CurrentBufferIdx + 1) % m_Buffers.size();
		m_ChunkOffset = 0;

		auto& nextBuf = m_Buffers[m_CurrentBufferIdx];
		if (nextBuf.state == BufferState::InKernel)
		{
			return waitForBuffer(m_CurrentBufferIdx);
		}
		return (nextBuf.bytesRead > 0);
	}

	bool IoUringPcapReaderDevice::readBytes(void* destination, size_t numBytes)
	{
		uint8_t* destPtr = static_cast<uint8_t*>(destination);
		size_t bytesGathered = 0;

		while (bytesGathered < numBytes)
		{
			if (m_Status != IoUringReaderStatus::Ok)
			{
				return false;
			}

			auto& curBuf = m_Buffers[m_CurrentBufferIdx];
			if (curBuf.state == BufferState::InKernel)
			{
				if (!waitForBuffer(m_CurrentBufferIdx))
				{
					return false;
				}
			}

			if (curBuf.bytesRead <= 0 || m_ChunkOffset >= static_cast<size_t>(curBuf.bytesRead))
			{
				if (!advanceToNextChunk())
				{
					return false;
				}
				continue;
			}

			size_t available = static_cast<size_t>(curBuf.bytesRead) - m_ChunkOffset;
			size_t toCopy = std::min(numBytes - bytesGathered, available);

			if (destPtr != nullptr)
			{
				std::memcpy(destPtr + bytesGathered, curBuf.data + m_ChunkOffset, toCopy);
			}
			m_ChunkOffset += toCopy;
			bytesGathered += toCopy;
		}

		return true;
	}

	bool IoUringPcapReaderDevice::readNextPacketInternal(timespec& packetTimestamp, const uint8_t*& packetData,
	                                                     uint32_t& capturedLength, uint32_t& frameLength)
	{
		while (m_Status == IoUringReaderStatus::Ok)
		{
			if (m_TotalBytesConsumed == m_FileSize)
			{
				m_Status = IoUringReaderStatus::EndOfFile;
				return false;
			}

			if (m_TotalBytesConsumed > m_FileSize)
			{
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			size_t unconsumed = static_cast<size_t>(m_FileSize - m_TotalBytesConsumed);
			if (unconsumed < sizeof(packet_header))
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: Truncated packet header at EOF (" << unconsumed
				                                                                           << " bytes, expected 16)");
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			if (m_CurrentBufferIdx >= m_Buffers.size())
			{
				return false;
			}

			auto& curBuf = m_Buffers[m_CurrentBufferIdx];
			if (curBuf.state == BufferState::InKernel)
			{
				if (!waitForBuffer(m_CurrentBufferIdx))
				{
					return false;
				}
			}

			if (curBuf.bytesRead <= 0 || m_ChunkOffset >= static_cast<size_t>(curBuf.bytesRead))
			{
				if (!advanceToNextChunk())
				{
					return false;
				}
				continue;
			}

			size_t bytesLeft = static_cast<size_t>(curBuf.bytesRead) - m_ChunkOffset;
			if (bytesLeft >= sizeof(packet_header))
			{
				const auto* ph = reinterpret_cast<const packet_header*>(curBuf.data + m_ChunkOffset);
				uint32_t caplen = m_NeedsSwap ? swap32(ph->caplen) : ph->caplen;
				uint32_t origlen = m_NeedsSwap ? swap32(ph->len) : ph->len;
				uint32_t sec = m_NeedsSwap ? swap32(ph->tv_sec) : ph->tv_sec;
				uint32_t usec = m_NeedsSwap ? swap32(ph->tv_usec) : ph->tv_usec;

				if (m_Precision == FileTimestampPrecision::Nanoseconds)
				{
					if (usec >= 1000000000)
					{
						PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid nanosecond timestamp: " << usec);
						m_Status = IoUringReaderStatus::FormatError;
						return false;
					}
				}
				else
				{
					if (usec >= 1000000)
					{
						PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid microsecond timestamp: " << usec);
						m_Status = IoUringReaderStatus::FormatError;
						return false;
					}
				}

				if (caplen > origlen)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Packet caplen (" << caplen << ") exceeds original len ("
					                                                          << origlen << ")");
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}

				if (caplen > MAX_PACKET_SIZE || caplen > m_SnapshotLength)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid caplen (" << caplen << "), exceeds snaplen ("
					                                                           << m_SnapshotLength << ")");
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}

				size_t totalPacketBytes = sizeof(packet_header) + caplen;
				if (unconsumed < totalPacketBytes)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Truncated packet payload at EOF (needed "
					               << caplen << ", only " << (unconsumed - sizeof(packet_header)) << " available)");
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}

				if (bytesLeft >= totalPacketBytes)
				{
					packetData = curBuf.data + m_ChunkOffset + sizeof(packet_header);
					capturedLength = caplen;
					frameLength = origlen;
					packetTimestamp.tv_sec = static_cast<time_t>(sec);
					packetTimestamp.tv_nsec =
					    static_cast<long>(m_Precision == FileTimestampPrecision::Microseconds ? usec * 1000L : usec);

					m_ChunkOffset += totalPacketBytes;
					m_TotalBytesConsumed += totalPacketBytes;
					return true;
				}
			}

			packet_header ph{};
			if (!readBytes(&ph, sizeof(packet_header)))
			{
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			uint32_t caplen = m_NeedsSwap ? swap32(ph.caplen) : ph.caplen;
			uint32_t origlen = m_NeedsSwap ? swap32(ph.len) : ph.len;
			uint32_t sec = m_NeedsSwap ? swap32(ph.tv_sec) : ph.tv_sec;
			uint32_t usec = m_NeedsSwap ? swap32(ph.tv_usec) : ph.tv_usec;

			if (m_Precision == FileTimestampPrecision::Nanoseconds)
			{
				if (usec >= 1000000000)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid nanosecond timestamp in split packet: " << usec);
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}
			}
			else
			{
				if (usec >= 1000000)
				{
					PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid microsecond timestamp in split packet: " << usec);
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}
			}

			if (caplen > origlen)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: Split packet caplen (" << caplen << ") exceeds orig len ("
				                                                                << origlen << ")");
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			if (caplen > MAX_PACKET_SIZE || caplen > m_SnapshotLength)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: Invalid caplen in split packet ("
				               << caplen << "), exceeds snaplen (" << m_SnapshotLength << ")");
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			size_t totalPacketBytes = sizeof(packet_header) + caplen;
			if (unconsumed < totalPacketBytes)
			{
				PCPP_LOG_ERROR("IoUringPcapReaderDevice: Truncated split packet payload at EOF");
				m_Status = IoUringReaderStatus::FormatError;
				return false;
			}

			m_StagingBuffer.resize(caplen);
			if (caplen > 0)
			{
				if (!readBytes(m_StagingBuffer.data(), caplen))
				{
					m_Status = IoUringReaderStatus::FormatError;
					return false;
				}
			}

			packetData = m_StagingBuffer.data();
			capturedLength = caplen;
			frameLength = origlen;
			packetTimestamp.tv_sec = static_cast<time_t>(sec);
			packetTimestamp.tv_nsec =
			    static_cast<long>(m_Precision == FileTimestampPrecision::Microseconds ? usec * 1000L : usec);

			m_TotalBytesConsumed += totalPacketBytes;
			return true;
		}

		return false;
	}

	bool IoUringPcapReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		timespec packetTimestamp{};
		const uint8_t* packetData = nullptr;
		uint32_t capturedLength = 0;
		uint32_t frameLength = 0;

		while (readNextPacketInternal(packetTimestamp, packetData, capturedLength, frameLength))
		{
			if (m_BpfWrapper.matches(packetData, capturedLength, packetTimestamp, m_PcapLinkLayerType))
			{
				uint8_t* copy = nullptr;
				if (capturedLength > 0 && packetData != nullptr)
				{
					copy = new uint8_t[capturedLength];
					std::memcpy(copy, packetData, capturedLength);
				}
				rawPacket.setRawData(copy, capturedLength, true, packetTimestamp, m_PcapLinkLayerType, frameLength);
				reportPacketProcessed();
				return true;
			}
			reportPacketDropped();
		}
		return false;
	}

	bool IoUringPcapReaderDevice::getNextPacketView(RawPacket& rawPacket)
	{
		timespec packetTimestamp{};
		const uint8_t* packetData = nullptr;
		uint32_t capturedLength = 0;
		uint32_t frameLength = 0;

		while (readNextPacketInternal(packetTimestamp, packetData, capturedLength, frameLength))
		{
			if (m_BpfWrapper.matches(packetData, capturedLength, packetTimestamp, m_PcapLinkLayerType))
			{
				rawPacket.setRawData(packetData, capturedLength, false, packetTimestamp, m_PcapLinkLayerType,
				                     frameLength);
				reportPacketProcessed();
				return true;
			}
			reportPacketDropped();
		}
		return false;
	}

}  // namespace pcpp

#endif  // __linux__ && PCPP_HAS_IO_URING_SUPPORT
