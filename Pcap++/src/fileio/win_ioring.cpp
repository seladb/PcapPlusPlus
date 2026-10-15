#include "win_ioring.h"
#include <Windows.h>
#include <Logger.h>
#include <memory>
#include <AssertionUtils.h>

namespace pcpp
{
	namespace internal
	{
		WindowsIoRingDriver::WindowsIoRingDriver(IoRingConfig config) : m_Config(config)
		{}

		bool WindowsIoRingDriver::isOpen() const
		{
			return m_IoRingHandle != nullptr;
		}
		bool WindowsIoRingDriver::open(std::string const& filename)
		{
			if (isOpen())
			{
				PCPP_LOG_ERROR("IO ring is already open");
				return false;
			}

			// Open the file for reading
			// NOTE: The file is locked for writing by other handles. This is due to the prefetcher reading the file in advance.
			// Writing to the file at the same time is not supported as it may break the prefetcher.
			HANDLE file = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
			                          FILE_ATTRIBUTE_NORMAL, nullptr);
			if (file == INVALID_HANDLE_VALUE)
			{
				PCPP_LOG_ERROR("Failed to open file: 0x" << std::hex << GetLastError());
				return false;
			}
			struct FileAutoClose
			{
				HANDLE& fileHandle;
				bool autoClose = true;
				FileAutoClose(HANDLE& handle) : fileHandle(handle)
				{}
				~FileAutoClose()
				{
					if (autoClose && fileHandle != INVALID_HANDLE_VALUE)
					{
						CloseHandle(fileHandle);
						fileHandle = INVALID_HANDLE_VALUE;
					}
				}
			} autoCloseFile(file);

			// Create the IO ring
			uint32_t sqeCount = m_Config.numBuffers;      // Number of submission queue entries
			uint32_t cqeCount = m_Config.numBuffers * 2;  // Number of completion queue entries

			HRESULT hr = CreateIoRing(IORING_VERSION_3, IORING_CREATE_FLAGS{}, sqeCount, cqeCount, &m_IoRingHandle);
			if (FAILED(hr))
			{
				PCPP_LOG_ERROR("Failed to create IO ring: " << std::hex << hr);
				return false;
			}
			struct IoRingAutoClose
			{
				HIORING& ioRingHandle;
				bool autoClose = true;

				IoRingAutoClose(HIORING& handle) : ioRingHandle(handle)
				{}
				~IoRingAutoClose()
				{
					if (autoClose && ioRingHandle != nullptr)
					{
						CloseIoRing(ioRingHandle);
						ioRingHandle = nullptr;
					}
				}
			} autoCloseIoRing(m_IoRingHandle);

			// Create prefetch buffers
			std::vector<IORING_BUFFER_INFO> bufferInfos;

			PCPP_ASSERT(m_PrefetchBuffers.empty(), "Prefetch buffers should be empty before allocation");
			m_PrefetchBuffers.reserve(m_Config.numBuffers);
			for (size_t i = 0; i < m_Config.numBuffers; ++i)
			{
				void* buffer = VirtualAlloc(nullptr, m_Config.bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (buffer == nullptr)
				{
					PCPP_LOG_ERROR("Failed to allocate prefetch buffer " << i << " LE: " << GetLastError());
					return false;
				}
				m_PrefetchBuffers.emplace_back(
				    PrefetchBuffer{ std::unique_ptr<void, VirtualAllocDeleter>(buffer), PrefetchBufferState::Idle });
				bufferInfos.emplace_back(IORING_BUFFER_INFO{ buffer, static_cast<UINT32>(m_Config.bufferSize) });
			}

			// TODO: Handle possible error conditions when registering buffers and file handles with the IO ring, such
			// as submission queue being full.

			// Register the buffers and file handle with the IO ring
			HRESULT buildResult;

			buildResult = BuildIoRingRegisterFileHandles(m_IoRingHandle, 1, &file, 0x001);
			if (buildResult != S_OK)
			{
				if (buildResult != IORING_E_SUBMISSION_QUEUE_FULL)
				{
					PCPP_LOG_ERROR("Failed to register file handle with IO ring: " << std::hex << buildResult);
					return false;
				}

				// Submit the queue if the submission queue is full and try again
				SubmitIoRing(m_IoRingHandle, 0, 0, nullptr);

				buildResult = BuildIoRingRegisterFileHandles(m_IoRingHandle, 1, &file, 0x001);
				if (buildResult != S_OK)
				{
					PCPP_LOG_ERROR("Failed to register file handle with IO ring after submission: " << std::hex
					                                                                                << buildResult);
					return false;
				}
			}
			buildResult = BuildIoRingRegisterBuffers(m_IoRingHandle, static_cast<UINT32>(bufferInfos.size()),
			                                         bufferInfos.data(), 0x002);
			if (buildResult != S_OK)
			{
				if (buildResult != IORING_E_SUBMISSION_QUEUE_FULL)
				{
					PCPP_LOG_ERROR("Failed to register buffers with IO ring: " << std::hex << buildResult);
					return false;
				}

				SubmitIoRing(m_IoRingHandle, 0, 0, nullptr);

				buildResult = BuildIoRingRegisterBuffers(m_IoRingHandle, static_cast<UINT32>(bufferInfos.size()),
				                                         bufferInfos.data(), 0x002);
				if (buildResult != S_OK)
				{
					PCPP_LOG_ERROR("Failed to register buffers with IO ring after submission: " << std::hex
					                                                                            << buildResult);
					return false;
				}
			}

			// Submit the registration requests and wait for completion
			SubmitIoRing(m_IoRingHandle, 2, INFINITE, nullptr);

			// Process the completions for the registration requests
			IORING_CQE cqe;
			while (PopIoRingCompletion(m_IoRingHandle, &cqe) == S_OK)
			{
				switch (cqe.UserData)
				{
				case 0x001:
				{
					if (FAILED(cqe.ResultCode))
					{
						PCPP_LOG_ERROR("Failed to register file handle with IO ring: " << std::hex << cqe.ResultCode);
						return false;
					}
					break;
				}
				case 0x002:
				{
					if (FAILED(cqe.ResultCode))
					{
						PCPP_LOG_ERROR("Failed to register buffers with IO ring: " << std::hex << cqe.ResultCode);
						return false;
					}
					break;
				}
				default:
					PCPP_LOG_ERROR("Unexpected completion with user data: " << cqe.UserData << " result: " << std::hex
					                                                        << cqe.ResultCode);
					return false;
				}
			}

			// Reset read pointers and EOF flags
			m_PrefetchEofReached = false;
			m_ReadEofReached = false;
			m_FileReadPtr = 0;
			m_FilePrefetchPtr = 0;

			// Submit all prefetch buffers.
			// - Prefetch requests are marked with user data starting at 0x100.
			for (size_t i = 0; i < m_PrefetchBuffers.size(); ++i)
			{
				// Submit false, to batch all prefetch requests into a single SubmitIoRing call.
				submitReadForBuffer(i, false);
			}
			SubmitIoRing(m_IoRingHandle, 0, 0, nullptr);

			// Discard the auto-close behavior since we want to keep the handles open after this function returns on
			// success
			autoCloseIoRing.autoClose = false;
			autoCloseFile.autoClose = false;
			return true;
		}

		void WindowsIoRingDriver::close()
		{
			// Wait for all in-flight prefetch buffers to complete before closing the IO ring and file handles
			for (size_t i = 0; i < m_PrefetchBuffers.size(); ++i)
			{
				auto& prefetchBuffer = m_PrefetchBuffers[i];
				if (prefetchBuffer.state == PrefetchBufferState::InKernel)
				{
					// Wait for the buffer to complete before closing the IO ring
					waitForBufferReady(i);
				}
			}

			if (m_IoRingHandle != nullptr)
			{
				// TODO: Drain the in-flight IO ring prior to closing the handle.
				CloseIoRing(m_IoRingHandle);
				m_IoRingHandle = nullptr;
			}

			if (m_FileHandle != nullptr)
			{
				CloseHandle(m_FileHandle);
				m_FileHandle = nullptr;
			}

			m_PrefetchBuffers.clear();
		}

		size_t WindowsIoRingDriver::readBytes(char* buffer, size_t size)
		{
			PCPP_ASSERT(buffer != nullptr, "Buffer cannot be nullptr for readBytes");
			return readBytesImpl(buffer, size);
		}

		size_t WindowsIoRingDriver::ignoreBytes(size_t size)
		{
			return readBytesImpl(nullptr, size);
		}

		size_t WindowsIoRingDriver::readBytesImpl(char* buffer, size_t size)
		{
			if (!isOpen())
			{
				PCPP_LOG_ERROR("IO driver is not open");
				return 0;
			}

			if (m_ReadEofReached)
			{
				PCPP_LOG_DEBUG("EOF has already been reached, no more bytes to read");
				return 0;
			}

			size_t bytesRead = 0;
			while (!m_ReadEofReached && bytesRead < size)
			{
				const size_t bufferIndex = getBufferIndexForRead(m_FileReadPtr);

				auto& prefetchBuffer = m_PrefetchBuffers[bufferIndex];
				if (prefetchBuffer.state != PrefetchBufferState::Ready)
				{
					waitForBufferReady(bufferIndex);
				}
				PCPP_ASSERT(prefetchBuffer.state == PrefetchBufferState::Ready,
				            "Prefetch buffer is not ready for reading");

				if (FAILED(prefetchBuffer.lastIoResult))
				{
					if (prefetchBuffer.lastIoResult == ERROR_HANDLE_EOF)
					{
						PCPP_LOG_DEBUG("Prefetch buffer fully past EOF for buffer " << bufferIndex);
						m_ReadEofReached = true;
						return bytesRead;
					}
					else
					{
						PCPP_LOG_ERROR("Prefetch read failed for buffer " << bufferIndex << " with result: " << std::hex
						                                                  << prefetchBuffer.lastIoResult);
						return bytesRead;
					}
				}

				const size_t bufferReadOffset = getBufferOffsetForRead(m_FileReadPtr);
				const size_t remainingBytesInBuffer = m_Config.bufferSize - bufferReadOffset;
				const size_t availableBytesInBuffer = prefetchBuffer.bytesRead - bufferReadOffset;

				const size_t bytesToReadInChunk = (std::min)({
				    size - bytesRead,        // Remaining bytes to read from the user request
				    remainingBytesInBuffer,  // Remaining bytes until the end of the current prefetch buffer
				    availableBytesInBuffer   // Remaining bytes available in the prefetch buffer
				});

				// Buffer is nullptr on ignore op.
				if (buffer != nullptr)
				{
					// Copy the data from the prefetch buffer to the user-provided buffer
					std::memcpy(buffer + bytesRead, static_cast<char*>(prefetchBuffer.buffer.get()) + bufferReadOffset,
					            bytesToReadInChunk);
				}

				// Advance the read pointer and update the consumed bytes count
				m_FileReadPtr += bytesToReadInChunk;
				bytesRead += bytesToReadInChunk;

				// The chunk has been fully consumed.
				if (bytesToReadInChunk == remainingBytesInBuffer)
				{
					// Mark the buffer as consumed and submit a new read for it
					consumeBuffer(bufferIndex);

					// Handle any completion entries, to get up to date prefetch EOF state.
					// Otherwise, the state might be stale.
					dequeCompletedIoRingEvents();
					if (!m_PrefetchEofReached)
					{
						submitReadForBuffer(bufferIndex);
					}
				}
				// If the chunk has not been fully consumed, but we have consumed all available bytes in the prefetch
				// buffer, we have reached EOF.
				else if (bufferReadOffset + bytesToReadInChunk >= prefetchBuffer.bytesRead)
				{
					m_ReadEofReached = true;
				}
			}

			return bytesRead;
		}

		void WindowsIoRingDriver::dequeCompletedIoRingEvents()
		{
			IORING_CQE cqe;
			while (PopIoRingCompletion(m_IoRingHandle, &cqe) == S_OK)
			{
				// Process completions and update buffer states
				// All prefetch reads are marked with user data starting at 0x100.
				PCPP_ASSERT(cqe.UserData >= 0x100 && cqe.UserData < 0x100 + m_PrefetchBuffers.size(),
				            "Unexpected completion token");

				auto bytesRead = static_cast<size_t>(cqe.Information);

				size_t bufferIndex = cqe.UserData - 0x100;
				auto& prefetchBuffer = m_PrefetchBuffers[bufferIndex];
				prefetchBuffer.state = PrefetchBufferState::Ready;
				prefetchBuffer.bytesRead = bytesRead;
				prefetchBuffer.lastIoResult = cqe.ResultCode;

				if (prefetchBuffer.bytesRead < m_Config.bufferSize)
				{
					PCPP_LOG_DEBUG("Prefetch buffer " << bufferIndex
					                                  << " read fewer bytes than buffer size, EOF reached");
					m_PrefetchEofReached = true;
				}
				if (prefetchBuffer.lastIoResult == ERROR_HANDLE_EOF)
				{
					PCPP_LOG_DEBUG("Prefetch buffer fully past EOF for buffer " << bufferIndex);
					m_PrefetchEofReached = true;
				}
				else if (FAILED(prefetchBuffer.lastIoResult))
				{
					PCPP_LOG_DEBUG("Prefetch read failed for buffer " << bufferIndex << " with result: " << std::hex
					                                                  << prefetchBuffer.lastIoResult);
				}
				else
				{
					PCPP_LOG_DEBUG("Prefetch read completed for buffer "
					               << bufferIndex << " with bytes read: " << prefetchBuffer.bytesRead);
				}
			}
		}

		void WindowsIoRingDriver::waitForBufferReady(size_t bufferIndex)
		{
			PCPP_ASSERT(bufferIndex < m_PrefetchBuffers.size(), "Buffer index out of range");

			auto& targetPrefetchBuffer = m_PrefetchBuffers[bufferIndex];
			PCPP_ASSERT(targetPrefetchBuffer.state == PrefetchBufferState::InKernel,
			            "Prefetch buffer is not in kernel state");

			do
			{
				dequeCompletedIoRingEvents();
			} while (targetPrefetchBuffer.state != PrefetchBufferState::Ready);
		}

		void WindowsIoRingDriver::consumeBuffer(size_t bufferIndex)
		{
			PCPP_ASSERT(bufferIndex < m_PrefetchBuffers.size(), "Buffer index out of range");
			auto& targetPrefetchBuffer = m_PrefetchBuffers[bufferIndex];
			PCPP_ASSERT(targetPrefetchBuffer.state == PrefetchBufferState::Ready,
			            "Prefetch buffer is not in ready state");
			targetPrefetchBuffer.state = PrefetchBufferState::Idle;
		}

		void WindowsIoRingDriver::submitReadForBuffer(size_t bufferIndex, bool submit)
		{
			PCPP_ASSERT(m_PrefetchEofReached == false, "Cannot submit read for buffer after EOF has been reached");
			PCPP_ASSERT(bufferIndex < m_PrefetchBuffers.size(), "Buffer index out of range");
			auto& targetPrefetchBuffer = m_PrefetchBuffers[bufferIndex];
			PCPP_ASSERT(targetPrefetchBuffer.state == PrefetchBufferState::Idle,
			            "Prefetch buffer is not in idle state");

			IORING_BUFFER_REF bufferRef = IoRingBufferRefFromIndexAndOffset(static_cast<UINT32>(bufferIndex), 0);
			IORING_HANDLE_REF handleRef = IoRingHandleRefFromIndex(0);
			BuildIoRingReadFile(m_IoRingHandle, handleRef, bufferRef, static_cast<UINT32>(m_Config.bufferSize),
			                    m_FilePrefetchPtr, 0x100 + bufferIndex, IOSQE_FLAGS_NONE);
			m_FilePrefetchPtr += m_Config.bufferSize;
			targetPrefetchBuffer.state = PrefetchBufferState::InKernel;

			if (submit)
			{
				SubmitIoRing(m_IoRingHandle, 0, 0, nullptr);
			}
		}

		void WindowsIoRingDriver::VirtualAllocDeleter::operator()(void* ptr) const noexcept
		{
			if (ptr != nullptr)
			{
				VirtualFree(ptr, 0, MEM_RELEASE);
			}
		}
	}  // namespace internal
}  // namespace pcpp