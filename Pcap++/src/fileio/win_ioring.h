#pragma once

#include "PcapFileDevice.h"
#include <ioringapi.h>
#include <array>
#include <vector>
#include <memory>
#include <Windows.h>

namespace pcpp
{
    namespace internal
    {
        class WindowsIoRingDriver final : public FileIOReadDriver
		{
		public:
			struct IoRingConfig
			{
				/// @brief The number of prefetch buffers to use.
				size_t numBuffers = 3;
				/// @brief The size of the prefetch buffers in bytes.
				size_t bufferSize = 4 * 1024 * 1024;
			};

			WindowsIoRingDriver(IoRingConfig config = IoRingConfig());

			~WindowsIoRingDriver() override
			{
				WindowsIoRingDriver::close();
			}

			// Inherited via FileIOReadDriver
			bool isOpen() const override;
			
			bool open(std::string const& filename) override;
			void close() override;

			size_t readBytes(char* buffer, size_t size) override;
			size_t ignoreBytes(size_t size) override;

			bool isEof() const
			{
				return m_ReadEofReached;
			}

		private:
			size_t readBytesImpl(char* buffer, size_t size);

			struct VirtualAllocDeleter
			{
				void operator()(void* ptr) const noexcept;
			};

			enum class PrefetchBufferState
			{
				Idle,
				InKernel,
				Ready,
			};

			struct PrefetchBuffer
			{
				std::unique_ptr<void, VirtualAllocDeleter> buffer;
				PrefetchBufferState state = PrefetchBufferState::Idle;
				HRESULT lastIoResult = S_OK;
				size_t bytesRead = 0;
			};

			IoRingConfig m_Config;
			HANDLE m_FileHandle = nullptr;
			HIORING m_IoRingHandle = nullptr;
			
			std::vector<PrefetchBuffer> m_PrefetchBuffers;

			size_t m_FilePrefetchPtr = 0;
			size_t m_FileReadPtr = 0;
			bool m_ReadEofReached = false;
			bool m_PrefetchEofReached = false;

			size_t getBufferIndexForRead(size_t readPtr) const
			{
				return (readPtr / m_Config.bufferSize) % m_PrefetchBuffers.size();
			}
			size_t getBufferOffsetForRead(size_t readPtr) const
			{
				return readPtr % m_Config.bufferSize;
			}

			void dequeCompletedIoRingEvents();
			void waitForBufferReady(size_t bufferIndex);
			void consumeBuffer(size_t bufferIndex);

			// Builds a read request for the given buffer index for the next part of the file.
			// If submitRing is true, the request is submitted to the IO ring immediately.
			void submitReadForBuffer(size_t bufferIndex, bool submitRing = true);
		};
    }
}