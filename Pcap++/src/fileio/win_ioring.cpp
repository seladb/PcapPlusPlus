#include "win_ioring.h"
#include <Windows.h>
#include <Logger.h>
#include <memory>

namespace pcpp
{
    namespace internal
	{
		WindowsIoRingDriver::WindowsIoRingDriver() : m_IoRingHandle(nullptr)
		{
		}

		bool WindowsIoRingDriver::isOpen() const
		{
			return m_IoRingHandle != nullptr;
		}
		bool WindowsIoRingDriver::open(std::string const& filename)
		{
			uint32_t sqSize = 16;
			uint32_t cqSize = 2 * sqSize;
			IORING_CREATE_FLAGS createFlags{};
			createFlags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
			createFlags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
			if(!CreateIoRing(IORING_VERSION_3,createFlags,sqSize,cqSize,&m_IoRingHandle))
			{
				PCPP_LOG_ERROR("Failed to create IO ring for file " << filename);
				return false;
			}

			struct VirtualFreeDeleter
			{
				void operator()(void* ptr) const
				{
					if (ptr != nullptr)
					{
						VirtualFree(ptr, 0, MEM_RELEASE);
					}
				}
			};

			const uint32_t bufferSize = 4096;
			std::unique_ptr<void, VirtualFreeDeleter> pBuffer(VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

			IORING_BUFFER_INFO bufferInfo{};
			bufferInfo.Address = pBuffer.get();
			bufferInfo.Length = bufferSize;

			uint32_t bufferIndex = 0;
			if(!BuildIoRingRegisterBuffers(m_IoRingHandle, 1, &bufferInfo, bufferIndex))
			{
				PCPP_LOG_ERROR("Failed to register IO ring buffers for file " << filename);
				return false;
			}

			// Open file
			HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

			
			IORING_BUFFER_REF bufferRef = IoRingBufferRefFromIndexAndOffset(bufferIndex, 0);
			



			return m_IoRingHandle != nullptr;
		}

		void WindowsIoRingDriver::close()
		{
			if (m_IoRingHandle != nullptr)
			{
				CloseIoRing(m_IoRingHandle);
				m_IoRingHandle = nullptr;
			}
		}

		size_t WindowsIoRingDriver::readBytes(char* buffer, size_t size)
		{
			return size_t();
		}
		size_t WindowsIoRingDriver::ignoreBytes(size_t size)
		{
			return size_t();
		}
	}  // namespace internal
}