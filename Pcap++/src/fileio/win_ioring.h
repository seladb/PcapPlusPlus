#pragma once

#include "PcapFileDevice.h"
#include <ioringapi.h>
#include <array>
#include <vector>

namespace pcpp
{
    namespace internal
    {
        class WindowsIoRingDriver : public FileIOReadDriver
		{
		public:
			WindowsIoRingDriver();

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

		private:
			HIORING m_IoRingHandle = nullptr;
		};
    }
}