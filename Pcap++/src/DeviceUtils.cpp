#include "DeviceUtils.h"

#include <array>
#include <string>

#include "pcap.h"
#include "Logger.h"
#include "IpAddress.h"

namespace pcpp
{
	namespace internal
	{
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> getAllLocalPcapDevices()
		{
			pcap_if_t* interfaceListRaw;
			std::array<char, PCAP_ERRBUF_SIZE> errbuf;
			int err = pcap_findalldevs(&interfaceListRaw, errbuf.data());
			if (err < 0)
			{
				throw std::runtime_error("Error searching for devices: " + std::string(errbuf.begin(), errbuf.end()));
			}
			// Assigns the raw pointer to the smart pointer with specialized deleter.
			return std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter>(interfaceListRaw);
		}
	}  // namespace internal
}  // namespace pcpp
