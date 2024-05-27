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
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> getAllRemotePcapDevices(const IPAddress& ipAddress, uint16_t port, pcap_rmtauth* pRmAuth)
		{
			PCPP_LOG_DEBUG("Searching remote devices on IP: " << ipAddress << " and port: " << port);
			std::array<char, PCAP_BUF_SIZE> remoteCaptureString;
			std::array<char, PCAP_ERRBUF_SIZE> errorBuf;
			if (pcap_createsrcstr(remoteCaptureString.data(), PCAP_SRC_IFREMOTE, ipAddress.toString().c_str(),
								  std::to_string(port).c_str(), nullptr, errorBuf.data()) != 0)
			{
				throw std::runtime_error("Error creating the remote connection string. Error: " + std::string(errorBuf.begin(), errorBuf.end()));
			}

			PCPP_LOG_DEBUG("Remote capture string: " << remoteCaptureString.data());

			pcap_if_t* interfaceListRaw;
			if (pcap_findalldevs_ex(remoteCaptureString.data(), pRmAuth, &interfaceListRaw, errorBuf.data()) < 0)
			{
				throw std::runtime_error("Error retrieving device on remote machine. Error: " + std::string(errorBuf.begin(), errorBuf.end()));
			}
			return std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter>(interfaceListRaw);
		}
	}
}