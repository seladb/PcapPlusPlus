#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDeviceList.h"
#include "Logger.h"
#include "IpUtils.h"
#include "PcapUtils.h"
#include "IpAddressUtils.h"
#include "pcap.h"
#include <array>
#include <ws2tcpip.h>

namespace pcpp
{

	namespace
	{
		/// Fetches a list of all network devices on a remote machine that WinPcap/NPcap can find.
		/// @param[in] ipAddress IP address of the remote machine.
		/// @param[in] port Port to use when connecting to the remote machine.
		/// @param[in] pRmAuth Pointer to an authentication structure to use when connecting to the remote machine.
		/// Nullptr if no authentication is required.
		/// @return A smart pointer to an interface list structure.
		/// @throws std::runtime_error The system encountered an error fetching the devices.
		std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> getAllRemotePcapDevices(
		    const IPAddress& ipAddress, uint16_t port, pcap_rmtauth* pRmAuth = nullptr)
		{
			PCPP_LOG_DEBUG("Searching remote devices on IP: " << ipAddress << " and port: " << port);
			std::array<char, PCAP_BUF_SIZE> remoteCaptureString;
			std::array<char, PCAP_ERRBUF_SIZE> errorBuf;
			if (pcap_createsrcstr(remoteCaptureString.data(), PCAP_SRC_IFREMOTE, ipAddress.toString().c_str(),
			                      std::to_string(port).c_str(), nullptr, errorBuf.data()) != 0)
			{
				throw std::runtime_error("Error creating the remote connection string. Error: " +
				                         std::string(errorBuf.begin(), errorBuf.end()));
			}

			PCPP_LOG_DEBUG("Remote capture string: " << remoteCaptureString.data());

			pcap_if_t* interfaceListRaw;
			if (pcap_findalldevs_ex(remoteCaptureString.data(), pRmAuth, &interfaceListRaw, errorBuf.data()) < 0)
			{
				throw std::runtime_error("Error retrieving device on remote machine. Error: " +
				                         std::string(errorBuf.begin(), errorBuf.end()));
			}
			return std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter>(interfaceListRaw);
		}
	}  // namespace

	PcapRemoteDeviceList::PcapRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
	                                           std::shared_ptr<PcapRemoteAuthentication> remoteAuth,
	                                           PointerVector<PcapRemoteDevice> deviceList)
	    : Base(std::move(deviceList)), m_RemoteMachineIpAddress(ipAddress), m_RemoteMachinePort(port),
	      m_RemoteAuthentication(std::move(remoteAuth))
	{}

	PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port)
	{
		auto result = PcapRemoteDeviceList::createRemoteDeviceList(ipAddress, port);
		return result.release();
	}

	std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::createRemoteDeviceList(const IPAddress& ipAddress,
	                                                                                   uint16_t port)
	{
		return PcapRemoteDeviceList::createRemoteDeviceList(ipAddress, port, nullptr);
	}

	PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
	                                                                PcapRemoteAuthentication* remoteAuth)
	{
		auto result = PcapRemoteDeviceList::createRemoteDeviceList(ipAddress, port, remoteAuth);
		return result.release();
	}

	std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::createRemoteDeviceList(
	    const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication const* remoteAuth)
	{
		std::shared_ptr<PcapRemoteAuthentication> pRemoteAuthCopy;
		pcap_rmtauth* pRmAuth = nullptr;
		pcap_rmtauth rmAuth;
		if (remoteAuth != nullptr)
		{
			PCPP_LOG_DEBUG("Authentication requested. Username: " << remoteAuth->userName
			                                                      << ", Password: " << remoteAuth->password);
			pRemoteAuthCopy = std::make_shared<PcapRemoteAuthentication>(*remoteAuth);
			rmAuth = pRemoteAuthCopy->getPcapRmAuth();
			pRmAuth = &rmAuth;
		}

		std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> interfaceList;
		try
		{
			interfaceList = getAllRemotePcapDevices(ipAddress, port, pRmAuth);
		}
		catch (const std::exception& e)
		{
			(void)e;  // Suppress the unreferenced local variable warning when PCPP_LOG_ERROR is disabled
			PCPP_LOG_ERROR(e.what());
			return nullptr;
		}

		PointerVector<PcapRemoteDevice> devices;
		try
		{
			for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr;
			     currInterface = currInterface->next)
			{
				auto pNewRemoteDevice = std::unique_ptr<PcapRemoteDevice>(
				    new PcapRemoteDevice(currInterface, pRemoteAuthCopy, ipAddress, port));
				devices.pushBack(std::move(pNewRemoteDevice));
			}
		}
		catch (const std::exception& e)
		{
			(void)e;  // Suppress the unreferenced local variable warning when PCPP_LOG_ERROR is disabled
			PCPP_LOG_ERROR("Error creating remote devices: " << e.what());
			return nullptr;
		}

		return std::unique_ptr<PcapRemoteDeviceList>(
		    new PcapRemoteDeviceList(ipAddress, port, pRemoteAuthCopy, std::move(devices)));
	}

	PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const std::string& ipAddrAsString) const
	{
		IPAddress ipAddr;

		try
		{
			ipAddr = IPAddress(ipAddrAsString);
		}
		catch (std::exception&)
		{
			PCPP_LOG_ERROR("IP address no valid: " + ipAddrAsString);
			return nullptr;
		}

		PcapRemoteDevice* result = getRemoteDeviceByIP(ipAddr);
		return result;
	}

	PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPAddress& ipAddr) const
	{
		if (ipAddr.getType() == IPAddress::IPv4AddressType)
		{
			return getRemoteDeviceByIP(ipAddr.getIPv4());
		}
		else  // IPAddress::IPv6AddressType
		{
			return getRemoteDeviceByIP(ipAddr.getIPv6());
		}
	}

	PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv4Address& ip4Addr) const
	{
		auto it = std::find_if(m_DeviceList.begin(), m_DeviceList.end(), [&ip4Addr](PcapRemoteDevice const* devPtr) {
			auto devIP = devPtr->getIPv4Address();
			return devIP == ip4Addr;
		});
		return it != m_DeviceList.end() ? *it : nullptr;
	}

	PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv6Address& ip6Addr) const
	{
		auto it = std::find_if(m_DeviceList.begin(), m_DeviceList.end(), [&ip6Addr](PcapRemoteDevice const* devPtr) {
			auto devIP = devPtr->getIPv6Address();
			return devIP == ip6Addr;
		});
		return it != m_DeviceList.end() ? *it : nullptr;
	}
}  // namespace pcpp
