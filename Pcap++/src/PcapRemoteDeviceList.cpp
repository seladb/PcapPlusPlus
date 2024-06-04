#if defined(_WIN32)

#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDeviceList.h"
#include "Logger.h"
#include "IpUtils.h"
#include "IpAddressUtils.h"
#include "DeviceUtils.h"
#include "MemoryUtils.h"
#include "pcap.h"
#include <array>
#include <ws2tcpip.h>

namespace pcpp
{

PcapRemoteDeviceList::PcapRemoteDeviceList(const IPAddress &ipAddress, uint16_t port, std::shared_ptr<PcapRemoteAuthentication> remoteAuth, std::vector<std::shared_ptr<PcapRemoteDevice>> deviceList)
	: m_RemoteDeviceList(std::move(deviceList)), m_RemoteMachineIpAddress(ipAddress), m_RemoteMachinePort(port), m_RemoteAuthentication(std::move(remoteAuth))
{
	updateDeviceListView();
}

void PcapRemoteDeviceList::updateDeviceListView() const
{
	// Technically if a device is removed and a different device is added, it might cause issues,
	// but as far as I can see the LiveDeviceList is only modified on construction and reset, and that is a whole list
	// refresh which can easily be handled by clearing the view list too.
	if (m_RemoteDeviceList.size() != m_RemoteDeviceListView.size())
	{
		m_RemoteDeviceListView.resize(m_RemoteDeviceList.size());
		// Full update of all elements of the view vector to synchronize them with the main vector.
		std::transform(m_RemoteDeviceList.begin(), m_RemoteDeviceList.end(), m_RemoteDeviceListView.begin(),
					   [](const std::shared_ptr<PcapRemoteDevice>& ptr) { return ptr.get(); });
	}
}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, nullptr, SmartPtrApi).release();
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress &ipAddress, uint16_t port, SmartPtrApiTag)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, std::unique_ptr<PcapRemoteAuthentication>());
}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth)
{
	return getRemoteDeviceList(ipAddress, port, remoteAuth, SmartPtrApi).release();
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth, SmartPtrApiTag)
{
	std::unique_ptr<PcapRemoteAuthentication> auth = remoteAuth != nullptr ? std::unique_ptr<PcapRemoteAuthentication>(new PcapRemoteAuthentication(*remoteAuth)) : nullptr;
	return getRemoteDeviceList(ipAddress, port, std::move(auth));
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, const PcapRemoteAuthentication& remoteAuth)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, std::unique_ptr<PcapRemoteAuthentication>(new PcapRemoteAuthentication(remoteAuth)));
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, std::unique_ptr<PcapRemoteAuthentication> remoteAuth)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, std::shared_ptr<PcapRemoteAuthentication>(std::move(remoteAuth)));
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, std::shared_ptr<PcapRemoteAuthentication> remoteAuth)
{
	pcap_rmtauth* pRmAuth = nullptr;
	pcap_rmtauth rmAuth;
	if (remoteAuth != nullptr)
	{
		PCPP_LOG_DEBUG("Authentication requested. Username: " << remoteAuth->userName << ", Password: " << remoteAuth->password);
		rmAuth = remoteAuth->getPcapRmAuth();
		pRmAuth = &rmAuth;
	}

	std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> interfaceList;
	try
	{
		interfaceList = internal::getAllRemotePcapDevices(ipAddress, port, pRmAuth);
	}
	catch (const std::exception& e)
	{
		PCPP_LOG_ERROR(e.what());
		return nullptr;
	}

	std::vector<std::shared_ptr<PcapRemoteDevice>> remoteDeviceList;
	for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr; currInterface = currInterface->next)
	{
		// PcapRemoteDevice ctor is private can't be accessed by std::make_shared.
		std::shared_ptr<PcapRemoteDevice> pNewRemoteDevice = std::shared_ptr<PcapRemoteDevice>(new PcapRemoteDevice(currInterface, remoteAuth, ipAddress, port));
		remoteDeviceList.push_back(std::move(pNewRemoteDevice));
	}

	return std::unique_ptr<PcapRemoteDeviceList>(new PcapRemoteDeviceList(ipAddress, port, std::move(remoteAuth), std::move(remoteDeviceList)));
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const std::string& ipAddrAsString) const
{
	// This line creates and immediately deconstructs an extra shared pointer which is slow due to the atomic reference
	// count. As the current function returns a non-owning pointer, the list's shared pointer copy is the only one keeping the device object alive.
	return getRemoteDeviceByIP(ipAddrAsString, SmartPtrApi).get();
}

std::shared_ptr<PcapRemoteDevice> PcapRemoteDeviceList::getRemoteDeviceByIP(const std::string& ipAddrAsString, SmartPtrApiTag) const
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

	return getRemoteDeviceByIP(ipAddr, SmartPtrApi);
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPAddress& ipAddr) const
{
	// This line creates and immediately deconstructs an extra shared pointer which is slow due to the atomic reference
	// count. As the current function returns a non-owning pointer, the list's shared pointer copy is the only one keeping the device object alive.
	return getRemoteDeviceByIP(ipAddr, SmartPtrApi).get();
}

std::shared_ptr<PcapRemoteDevice> PcapRemoteDeviceList::getRemoteDeviceByIP(const IPAddress& ipAddr, SmartPtrApiTag) const
{
	switch (ipAddr.getType())
	{
	case IPAddress::IPv4AddressType:
		return getRemoteDeviceByIP(ipAddr.getIPv4(), SmartPtrApi);
	case IPAddress::IPv6AddressType:
		return getRemoteDeviceByIP(ipAddr.getIPv6(), SmartPtrApi);
	default:
		throw std::invalid_argument("Unsupported IP Address type.");
	}
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv4Address& ip4Addr) const
{
	// This line creates and immediately deconstructs an extra shared pointer which is slow due to the atomic reference
	// count. As the current function returns a non-owning pointer, the list's shared pointer copy is the only one keeping the device object alive.
	return getRemoteDeviceByIP(ip4Addr, SmartPtrApi).get();
}

std::shared_ptr<PcapRemoteDevice> PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv4Address& ip4Addr, SmartPtrApiTag) const
{
	PCPP_LOG_DEBUG("Searching all remote devices in list...");
	for(const auto& device : m_RemoteDeviceList)
	{
		PCPP_LOG_DEBUG("Searching device '" << device->m_Name << "'. Searching all addresses...");
		for(const auto& addressInfo : device->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addressInfo.addr != nullptr)
			{
				std::array<char, INET6_ADDRSTRLEN> addrAsString;
				internal::sockaddr2string(addressInfo.addr, addrAsString.data(), addrAsString.size());
				PCPP_LOG_DEBUG("Searching address " << addrAsString.data());
			}

			in_addr* currAddr = internal::try_sockaddr2in_addr(addressInfo.addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (*currAddr == ip4Addr)
			{
				PCPP_LOG_DEBUG("Found matching address!");
				return device;
			}
		}
	}

	return nullptr;

}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv6Address &ip6Addr) const
{
	// This line creates and immediately deconstructs an extra shared pointer which is slow due to the atomic reference
	// count. As the current function returns a non-owning pointer, the list's shared pointer copy is the only one keeping the device object alive.
	return getRemoteDeviceByIP(ip6Addr, SmartPtrApi).get();
}

std::shared_ptr<PcapRemoteDevice> PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv6Address& ip6Addr, SmartPtrApiTag) const
{
	PCPP_LOG_DEBUG("Searching all remote devices in list...");
	for(const auto& device : m_RemoteDeviceList)
	{
		PCPP_LOG_DEBUG("Searching device '" << device->m_Name << "'. Searching all addresses...");
		for(const auto& addressInfo : device->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addressInfo.addr != nullptr)
			{
				std::array<char, INET6_ADDRSTRLEN> addrAsString;
				internal::sockaddr2string(addressInfo.addr, addrAsString.data(), addrAsString.size());
				PCPP_LOG_DEBUG("Searching address " << addrAsString.data());
			}

			in6_addr* currAddr = internal::try_sockaddr2in6_addr(addressInfo.addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (*currAddr == ip6Addr)
			{
				PCPP_LOG_DEBUG("Found matching address!");
				return device;
			}
		}
	}

	return nullptr;
}

} // namespace pcpp

#endif // _WIN32
