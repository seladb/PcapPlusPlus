#define LOG_MODULE PcapLogModuleLiveDevice

#include "IpUtils.h"
#include "IpAddressUtils.h"
#include "PcapLiveDeviceList.h"
#include "Logger.h"
#include "PcapUtils.h"
#include "DeviceUtils.h"
#include "SystemUtils.h"
#include "pcap.h"
#include <array>
#include <sstream>
#include <algorithm>
#if defined(_WIN32)
#	include <ws2tcpip.h>
#	include <iphlpapi.h>
#	include "WinPcapLiveDevice.h"
#elif defined(__APPLE__)
#	include <systemconfiguration/scdynamicstore.h>
#elif defined(__FreeBSD__)
#	include <arpa/nameser.h>
#	include <resolv.h>
#endif

namespace pcpp
{
	namespace
	{
		void syncPointerVectors(PointerVector<PcapLiveDevice> const& mainVector,
		                        std::vector<PcapLiveDevice*>& viewVector)
		{
			viewVector.resize(mainVector.size());
			// Full update of all elements of the view vector to synchronize them with the main vector.
			std::copy(mainVector.begin(), mainVector.end(), viewVector.begin());
		}
	}  // namespace

	PcapLiveDeviceList::PcapLiveDeviceList() : Base(fetchAllLocalDevices()), m_DnsServers(fetchDnsServers())
	{
		syncPointerVectors(m_DeviceList, m_LiveDeviceListView);
	}

	PointerVector<PcapLiveDevice> PcapLiveDeviceList::fetchAllLocalDevices()
	{
		PointerVector<PcapLiveDevice> deviceList;
		std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> interfaceList;
		try
		{
			interfaceList = internal::getAllLocalPcapDevices();
		}
		catch (const std::exception& e)
		{
			(void)e;  // Suppress the unreferenced local variable warning when PCPP_LOG_ERROR is disabled
			PCPP_LOG_ERROR(e.what());
		}

		PCPP_LOG_DEBUG("Pcap lib version info: " << IPcapDevice::getPcapLibVersionInfo());

		for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr;
		     currInterface = currInterface->next)
		{
#if defined(_WIN32)
			auto dev = std::unique_ptr<PcapLiveDevice>(new WinPcapLiveDevice(currInterface, true, true, true));
#else  //__linux__, __APPLE__, __FreeBSD__
			auto dev = std::unique_ptr<PcapLiveDevice>(new PcapLiveDevice(currInterface, true, true, true));
#endif
			deviceList.pushBack(std::move(dev));
		}
		return deviceList;
	}

	std::vector<IPv4Address> PcapLiveDeviceList::fetchDnsServers()
	{
		std::vector<IPv4Address> dnsServers;
#if defined(_WIN32)
		FIXED_INFO* fixedInfo;
		ULONG ulOutBufLen;
		DWORD dwRetVal;
		IP_ADDR_STRING* pIPAddr;

		std::array<uint8_t, sizeof(FIXED_INFO)> bufferOnStack;
		fixedInfo = reinterpret_cast<FIXED_INFO*>(bufferOnStack.data());
		ulOutBufLen = bufferOnStack.size();

		dwRetVal = GetNetworkParams(fixedInfo, &ulOutBufLen);
		std::vector<uint8_t> bufferOnHeap;
		if (ERROR_BUFFER_OVERFLOW == dwRetVal)
		{
			// Stack buffer was not enough. Allocating a heap buffer.
			bufferOnHeap.resize(ulOutBufLen);
			fixedInfo = reinterpret_cast<FIXED_INFO*>(bufferOnHeap.data());
			ulOutBufLen = bufferOnHeap.size();
			// Retrying to get network info.
			dwRetVal = GetNetworkParams(fixedInfo, &ulOutBufLen);
		}

		if (dwRetVal != 0)
			PCPP_LOG_ERROR("Call to GetNetworkParams failed. Return Value: " << std::hex << dwRetVal);
		else
		{
			int dnsServerCounter = 0;
			try
			{
				dnsServers.push_back(IPv4Address(fixedInfo->DnsServerList.IpAddress.String));
				PCPP_LOG_DEBUG("Default DNS server IP #" << dnsServerCounter++ << ": "
				                                         << fixedInfo->DnsServerList.IpAddress.String);
			}
			catch (const std::exception&)
			{
				PCPP_LOG_DEBUG(
				    "Failed to parse default DNS server IP address: " << fixedInfo->DnsServerList.IpAddress.String);
			}

			pIPAddr = fixedInfo->DnsServerList.Next;
			while (pIPAddr)
			{
				try
				{
					dnsServers.push_back(IPv4Address(pIPAddr->IpAddress.String));
					PCPP_LOG_DEBUG("Default DNS server IP #" << dnsServerCounter++ << ": "
					                                         << pIPAddr->IpAddress.String);
				}
				catch (const std::exception&)
				{
					PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << pIPAddr->IpAddress.String);
				}
				pIPAddr = pIPAddr->Next;
			}
		}
#elif defined(__linux__)
		// verify that nmcli exist
		std::string command = "command -v nmcli >/dev/null 2>&1 || { echo 'nmcli not installed'; }";
		std::string nmcliExists = executeShellCommand(command);
		if (nmcliExists != "")
		{
			PCPP_LOG_DEBUG("Error retrieving DNS server list: nmcli doesn't exist");
			return {};
		}

		// check nmcli major version (0 or 1)
		command = "nmcli -v | awk -F' ' '{print $NF}' | awk -F'.' '{print $1}'";
		std::string nmcliMajorVer = executeShellCommand(command);
		nmcliMajorVer.erase(std::remove(nmcliMajorVer.begin(), nmcliMajorVer.end(), '\n'), nmcliMajorVer.end());
		PCPP_LOG_DEBUG("Found nmcli. nmcli major version is: '" << nmcliMajorVer << "'");

		// build nmcli command according to its major version
		if (nmcliMajorVer == "0")
			command = "nmcli dev list | grep IP4.DNS";
		else
			command = "nmcli dev show | grep IP4.DNS";

		std::string dnsServersInfo = executeShellCommand(command);
		if (dnsServersInfo == "")
		{
			PCPP_LOG_DEBUG("Error retrieving DNS server list: call to nmcli gave no output");
			return {};
		}

		std::istringstream stream(dnsServersInfo);
		std::string line;
		int i = 1;
		while (std::getline(stream, line))
		{
			std::istringstream lineStream(line);
			std::string headline;
			std::string dnsIP;
			lineStream >> headline;
			lineStream >> dnsIP;
			IPv4Address dnsIPAddr;
			try
			{
				dnsIPAddr = IPv4Address(dnsIP);
			}
			catch (const std::exception& e)
			{
				PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << dnsIP << ": " << e.what());
				continue;
			}

			if (std::find(dnsServers.begin(), dnsServers.end(), dnsIPAddr) == dnsServers.end())
			{
				dnsServers.push_back(dnsIPAddr);
				PCPP_LOG_DEBUG("Default DNS server IP #" << i++ << ": " << dnsIPAddr);
			}
		}
#elif defined(__APPLE__)

		SCDynamicStoreRef dynRef = SCDynamicStoreCreate(kCFAllocatorSystemDefault, CFSTR("iked"), nullptr, nullptr);
		if (dynRef == nullptr)
		{
			PCPP_LOG_DEBUG("Couldn't set DNS server list: failed to retrieve SCDynamicStore");
			return {};
		}

		CFDictionaryRef dnsDict = (CFDictionaryRef)SCDynamicStoreCopyValue(dynRef, CFSTR("State:/Network/Global/DNS"));

		if (dnsDict == nullptr)
		{
			PCPP_LOG_DEBUG("Couldn't set DNS server list: failed to get DNS dictionary");
			CFRelease(dynRef);
			return {};
		}

		CFArrayRef serverAddresses = (CFArrayRef)CFDictionaryGetValue(dnsDict, CFSTR("ServerAddresses"));

		if (serverAddresses == nullptr)
		{
			PCPP_LOG_DEBUG("Couldn't set DNS server list: server addresses array is null");
			CFRelease(dynRef);
			CFRelease(dnsDict);
			return {};
		}

		CFIndex count = CFArrayGetCount(serverAddresses);
		for (CFIndex i = 0; i < count; i++)
		{
			CFStringRef serverAddress = (CFStringRef)CFArrayGetValueAtIndex(serverAddresses, i);

			if (serverAddress == nullptr)
				continue;

			uint8_t buf[20];
			char* serverAddressCString = (char*)buf;
			CFStringGetCString(serverAddress, serverAddressCString, 20, kCFStringEncodingUTF8);
			try
			{
				dnsServers.push_back(IPv4Address(serverAddressCString));
				PCPP_LOG_DEBUG("Default DNS server IP #" << (int)(i + 1) << ": " << serverAddressCString);
			}
			catch (const std::exception& e)
			{
				PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << serverAddressCString << ": " << e.what());
			}
		}

		CFRelease(dynRef);
		CFRelease(dnsDict);

#elif defined(__FreeBSD__)

		res_init();

		for (int i = 0; i < _res.nscount; i++)
		{
			sockaddr* saddr = (sockaddr*)&_res.nsaddr_list[i];
			if (saddr == nullptr)
				continue;
			in_addr* inaddr = internal::try_sockaddr2in_addr(saddr);
			if (inaddr == nullptr)
				continue;

			try
			{
				dnsServers.push_back(IPv4Address(internal::in_addr2int(*inaddr)));
			}
			catch (const std::exception& e)
			{
				PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << internal::in_addr2int(*inaddr) << ": "
				                                                         << e.what());
			}
		}

#endif
		return dnsServers;
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPAddress& ipAddr) const
	{
		return getDeviceByIp(ipAddr);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByIp(const IPAddress& ipAddr) const
	{
		if (ipAddr.getType() == IPAddress::IPv4AddressType)
		{
			return getDeviceByIp(ipAddr.getIPv4());
		}
		else  // IPAddress::IPv6AddressType
		{
			return getDeviceByIp(ipAddr.getIPv6());
		}
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const
	{
		return getDeviceByIp(ipAddr);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByIp(const IPv4Address& ipAddr) const
	{
		auto it = std::find_if(m_DeviceList.begin(), m_DeviceList.end(), [&ipAddr](PcapLiveDevice const* devPtr) {
			auto devIP = devPtr->getIPv4Address();
			return devIP == ipAddr;
		});
		return it != m_DeviceList.end() ? *it : nullptr;
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const
	{
		return getDeviceByIp(ip6Addr);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByIp(const IPv6Address& ip6Addr) const
	{
		auto it = std::find_if(m_DeviceList.begin(), m_DeviceList.end(), [&ip6Addr](PcapLiveDevice const* devPtr) {
			auto devIP = devPtr->getIPv6Address();
			return devIP == ip6Addr;
		});
		return it != m_DeviceList.end() ? *it : nullptr;
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const
	{
		return getDeviceByIp(ipAddrAsString);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByIp(const std::string& ipAddrAsString) const
	{
		IPAddress ipAddr;
		try
		{
			ipAddr = IPAddress(ipAddrAsString);
		}
		catch (const std::exception&)
		{
			PCPP_LOG_ERROR("IP address is not valid: " + ipAddrAsString);
			return nullptr;
		}

		PcapLiveDevice* result = getDeviceByIp(ipAddr);
		return result;
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByName(const std::string& name) const
	{
		return getDeviceByName(name);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByName(const std::string& name) const
	{
		PCPP_LOG_DEBUG("Searching all live devices...");
		auto devIter = std::find_if(m_DeviceList.begin(), m_DeviceList.end(),
		                            [&name](PcapLiveDevice* dev) { return dev->getName() == name; });

		if (devIter == m_DeviceList.end())
		{
			PCPP_LOG_DEBUG("Found no live device with name '" << name << "'");
			return nullptr;
		}

		return *devIter;
	}

	PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const
	{
		return getDeviceByIpOrName(ipOrName);
	}

	PcapLiveDevice* PcapLiveDeviceList::getDeviceByIpOrName(const std::string& ipOrName) const
	{
		try
		{
			IPAddress interfaceIP = IPAddress(ipOrName);
			return getDeviceByIp(interfaceIP);
		}
		catch (std::exception&)
		{
			return getDeviceByName(ipOrName);
		}
	}

	PcapLiveDeviceList* PcapLiveDeviceList::clone()
	{
		return new PcapLiveDeviceList;
	}

	void PcapLiveDeviceList::reset()
	{
		m_LiveDeviceListView.clear();

		m_DeviceList = fetchAllLocalDevices();
		m_DnsServers = fetchDnsServers();

		syncPointerVectors(m_DeviceList, m_LiveDeviceListView);
	}

}  // namespace pcpp
