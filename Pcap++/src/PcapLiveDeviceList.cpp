#define LOG_MODULE PcapLogModuleLiveDevice

#include "IpUtils.h"
#include "PcapLiveDeviceList.h"
#include "Logger.h"
#include "SystemUtils.h"
#include "MemoryUtils.h"
#include "pcap.h"
#include <string.h>
#include <sstream>
#include <algorithm>
#if defined(_WIN32)
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "WinPcapLiveDevice.h"
#elif defined(__APPLE__)
#include <systemconfiguration/scdynamicstore.h>
#elif defined(__FreeBSD__)
#include <arpa/nameser.h>
#include <resolv.h>
#endif


namespace pcpp
{

PcapLiveDeviceList::PcapLiveDeviceList()
{
	init();
}

void PcapLiveDeviceList::init()
{
	std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> interfaceList;
	{
		pcap_if_t* interfaceListRaw;
		char errbuf[PCAP_ERRBUF_SIZE];
		int err = pcap_findalldevs(&interfaceListRaw, errbuf);
		if (err < 0)
		{
			PCPP_LOG_ERROR("Error searching for devices: " << errbuf);
		}
		// Assigns the raw pointer to the smart pointer with specialized deleter.
		interfaceList = std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter>(interfaceListRaw);
	}

	PCPP_LOG_DEBUG("Pcap lib version info: " << IPcapDevice::getPcapLibVersionInfo());

	for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr; currInterface = currInterface->next)
	{
#if defined(_WIN32)
		std::unique_ptr<PcapLiveDevice> dev = std::unique_ptr<PcapLiveDevice>(new WinPcapLiveDevice(currInterface, true, true, true));
#else //__linux__, __APPLE__, __FreeBSD__
		std::unique_ptr<PcapLiveDevice> dev = std::unique_ptr<PcapLiveDevice>(new PcapLiveDevice(currInterface, true, true, true));
#endif
		m_LiveDeviceList.push_back(std::move(dev));
	}

	setDnsServers();

	// TODO: What to do with this log message? Free All devs is no longer needed here as that is handled by the deleter.
	PCPP_LOG_DEBUG("Freeing live device data");
}

void PcapLiveDeviceList::setDnsServers()
{
#if defined(_WIN32)
	FIXED_INFO * fixedInfo;
	ULONG    ulOutBufLen;
	DWORD    dwRetVal;
	IP_ADDR_STRING * pIPAddr;

	uint8_t buf1[sizeof(FIXED_INFO)];
	fixedInfo = (FIXED_INFO *) buf1;
	ulOutBufLen = sizeof( FIXED_INFO );

	dwRetVal = GetNetworkParams( fixedInfo, &ulOutBufLen );
	uint8_t* buf2 = new uint8_t[ulOutBufLen];
	if(ERROR_BUFFER_OVERFLOW == dwRetVal)
	{
		fixedInfo = (FIXED_INFO *)buf2;
	}

	if ((dwRetVal = GetNetworkParams( fixedInfo, &ulOutBufLen )) != 0)
		PCPP_LOG_ERROR("Call to GetNetworkParams failed. Return Value: " << std::hex << dwRetVal);
	else
	{
		int dnsServerCounter = 0;
		try
		{
			m_DnsServers.push_back(IPv4Address(fixedInfo->DnsServerList.IpAddress.String));
			PCPP_LOG_DEBUG("Default DNS server IP #" << dnsServerCounter++ << ": " << fixedInfo->DnsServerList.IpAddress.String);
		}
		catch(const std::exception&)
		{
			PCPP_LOG_DEBUG("Failed to parse default DNS server IP address: " << fixedInfo->DnsServerList.IpAddress.String);
		}

		pIPAddr = fixedInfo->DnsServerList.Next;
		while ( pIPAddr )
		{
			try
			{
				m_DnsServers.push_back(IPv4Address(pIPAddr->IpAddress.String));
				PCPP_LOG_DEBUG("Default DNS server IP #" << dnsServerCounter++ << ": " << pIPAddr->IpAddress.String);
			}
			catch(const std::exception&)
			{
				PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << pIPAddr->IpAddress.String);
			}
			pIPAddr = pIPAddr -> Next;
		}
	}

	delete[] buf2;
#elif defined(__linux__)
	// verify that nmcli exist
	std::string command = "command -v nmcli >/dev/null 2>&1 || { echo 'nmcli not installed'; }";
	std::string nmcliExists = executeShellCommand(command);
	if (nmcliExists != "")
	{
		PCPP_LOG_DEBUG("Error retrieving DNS server list: nmcli doesn't exist");
		return;
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
		return;
	}

	std::istringstream stream(dnsServersInfo);
	std::string line;
	int i = 1;
	while(std::getline(stream, line))
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
		catch(const std::exception& e)
		{
			PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << dnsIP << ": " << e.what());
			continue;
		}

		if (std::find(m_DnsServers.begin(), m_DnsServers.end(), dnsIPAddr) == m_DnsServers.end())
		{
			m_DnsServers.push_back(dnsIPAddr);
			PCPP_LOG_DEBUG("Default DNS server IP #" << i++ << ": " << dnsIPAddr);
		}
	}
#elif defined(__APPLE__)

	SCDynamicStoreRef dynRef = SCDynamicStoreCreate(kCFAllocatorSystemDefault, CFSTR("iked"), nullptr, nullptr);
	if (dynRef == nullptr)
	{
		PCPP_LOG_DEBUG("Couldn't set DNS server list: failed to retrieve SCDynamicStore");
		return;
	}

	CFDictionaryRef dnsDict = (CFDictionaryRef)SCDynamicStoreCopyValue(dynRef,CFSTR("State:/Network/Global/DNS"));

	if (dnsDict == nullptr)
	{
		PCPP_LOG_DEBUG("Couldn't set DNS server list: failed to get DNS dictionary");
		CFRelease(dynRef);
		return;
	}

	CFArrayRef serverAddresses = (CFArrayRef)CFDictionaryGetValue(dnsDict, CFSTR("ServerAddresses"));

	if (serverAddresses == nullptr)
	{
		PCPP_LOG_DEBUG("Couldn't set DNS server list: server addresses array is null");
		CFRelease(dynRef);
		CFRelease(dnsDict);
		return;
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
			m_DnsServers.push_back(IPv4Address(serverAddressCString));
			PCPP_LOG_DEBUG("Default DNS server IP #" << (int)(i+1) << ": " << serverAddressCString);
		}
		catch(const std::exception& e)
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
		in_addr* inaddr = internal::sockaddr2in_addr(saddr);
		if (inaddr == nullptr)
			continue;

		try
		{
			m_DnsServers.push_back(IPv4Address(internal::in_addr2int(*inaddr)));
		}
		catch(const std::exception& e)
		{
			PCPP_LOG_DEBUG("Failed to parse DNS server IP address: " << internal::in_addr2int(*inaddr) << ": " << e.what());
		}
	}

#endif
}

void PcapLiveDeviceList::updateLiveDeviceListView() const
{
	// Technically if a device is removed and a different device is added, it might cause issues,
	// but as far as I can see the LiveDeviceList is only modified on construction and reset, and that is a whole list refresh
	// which can easily be handled by clearing the view list too.
	if (m_LiveDeviceList.size() != m_LiveDeviceListView.size())
	{
		m_LiveDeviceListView.resize(m_LiveDeviceList.size());
		// Full update of all elements of the view vector to synchronize them with the main vector.
		std::transform(m_LiveDeviceList.begin(), m_LiveDeviceList.end(), m_LiveDeviceListView.begin(),
					   [](const std::shared_ptr<PcapLiveDevice>& ptr) { return ptr.get(); }
		);
	}
}

const std::vector<PcapLiveDevice*>& PcapLiveDeviceList::getPcapLiveDevicesList() const
{
	updateLiveDeviceListView();
	return m_LiveDeviceListView;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPAddress& ipAddr) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByIp(ipAddr, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPAddress& ipAddr, smart_ptr_api_tag) const
{
	if (ipAddr.getType() == IPAddress::IPv4AddressType)
	{
		return getPcapLiveDeviceByIp(ipAddr.getIPv4(), smart_ptr_api);
	}
	else //IPAddress::IPv6AddressType
	{
		return getPcapLiveDeviceByIp(ipAddr.getIPv6(), smart_ptr_api);
	}
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByIp(ipAddr, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv4Address& ipAddr, smart_ptr_api_tag) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(const auto &devIter : m_LiveDeviceList)
	{
		PCPP_LOG_DEBUG("Searching device '" << devIter->m_Name << "'. Searching all addresses...");
		for(const auto &addrIter : devIter->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter.addr != nullptr)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter.addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in_addr* currAddr = internal::sockaddr2in_addr(addrIter.addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is nullptr");
				continue;
			}

			if (currAddr->s_addr == ipAddr.toInt())
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return devIter;
			}
		}
	}

	return nullptr;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByIp(ip6Addr, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv6Address& ip6Addr, smart_ptr_api_tag) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(const auto &devIter : m_LiveDeviceList)
	{
		PCPP_LOG_DEBUG("Searching device '" << devIter->m_Name << "'. Searching all addresses...");
		for(const auto &addrIter : devIter->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter.addr != nullptr)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter.addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in6_addr* currAddr = internal::sockaddr2in6_addr(addrIter.addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is nullptr");
				continue;
			}

			if (memcmp(currAddr, ip6Addr.toBytes(), sizeof(struct in6_addr)) == 0)
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return devIter;
			}
		}
	}

	return nullptr;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByIp(ipAddrAsString, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByIp(const std::string& ipAddrAsString, smart_ptr_api_tag) const
{
	IPAddress ipAddr;
	try
	{
		ipAddr = IPAddress(ipAddrAsString);
	}
	catch(const std::exception&)
	{
		PCPP_LOG_ERROR("IP address is not valid: " + ipAddrAsString);
		return nullptr;
	}

	return PcapLiveDeviceList::getPcapLiveDeviceByIp(ipAddr, smart_ptr_api);
}


PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByName(const std::string& name) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByName(name, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByName(const std::string& name, smart_ptr_api_tag) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	auto devIter = std::find_if(m_LiveDeviceList.begin(), m_LiveDeviceList.end(),
								[&name](const std::shared_ptr<PcapLiveDevice>& dev) { return dev->getName() == name; });

	if (devIter == m_LiveDeviceList.end())
	{
		PCPP_LOG_DEBUG("Found no live device with name '" << name << "'");
		return nullptr;
	}

	return *devIter;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const
{
	// Technically this creates and deconstructs an extra shared ptr leading to some inneficiencies but its shorter.
	// As the current function is to return a non-owning pointer, the shared pointer in the list is left to keep the
	// device alive.
	return getPcapLiveDeviceByIpOrName(ipOrName, smart_ptr_api).get();
}

std::shared_ptr<PcapLiveDevice> PcapLiveDeviceList::getPcapLiveDeviceByIpOrName(const std::string& ipOrName, smart_ptr_api_tag) const
{
	try
	{
		IPAddress interfaceIP = IPAddress(ipOrName);
		return PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP, smart_ptr_api);
	}
	catch (std::exception&)
	{
		return PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ipOrName, smart_ptr_api);
	}
}

PcapLiveDeviceList* PcapLiveDeviceList::clone() const { return clone(smart_ptr_api).release(); }

std::unique_ptr<PcapLiveDeviceList> PcapLiveDeviceList::clone(smart_ptr_api_tag) const
{
	return std::unique_ptr<PcapLiveDeviceList>(new PcapLiveDeviceList());
}

void PcapLiveDeviceList::reset()
{
	m_LiveDeviceListView.clear();
	m_LiveDeviceList.clear();
	m_DnsServers.clear();

	init();
}

} // namespace pcpp
