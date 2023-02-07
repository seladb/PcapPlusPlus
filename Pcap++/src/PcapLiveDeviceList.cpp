#define LOG_MODULE PcapLogModuleLiveDevice

#include "IpUtils.h"
#include "PcapLiveDeviceList.h"
#include "Logger.h"
#include "SystemUtils.h"
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

PcapLiveDeviceList::~PcapLiveDeviceList()
{
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}
}

void PcapLiveDeviceList::init()
{
	pcap_if_t* interfaceList;
	char errbuf[PCAP_ERRBUF_SIZE];
	int err = pcap_findalldevs(&interfaceList, errbuf);
	if (err < 0)
	{
		PCPP_LOG_ERROR("Error searching for devices: " << errbuf);
	}

	PCPP_LOG_DEBUG("Pcap lib version info: " << IPcapDevice::getPcapLibVersionInfo());

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != nullptr)
	{
#if defined(_WIN32)
		PcapLiveDevice* dev = new WinPcapLiveDevice(currInterface, true, true, true);
#else //__linux__, __APPLE__, __FreeBSD__
		PcapLiveDevice* dev = new PcapLiveDevice(currInterface, true, true, true);
#endif
		currInterface = currInterface->next;
		m_LiveDeviceList.insert(m_LiveDeviceList.end(), dev);
	}

	setDnsServers();

	PCPP_LOG_DEBUG("Freeing live device data");
	pcap_freealldevs(interfaceList);
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
		m_DnsServers.push_back(IPv4Address(fixedInfo->DnsServerList.IpAddress.String));
		int i = 1;
		PCPP_LOG_DEBUG("Default DNS server IP #" << i++ << ": " << fixedInfo->DnsServerList.IpAddress.String);

		pIPAddr = fixedInfo->DnsServerList.Next;
		while ( pIPAddr )
		{
			m_DnsServers.push_back(IPv4Address(pIPAddr->IpAddress.String));
			PCPP_LOG_DEBUG("Default DNS server IP #" << i++ << ": " << pIPAddr->IpAddress.String);
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
		IPv4Address dnsIPAddr(dnsIP);
		if (!dnsIPAddr.isValid())
			continue;

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
		m_DnsServers.push_back(IPv4Address(serverAddressCString));
		PCPP_LOG_DEBUG("Default DNS server IP #" << (int)(i+1) << ": " << serverAddressCString);
	}

	CFRelease(dynRef);
	CFRelease(dnsDict);

#elif defined(__FreeBSD__)

	res_init();

	for (int i = 0; i < _res.nscount; i++)
	{
		sockaddr* saddr = (sockaddr*)&_res.nsaddr_list[i];
		if (saddr == NULL)
			continue;
		in_addr* inaddr = internal::sockaddr2in_addr(saddr);
		if (inaddr == NULL)
			continue;
		m_DnsServers.push_back(IPv4Address(internal::in_addr2int(*inaddr)));
	}

#endif
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPAddress& ipAddr) const
{
	if (ipAddr.getType() == IPAddress::IPv4AddressType)
	{
		return getPcapLiveDeviceByIp(ipAddr.getIPv4());
	}
	else //IPAddress::IPv6AddressType
	{
		return getPcapLiveDeviceByIp(ipAddr.getIPv6());
	}
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::const_iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		PCPP_LOG_DEBUG("Searching device '" << (*devIter)->m_Name << "'. Searching all addresses...");
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter->addr != nullptr)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter->addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in_addr* currAddr = internal::sockaddr2in_addr(addrIter->addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (currAddr->s_addr == ipAddr.toInt())
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return nullptr;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::const_iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		PCPP_LOG_DEBUG("Searching device '" << (*devIter)->m_Name << "'. Searching all addresses...");
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter->addr != nullptr)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter->addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in6_addr* currAddr = internal::sockaddr2in6_addr(addrIter->addr);
			if (currAddr == nullptr)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			uint8_t* addrAsArr; size_t addrLen;
			ip6Addr.copyTo(&addrAsArr, addrLen);
			if (memcmp(currAddr, addrAsArr, sizeof(struct in6_addr)) == 0)
			{
				PCPP_LOG_DEBUG("Found matched address!");
				delete [] addrAsArr;
				return (*devIter);
			}

			delete [] addrAsArr;
		}
	}

	return nullptr;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const
{
	IPAddress ipAddr(ipAddrAsString);
	if (!ipAddr.isValid())
	{
		PCPP_LOG_ERROR("IP address illegal");
		return nullptr;
	}

	PcapLiveDevice* result = PcapLiveDeviceList::getPcapLiveDeviceByIp(ipAddr);
	return result;
}


PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByName(const std::string& name) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::const_iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		if (name == (*devIter)->getName())
			return (*devIter);
	}

	return nullptr;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const
{
	IPAddress interfaceIP(ipOrName);
	if (interfaceIP.isValid())
	{
		return PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
	}
	else
	{
		return PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ipOrName);
	}
}

PcapLiveDeviceList* PcapLiveDeviceList::clone()
{
	return new PcapLiveDeviceList;
}

void PcapLiveDeviceList::reset()
{
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}

	m_LiveDeviceList.clear();
	m_DnsServers.clear();

	init();
}

} // namespace pcpp
