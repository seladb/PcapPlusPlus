#define LOG_MODULE PcapLogModuleLiveDevice

#include "IpUtils.h"
#include "PcapLiveDeviceList.h"
#include "Logger.h"
#include "SystemUtils.h"
#include <string.h>
#include <sstream>
#include <algorithm>
#if defined(WIN32) || defined(WINx64)
#include <ws2tcpip.h>
#include <iphlpapi.h>
#elif MAC_OS_X
#include <systemconfiguration/scdynamicstore.h>
#endif


namespace pcpp
{

PcapLiveDeviceList::PcapLiveDeviceList()
{
	pcap_if_t* interfaceList;
	char errbuf[PCAP_ERRBUF_SIZE];
	int err = pcap_findalldevs(&interfaceList, errbuf);
	if (err < 0)
	{
		LOG_ERROR("Error searching for devices: %s", errbuf);
	}

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
#ifdef WIN32
		PcapLiveDevice* dev = new WinPcapLiveDevice(currInterface, true, true, true);
#else //LINUX, MAC_OSX
		PcapLiveDevice* dev = new PcapLiveDevice(currInterface, true, true, true);
#endif
		currInterface = currInterface->next;
		m_LiveDeviceList.insert(m_LiveDeviceList.end(), dev);
	}

	setDnsServers();

	LOG_DEBUG("Freeing live device data");
	pcap_freealldevs(interfaceList);
}

PcapLiveDeviceList::~PcapLiveDeviceList()
{
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}

}

void PcapLiveDeviceList::setDnsServers()
{
#if defined(WIN32) || defined(WINx64)
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
		LOG_ERROR("Call to GetNetworkParams failed. Return Value: %08lx\n", dwRetVal);
	else
	{
		m_DnsServers.push_back(IPv4Address(fixedInfo->DnsServerList.IpAddress.String));
		int i = 1;
		LOG_DEBUG("Default DNS server IP #%d: %s\n", i++, fixedInfo->DnsServerList.IpAddress.String );

		pIPAddr = fixedInfo->DnsServerList.Next;
		while ( pIPAddr )
		{
			m_DnsServers.push_back(IPv4Address(pIPAddr->IpAddress.String));
			LOG_DEBUG("Default DNS server IP #%d: %s\n", i++, pIPAddr->IpAddress.String);
			pIPAddr = pIPAddr -> Next;
		}
	}

	delete[] buf2;
#elif LINUX
	// verify that nmcli exist
	std::string command = "command -v nmcli >/dev/null 2>&1 || { echo 'nmcli not installed'; }";
	std::string nmcliExists = executeShellCommand(command);
	if (nmcliExists != "")
	{
		LOG_DEBUG("Error retrieving DNS server list: nmcli doesn't exist");
		return;
	}

	// check nmcli major version (0 or 1)
	command = "nmcli -v | awk -F' ' '{print $NF}' | awk -F'.' '{print $1}'";
	std::string nmcliMajorVer = executeShellCommand(command);
	nmcliMajorVer.erase(std::remove(nmcliMajorVer.begin(), nmcliMajorVer.end(), '\n'), nmcliMajorVer.end());
	LOG_DEBUG("Found nmcli. nmcli major version is: '%s'", nmcliMajorVer.c_str());

	// build nmcli command according to its major version
	if (nmcliMajorVer == "0")
		command = "nmcli dev list | grep IP4.DNS";
	else
		command = "nmcli dev show | grep IP4.DNS";

	std::string dnsServersInfo = executeShellCommand(command);
	if (dnsServersInfo == "")
	{
		LOG_DEBUG("Error retrieving DNS server list: call to nmcli gave no output");
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
			LOG_DEBUG("Default DNS server IP #%d: %s\n", i++, dnsIPAddr.toString().c_str());
		}
	}
#elif MAC_OS_X

	SCDynamicStoreRef dynRef = SCDynamicStoreCreate(kCFAllocatorSystemDefault, CFSTR("iked"), NULL, NULL);
	if (dynRef == NULL)
	{
		LOG_DEBUG("Couldn't set DNS server list: failed to retrieve SCDynamicStore");
		return;
	}

	CFDictionaryRef dnsDict = (CFDictionaryRef)SCDynamicStoreCopyValue(dynRef,CFSTR("State:/Network/Global/DNS"));

	if (dnsDict == NULL)
	{
		LOG_DEBUG("Couldn't set DNS server list: failed to get DNS dictionary");
		CFRelease(dynRef);
		return;
	}

	CFArrayRef serverAddresses = (CFArrayRef)CFDictionaryGetValue(dnsDict, CFSTR("ServerAddresses"));

	if (serverAddresses == NULL)
	{
		LOG_DEBUG("Couldn't set DNS server list: server addresses array is null");
		CFRelease(dynRef);
		CFRelease(dnsDict);
		return;
	}

	CFIndex count = CFArrayGetCount(serverAddresses);
	for (CFIndex i = 0; i < count; i++)
	{
		CFStringRef serverAddress = (CFStringRef)CFArrayGetValueAtIndex(serverAddresses, i);

		if (serverAddress == NULL)
			continue;

		uint8_t buf[20];
		char* serverAddressCString = (char*)buf;
		CFStringGetCString(serverAddress, serverAddressCString, 20, kCFStringEncodingUTF8);
		m_DnsServers.push_back(IPv4Address(serverAddressCString));
		LOG_DEBUG("Default DNS server IP #%d: %s\n", (int)(i+1), serverAddressCString);
	}

	CFRelease(dynRef);
	CFRelease(dnsDict);
#endif
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(IPAddress* ipAddr)
{
	if (ipAddr->getType() == IPAddress::IPv4AddressType)
	{
		IPv4Address* ip4Addr = static_cast<IPv4Address*>(ipAddr);
		return getPcapLiveDeviceByIp(*ip4Addr);
	}
	else //IPAddress::IPv6AddressType
	{
		IPv6Address* ip6Addr = static_cast<IPv6Address*>(ipAddr);
		return getPcapLiveDeviceByIp(*ip6Addr);
	}
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(IPv4Address ipAddr)
{
	LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
		{
			if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter->addr != NULL)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				sockaddr2string(addrIter->addr, addrAsString);
				LOG_DEBUG("Searching address %s", addrAsString);
			}

			in_addr* currAddr = sockaddr2in_addr(addrIter->addr);
			if (currAddr == NULL)
			{
				LOG_DEBUG("Address is NULL");
				continue;
			}

			if (currAddr->s_addr == ipAddr.toInAddr()->s_addr)
			{
				LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(IPv6Address ip6Addr)
{
	LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
		{
			if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleLiveDevice) && addrIter->addr != NULL)
			{
				char addrAsString[INET6_ADDRSTRLEN];
				sockaddr2string(addrIter->addr, addrAsString);
				LOG_DEBUG("Searching address %s", addrAsString);
			}

			in6_addr* currAddr = sockaddr2in6_addr(addrIter->addr);
			if (currAddr == NULL)
			{
				LOG_DEBUG("Address is NULL");
				continue;
			}

			uint8_t* addrAsArr; size_t addrLen;
			ip6Addr.copyTo(&addrAsArr, addrLen);
			if (memcmp(currAddr, addrAsArr, sizeof(struct in6_addr)) == 0)
			{
				LOG_DEBUG("Found matched address!");
				return (*devIter);
			}

			delete [] addrAsArr;
		}
	}

	return NULL;
}

std::vector<IPv4Address>& PcapLiveDeviceList::getDnsServers()
{
	return m_DnsServers;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const char* ipAddrAsString)
{
	IPAddress::Ptr_t apAddr = IPAddress::fromString(ipAddrAsString);
	if (!apAddr->isValid())
	{
		LOG_ERROR("IP address illegal");
		return NULL;
	}

	PcapLiveDevice* result = PcapLiveDeviceList::getPcapLiveDeviceByIp(apAddr.get());
	return result;
}


PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByName(const std::string& name)
{
	LOG_DEBUG("Searching all live devices...");
	for(std::vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		std::string devName((*devIter)->getName());
		if (name == devName)
			return (*devIter);
	}

	return NULL;

}

} // namespace pcpp
