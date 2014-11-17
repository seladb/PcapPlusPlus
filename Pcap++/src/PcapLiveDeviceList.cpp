#define LOG_MODULE PcapLogModuleLiveDevice

#include <IpUtils.h>
#include <PcapLiveDeviceList.h>
#include <Logger.h>
#include <string.h>
#ifdef WIN32
#include <ws2tcpip.h>
#endif


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
		PcapLiveDevice* dev = new WinPcapLiveDevice(currInterface, true);
#else //LINUX
		PcapLiveDevice* dev = new PcapLiveDevice(currInterface, true);
#endif
		currInterface = currInterface->next;
		m_LiveDeviceList.insert(m_LiveDeviceList.end(), dev);
	}

	LOG_DEBUG("Freeing live device data");
	pcap_freealldevs(interfaceList);
}

PcapLiveDeviceList::~PcapLiveDeviceList()
{
	for(vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}

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
	for(vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
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
	for(vector<PcapLiveDevice*>::iterator devIter = m_LiveDeviceList.begin(); devIter != m_LiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
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

			if (memcmp(currAddr, ip6Addr.toByteArray(), sizeof(struct in6_addr)) == 0)
			{
				LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;
}



PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(const char* ipAddrAsString)
{
	auto_ptr<IPAddress> apAddr = IPAddress::fromString(ipAddrAsString);
	if (!apAddr->isValid())
	{
		LOG_ERROR("IP address illegal");
		return NULL;
	}

	PcapLiveDevice* result = PcapLiveDeviceList::getPcapLiveDeviceByIp(apAddr.get());
	return result;
}
