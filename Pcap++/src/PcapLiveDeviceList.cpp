#define LOG_MODULE PcapLogModuleLiveDevice

#include <IpUtils.h>
#include <PcapLiveDeviceList.h>
#include <Logger.h>
#include <string.h>
#ifdef WIN32
#include <ws2tcpip.h>
#endif


bool PcapLiveDeviceList::m_IsInitialized = false;
vector<PcapLiveDevice*> PcapLiveDeviceList::m_xLiveDeviceList;


const vector<PcapLiveDevice*>& PcapLiveDeviceList::getPcapLiveDevicesList()
{
	if (PcapLiveDeviceList::m_IsInitialized)
	{
		LOG_DEBUG("Device list already initialized");
		return PcapLiveDeviceList::m_xLiveDeviceList;
	}

	pcap_if_t* interfaceList;
	char errbuf[PCAP_ERRBUF_SIZE];
	int err = pcap_findalldevs(&interfaceList, errbuf);
	if (err < 0)
	{
		LOG_ERROR("Error searching for devices: %s", errbuf);
		return PcapLiveDeviceList::m_xLiveDeviceList;
	}

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
#ifdef WIN32
		PcapLiveDevice* pDev = new WinPcapLiveDevice(currInterface, true);
#else //LINUX
		PcapLiveDevice* pDev = new PcapLiveDevice(currInterface, true);
#endif
		currInterface = currInterface->next;
		PcapLiveDeviceList::m_xLiveDeviceList.insert(PcapLiveDeviceList::m_xLiveDeviceList.end(), pDev);
	}

	LOG_DEBUG("Freeing live device data");
	pcap_freealldevs(interfaceList);

	PcapLiveDeviceList::m_IsInitialized = true;

	return PcapLiveDeviceList::m_xLiveDeviceList;
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(IPAddress* pIPAddr)
{
	if (pIPAddr->getType() == IPAddress::IPv4AddressType)
	{
		IPv4Address* pIp4Addr = static_cast<IPv4Address*>(pIPAddr);
		return getPcapLiveDeviceByIp(*pIp4Addr);
	}
	else //IPAddress::IPv6AddressType
	{
		IPv6Address* pIp6Addr = static_cast<IPv6Address*>(pIPAddr);
		return getPcapLiveDeviceByIp(*pIp6Addr);
	}
}

PcapLiveDevice* PcapLiveDeviceList::getPcapLiveDeviceByIp(IPv4Address ipAddr)
{
	if (!PcapLiveDeviceList::m_IsInitialized)
	{
		LOG_DEBUG("PcapLiveDeviceList not initialized. Initializing first...");
		PcapLiveDeviceList::getPcapLiveDevicesList();
	}

	LOG_DEBUG("Searching all live devices...");
	for(vector<PcapLiveDevice*>::iterator devIter = PcapLiveDeviceList::m_xLiveDeviceList.begin(); devIter != PcapLiveDeviceList::m_xLiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_pName);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_xAddresses.begin(); addrIter != (*devIter)->m_xAddresses.end(); addrIter++)
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
	if (!PcapLiveDeviceList::m_IsInitialized)
	{
		LOG_DEBUG("PcapLiveDeviceList not initialized. Initializing first...");
		PcapLiveDeviceList::getPcapLiveDevicesList();
	}

	LOG_DEBUG("Searching all live devices...");
	for(vector<PcapLiveDevice*>::iterator devIter = PcapLiveDeviceList::m_xLiveDeviceList.begin(); devIter != PcapLiveDeviceList::m_xLiveDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_pName);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_xAddresses.begin(); addrIter != (*devIter)->m_xAddresses.end(); addrIter++)
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
