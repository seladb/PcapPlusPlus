#ifdef WIN32

#define LOG_MODULE PcapLogModuleRemoteDevice

#include <PcapRemoteDeviceList.h>
#include <Logger.h>
#include <IpUtils.h>
#ifdef WIN32
#include <ws2tcpip.h>
#endif

const bool PcapRemoteDeviceList::getRemoteDeviceList(string ipAddress, uint16_t port, PcapRemoteDeviceList& resultList)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, NULL, resultList);
}

const bool PcapRemoteDeviceList::getRemoteDeviceList(string ipAddress, uint16_t port, PcapRemoteAuthentication* pRemoteAuth, PcapRemoteDeviceList& resultList)
{
	char portAsCharArr[5];
	sprintf(portAsCharArr, "%d", port);
	LOG_DEBUG("Searching remote devices on IP: %s and port: %d", ipAddress.c_str(), port);
	char remoteCaptureString[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_createsrcstr(remoteCaptureString, PCAP_SRC_IFREMOTE, ipAddress.c_str(), portAsCharArr, NULL, errbuf) != 0)
	{
		LOG_ERROR("Error in creating the remote connection string. Error was: %s", errbuf);
		return false;
	}

	LOG_DEBUG("Remote capture string: %s", remoteCaptureString);

	pcap_rmtauth* pRmAuth = NULL;
	if (pRemoteAuth != NULL)
	{
		LOG_DEBUG("Authentication requested. Username: %s, Password: %s", pRemoteAuth->userName, pRemoteAuth->password);
		pRmAuth = new pcap_rmtauth();
		pRmAuth->type = RPCAP_RMTAUTH_PWD;
		pRmAuth->username = new char[1+strlen(pRemoteAuth->userName)];
		strncpy(pRmAuth->username, pRemoteAuth->userName, 1+strlen(pRemoteAuth->userName));
		pRmAuth->password = new char[1+strlen(pRemoteAuth->password)];
		strncpy(pRmAuth->password, pRemoteAuth->password, 1+strlen(pRemoteAuth->password));
	}

	pcap_if_t* interfaceList;
	char errorBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(remoteCaptureString, pRmAuth, &interfaceList, errorBuf) < 0)
	{
		LOG_ERROR("Error retrieving device on remote machine. Error string is: %s", errorBuf);
		return false;
	}

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
		PcapRemoteDevice* pNewRemoteDevice = new PcapRemoteDevice(currInterface, pRmAuth);
		resultList.push_back(pNewRemoteDevice);
		currInterface = currInterface->next;
	}

	pcap_freealldevs(interfaceList);
	return true;
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const char* ipAddrAsString)
{
	auto_ptr<IPAddress> apAddr = IPAddress::fromString(ipAddrAsString);
	if (!apAddr->isValid())
	{
		LOG_ERROR("IP address illegal");
		return NULL;
	}

	PcapRemoteDevice* result = getRemoteDeviceByIP(apAddr.get());
	return result;
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(IPAddress* pIPAddr)
{
	if (pIPAddr->getType() == IPAddress::IPv4AddressType)
	{
		IPv4Address* pIp4Addr = static_cast<IPv4Address*>(pIPAddr);
		return getRemoteDeviceByIP(*pIp4Addr);
	}
	else //IPAddress::IPv6AddressType
	{
		IPv6Address* pIp6Addr = static_cast<IPv6Address*>(pIPAddr);
		return getRemoteDeviceByIP(*pIp6Addr);
	}
}


PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(IPv4Address ip4Addr)
{
	LOG_DEBUG("Searching all remote devices in list...");
	for(vector<PcapRemoteDevice*>::iterator devIter = begin(); devIter != end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_pName);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_xAddresses.begin(); addrIter != (*devIter)->m_xAddresses.end(); addrIter++)
		{
			if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addrIter->addr != NULL)
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

			if (currAddr->s_addr == ip4Addr.toInAddr()->s_addr)
			{
				LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;

}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(IPv6Address ip6Addr)
{
	LOG_DEBUG("Searching all remote devices in list...");
	for(vector<PcapRemoteDevice*>::iterator devIter = begin(); devIter != end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_pName);
		for(vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_xAddresses.begin(); addrIter != (*devIter)->m_xAddresses.end(); addrIter++)
		{
			if (LoggerPP::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addrIter->addr != NULL)
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

PcapRemoteDeviceList::~PcapRemoteDeviceList()
{
	for(vector<PcapRemoteDevice*>::iterator devIter = begin(); devIter != end(); )
	{
	   delete (*devIter);
	   erase(devIter);
	}
}

#endif // WIN32
