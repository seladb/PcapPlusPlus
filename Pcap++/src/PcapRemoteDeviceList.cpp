#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDeviceList.h"
#include "Logger.h"
#include "IpUtils.h"
#include "pcap.h"
#include <ws2tcpip.h>

namespace pcpp
{

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, NULL);
}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth)
{
	if (!ipAddress.isValid())
	{
		LOG_ERROR("IP address is NULL or not valid");
		return NULL;
	}

	char portAsCharArr[6];
	sprintf(portAsCharArr, "%d", port);
	LOG_DEBUG("Searching remote devices on IP: %s and port: %d", ipAddress.toString().c_str(), port);
	char remoteCaptureString[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_createsrcstr(remoteCaptureString, PCAP_SRC_IFREMOTE, ipAddress.toString().c_str(), portAsCharArr, NULL, errbuf) != 0)
	{
		LOG_ERROR("Error in creating the remote connection string. Error was: %s", errbuf);
		return NULL;
	}

	LOG_DEBUG("Remote capture string: %s", remoteCaptureString);

	pcap_rmtauth* pRmAuth = NULL;
	pcap_rmtauth rmAuth;
	if (remoteAuth != NULL)
	{
		LOG_DEBUG("Authentication requested. Username: %s, Password: %s", remoteAuth->userName.c_str(), remoteAuth->password.c_str());
		rmAuth = remoteAuth->getPcapRmAuth();
		pRmAuth = &rmAuth;
	}

	pcap_if_t* interfaceList;
	char errorBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(remoteCaptureString, pRmAuth, &interfaceList, errorBuf) < 0)
	{
		LOG_ERROR("Error retrieving device on remote machine. Error string is: %s", errorBuf);
		return NULL;
	}

	PcapRemoteDeviceList* resultList = new PcapRemoteDeviceList();
	resultList->setRemoteMachineIpAddress(ipAddress);
	resultList->setRemoteMachinePort(port);
	resultList->setRemoteAuthentication(remoteAuth);

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
		PcapRemoteDevice* pNewRemoteDevice = new PcapRemoteDevice(currInterface, resultList->m_RemoteAuthentication,
				resultList->getRemoteMachineIpAddress(), resultList->getRemoteMachinePort());
		resultList->m_RemoteDeviceList.push_back(pNewRemoteDevice);
		currInterface = currInterface->next;
	}

	pcap_freealldevs(interfaceList);
	return resultList;
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const std::string& ipAddrAsString) const
{
	IPAddress ipAddr = IPAddress(ipAddrAsString);
	if (!ipAddr.isValid())
	{
		LOG_ERROR("IP address no valid");
		return NULL;
	}

	PcapRemoteDevice* result = getRemoteDeviceByIP(ipAddr);
	return result;
}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPAddress& ipAddr) const
{
	if (!ipAddr.isValid())
	{
		LOG_ERROR("IP address not valid");
		return NULL;
	}
	if (ipAddr.getType() == IPAddress::IPv4AddressType)
	{
		return getRemoteDeviceByIP(ipAddr.getIPv4());
	}
	else //IPAddress::IPv6AddressType
	{
		return getRemoteDeviceByIP(ipAddr.getIPv6());
	}
}


PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv4Address& ip4Addr) const
{
	LOG_DEBUG("Searching all remote devices in list...");
	for(ConstRemoteDeviceListIterator devIter = m_RemoteDeviceList.begin(); devIter != m_RemoteDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
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

			if (currAddr->s_addr == ip4Addr.toInt())
			{
				LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;

}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv6Address& ip6Addr) const
{
	LOG_DEBUG("Searching all remote devices in list...");
	for(ConstRemoteDeviceListIterator devIter = m_RemoteDeviceList.begin(); devIter != m_RemoteDeviceList.end(); devIter++)
	{
		LOG_DEBUG("Searching device '%s'. Searching all addresses...", (*devIter)->m_Name);
		for(std::vector<pcap_addr_t>::iterator addrIter = (*devIter)->m_Addresses.begin(); addrIter != (*devIter)->m_Addresses.end(); addrIter++)
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

			uint8_t* addrAsArr; size_t addrLen;
			ip6Addr.copyTo(&addrAsArr, addrLen);
			if (memcmp(currAddr, addrAsArr, sizeof(struct in6_addr)) == 0)
			{
				LOG_DEBUG("Found matched address!");
				delete [] addrAsArr;
				return (*devIter);
			}
			delete [] addrAsArr;
		}
	}

	return NULL;

}

void PcapRemoteDeviceList::setRemoteMachineIpAddress(const IPAddress& ipAddress)
{
	if (!ipAddress.isValid())
	{
		LOG_ERROR("Trying to set an invalid IP address to PcapRemoteDeviceList");
		return;
	}

	m_RemoteMachineIpAddress = ipAddress;
}

void PcapRemoteDeviceList::setRemoteMachinePort(uint16_t port)
{
	m_RemoteMachinePort = port;
}

void PcapRemoteDeviceList::setRemoteAuthentication(const PcapRemoteAuthentication* remoteAuth)
{
	if (remoteAuth != NULL)
		m_RemoteAuthentication = new PcapRemoteAuthentication(*remoteAuth);
	else
	{
		if (m_RemoteAuthentication != NULL)
			delete m_RemoteAuthentication;
		m_RemoteAuthentication = NULL;
	}
}

PcapRemoteDeviceList::~PcapRemoteDeviceList()
{
	while (m_RemoteDeviceList.size() > 0)
	{
		RemoteDeviceListIterator devIter = m_RemoteDeviceList.begin();
		delete (*devIter);
		m_RemoteDeviceList.erase(devIter);
	}

	if (m_RemoteAuthentication != NULL)
	{
		delete m_RemoteAuthentication;
	}
}

} // namespace pcpp

#endif // WIN32 || WINx64
