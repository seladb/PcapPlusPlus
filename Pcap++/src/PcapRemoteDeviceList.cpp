#if defined(_WIN32)

#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDeviceList.h"
#include "Logger.h"
#include "IpUtils.h"
#include "IpAddressUtils.h"
#include "pcap.h"
#include <array>
#include <ws2tcpip.h>

namespace pcpp
{

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, NULL);
}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth)
{
	PCPP_LOG_DEBUG("Searching remote devices on IP: " << ipAddress << " and port: " << port);
	char remoteCaptureString[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	std::ostringstream portAsString;
	portAsString << port;
	if (pcap_createsrcstr(remoteCaptureString, PCAP_SRC_IFREMOTE, ipAddress.toString().c_str(), portAsString.str().c_str(), NULL, errbuf) != 0)
	{
		PCPP_LOG_ERROR("Error in creating the remote connection string. Error was: " << errbuf);
		return NULL;
	}

	PCPP_LOG_DEBUG("Remote capture string: " << remoteCaptureString);

	pcap_rmtauth* pRmAuth = NULL;
	pcap_rmtauth rmAuth;
	if (remoteAuth != NULL)
	{
		PCPP_LOG_DEBUG("Authentication requested. Username: " << remoteAuth->userName << ", Password: " << remoteAuth->password);
		rmAuth = remoteAuth->getPcapRmAuth();
		pRmAuth = &rmAuth;
	}

	pcap_if_t* interfaceList;
	char errorBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(remoteCaptureString, pRmAuth, &interfaceList, errorBuf) < 0)
	{
		PCPP_LOG_ERROR("Error retrieving device on remote machine. Error string is: " << errorBuf);
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
	else //IPAddress::IPv6AddressType
	{
		return getRemoteDeviceByIP(ipAddr.getIPv6());
	}
}


PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv4Address& ip4Addr) const
{
	PCPP_LOG_DEBUG("Searching all remote devices in list...");
	for(ConstRemoteDeviceListIterator devIter = m_RemoteDeviceList.begin(); devIter != m_RemoteDeviceList.end(); devIter++)
	{
		PCPP_LOG_DEBUG("Searching device '" << (*devIter)->m_Name << "'. Searching all addresses...");
		for(const auto &addrIter : (*devIter)->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addrIter.addr != NULL)
			{
				std::array<char, INET6_ADDRSTRLEN> addrAsString;
				internal::sockaddr2string(addrIter.addr, addrAsString.data(), addrAsString.size());
				PCPP_LOG_DEBUG("Searching address " << addrAsString.data());
			}

			in_addr* currAddr = internal::try_sockaddr2in_addr(addrIter.addr);
			if (currAddr == NULL)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (*currAddr == ip4Addr)
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;

}

PcapRemoteDevice* PcapRemoteDeviceList::getRemoteDeviceByIP(const IPv6Address& ip6Addr) const
{
	PCPP_LOG_DEBUG("Searching all remote devices in list...");
	for(ConstRemoteDeviceListIterator devIter = m_RemoteDeviceList.begin(); devIter != m_RemoteDeviceList.end(); devIter++)
	{
		PCPP_LOG_DEBUG("Searching device '" << (*devIter)->m_Name << "'. Searching all addresses...");
		for(const auto &addrIter : (*devIter)->m_Addresses)
		{
			if (Logger::getInstance().isDebugEnabled(PcapLogModuleRemoteDevice) && addrIter.addr != NULL)
			{
				std::array<char, INET6_ADDRSTRLEN> addrAsString;
				internal::sockaddr2string(addrIter.addr, addrAsString.data(), addrAsString.size());
				PCPP_LOG_DEBUG("Searching address " << addrAsString.data());
			}

			in6_addr* currAddr = internal::try_sockaddr2in6_addr(addrIter.addr);
			if (currAddr == NULL)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (*currAddr == ip6Addr)
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return NULL;

}

void PcapRemoteDeviceList::setRemoteMachineIpAddress(const IPAddress& ipAddress)
{
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

#endif // _WIN32
