#if defined(_WIN32)

#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDeviceList.h"
#include "Logger.h"
#include "IpUtils.h"
#include "MemoryUtils.h"
#include "pcap.h"
#include <ws2tcpip.h>

namespace pcpp
{

PcapRemoteDeviceList::PcapRemoteDeviceList(const IPAddress &ipAddress, uint16_t port, std::shared_ptr<PcapRemoteAuthentication> remoteAuth, std::vector<PcapRemoteDevice*> deviceList)
	: m_RemoteDeviceList(std::move(deviceList)), m_RemoteMachineIpAddress(ipAddress), m_RemoteMachinePort(port), m_RemoteAuthentication(std::move(remoteAuth)) {}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, nullptr);
}

std::unique_ptr<PcapRemoteDeviceList> PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress &ipAddress, uint16_t port, PcapRemoteDeviceList::smart_ptr_tag)
{
	return PcapRemoteDeviceList::getRemoteDeviceList(ipAddress, port, std::unique_ptr<PcapRemoteAuthentication>());
}

PcapRemoteDeviceList* PcapRemoteDeviceList::getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth)
{
	// Uses the smart pointer version and releases management of the object to the caller.
	std::unique_ptr<PcapRemoteAuthentication> auth = remoteAuth != nullptr ? std::unique_ptr<PcapRemoteAuthentication>(new PcapRemoteAuthentication(*remoteAuth)) : nullptr;
	std::unique_ptr<PcapRemoteDeviceList> uPtr = getRemoteDeviceList(ipAddress, port, std::move(auth));
	return uPtr.release();
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
	PCPP_LOG_DEBUG("Searching remote devices on IP: " << ipAddress << " and port: " << port);
	char remoteCaptureString[PCAP_BUF_SIZE];
	char errorBuf[PCAP_ERRBUF_SIZE];
	if (pcap_createsrcstr(remoteCaptureString, PCAP_SRC_IFREMOTE, ipAddress.toString().c_str(), std::to_string(port).c_str(), nullptr, errorBuf) != 0)
	{
		PCPP_LOG_ERROR("Error in creating the remote connection string. Error was: " << errorBuf);
		return nullptr;
	}

	PCPP_LOG_DEBUG("Remote capture string: " << remoteCaptureString);

	pcap_rmtauth* pRmAuth = nullptr;
	pcap_rmtauth rmAuth;
	if (remoteAuth != nullptr)
	{
		PCPP_LOG_DEBUG("Authentication requested. Username: " << remoteAuth->userName << ", Password: " << remoteAuth->password);
		rmAuth = remoteAuth->getPcapRmAuth();
		pRmAuth = &rmAuth;
	}

	std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter> interfaceList;
	{
		pcap_if_t *interfaceListRaw;
		if (pcap_findalldevs_ex(remoteCaptureString, pRmAuth, &interfaceListRaw, errorBuf) < 0)
		{
			PCPP_LOG_ERROR("Error retrieving device on remote machine. Error string is: " << errorBuf);
			return nullptr;
		}
		interfaceList = std::unique_ptr<pcap_if_t, internal::PcapFreeAllDevsDeleter>(interfaceListRaw);
	}

	std::vector<PcapRemoteDevice*> remoteDeviceList;
	for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr; currInterface = currInterface->next)
	{
		PcapRemoteDevice *pNewRemoteDevice = new PcapRemoteDevice(currInterface, remoteAuth, ipAddress, port);
		remoteDeviceList.push_back(pNewRemoteDevice);
	}

	return std::unique_ptr<PcapRemoteDeviceList>(new PcapRemoteDeviceList(ipAddress, port, std::move(remoteAuth), std::move(remoteDeviceList)));
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
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter.addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in_addr* currAddr = internal::sockaddr2in_addr(addrIter.addr);
			if (currAddr == NULL)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (currAddr->s_addr == ip4Addr.toInt())
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return nullptr;

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
				char addrAsString[INET6_ADDRSTRLEN];
				internal::sockaddr2string(addrIter.addr, addrAsString);
				PCPP_LOG_DEBUG("Searching address " << addrAsString);
			}

			in6_addr* currAddr = internal::sockaddr2in6_addr(addrIter.addr);
			if (currAddr == NULL)
			{
				PCPP_LOG_DEBUG("Address is NULL");
				continue;
			}

			if (memcmp(currAddr, ip6Addr.toBytes(), sizeof(struct in6_addr)) == 0)
			{
				PCPP_LOG_DEBUG("Found matched address!");
				return (*devIter);
			}
		}
	}

	return nullptr;

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
	setRemoteAuthentication(remoteAuth != nullptr ? std::move(std::make_shared<PcapRemoteAuthentication>(*remoteAuth)) : nullptr);
}
void PcapRemoteDeviceList::setRemoteAuthentication(std::shared_ptr<PcapRemoteAuthentication> remoteAuth)
{
	m_RemoteAuthentication = std::move(remoteAuth);
}

PcapRemoteDeviceList::~PcapRemoteDeviceList()
{
	while (m_RemoteDeviceList.size() > 0)
	{
		RemoteDeviceListIterator devIter = m_RemoteDeviceList.begin();
		delete (*devIter);
		m_RemoteDeviceList.erase(devIter);
	}
}

} // namespace pcpp

#endif // _WIN32
