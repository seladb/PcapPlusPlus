#include "RawSocketDevice.h"
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifdef LINUX
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif
#include <string.h>
#include "Logger.h"
#include "IpUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"

namespace pcpp
{

#define RAW_SOCKET_BUFFER_LEN 65536

#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

#ifndef SIO_RCVALL
/* SIO_RCVALL defined on w2k and later. Not defined in Mingw32 */
/* 0x98000001 = _WSAIOW(IOC_VENDOR,1)       */
#  define SIO_RCVALL	0x98000001
#endif // SIO_RCVALL

class WinSockInitializer
{
private:
	static bool m_IsInitialized;

public:

	static void initialize()
	{
		if (m_IsInitialized)
			return;

	    // Load Winsock
		WSADATA wsaData;
		int res;
	    if ((res = WSAStartup(MAKEWORD(2,2), &wsaData)) != 0)
	    {
	    	LOG_ERROR("WSAStartup failed with error code: %d", res);
	    	m_IsInitialized = false;
	    }

	    m_IsInitialized = true;
	}
};

bool WinSockInitializer::m_IsInitialized = false;

#endif // defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

struct SocketContainer
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
	SOCKET fd;
#elif LINUX
	int fd;
	int interfaceIndex;
	std::string interfaceName;
#endif
};

RawSocketDevice::RawSocketDevice(const IPAddress& interfaceIP) : IDevice(), m_Socket(NULL)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	WinSockInitializer::initialize();
	m_InterfaceIP = interfaceIP.clone();
	m_SockFamily = (m_InterfaceIP->getType() == IPAddress::IPv4AddressType ? IPv4 : IPv6);

#elif LINUX

	m_InterfaceIP = interfaceIP.clone();
	m_SockFamily = Ethernet;

#else

	m_InterfaceIP = NULL;
	m_SockFamily = Ethernet;
	
#endif
}


RawSocketDevice::~RawSocketDevice()
{
	close();

	if (m_InterfaceIP != NULL)
		delete m_InterfaceIP;
}

RawSocketDevice::RecvPacketResult RawSocketDevice::receivePacket(RawPacket& rawPacket, bool blocking, int timeout)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	if (!isOpened())
	{
		LOG_ERROR("Device is not open");
		return RecvError;
	}

	SOCKET fd = ((SocketContainer*)m_Socket)->fd;
	char* buffer = new char[RAW_SOCKET_BUFFER_LEN];
	memset(buffer, 0, RAW_SOCKET_BUFFER_LEN);

	// value of 0 timeout means disabling timeout
	if (timeout < 0)
		timeout = 0;

	u_long blockingMode = (blocking? 0 : 1);
	ioctlsocket(fd, FIONBIO, &blockingMode);

	DWORD timeoutVal = timeout * 1000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutVal, sizeof(timeoutVal));

	//recvfrom(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0, (struct sockaddr*)&sockAddr,(socklen_t*)&sockAddrLen);
	int bufferLen = recv(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0);
	if (bufferLen < 0)
	{
		delete [] buffer;
		int errorCode = 0;
		RecvPacketResult error = getError(errorCode);

		if (error == RecvError)
			LOG_ERROR("Error reading from recvfrom. Error code is %d", errorCode);

		return error;
	}

	if (bufferLen > 0)
	{
		timeval time;
		gettimeofday(&time, NULL);
		rawPacket.setRawData((const uint8_t*)buffer, bufferLen, time, LINKTYPE_DLT_RAW1);
		return RecvSuccess;
	}

	LOG_ERROR("Buffer length is zero");
	delete [] buffer;
	return RecvError;

#elif LINUX

	if (!isOpened())
	{
		LOG_ERROR("Device is not open");
		return RecvError;
	}

	int fd = ((SocketContainer*)m_Socket)->fd;
	char* buffer = new char[RAW_SOCKET_BUFFER_LEN];
	memset(buffer, 0, RAW_SOCKET_BUFFER_LEN);

	// value of 0 timeout means disabling timeout
	if (timeout < 0)
		timeout = 0;

	// set blocking or non-blocking flag
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
	{
		LOG_ERROR("Cannot get socket flags");
		return RecvError;
	} 
	flags = (blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
	if (fcntl(fd, F_SETFL, flags) != 0)
	{
		LOG_ERROR("Cannot set socket non-blocking flag");
		return RecvError;
	}

	// set timeout on socket
	struct timeval timeoutVal;
	timeoutVal.tv_sec = timeout;
	timeoutVal.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutVal, sizeof(timeoutVal));

	int bufferLen = recv(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0);
	if (bufferLen < 0)
	{
		delete [] buffer;
		int errorCode = errno;
		RecvPacketResult error = getError(errorCode);

		if (error == RecvError)
			LOG_ERROR("Error reading from recvfrom. Error code is %d", errorCode);

		return error;
	}

	if (bufferLen > 0)
	{
		timeval time;
		gettimeofday(&time, NULL);
		rawPacket.setRawData((const uint8_t*)buffer, bufferLen, time, LINKTYPE_ETHERNET);
		return RecvSuccess;
	}

	LOG_ERROR("Buffer length is zero");
	delete [] buffer;
	return RecvError;

#else

	LOG_ERROR("Raw socket are not supported on this platform");
	return RecvError;

#endif
}

int RawSocketDevice::receivePackets(RawPacketVector& packetVec, int timeout, int& failedRecv)
{
	if (!isOpened())
	{
		LOG_ERROR("Device is not open");
		return 0;
	}

	long curSec, curNsec;
	clockGetTime(curSec, curNsec);

	int packetCount = 0;
	failedRecv = 0;

	long timeoutSec = curSec + timeout;

	while (curSec < timeoutSec)
	{
		RawPacket* rawPacket = new RawPacket();
		if (receivePacket(*rawPacket, true, timeoutSec-curSec) == RecvSuccess)
		{
			packetVec.pushBack(rawPacket);
			packetCount++;
		}
		else
		{
			failedRecv++;
			delete rawPacket;
		}

		clockGetTime(curSec, curNsec);
	}

	return packetCount;
}

bool RawSocketDevice::sendPacket(const RawPacket* rawPacket)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	LOG_ERROR("Sending packets with raw socket are not supported on Windows");
	return 0;

#elif LINUX

	if (!isOpened())
	{
		LOG_ERROR("Device is not open");
		return false;
	}

	Packet packet((RawPacket*)rawPacket, OsiModelDataLinkLayer);
	if (!packet.isPacketOfType(pcpp::Ethernet))
	{
		LOG_ERROR("Can't send non-Ethernet packets");
		return false;
	}

	int fd = ((SocketContainer*)m_Socket)->fd;

	sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = htons(PF_PACKET);
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_halen = 6;
	addr.sll_ifindex = ((SocketContainer*)m_Socket)->interfaceIndex;

	EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
	MacAddress dstMac = ethLayer->getDestMac();
	dstMac.copyTo((uint8_t*)&(addr.sll_addr));

	if (::sendto(fd, ((RawPacket*)rawPacket)->getRawData(), ((RawPacket*)rawPacket)->getRawDataLen(), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		LOG_ERROR("Failed to send packet. Error was: '%s'", strerror(errno));
		return false;
	}

	return true;

#else

	LOG_ERROR("Raw socket are not supported on this platform");
	return 0;

#endif
}

int RawSocketDevice::sendPackets(const RawPacketVector& packetVec)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	LOG_ERROR("Sending packets with raw socket are not supported on Windows");
	return false;

#elif LINUX

	if (!isOpened())
	{
		LOG_ERROR("Device is not open");
		return 0;
	}

	int fd = ((SocketContainer*)m_Socket)->fd;

	sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = htons(PF_PACKET);
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_halen = 6;
	addr.sll_ifindex = ((SocketContainer*)m_Socket)->interfaceIndex;

	int sendCount = 0;

	for (RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		Packet packet(*iter, OsiModelDataLinkLayer);
		if (!packet.isPacketOfType(pcpp::Ethernet))
		{
			LOG_DEBUG("Can't send non-Ethernet packets");
			continue;
		}

		EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
		MacAddress dstMac = ethLayer->getDestMac();
		dstMac.copyTo((uint8_t*)&(addr.sll_addr));

		if (::sendto(fd, (*iter)->getRawData(), (*iter)->getRawDataLen(), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1)
		{
			LOG_DEBUG("Failed to send packet. Error was: '%s'", strerror(errno));
			continue;
		}

		sendCount++;
	}

	return sendCount;

#else

	LOG_ERROR("Raw socket are not supported on this platform");
	return false;

#endif
}


bool RawSocketDevice::open()
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)

	if (!m_InterfaceIP->isValid())
	{
		LOG_ERROR("IP address is not valid");
		return false;
	}

	int family = (m_SockFamily == IPv4 ? AF_INET : AF_INET6);
	SOCKET fd = socket(family, SOCK_RAW, IPPROTO_IP);
	if ((int)fd == SOCKET_ERROR)
	{
		int error = WSAGetLastError();
		std::string additionalMessage = "";
		if (error == WSAEACCES)
			additionalMessage = ", you may not be running with administrative privileges which is required for opening raw sockets on Windows";
		LOG_ERROR("Failed to create raw socket. Error code was %d%s", error, additionalMessage.c_str());
		return false;
	}

	void* localAddr = NULL;
	struct sockaddr_in localAddrIPv4;
	struct sockaddr_in6 localAddrIPv6;
	size_t localAddrSize = 0;

	if (m_SockFamily == IPv4)
	{
		localAddrIPv4.sin_family = family;
		int res = inet_pton(family, m_InterfaceIP->toString().c_str(), &localAddrIPv4.sin_addr.s_addr);
		if (res <= 0)
		{
			LOG_ERROR("inet_pton failed, probably IP address provided is in bad format");
			closesocket(fd);
			return false;
		}
		localAddrIPv4.sin_port = 0;  // Any local port will do
		localAddr = &localAddrIPv4;
		localAddrSize = sizeof(localAddrIPv4);
	}
	else
	{
		localAddrIPv6.sin6_family = family;
		int res = inet_pton(AF_INET6, m_InterfaceIP->toString().c_str(), &localAddrIPv6.sin6_addr.s6_addr);
		if (res <= 0)
		{
			LOG_ERROR("inet_pton failed, probably IP address provided is in bad format");
			closesocket(fd);
			return false;
		}
		localAddrIPv6.sin6_port = 0; // Any local port will do
		localAddrIPv6.sin6_scope_id = 0;
		localAddr = &localAddrIPv6;
		localAddrSize = sizeof(localAddrIPv6);
	}

	if (bind(fd, (struct sockaddr *)localAddr, localAddrSize) == SOCKET_ERROR)
	{
		LOG_ERROR("Failed to bind to interface. Error code was '%d'", WSAGetLastError());
		closesocket(fd);
		return false;
	}

	int n = 1;
	DWORD dwBytesRet;
	if (WSAIoctl(fd, SIO_RCVALL, &n, sizeof(n), NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR)
	{
		LOG_ERROR("Call to WSAIotcl(%ul) failed with error code %d", SIO_RCVALL, WSAGetLastError());
		closesocket(fd);
		return false;
	}

	m_Socket = new SocketContainer();
	((SocketContainer*)m_Socket)->fd = fd;

	m_DeviceOpened = true;

	return true;

#elif LINUX

	if (!m_InterfaceIP->isValid())
	{
		LOG_ERROR("IP address is not valid");
		return false;
	}

	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
	{
		LOG_ERROR("Failed to create raw socket. Error code was %d", errno);
		return false;
	}

	// find interface name and index from IP address
	struct ifaddrs* addrs;
	getifaddrs(&addrs);
	std::string ifaceName = "";
	int ifaceIndex = -1;
	for (struct ifaddrs* curAddr = addrs; curAddr != NULL; curAddr = curAddr->ifa_next) 
	{
		if (curAddr->ifa_addr && (curAddr->ifa_flags & IFF_UP)) 
		{
			if  (curAddr->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in* sockAddr = (struct sockaddr_in*)(curAddr->ifa_addr);
				char addrAsCharArr[32];
				inet_ntop(curAddr->ifa_addr->sa_family, (void *)&(sockAddr->sin_addr), addrAsCharArr, sizeof(addrAsCharArr));
				if (!strcmp(m_InterfaceIP->toString().c_str(), addrAsCharArr))
				{
					ifaceName = curAddr->ifa_name;
					ifaceIndex = if_nametoindex(curAddr->ifa_name);
				}
			}
			else if (curAddr->ifa_addr->sa_family == AF_INET6)
			{
				struct sockaddr_in6* sockAddr = (struct sockaddr_in6*)(curAddr->ifa_addr);
				char addrAsCharArr[40];
				inet_ntop(curAddr->ifa_addr->sa_family, (void *)&(sockAddr->sin6_addr), addrAsCharArr, sizeof(addrAsCharArr));
				if (!strcmp(m_InterfaceIP->toString().c_str(), addrAsCharArr))
				{
					ifaceName = curAddr->ifa_name;
					ifaceIndex = if_nametoindex(curAddr->ifa_name);
				}
			}

		}
	}
	freeifaddrs(addrs);

	if (ifaceName == "" || ifaceIndex < 0)
	{
		LOG_ERROR("Cannot detect interface name or index from IP address");
		::close(fd);
		return false;
	}

	// bind raw socket to interface
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifaceName.c_str());
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) == -1)
	{
		LOG_ERROR("Cannot bind raw socket to interface '%s'", ifaceName.c_str());
		::close(fd);
		return false;		
	}

	m_Socket = new SocketContainer();
	((SocketContainer*)m_Socket)->fd = fd;
	((SocketContainer*)m_Socket)->interfaceIndex = ifaceIndex;
	((SocketContainer*)m_Socket)->interfaceName = ifaceName;

	m_DeviceOpened = true;

	return true;

#else

	LOG_ERROR("Raw socket are not supported on this platform");
	return false;

#endif
}

void RawSocketDevice::close()
{
	if (m_Socket != NULL && isOpened())
	{
		SocketContainer* sockContainer = (SocketContainer*)m_Socket;
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
		closesocket(sockContainer->fd);
#elif LINUX
		::close(sockContainer->fd);
#endif
		delete sockContainer;
		m_Socket = NULL;
		m_DeviceOpened = false;
	}
}

RawSocketDevice::RecvPacketResult RawSocketDevice::getError(int& errorCode)
{
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
	errorCode = WSAGetLastError();
	if (errorCode == WSAEWOULDBLOCK)
		return RecvWouldBlock;
	if (errorCode == WSAETIMEDOUT)
		return RecvTimeout;

	return RecvError;
#elif LINUX
	if ((errorCode == EAGAIN) || (errorCode == EWOULDBLOCK))
		return RecvWouldBlock;

	return RecvError;
#else
	return RecvError;
#endif
}

}
