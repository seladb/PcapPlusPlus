#include "RawSocketDevice.h"
#include "EndianPortable.h"
#include <chrono>
#ifdef __linux__
#	include <fcntl.h>
#	include <errno.h>
#	include <unistd.h>
#	include <netinet/if_ether.h>
#	include <netpacket/packet.h>
#	include <ifaddrs.h>
#	include <net/if.h>
#endif
#include "Logger.h"
#include "IpUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"

namespace pcpp
{

#define RAW_SOCKET_BUFFER_LEN 65536

#if defined(_WIN32)

#	ifndef SIO_RCVALL
// SIO_RCVALL defined on w2k and later. Not defined in Mingw32
// 0x98000001 = _WSAIOW(IOC_VENDOR,1)
#		define SIO_RCVALL 0x98000001
#	endif  // SIO_RCVALL

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
			int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (res != 0)
			{
				PCPP_LOG_ERROR("WSAStartup failed with error code: " << res);
				m_IsInitialized = false;
			}

			m_IsInitialized = true;
		}
	};

	bool WinSockInitializer::m_IsInitialized = false;

#endif  // defined(_WIN32)

	struct SocketContainer
	{
#if defined(_WIN32)
		SOCKET fd;
#elif defined(__linux__)
		int fd;
		int interfaceIndex;
		std::string interfaceName;
#endif
	};

	RawSocketDevice::RawSocketDevice(const IPAddress& interfaceIP) : IDevice(), m_Socket(nullptr)
	{
#if defined(_WIN32)

		WinSockInitializer::initialize();
		m_InterfaceIP = interfaceIP;
		m_SockFamily = (m_InterfaceIP.getType() == IPAddress::IPv4AddressType ? IPv4 : IPv6);

#elif defined(__linux__)

		m_InterfaceIP = interfaceIP;
		m_SockFamily = Ethernet;

#else

		m_SockFamily = Ethernet;

#endif
	}

	RawSocketDevice::~RawSocketDevice()
	{
		close();
	}

	RawSocketDevice::RecvPacketResult RawSocketDevice::receivePacket(RawPacket& rawPacket, bool blocking,
	                                                                 double timeout)
	{
#if defined(_WIN32)

		if (!isOpened())
		{
			PCPP_LOG_ERROR("Device is not open");
			return RecvError;
		}

		SOCKET fd = ((SocketContainer*)m_Socket)->fd;
		char* buffer = new char[RAW_SOCKET_BUFFER_LEN];
		memset(buffer, 0, RAW_SOCKET_BUFFER_LEN);

		// value of 0 timeout means disabling timeout
		if (timeout < 0)
			timeout = 0;

		u_long blockingMode = (blocking ? 0 : 1);
		ioctlsocket(fd, FIONBIO, &blockingMode);

		DWORD timeoutVal = timeout * 1000;  // convert to milliseconds
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutVal, sizeof(timeoutVal));

		// recvfrom(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0, (struct sockaddr*)&sockAddr,(socklen_t*)&sockAddrLen);
		int bufferLen = recv(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0);
		if (bufferLen < 0)
		{
			delete[] buffer;
			int errorCode = 0;
			RecvPacketResult error = getError(errorCode);

			if (error == RecvError)
				PCPP_LOG_ERROR("Error reading from recvfrom. Error code is " << errorCode);

			return error;
		}

		if (bufferLen > 0)
		{
			timeval time;
			gettimeofday(&time, nullptr);
			rawPacket.setRawData((const uint8_t*)buffer, bufferLen, time, LINKTYPE_DLT_RAW1);
			return RecvSuccess;
		}

		PCPP_LOG_ERROR("Buffer length is zero");
		delete[] buffer;
		return RecvError;

#elif defined(__linux__)

		if (!isOpened())
		{
			PCPP_LOG_ERROR("Device is not open");
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
			delete[] buffer;
			PCPP_LOG_ERROR("Cannot get socket flags");
			return RecvError;
		}
		flags = (blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
		if (fcntl(fd, F_SETFL, flags) != 0)
		{
			delete[] buffer;
			PCPP_LOG_ERROR("Cannot set socket non-blocking flag");
			return RecvError;
		}

		// set timeout on socket
		struct timeval timeoutVal;
		timeoutVal.tv_sec = static_cast<int>(timeout);
		timeoutVal.tv_usec = static_cast<long int>((timeout - timeoutVal.tv_sec) * 1000000);
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutVal, sizeof(timeoutVal));

		int bufferLen = recv(fd, buffer, RAW_SOCKET_BUFFER_LEN, 0);
		if (bufferLen < 0)
		{
			delete[] buffer;
			int errorCode = errno;
			RecvPacketResult error = getError(errorCode);

			if (error == RecvError)
				PCPP_LOG_ERROR("Error reading from recvfrom. Error code is " << errorCode);

			return error;
		}

		if (bufferLen > 0)
		{
			timeval time;
			gettimeofday(&time, nullptr);
			rawPacket.setRawData((const uint8_t*)buffer, bufferLen, time, LINKTYPE_ETHERNET);
			return RecvSuccess;
		}

		PCPP_LOG_ERROR("Buffer length is zero");
		delete[] buffer;
		return RecvError;

#else

		PCPP_LOG_ERROR("Raw socket are not supported on this platform");
		return RecvError;

#endif
	}

	int RawSocketDevice::receivePackets(RawPacketVector& packetVec, double timeout, int& failedRecv)
	{
		if (!isOpened())
		{
			PCPP_LOG_ERROR("Device is not open");
			return 0;
		}

		int64_t timeoutMilli = timeout * 1000;

		int packetCount = 0;
		failedRecv = 0;

		auto start = std::chrono::steady_clock::now();

		while (true)
		{
			auto now = std::chrono::steady_clock::now();
			auto elapsedMilli = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
			double elapsedSec = static_cast<double>(elapsedMilli) / 1000;

			if (elapsedMilli >= timeoutMilli)
			{
				break;
			}

			RawPacket* rawPacket = new RawPacket();
			if (receivePacket(*rawPacket, true, elapsedSec) == RecvSuccess)
			{
				packetVec.pushBack(rawPacket);
				packetCount++;
			}
			else
			{
				failedRecv++;
				delete rawPacket;
			}
		}

		return packetCount;
	}

	bool RawSocketDevice::sendPacket(const RawPacket* rawPacket)
	{
#if defined(_WIN32)

		PCPP_LOG_ERROR("Sending packets with raw socket are not supported on Windows");
		return 0;

#elif defined(__linux__)

		if (!isOpened())
		{
			PCPP_LOG_ERROR("Device is not open");
			return false;
		}

		Packet packet((RawPacket*)rawPacket, OsiModelDataLinkLayer);
		if (!packet.isPacketOfType(pcpp::Ethernet))
		{
			PCPP_LOG_ERROR("Can't send non-Ethernet packets");
			return false;
		}

		int fd = ((SocketContainer*)m_Socket)->fd;

		sockaddr_ll addr;
		memset(&addr, 0, sizeof(struct sockaddr_ll));
		addr.sll_family = htobe16(PF_PACKET);
		addr.sll_protocol = htobe16(ETH_P_ALL);
		addr.sll_halen = 6;
		addr.sll_ifindex = ((SocketContainer*)m_Socket)->interfaceIndex;

		EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
		MacAddress dstMac = ethLayer->getDestMac();
		dstMac.copyTo((uint8_t*)&(addr.sll_addr));

		if (::sendto(fd, ((RawPacket*)rawPacket)->getRawData(), ((RawPacket*)rawPacket)->getRawDataLen(), 0,
		             (struct sockaddr*)&addr, sizeof(addr)) == -1)
		{
			PCPP_LOG_ERROR("Failed to send packet. Error was: '" << strerror(errno) << "'");
			return false;
		}

		return true;

#else

		PCPP_LOG_ERROR("Raw socket are not supported on this platform");
		return 0;

#endif
	}

	int RawSocketDevice::sendPackets(const RawPacketVector& packetVec)
	{
#if defined(_WIN32)

		PCPP_LOG_ERROR("Sending packets with raw socket are not supported on Windows");
		return false;

#elif defined(__linux__)

		if (!isOpened())
		{
			PCPP_LOG_ERROR("Device is not open");
			return 0;
		}

		int fd = ((SocketContainer*)m_Socket)->fd;

		sockaddr_ll addr;
		memset(&addr, 0, sizeof(struct sockaddr_ll));
		addr.sll_family = htobe16(PF_PACKET);
		addr.sll_protocol = htobe16(ETH_P_ALL);
		addr.sll_halen = 6;
		addr.sll_ifindex = ((SocketContainer*)m_Socket)->interfaceIndex;

		int sendCount = 0;

		for (RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
		{
			Packet packet(*iter, OsiModelDataLinkLayer);
			if (!packet.isPacketOfType(pcpp::Ethernet))
			{
				PCPP_LOG_DEBUG("Can't send non-Ethernet packets");
				continue;
			}

			EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
			MacAddress dstMac = ethLayer->getDestMac();
			dstMac.copyTo((uint8_t*)&(addr.sll_addr));

			if (::sendto(fd, (*iter)->getRawData(), (*iter)->getRawDataLen(), 0, (struct sockaddr*)&addr,
			             sizeof(addr)) == -1)
			{
				PCPP_LOG_DEBUG("Failed to send packet. Error was: '" << strerror(errno) << "'");
				continue;
			}

			sendCount++;
		}

		return sendCount;

#else

		PCPP_LOG_ERROR("Raw socket are not supported on this platform");
		return false;

#endif
	}

	bool RawSocketDevice::open()
	{
#if defined(_WIN32)

		int family = (m_SockFamily == IPv4 ? AF_INET : AF_INET6);
		SOCKET fd = socket(family, SOCK_RAW, IPPROTO_IP);
		if ((int)fd == SOCKET_ERROR)
		{
			int error = WSAGetLastError();
			std::string additionalMessage = "";
			if (error == WSAEACCES)
				additionalMessage =
				    ", you may not be running with administrative privileges which is required for opening raw sockets on Windows";
			PCPP_LOG_ERROR("Failed to create raw socket. Error code was " << error << " " << additionalMessage);
			return false;
		}

		void* localAddr = nullptr;
		struct sockaddr_in localAddrIPv4;
		struct sockaddr_in6 localAddrIPv6;
		size_t localAddrSize = 0;

		if (m_SockFamily == IPv4)
		{
			localAddrIPv4.sin_family = family;
			int res = inet_pton(family, m_InterfaceIP.toString().c_str(), &localAddrIPv4.sin_addr.s_addr);
			if (res <= 0)
			{
				PCPP_LOG_ERROR("inet_pton failed, probably IP address provided is in bad format");
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
			int res = inet_pton(AF_INET6, m_InterfaceIP.toString().c_str(), &localAddrIPv6.sin6_addr.s6_addr);
			if (res <= 0)
			{
				PCPP_LOG_ERROR("inet_pton failed, probably IP address provided is in bad format");
				closesocket(fd);
				return false;
			}
			localAddrIPv6.sin6_port = 0;  // Any local port will do
			localAddrIPv6.sin6_scope_id = 0;
			localAddr = &localAddrIPv6;
			localAddrSize = sizeof(localAddrIPv6);
		}

		if (bind(fd, (struct sockaddr*)localAddr, localAddrSize) == SOCKET_ERROR)
		{
			PCPP_LOG_ERROR("Failed to bind to interface. Error code was '" << WSAGetLastError() << "'");
			closesocket(fd);
			return false;
		}

		int n = 1;
		DWORD dwBytesRet;
		// NULL is used instead of nullptr for Windows APIs. Check
		// https://devblogs.microsoft.com/oldnewthing/20180307-00/?p=98175
		if (WSAIoctl(fd, SIO_RCVALL, &n, sizeof(n), NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR)
		{
			PCPP_LOG_ERROR("Call to WSAIotcl(" << std::hex << SIO_RCVALL << ") failed with error code "
			                                   << WSAGetLastError());
			closesocket(fd);
			return false;
		}

		m_Socket = new SocketContainer();
		((SocketContainer*)m_Socket)->fd = fd;

		m_DeviceOpened = true;

		return true;

#elif defined(__linux__)

#	if defined(__ANDROID_API__) && __ANDROID_API__ < 24
		PCPP_LOG_ERROR("Raw sockets aren't supported in Android API < 24");
		return false;
#	else

		int fd = socket(AF_PACKET, SOCK_RAW, htobe16(ETH_P_ALL));
		if (fd < 0)
		{
			PCPP_LOG_ERROR("Failed to create raw socket. Error code was " << strerror(errno));
			return false;
		}

		// find interface name and index from IP address
		struct ifaddrs* addrs;
		getifaddrs(&addrs);
		std::string ifaceName = "";
		int ifaceIndex = -1;
		for (struct ifaddrs* curAddr = addrs; curAddr != nullptr; curAddr = curAddr->ifa_next)
		{
			if (curAddr->ifa_addr && (curAddr->ifa_flags & IFF_UP))
			{
				if (curAddr->ifa_addr->sa_family == AF_INET)
				{
					struct sockaddr_in* sockAddr = (struct sockaddr_in*)(curAddr->ifa_addr);
					char addrAsCharArr[32];
					inet_ntop(curAddr->ifa_addr->sa_family, (void*)&(sockAddr->sin_addr), addrAsCharArr,
					          sizeof(addrAsCharArr));
					if (!strcmp(m_InterfaceIP.toString().c_str(), addrAsCharArr))
					{
						ifaceName = curAddr->ifa_name;
						ifaceIndex = if_nametoindex(curAddr->ifa_name);
					}
				}
				else if (curAddr->ifa_addr->sa_family == AF_INET6)
				{
					struct sockaddr_in6* sockAddr = (struct sockaddr_in6*)(curAddr->ifa_addr);
					char addrAsCharArr[40];
					inet_ntop(curAddr->ifa_addr->sa_family, (void*)&(sockAddr->sin6_addr), addrAsCharArr,
					          sizeof(addrAsCharArr));
					if (!strcmp(m_InterfaceIP.toString().c_str(), addrAsCharArr))
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
			PCPP_LOG_ERROR("Cannot detect interface name or index from IP address");
			::close(fd);
			return false;
		}

		// bind raw socket to interface
		sockaddr_ll saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sll_family = AF_PACKET;
		saddr.sll_protocol = htons(ETH_P_ALL);
		saddr.sll_ifindex = if_nametoindex(ifaceName.c_str());

		if (bind(fd, reinterpret_cast<sockaddr*>(&saddr), sizeof(saddr)) < 0)
		{
			PCPP_LOG_ERROR("Cannot bind raw socket to interface '" << ifaceName << "': " << strerror(errno));
			::close(fd);
			return false;
		}

		m_Socket = new SocketContainer();
		((SocketContainer*)m_Socket)->fd = fd;
		((SocketContainer*)m_Socket)->interfaceIndex = ifaceIndex;
		((SocketContainer*)m_Socket)->interfaceName = ifaceName;

		m_DeviceOpened = true;

		return true;
#	endif  // __ANDROID_API__

#else

		PCPP_LOG_ERROR("Raw socket are not supported on this platform");
		return false;

#endif
	}

	void RawSocketDevice::close()
	{
		if (m_Socket != nullptr && isOpened())
		{
			SocketContainer* sockContainer = (SocketContainer*)m_Socket;
#if defined(_WIN32)
			closesocket(sockContainer->fd);
#elif defined(__linux__)
			::close(sockContainer->fd);
#endif
			delete sockContainer;
			m_Socket = nullptr;
			m_DeviceOpened = false;
		}
	}

	RawSocketDevice::RecvPacketResult RawSocketDevice::getError(int& errorCode) const
	{
#if defined(_WIN32)
		errorCode = WSAGetLastError();
		if (errorCode == WSAEWOULDBLOCK)
			return RecvWouldBlock;
		if (errorCode == WSAETIMEDOUT)
			return RecvTimeout;

		return RecvError;
#elif defined(__linux__)
		if ((errorCode == EAGAIN) || (errorCode == EWOULDBLOCK))
			return RecvWouldBlock;

		return RecvError;
#else
		return RecvError;
#endif
	}

}  // namespace pcpp
