#define LOG_MODULE UndefinedLogModule

#include "Logger.h"
#include "LinuxNicInformationSocket.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#define INVALID_SOCKET_VALUE (-1)

namespace pcpp
{

	static inline LinuxNicInformationSocket::LinuxSocket openLinuxNicInformationSocket()
	{
		LinuxNicInformationSocket::LinuxSocket soc = socket(AF_INET, SOCK_DGRAM, 0);
		if (soc < 0)
		{
			const char* error = std::strerror(errno);
			PCPP_LOG_DEBUG("Can't open Linux information socket. Errno string: " << error);
			return soc = INVALID_SOCKET_VALUE;
		}
		return soc;
	}

	LinuxNicInformationSocket::LinuxNicInformationSocket() : m_Socket(openLinuxNicInformationSocket())
	{}

	LinuxNicInformationSocket::~LinuxNicInformationSocket()
	{
		if (m_Socket == INVALID_SOCKET_VALUE)
		{
			PCPP_LOG_DEBUG("Closing not opened Linux NIC information socket");
		}
		else
		{
			close(m_Socket);
		}
	}

	bool LinuxNicInformationSocket::makeRequest(const char* nicName, const IoctlType ioctlType, ifreq* request)
	{
		if (m_Socket == INVALID_SOCKET_VALUE)
		{
			m_Socket = openLinuxNicInformationSocket();
			if (m_Socket == INVALID_SOCKET_VALUE)
			{
				PCPP_LOG_ERROR("Request to Linux NIC incformation socket failed. "
				               "Can't open socket");
				return false;
			}
		}
		snprintf(request->ifr_name, IFNAMSIZ, "%s", nicName);
		if (ioctl(m_Socket, ioctlType, request))
		{
			const char* error = std::strerror(errno);
			PCPP_LOG_ERROR("Request to Linux NIC incformation socket failed. "
			               "ioctl(2) failed with error string: "
			               << error);
			return false;
		}
		return true;
	}
}  // namespace pcpp
