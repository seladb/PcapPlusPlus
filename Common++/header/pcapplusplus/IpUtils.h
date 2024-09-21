#pragma once

#include <stdint.h>
#ifdef __linux__
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif
#if defined(__APPLE__)
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif
#if defined(_WIN32)
#	include <ws2tcpip.h>
#endif
#if defined(__FreeBSD__)
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif

/// @file

// Both Visual C++ Compiler and MinGW-w64 define inet_ntop() and inet_pton()
// Add compatibility functions for old MinGW (aka MinGW32)
// We use "__MINGW64_VERSION_MAJOR" and not __MINGW64__ to detect MinGW-w64 compiler
// because the second one is not defined for MinGW-w64 in 32bits mode
#if defined(_WIN32) && !defined(_MSC_VER) && (!defined(__MINGW64_VERSION_MAJOR) || (__MINGW64_VERSION_MAJOR < 8))
/**
 * Convert a network format address to presentation format.
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address structure, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @param[out] dst Network address string representation
 * @param[in] size 'dst' Maximum size
 * @return pointer to presentation format address ('dst'), or nullptr (see errno).
 */
const char* inet_ntop(int af, const void* src, char* dst, size_t size);

/**
 * Convert from presentation format (which usually means ASCII printable)
 * to network format (which is usually some kind of binary format).
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address string representation
 * @param[out] dst Network address structure result, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @return
 * 1 if the address was valid for the specified address family;
 * 0 if the address wasn't valid ('dst' is untouched in this case);
 * -1 if some other error occurred ('dst' is untouched in this case, too)
 */
int inet_pton(int af, const char* src, void* dst);
#endif

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	namespace internal
	{
		/**
		 * Extract IPv4 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in_addr format
		 * @throws std::invalid_argument Sockaddr family is not AF_INET or sockaddr is nullptr.
		 */
		in_addr* sockaddr2in_addr(sockaddr* sa);

		/**
		 * Attempt to extract IPv4 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Pointer to address in in_addr format or nullptr if extraction fails.
		 */
		in_addr* try_sockaddr2in_addr(sockaddr* sa);

		/**
		 * Extract IPv6 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in6_addr format
		 * @throws std::invalid_argument Sockaddr family is not AF_INET6 or sockaddr is nullptr.
		 */
		in6_addr* sockaddr2in6_addr(sockaddr* sa);

		/**
		 * Attempt to extract IPv6 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Pointer to address in in6_addr format or nullptr if extraction fails.
		 */
		in6_addr* try_sockaddr2in6_addr(sockaddr* sa);

		/**
		 * Converts a sockaddr format address to its string representation
		 * @param[in] sa Address in sockaddr format
		 * @param[out] resultString String representation of the address
		 * @param[in] resultBufLen Length of the result buffer.
		 * @throws std::invalid_argument Sockaddr family is not AF_INET or AF_INET6, sockaddr is nullptr or the result
		 * str buffer is insufficient.
		 */
		void sockaddr2string(sockaddr const* sa, char* resultString, size_t resultBufLen);

		/**
		 * Convert a in_addr format address to 32bit representation
		 * @param[in] inAddr Address in in_addr format
		 * @return Address in 32bit format
		 */
		uint32_t in_addr2int(in_addr inAddr);
	}  // namespace internal
}  // namespace pcpp
