#ifndef PCAPPP_IP_UTILS
#define PCAPPP_IP_UTILS

//#include <pcap.h>
#include <stdint.h>
#ifndef WIN32
#include <in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef WIN32
/**
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char* inet_ntop(int af, const void* src, char* dst, size_t size);

/**
 *	convert from presentation format (which usually means ASCII printable)
 *	to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *	Paul Vixie, 1996.
 */
int inet_pton(int af, const char* src, void* dst);
#endif


/**
 * extract IPv4 address from sockaddr
 * @param sa - input sockaddr
 * @return - in_addr
 */
in_addr* sockaddr2in_addr(struct sockaddr *sa);

/**
 * extract IPv6 address from sockaddr
 * @param sa - input sockaddr
 * @return - in6_addr
 */
in6_addr* sockaddr2in6_addr(struct sockaddr *sa);

void sockaddr2string(struct sockaddr *sa, char* resultString);

uint32_t in_addr2int(in_addr inAddr);

struct ScalarBuffer
{
	uint16_t* buffer;
	size_t len;
};

//uint16_t compute_checksum(uint16_t* addr, uint32_t count, uint16_t protocol);
uint16_t compute_checksum(ScalarBuffer vec[], size_t vecSize);

#endif
