#define LOG_MODULE CommonLogModuleIpUtils

#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#ifndef NS_INADDRSZ
#define NS_INADDRSZ	4
#endif
#ifndef NS_IN6ADDRSZ
#define NS_IN6ADDRSZ	16
#endif
#ifndef NS_INT16SZ
#define NS_INT16SZ	2
#endif

namespace pcpp
{

in_addr* sockaddr2in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    LOG_DEBUG("sockaddr family is not AF_INET. Returning NULL");
    return NULL;
}

in6_addr* sockaddr2in6_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET6)
    	return &(((struct sockaddr_in6*)sa)->sin6_addr);
    LOG_DEBUG("sockaddr family is not AF_INET6. Returning NULL");
    return NULL;
}

void sockaddr2string(struct sockaddr *sa, char* resultString)
{
	in_addr* ipv4Addr = sockaddr2in_addr(sa);
	if (ipv4Addr != NULL)
	{
		LOG_DEBUG("IPv4 packet address");
		inet_ntop(AF_INET, &(((sockaddr_in*)sa)->sin_addr), resultString, INET_ADDRSTRLEN);
	}
	else
	{
		LOG_DEBUG("Not IPv4 packet address. Assuming IPv6 packet");
		inet_ntop(AF_INET6, &(((sockaddr_in6*)sa)->sin6_addr), resultString, INET6_ADDRSTRLEN);
	}
}

uint32_t in_addr2int(in_addr inAddr)
{
#ifdef WIN32
	return inAddr.S_un.S_addr;
#else
	return inAddr.s_addr;
#endif
}

uint16_t compute_checksum(ScalarBuffer<uint16_t> vec[], size_t vecSize)
{
	uint32_t sum = 0;
	for (size_t i = 0; i<vecSize; i++)
	{
		uint32_t local_sum = 0;
		size_t buff_len = vec[i].len;
		while (buff_len > 1) {
			LOG_DEBUG("Value to add = 0x%4X", *(vec[i].buffer));
			local_sum += *(vec[i].buffer);
			++(vec[i].buffer);
			buff_len -= 2;
		}
		LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);

		if (buff_len == 1)
		{
			uint8_t lastByte = *(vec[i].buffer);
			LOG_DEBUG("1 byte left, adding value: 0x%4X", lastByte);
			local_sum += lastByte;
			LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);
		}

		while (local_sum>>16) {
			local_sum = (local_sum & 0xffff) + (local_sum >> 16);
		}
		local_sum = ntohs(local_sum);
		LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);
		sum += local_sum;
	}

	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	LOG_DEBUG("Sum before invert = %d, 0x%4X", sum, sum);

	sum = ~sum;

	LOG_DEBUG("Calculated checksum = %d, 0x%4X", sum, sum);

	return ((uint16_t) sum);
}


static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;

uint32_t fnv_hash(ScalarBuffer<uint8_t> vec[], size_t vecSize)
{
    uint32_t hash = OFFSET_BASIS;
    for (size_t i = 0; i < vecSize; ++i)
    {
    	for (size_t j = 0; j < vec[i].len; ++j)
    	{
    		hash *= FNV_PRIME;
            hash ^= vec[i].buffer[j];
    	}
    }
    return hash;
}

uint32_t fnv_hash(uint8_t* buffer, size_t bufSize)
{
	ScalarBuffer<uint8_t> scalarBuf;
	scalarBuf.buffer = buffer;
	scalarBuf.len = bufSize;
	return fnv_hash(&scalarBuf, 1);
}

} // namespace pcpp

#if defined(WIN32) && !defined(_MSC_VER)
/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const uint8_t* src, char* dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int nprinted;

	nprinted = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
        /* Note: nprinted *excludes* the trailing '\0' character */
	if ((size_t)nprinted >= size) {
		return (NULL);
	}
	strncpy(dst, tmp, size);
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const uint8_t* src, char* dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	best.len = 0;
	cur.base = -1;
	cur.len = 0;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp += snprintf(tp, (unsigned long) (sizeof tmp - (tp - tmp)), "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		return (NULL);
	}
	strncpy(dst, tmp, size);
	return (dst);
}


/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton4(const char* src, uint8_t* dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	u_char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			size_t newSize = *tp * 10 + (pch - digits);

			if (newSize > 255)
				return (0);
			*tp = (u_char) newSize;
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton6(const char* src, uint8_t* dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = (int) (tp - colonp);
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}


const char* inet_ntop(int af, const void* src, char* dst, size_t size)
{
	switch (af) {
	case AF_INET:
		return (inet_ntop4((const uint8_t*)src, dst, size));
	case AF_INET6:
		return (inet_ntop6((const uint8_t*)src, dst, size));
	default:
		return (NULL);
	}
	/* NOTREACHED */
}

int inet_pton(int af, const char* src, void* dst)
{
	switch (af) {
#ifdef AF_INET
	case AF_INET:
		return (inet_pton4(src, (uint8_t*)dst));
#endif
#ifdef AF_INET6
	case AF_INET6:
		return (inet_pton6(src, (uint8_t*)dst));
#endif
	default:
		return (-1);
	}
	/* NOTREACHED */
}

#endif

