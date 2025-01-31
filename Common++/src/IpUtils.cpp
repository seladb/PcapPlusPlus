#define LOG_MODULE CommonLogModuleIpUtils

#include "IpUtils.h"
#include "Logger.h"
#include <cstring>
#include <stdexcept>
#ifndef NS_INADDRSZ
#	define NS_INADDRSZ 4
#endif
#ifndef NS_IN6ADDRSZ
#	define NS_IN6ADDRSZ 16
#endif
#ifndef NS_INT16SZ
#	define NS_INT16SZ 2
#endif

namespace pcpp
{
	namespace internal
	{
		in_addr* sockaddr2in_addr(sockaddr* sAddr)
		{
			if (sAddr == nullptr)
			{
				throw std::invalid_argument("sockaddr is nullptr");
			}

			if (sAddr->sa_family != AF_INET)
			{
				throw std::invalid_argument("sockaddr family is not AF_INET.");
			}

			return &(reinterpret_cast<sockaddr_in*>(sAddr)->sin_addr);
		}

		in_addr* try_sockaddr2in_addr(sockaddr* sAddr)
		{
			try
			{
				return sockaddr2in_addr(sAddr);
			}
			catch (const std::invalid_argument& e)
			{
				(void)e;  // Suppress the unreferenced local variable warning when PCPP_LOG_DEBUG is disabled
				PCPP_LOG_DEBUG("Extraction failed: " << e.what() << " Returning nullptr.");
				return nullptr;
			}
		}

		in6_addr* sockaddr2in6_addr(sockaddr* sAddr)
		{
			if (sAddr == nullptr)
			{
				throw std::invalid_argument("sockaddr is nullptr");
			}

			if (sAddr->sa_family != AF_INET6)
			{
				throw std::invalid_argument("sockaddr family is not AF_INET6.");
			}

			return &(reinterpret_cast<sockaddr_in6*>(sAddr)->sin6_addr);
		}

		in6_addr* try_sockaddr2in6_addr(sockaddr* sAddr)
		{
			try
			{
				return sockaddr2in6_addr(sAddr);
			}
			catch (const std::invalid_argument& e)
			{
				(void)e;  // Suppress the unreferenced local variable warning when PCPP_LOG_DEBUG is disabled
				PCPP_LOG_DEBUG("Extraction failed: " << e.what() << " Returning nullptr.");
				return nullptr;
			}
		}

		void sockaddr2string(const sockaddr* sAddr, char* resultString, size_t resultBufLen)
		{
			if (sAddr == nullptr)
			{
				throw std::invalid_argument("sockaddr is nullptr");
			}

			switch (sAddr->sa_family)
			{
			case AF_INET:
			{
				PCPP_LOG_DEBUG("IPv4 packet address");
				if (resultBufLen < INET_ADDRSTRLEN)
				{
					throw std::invalid_argument("Insufficient buffer");
				}

				if (inet_ntop(AF_INET, &(reinterpret_cast<const sockaddr_in*>(sAddr)->sin_addr), resultString,
				              resultBufLen) == nullptr)
				{
					throw std::runtime_error("Unknown error during conversion");
				}
				break;
			}
			case AF_INET6:
			{
				PCPP_LOG_DEBUG("IPv6 packet address");
				if (resultBufLen < INET6_ADDRSTRLEN)
				{
					throw std::invalid_argument("Insufficient buffer");
				}

				if (inet_ntop(AF_INET6, &(reinterpret_cast<const sockaddr_in6*>(sAddr)->sin6_addr), resultString,
				              resultBufLen) == nullptr)
				{
					throw std::runtime_error("Unknown error during conversion");
				}
				break;
			}
			default:
				throw std::invalid_argument("Unsupported sockaddr family. Family is not AF_INET or AF_INET6.");
			}
		}

		uint32_t in_addr2int(in_addr inAddr)
		{
#ifdef _WIN32
			return inAddr.S_un.S_addr;
#else
			return inAddr.s_addr;
#endif
		}
	}  // namespace internal
}  // namespace pcpp

// Only MinGW32 doesn't have these functions (not MinGW-w64 nor Visual C++)
#if defined(_WIN32) && !defined(_MSC_VER) && (!defined(__MINGW64_VERSION_MAJOR) || (__MINGW64_VERSION_MAJOR < 8))
/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statistics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char* inet_ntop4(const uint8_t* src, char* dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int nprinted;
	nprinted = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
	/* Note: nprinted *excludes* the trailing '\0' character */
	if ((size_t)nprinted >= size)
	{
		return (nullptr);
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
static const char* inet_ntop6(const uint8_t* src, char* dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct
	{
		int base, len;
	} best, cur;
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
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++)
	{
		if (words[i] == 0)
		{
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		}
		else
		{
			if (cur.base != -1)
			{
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1)
	{
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++)
	{
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 && (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
		{
			if (!inet_ntop4(src + 12, tp, sizeof tmp - (tp - tmp)))
				return (nullptr);
			tp += strlen(tp);
			break;
		}
		tp += snprintf(tp, (unsigned long)(sizeof tmp - (tp - tmp)), "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size)
	{
		return (nullptr);
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
static int inet_pton4(const char* src, uint8_t* dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	u_char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0')
	{
		const char* pch;

		if ((pch = strchr(digits, ch)) != nullptr)
		{
			size_t newSize = *tp * 10 + (pch - digits);

			if (newSize > 255)
				return (0);
			*tp = (u_char)newSize;
			if (!saw_digit)
			{
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		}
		else if (ch == '.' && saw_digit)
		{
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		}
		else
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
static int inet_pton6(const char* src, uint8_t* dst)
{
	static const char xdigits_l[] = "0123456789abcdef", xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char* curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = nullptr;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0')
	{
		const char *pch, *xdigits;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == nullptr)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != nullptr)
		{
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':')
		{
			curtok = src;
			if (!saw_xdigit)
			{
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			else if (*src == '\0')
			{
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char)(val >> 8) & 0xff;
			*tp++ = (u_char)val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) && inet_pton4(curtok, tp) > 0)
		{
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break; /* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit)
	{
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (u_char)(val >> 8) & 0xff;
		*tp++ = (u_char)val & 0xff;
	}
	if (colonp != nullptr)
	{
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = (int)(tp - colonp);
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++)
		{
			endp[-i] = colonp[n - i];
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
	switch (af)
	{
	case AF_INET:
		return (inet_ntop4((const uint8_t*)src, dst, size));
	case AF_INET6:
		return (inet_ntop6((const uint8_t*)src, dst, size));
	default:
		return (nullptr);
	}
	/* NOTREACHED */
}

int inet_pton(int af, const char* src, void* dst)
{
	switch (af)
	{
#	ifdef AF_INET
	case AF_INET:
		return (inet_pton4(src, (uint8_t*)dst));
#	endif
#	ifdef AF_INET6
	case AF_INET6:
		return (inet_pton6(src, (uint8_t*)dst));
#	endif
	default:
		return (-1);
	}
	/* NOTREACHED */
}

#endif
