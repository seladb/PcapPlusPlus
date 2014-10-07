#ifndef PCAPPP_PLATFORM_SPECIFIC_UTILS
#define PCAPPP_PLATFORM_SPECIFIC_UTILS

#ifdef WIN32
#include <winbase.h>
#endif

#ifdef WIN32
#define PCAP_SLEEP(seconds) Sleep(seconds*1000)
#else
#define PCAP_SLEEP(seconds) sleep(seconds)
#endif

#endif /* PCAPPP_PLATFORM_SPECIFIC_UTILS */
