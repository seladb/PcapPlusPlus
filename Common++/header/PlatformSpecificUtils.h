#ifndef PCAPPP_PLATFORM_SPECIFIC_UTILS
#define PCAPPP_PLATFORM_SPECIFIC_UTILS

#ifdef WIN32
#include <winbase.h>
#else
#include <unistd.h>
#endif

#ifdef WIN32
#define PCAP_SLEEP(seconds) Sleep(seconds*1000)
#else
#define PCAP_SLEEP(seconds) sleep(seconds)
#endif

#ifdef WIN32
#define CREATE_DIRECTORY(dir) CreateDirectory(dir, NULL)
#else
#define CREATE_DIRECTORY(dir) mkdir(dir, NULL)
#endif

#endif /* PCAPPP_PLATFORM_SPECIFIC_UTILS */
