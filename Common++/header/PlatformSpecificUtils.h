#ifndef PCAPPP_PLATFORM_SPECIFIC_UTILS
#define PCAPPP_PLATFORM_SPECIFIC_UTILS

#if defined(WIN32) || defined(WINx64)
#include <Windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#ifdef WIN32
#define PCAP_SLEEP(seconds) Sleep(seconds*1000)
#else
#define PCAP_SLEEP(seconds) sleep(seconds)
#endif

#ifdef WIN32
#define POPEN _popen
#else
#define POPEN popen
#endif

#ifdef WIN32
#define PCLOSE _pclose
#else
#define PCLOSE pclose
#endif

#endif /* PCAPPP_PLATFORM_SPECIFIC_UTILS */
