#ifndef PCAPPP_PCAP_EXPORT
#define PCAPPP_PCAP_EXPORT

#if defined(_WIN32) && defined(Pcap___EXPORTS) && defined(PCPP_PCAP_BUILD_DLL)
#define PCAPPP_PCAP_API __declspec(dllexport)
#elif defined(_WIN32) && defined(PCPP_PCAP_BUILD_DLL)
#define PCAPPP_PCAP_API __declspec(dllimport)
#else
#define PCAPPP_PCAP_API
#endif

#endif // PCAPPP_PCAP_EXPORT
