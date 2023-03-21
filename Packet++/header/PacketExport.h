#ifndef PCAPPP_PACKET_EXPORT
#define PCAPPP_PACKET_EXPORT

#if defined(_WIN32) && defined(Packet___EXPORTS) && defined(PCPP_PACKET_BUILD_DLL)
#define PCAPPP_PACKET_API __declspec(dllexport)
#elif defined(_WIN32) && defined(PCPP_PACKET_BUILD_DLL)
#define PCAPPP_PACKET_API __declspec(dllimport)
#else
#define PCAPPP_PACKET_API
#endif


#endif // PCAPPP_PACKET_EXPORT
