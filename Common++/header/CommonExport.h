#ifndef PCAPPP_COMMON_EXPORT
#define PCAPPP_COMMON_EXPORT

#if defined(_WIN32) && defined(Common___EXPORTS) && defined(PCPP_COMMON_BUILD_DLL)
#define PCAPPP_COMMON_API __declspec(dllexport)
#elif defined(_WIN32) && defined(PCPP_COMMON_BUILD_DLL)
#define PCAPPP_COMMON_API __declspec(dllimport)
#else
#define PCAPPP_COMMON_API
#endif


#endif // PCAPPP_COMMON_EXPORT
