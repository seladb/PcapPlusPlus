#pragma once

/// @file

#ifndef PCPP_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define PCPP_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define PCPP_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: DEPRECATED feature is not implemented for this compiler")
#define PCPP_DEPRECATED
#endif
#endif
