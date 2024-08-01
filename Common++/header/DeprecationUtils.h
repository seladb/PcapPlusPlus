#pragma once

/// @file

#ifndef __PCPP_DEPRECATED_GNU
#	if defined(__GUNC__) || defined(__clang__)
#		define __PCPP_DEPRECATED_GNU(msg) __attribute__((deprecated(msg)))
#	else
#		define __PCPP_DEPRECATED_GNU(msg)
#	endif  // defined(__GUNC__) || defined(__clang__)
#endif  // !__PCPP_DEPRECATED_GNU

#ifndef __PCPP_DEPRECATED_MSVC
#	ifdef _MSC_VER
#		define __PCPP_DEPRECATED_MSVC(msg) __declspec(deprecated(msg))
#	else
#		define __PCPP_DEPRECATED_MSVC(msg)
#	endif  // __MSC_VER
#endif  // !__PCPP_DEPRECATED_MSVC

#ifndef PCPP_DEPRECATED
#	if defined(__GNUC__) || defined(__clang__)
#		define PCPP_DEPRECATED(msg) __PCPP_DEPRECATED_GNU(msg)
#	elif defined(_MSC_VER)
#		define PCPP_DEPRECATED(msg) __PCPP_DEPRECATED_MSVC(msg)
#	else
#		pragma message("WARNING: DEPRECATED feature is not implemented for this compiler")
#		define PCPP_DEPRECATED(msg)
#	endif
#endif

#if !defined(DISABLE_WARNING_PUSH) || !defined(DISABLE_WARNING_POP)
#	if defined(_MSC_VER)
#		define DISABLE_WARNING_PUSH __pragma(warning(push))
#		define DISABLE_WARNING_POP __pragma(warning(pop))
#		define DISABLE_WARNING(warningNumber) __pragma(warning(disable : warningNumber))

#		define DISABLE_WARNING_DEPRECATED DISABLE_WARNING(4996)
#	elif defined(__GNUC__) || defined(__clang__)
#		define DO_PRAGMA(X) _Pragma(#X)
#		define DISABLE_WARNING_PUSH DO_PRAGMA(GCC diagnostic push)
#		define DISABLE_WARNING_POP DO_PRAGMA(GCC diagnostic pop)
#		define DISABLE_WARNING(warningName) DO_PRAGMA(GCC diagnostic ignored #warningName)

// clang-format off
#		define DISABLE_WARNING_DEPRECATED DISABLE_WARNING(-Wdeprecated-declarations)
// clang-format on
#	else
#		pragma message("WARNING: Disabling of warnings is not implemented for this compiler")
#		define DISABLE_WARNING_PUSH
#		define DISABLE_WARNING_POP

#		define DISABLE_WARNING_DEPRECATED
#	endif
#endif
