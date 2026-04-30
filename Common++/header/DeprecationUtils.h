#pragma once

/// @file

#ifndef PCPP_DEPRECATED
#	define PCPP_DEPRECATED(msg) [[deprecated(msg)]]
#endif

// Provides backwards compatibility for enum class types that have been upgraded.
//
// This macro should be once used in the header file of the upgraded enum class type with each enum value.
// This will define the enum value as a const auto with the same name, mimicing the old enum value, but
// with a deprecation warning to encourage users to switch to the new enum class value.
//
#define PCPP_ENUM_CLASS_UPGRADE_COMPAT(cls, val)                                                                       \
	PCPP_DEPRECATED("Enum class upgrade: Use " #cls "::" #val " instead.")                                             \
	const auto val = cls::val

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
