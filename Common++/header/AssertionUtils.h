#pragma once

/// @file
/// @brief This file contains internal assertion utilities used in PcapPlusPlus for debugging.

#ifndef PCPP_ASSERT_USE_C_ASSERT
#	define PCPP_ASSERT_USE_C_ASSERT 0
#endif  // !PCPP_ASSERT_USE_C_ASSERT

#include <stdexcept>
#if PCPP_ASSERT_USE_C_ASSERT
#	include <cassert>
#else
#	include <string>
#	include <sstream>
#endif  // PCPP_ASSERT_USE_C_ASSERT

namespace pcpp
{
	namespace internal
	{
		/// @brief A custom assertion error class derived from std::logic_error to be used with PCPP_ASSERT.
		class AssertionError : public std::logic_error
		{
		public:
			using std::logic_error::logic_error;
		};
	}  // namespace internal
}  // namespace pcpp

#ifndef NDEBUG
#	if PCPP_ASSERT_USE_C_ASSERT
#		define PCPP_ASSERT(condition, message) assert((condition) && (message))
#	else  // !PCPP_ASSERT_USE_C_ASSERT
#		define PCPP_ASSERT(condition, message)                                                                        \
			do                                                                                                         \
			{                                                                                                          \
				if (!(condition))                                                                                      \
				{                                                                                                      \
					std::stringstream ss;                                                                              \
					ss << "[PCPP] Assertion failed on [" << __FILE__ << ":" << __LINE__ << "] with: " << (message);    \
					throw pcpp::internal::AssertionError(ss.str());                                                    \
				}                                                                                                      \
			} while (false)
#	endif  // PCPP_ASSERT_USE_C_ASSERT
#else
#	define PCPP_ASSERT(condition, message) (void)0;
#endif  // !NDEBUG
