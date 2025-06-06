/// these conversion macros are not defined on some of the platforms, including
/// Windows
#pragma once

#ifdef _MSC_VER
#	include <winsock2.h>
#	include <time.h>
#else
#	include <sys/time.h>
#endif

#ifndef TIMEVAL_TO_TIMESPEC
#	define TIMEVAL_TO_TIMESPEC(tv, ts)                                                                                \
		{                                                                                                              \
			(ts)->tv_sec = (tv)->tv_sec;                                                                               \
			(ts)->tv_nsec = (tv)->tv_usec * 1000;                                                                      \
		}
#endif

#ifndef TIMESPEC_TO_TIMEVAL
#	define TIMESPEC_TO_TIMEVAL(tv, ts)                                                                                \
		{                                                                                                              \
			(tv)->tv_sec = (ts)->tv_sec;                                                                               \
			(tv)->tv_usec = (ts)->tv_nsec / 1000;                                                                      \
		}
#endif

namespace pcpp
{
	namespace internal
	{
		/// Converts a timeval structure to a timespec structure
		inline timespec toTimespec(timeval value)
		{
			timespec nsec_time = {};
			TIMEVAL_TO_TIMESPEC(&value, &nsec_time);
			return nsec_time;
		}

		/// Converts a timespec structure to a timeval structure
		inline timeval toTimeval(timespec value)
		{
			timeval tv = {};
			TIMESPEC_TO_TIMEVAL(&tv, &value);
			return tv;
		}
	}  // namespace internal
}  // namespace pcpp
