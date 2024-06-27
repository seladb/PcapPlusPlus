/// these conversion macros are not defined on some of the platforms, including
/// Windows
#pragma once

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
