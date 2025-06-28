#include "pch.h"

#include "TimespecTimeval.h"

namespace pcpp
{
	namespace internal
	{
		TEST(TimespecTimevalConversion, TimevalToTimespecMacro)
		{
			timeval tv;
			tv.tv_sec = 5000;
			tv.tv_usec = 45888;
			timespec ts;
			TIMEVAL_TO_TIMESPEC(&tv, &ts);
			EXPECT_EQ(ts.tv_sec, tv.tv_sec);
			EXPECT_EQ(ts.tv_nsec, tv.tv_usec * 1000);
		}

		TEST(TimespecTimevalConversion, TimespecToTimespecMacro)
		{
			timespec ts;
			ts.tv_sec = 5000;
			ts.tv_nsec = 45888;
			timeval tv;
			TIMESPEC_TO_TIMEVAL(&tv, &ts);
			EXPECT_EQ(tv.tv_sec, ts.tv_sec);
			EXPECT_EQ(tv.tv_usec, ts.tv_nsec / 1000);
		}

		TEST(TimespecTimevalConversion, TimevalToTimespec)
		{
			timeval tv;
			tv.tv_sec = 5000;
			tv.tv_usec = 45;
			timespec ts = toTimespec(tv);
			EXPECT_EQ(ts.tv_sec, tv.tv_sec);
			EXPECT_EQ(ts.tv_nsec, tv.tv_usec * 1000);
		}

		TEST(TimespecTimevalConversion, TimespecToTimeval)
		{
			timespec ts;
			ts.tv_sec = 5000;
			ts.tv_nsec = 45888;
			timeval tv = toTimeval(ts);
			EXPECT_EQ(tv.tv_sec, ts.tv_sec);
			EXPECT_EQ(tv.tv_usec, ts.tv_nsec / 1000);
		}
	}  // namespace internal
}  // namespace pcpp