#include <array>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "LRUList.h"

namespace pcpp
{
	TEST(LRUListTest, PutAndErase)
	{
		int deletedValue = 0;
		LRUList<int> lruCache(4);
		EXPECT_EQ(lruCache.getMaxSize(), 4);
		EXPECT_EQ(lruCache.getSize(), 0);
		ASSERT_EQ(deletedValue, 0);

		lruCache.put(1, &deletedValue);
		EXPECT_EQ(lruCache.getSize(), 1);
		EXPECT_EQ(deletedValue, 0);

		lruCache.put(1, &deletedValue);
		EXPECT_EQ(lruCache.getSize(), 1);
		EXPECT_EQ(deletedValue, 0);

		lruCache.put(2, &deletedValue);
		EXPECT_EQ(deletedValue, 0);
		lruCache.put(3, &deletedValue);
		EXPECT_EQ(deletedValue, 0);
		lruCache.put(4, &deletedValue);
		EXPECT_EQ(lruCache.getMaxSize(), 4);
		EXPECT_EQ(lruCache.getSize(), 4);
		EXPECT_EQ(deletedValue, 0);

		lruCache.put(5, &deletedValue);
		EXPECT_EQ(lruCache.getMaxSize(), 4);
		EXPECT_EQ(lruCache.getSize(), 4);
		EXPECT_EQ(deletedValue, 1);

		deletedValue = 0;
		ASSERT_EQ(deletedValue, 0);
		lruCache.eraseElement(3);
		EXPECT_EQ(lruCache.getSize(), 3);

		lruCache.put(6, &deletedValue);
		EXPECT_EQ(deletedValue, 0);
		EXPECT_EQ(lruCache.getSize(), 4);

		lruCache.eraseElement(7);
		EXPECT_EQ(lruCache.getSize(), 4);
	};

	TEST(LRUListTest, RecentlyUsedElementAccessors)
	{
		LRUList<int> lruCache(4);
		ASSERT_EQ(lruCache.getMaxSize(), 4);

		lruCache.put(1);
		lruCache.put(2);
		lruCache.put(3);
		lruCache.put(4);

		EXPECT_EQ(lruCache.getMRUElement(), 4);
		EXPECT_EQ(lruCache.getLRUElement(), 1);

		lruCache.put(5);
		EXPECT_EQ(lruCache.getMRUElement(), 5);
		EXPECT_EQ(lruCache.getLRUElement(), 2);

		lruCache.put(3);
		EXPECT_EQ(lruCache.getMRUElement(), 3);
		EXPECT_EQ(lruCache.getLRUElement(), 2);
	};
}  // namespace pcpp
