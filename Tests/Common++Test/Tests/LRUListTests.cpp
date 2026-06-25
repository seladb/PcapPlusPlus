#include "pch.h"

#include "LRUList.h"

namespace pcpp_test
{
	TEST(LRUListTest, TestBasicUsage)
	{
		pcpp::LRUList<int> lruList(999);

		EXPECT_EQ(lruList.put(1), 0);
		EXPECT_EQ(lruList.put(2), 0);
		EXPECT_EQ(lruList.put(3), 0);
		EXPECT_EQ(lruList.getSize(), 3);

		EXPECT_EQ(lruList.getMRUElement(), 3);
		EXPECT_EQ(lruList.getLRUElement(), 1);

		// Put duplicate element.
		EXPECT_EQ(lruList.put(2), 0);
		EXPECT_EQ(lruList.getSize(), 3);

		// Test erase element
		lruList.eraseElement(2);
		EXPECT_EQ(lruList.getLRUElement(), 1);
		EXPECT_EQ(lruList.getMRUElement(), 3);
	}

	TEST(LRUListTest, TestLruElementDrop)
	{
		pcpp::LRUList<int> lruList(3);
		ASSERT_EQ(lruList.getMaxSize(), 3);

		EXPECT_EQ(lruList.put(1), 0);
		EXPECT_EQ(lruList.put(2), 0);
		EXPECT_EQ(lruList.put(3), 0);

		EXPECT_EQ(lruList.put(3), 0) << "Duplicate insertions should not destroy elements";

		int deletedValue;
		EXPECT_EQ(lruList.put(4, &deletedValue), 1);
		EXPECT_EQ(deletedValue, 1) << "The least recently used element should be deleted when max size is exceeded";

		EXPECT_EQ(lruList.getSize(), lruList.getMaxSize());
	}
}  // namespace pcpp_test
