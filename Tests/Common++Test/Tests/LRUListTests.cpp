#include "pch.h"

#include "LRUList.h"

namespace pcpp
{
	TEST(LRUListTest, PutTest)
	{
		LRUList<int> lruList(3);
		int deletedValue;

		// Test inserting elements
		EXPECT_EQ(lruList.put(1), 0);
		EXPECT_EQ(lruList.put(2), 0);
		EXPECT_EQ(lruList.put(3), 0);
		EXPECT_EQ(lruList.getSize(), 3);

		// Test inserting an element that exceeds the max size
		EXPECT_EQ(lruList.put(4, &deletedValue), 1);
		EXPECT_EQ(deletedValue, 1);
		EXPECT_EQ(lruList.getSize(), 3);

		// Test inserting an existing element
		EXPECT_EQ(lruList.put(2), 0);
		EXPECT_EQ(lruList.getSize(), 3);
	}

	TEST(LRUListTest, GetTest)
	{
		LRUList<std::string> lruList(2);

		lruList.put("first");
		lruList.put("second");

		// Test getting the most recently used element
		EXPECT_EQ(lruList.getMRUElement(), "second");

		// Test getting the least recently used element
		EXPECT_EQ(lruList.getLRUElement(), "first");

		lruList.put("third");

		// Test getting the new most recently used element
		EXPECT_EQ(lruList.getMRUElement(), "third");

		// Test getting the new least recently used element
		EXPECT_EQ(lruList.getLRUElement(), "second");
	}

	TEST(LRUListTest, EraseTest)
	{
		LRUList<int> lruList(3);

		lruList.put(1);
		lruList.put(2);
		lruList.put(3);

		// Test erasing an element
		lruList.eraseElement(2);
		EXPECT_EQ(lruList.getSize(), 2);

		// Test erasing a non-existing element
		lruList.eraseElement(4);
		EXPECT_EQ(lruList.getSize(), 2);
	}

	TEST(LRUListTest, SizeTest)
	{
		LRUList<int> lruList(3);

		// Test initial size
		EXPECT_EQ(lruList.getSize(), 0);

		lruList.put(1);
		lruList.put(2);

		// Test size after inserting elements
		EXPECT_EQ(lruList.getSize(), 2);

		lruList.put(3);
		lruList.put(4);

		// Test size after exceeding max size
		EXPECT_EQ(lruList.getSize(), 3);
	}
}  // namespace pcpp
