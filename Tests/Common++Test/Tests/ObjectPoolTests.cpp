#include "pch.h"

#include "ObjectPool.h"

namespace pcpp
{
	namespace internal
	{

		TEST(DynamicObjectPoolTest, BasicUsage)
		{
			DynamicObjectPool<int> pool(10);  // Create a pool with limit 10 objects
			EXPECT_EQ(pool.maxSize(), 10);
			EXPECT_EQ(pool.size(), 0);

			auto obj1 = pool.acquireObject();  // Acquire an object from the pool
			EXPECT_NE(obj1, nullptr);
			EXPECT_EQ(*obj1, 0);  // Default initialized to 0
			EXPECT_EQ(pool.size(), 0);
			*obj1 = 42;  // Modify the object

			// Save the address of the object before releasing it
			int* obj1Raw = obj1.get();
			pool.releaseObject(std::move(obj1));
			EXPECT_EQ(pool.size(), 1);

			auto obj2 = pool.acquireObject();
			EXPECT_EQ(obj1Raw, obj2.get());  // Should return the same object
			pool.clear();                    // Clear the pool
		}

		TEST(DynamicObjectPoolTest, Preallocation)
		{
			DynamicObjectPool<int> pool(10, 5);  // Create a pool with limit 10 and preallocate 5 objects
			EXPECT_EQ(pool.maxSize(), 10);
			EXPECT_EQ(pool.size(), 5);
		}

		TEST(DynamicObjectPoolTest, MaxPoolSize)
		{
			DynamicObjectPool<int> pool(2);  // Create a pool with limit 2 objects

			for (int i = 0; i < 4; ++i)
			{
				auto obj = std::make_unique<int>(i);
				pool.releaseObject(std::move(obj));  // Release objects to the pool
				EXPECT_LE(pool.size(), 2);           // Pool should free released objects if it exceeds the limit
			}
		}
	}  // namespace internal
}  // namespace pcpp
