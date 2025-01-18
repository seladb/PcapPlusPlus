
#include "../TestDefinition.h"

#include "ObjectPool.h"

PTF_TEST_CASE(TestObjectPool)
{
	using pcpp::internal::DynamicObjectPool;

	{
		DynamicObjectPool<int> pool;
		PTF_ASSERT_EQUAL(pool.size(), 0);
		PTF_ASSERT_EQUAL(pool.maxSize(), 100);

		pool.preallocate(2);
		PTF_ASSERT_EQUAL(pool.size(), 2);

		pool.setMaxSize(1);
		PTF_ASSERT_EQUAL(pool.size(), 1);
		PTF_ASSERT_EQUAL(pool.maxSize(), 1);

		PTF_ASSERT_RAISES(pool.preallocate(2), std::invalid_argument,
		                  "Preallocated objects cannot exceed the maximum pool size");

		pool.clear();
		PTF_ASSERT_EQUAL(pool.size(), 0);
		PTF_ASSERT_EQUAL(pool.maxSize(), 1);
	}

	{
		DynamicObjectPool<int> pool(10, 2);
		PTF_ASSERT_EQUAL(pool.size(), 2);
		PTF_ASSERT_EQUAL(pool.maxSize(), 10);

		PTF_ASSERT_RAISES(DynamicObjectPool<int>(0, 2), std::invalid_argument,
		                  "Preallocated objects cannot exceed the maximum pool size");
	}

	{
		DynamicObjectPool<int> pool;
		PTF_ASSERT_EQUAL(pool.size(), 0);

		// Acquire an object, since the pool is empty, a new object will be created.
		auto obj1 = pool.acquireObject();
		PTF_ASSERT_NOT_NULL(obj1);

		// Acquire a second object, since the pool is still empty, a new object will be created.
		auto obj2 = pool.acquireObject();

		// For the purposes of this test a value will be assigned to track the object.
		*obj1 = 55;
		*obj2 = 66;

		// Release the objects back to the pool.
		pool.releaseObject(std::move(obj1));
		pool.releaseObject(std::move(obj2));

		PTF_ASSERT_EQUAL(pool.size(), 2);

		// Acquire an object again, this time the object should be reused.
		// Since the pool is a LIFO stack the object that was released last should be acquired first.
		obj1 = pool.acquireObject();

		// The value should be the same as the one assigned before releasing the object.
		PTF_ASSERT_EQUAL(*obj1, 66);

		// Acquire the second object, this time the object that was released first should be acquired.
		obj2 = pool.acquireObject();
		PTF_ASSERT_EQUAL(*obj2, 55);

		// Set the max size of the pool to zero to test the deletion of objects.
		pool.setMaxSize(0);

		// Release the objects back to the pool, this time the objects should be deleted.
		pool.releaseObject(std::move(obj1));
		pool.releaseObject(std::move(obj2));
		PTF_ASSERT_EQUAL(pool.size(), 0);
	}
}
