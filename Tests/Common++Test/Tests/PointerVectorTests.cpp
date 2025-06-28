#include "pch.h"

#include <algorithm>
#include <stdexcept>

#include "MemoryLeakDetectorFixture.hpp"

#include "PointerVector.h"

namespace pcpp
{
	class TestObject
	{
	public:
		TestObject(int value) : m_Value(value)
		{}
		int getValue() const
		{
			return m_Value;
		}
		std::unique_ptr<TestObject> clone() const
		{
			return std::unique_ptr<TestObject>(new TestObject(*this));
		}

	private:
		int m_Value;
	};

	class PointerVectorTest : public MemoryLeakDetectorTest
	{
	};

	TEST_F(PointerVectorTest, DefaultConstructor)
	{
		pcpp::PointerVector<TestObject> vec;
		EXPECT_EQ(vec.size(), 0);
	}

	TEST_F(PointerVectorTest, CopyConstructor)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		pcpp::PointerVector<TestObject> copyVec(vec);
		EXPECT_EQ(copyVec.size(), 2);
		EXPECT_EQ(copyVec.at(0)->getValue(), 1);
		EXPECT_EQ(copyVec.at(1)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, MoveConstructor)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		pcpp::PointerVector<TestObject> movedVec(std::move(vec));
		EXPECT_EQ(movedVec.size(), 2);
		EXPECT_EQ(movedVec.at(0)->getValue(), 1);
		EXPECT_EQ(movedVec.at(1)->getValue(), 2);
		EXPECT_EQ(vec.size(), 0);
	}

	TEST_F(PointerVectorTest, CopyAssignmentOperator)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		pcpp::PointerVector<TestObject> copyVec;
		copyVec = vec;
		EXPECT_EQ(copyVec.size(), 2);
		EXPECT_EQ(copyVec.at(0)->getValue(), 1);
		EXPECT_EQ(copyVec.at(1)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, MoveAssignmentOperator)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		pcpp::PointerVector<TestObject> movedVec;
		movedVec = std::move(vec);
		EXPECT_EQ(movedVec.size(), 2);
		EXPECT_EQ(movedVec.at(0)->getValue(), 1);
		EXPECT_EQ(movedVec.at(1)->getValue(), 2);
		EXPECT_EQ(vec.size(), 0);
	}

	TEST_F(PointerVectorTest, PushBack)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.size(), 2);
		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, PushBackUniquePtr)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(std::unique_ptr<TestObject>(new TestObject(1)));
		vec.pushBack(std::unique_ptr<TestObject>(new TestObject(2)));

		EXPECT_EQ(vec.size(), 2);
		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, Clear)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));
		vec.clear();

		EXPECT_EQ(vec.size(), 0);
	}

	TEST_F(PointerVectorTest, Erase)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));
		vec.pushBack(new TestObject(3));

		auto it = vec.begin();
		++it;
		vec.erase(it);

		EXPECT_EQ(vec.size(), 2);
		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 3);
	}

	TEST_F(PointerVectorTest, GetAndDetach)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		auto obj = vec.getAndDetach(0);
		EXPECT_EQ(obj->getValue(), 1);
		EXPECT_EQ(vec.size(), 1);
		EXPECT_EQ(vec.at(0)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, At)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST_F(PointerVectorTest, FrontBack)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.front()->getValue(), 1);
		EXPECT_EQ(vec.back()->getValue(), 2);
	}

	TEST_F(PointerVectorTest, PushBackNullptr)
	{
		pcpp::PointerVector<TestObject> vec;
		TestObject* obj = nullptr;  // Using nullptr directly in pushBack is a compile time error.
		EXPECT_THROW(vec.pushBack(obj), std::invalid_argument);
	}
}  // namespace pcpp
