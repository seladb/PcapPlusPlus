#include "pch.h"

#include <algorithm>
#include <stdexcept>

#include "PointerVector.h"

namespace pcpp
{
	class TestObject
	{
	public:
		explicit TestObject(int value) : m_Value(value)
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

	TEST(PointerVectorTest, DefaultConstructor)
	{
		pcpp::PointerVector<TestObject> vec;
		EXPECT_EQ(vec.size(), 0);
	}

	TEST(PointerVectorTest, CopyConstructor)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		pcpp::PointerVector<TestObject> copyVec(vec);
		EXPECT_EQ(copyVec.size(), 2);
		EXPECT_EQ(copyVec.at(0)->getValue(), 1);
		EXPECT_EQ(copyVec.at(1)->getValue(), 2);
	}

	TEST(PointerVectorTest, MoveConstructor)
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

	TEST(PointerVectorTest, CopyAssignmentOperator)
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

	TEST(PointerVectorTest, MoveAssignmentOperator)
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

	TEST(PointerVectorTest, PushBack)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.size(), 2);
		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST(PointerVectorTest, PushBackUniquePtr)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(std::unique_ptr<TestObject>(new TestObject(1)));
		vec.pushBack(std::unique_ptr<TestObject>(new TestObject(2)));

		EXPECT_EQ(vec.size(), 2);
		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST(PointerVectorTest, Clear)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));
		vec.clear();

		EXPECT_EQ(vec.size(), 0);
	}

	TEST(PointerVectorTest, Erase)
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

	TEST(PointerVectorTest, GetAndDetach)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		auto obj = vec.getAndDetach(0);
		EXPECT_EQ(obj->getValue(), 1);
		EXPECT_EQ(vec.size(), 1);
		EXPECT_EQ(vec.at(0)->getValue(), 2);
	}

	TEST(PointerVectorTest, At)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.at(0)->getValue(), 1);
		EXPECT_EQ(vec.at(1)->getValue(), 2);
	}

	TEST(PointerVectorTest, FrontBack)
	{
		pcpp::PointerVector<TestObject> vec;
		vec.pushBack(new TestObject(1));
		vec.pushBack(new TestObject(2));

		EXPECT_EQ(vec.front()->getValue(), 1);
		EXPECT_EQ(vec.back()->getValue(), 2);
	}

	TEST(PointerVectorTest, PushBackNullptr)
	{
		pcpp::PointerVector<TestObject> vec;
		TestObject* obj = nullptr;  // Using nullptr directly in pushBack is a compile time error.
		EXPECT_THROW(vec.pushBack(obj), std::invalid_argument);
	}
}  // namespace pcpp
