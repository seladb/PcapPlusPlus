#include <array>
#include <algorithm>
#include <memory>
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "MemoryLeakDetectorFixture.hpp"

#include "PointerVector.h"

namespace pcpp
{
	class PointerVectorTest : public MemoryLeakDetectorTest
	{
	};

	TEST_F(PointerVectorTest, PointerVectorBasics)
	{
		PointerVector<int> pVector;
		PointerVector<int> const& cpVector = pVector;
		EXPECT_EQ(pVector.size(), 0);

		pVector.pushBack(new int(1));
		EXPECT_EQ(pVector.size(), 1);

		EXPECT_THROW(pVector.pushBack(static_cast<int*>(nullptr)), std::invalid_argument);
		EXPECT_THROW(pVector.pushBack(std::unique_ptr<int>()), std::invalid_argument);

		int* atIdx0 = pVector.at(0);
		ASSERT_NE(atIdx0, nullptr);
		EXPECT_EQ(*atIdx0, 1);

		int const* cAtIdx0 = cpVector.at(0);
		ASSERT_NE(cAtIdx0, nullptr);
		EXPECT_EQ(*cAtIdx0, 1);

		pVector.pushBack(std::unique_ptr<int>(new int(2)));
		EXPECT_EQ(pVector.size(), 2);

		{
			int* atFront = pVector.front();
			ASSERT_NE(atFront, nullptr);
			EXPECT_EQ(*atFront, 1);

			int const* cAtFront = cpVector.front();
			ASSERT_NE(cAtFront, nullptr);
			EXPECT_EQ(*cAtFront, 1);

			int* atBack = pVector.back();
			ASSERT_NE(atBack, nullptr);
			EXPECT_EQ(*atBack, 2);

			int const* cAtBack = cpVector.back();
			ASSERT_NE(cAtBack, nullptr);
			EXPECT_EQ(*cAtBack, 2);
		}

		{
			auto itBegin = pVector.begin();
			auto itEnd = pVector.end();

			EXPECT_EQ(std::distance(itBegin, itEnd), 2);
			EXPECT_EQ(**itBegin, 1);
			EXPECT_EQ(**std::next(itBegin), 2);
		}

		{
			std::unique_ptr<int> p = pVector.getAndDetach(1);
			EXPECT_EQ(*p, 2);
			EXPECT_EQ(pVector.size(), 1);
		}

		PointerVector<int> pVectorCopy = pVector;
		EXPECT_EQ(pVectorCopy.size(), pVector.size());
		EXPECT_NE(pVectorCopy.at(0), pVector.at(0));
		EXPECT_EQ(*pVectorCopy.at(0), *pVector.at(0));

		{
			PointerVector<int> pVectorMove = std::move(pVector);
			EXPECT_EQ(pVector.size(), 0);
			EXPECT_EQ(pVectorMove.size(), 1);
			EXPECT_EQ(*pVectorMove.at(0), 1);

			pVector = std::move(pVectorMove);
			ASSERT_EQ(pVector.size(), 1);
		}

		pVectorCopy.clear();
		EXPECT_EQ(pVectorCopy.size(), 0);
		EXPECT_EQ(pVector.size(), 1);

		pVector.pushBack(new int(3));
		EXPECT_EQ(pVector.size(), 2);

		{
			int* removed = pVector.getAndRemoveFromVector(pVector.begin());
			EXPECT_EQ(*removed, 1);
			EXPECT_EQ(pVector.size(), 1);
			EXPECT_EQ(*pVector.front(), 3);
			delete removed;
		}

		pVector.erase(pVector.begin());
		EXPECT_EQ(pVector.size(), 0);

		pVector.pushBack(new int(4));
		pVector.pushBack(new int(5));
		EXPECT_EQ(pVector.size(), 2);

		{
			std::unique_ptr<int> p = pVector.getAndDetach(pVector.begin());
			ASSERT_NE(p, nullptr);
			EXPECT_EQ(*p, 4);
			EXPECT_EQ(pVector.size(), 1);
		}
	}
}  // namespace pcpp
