#include "../TestDefinition.h"

#include "StopToken.h"

PTF_TEST_CASE(TestStopToken)
{
	using pcpp::internal::NoStopStateTag;
	using pcpp::internal::StopToken;
	using pcpp::internal::StopTokenSource;

	{
		// A stop token source without a shared state should not be able to request a stop.
		StopTokenSource stopTokenSource{ NoStopStateTag{} };

		PTF_ASSERT_FALSE(stopTokenSource.stopPossible());
		PTF_ASSERT_FALSE(stopTokenSource.stopRequested());
		PTF_ASSERT_FALSE(stopTokenSource.requestStop());

		// A stop token source without a shared state should generate an empty stop token.
		StopToken stopToken = stopTokenSource.getToken();

		PTF_ASSERT_FALSE(stopToken.stopRequested());
		PTF_ASSERT_FALSE(stopTokenSource.stopPossible());
	}

	{
		// A default constructed stop token source should have a shared state and not have a stop requested.
		StopTokenSource stopTokenSource;

		PTF_ASSERT_TRUE(stopTokenSource.stopPossible());
		PTF_ASSERT_FALSE(stopTokenSource.stopRequested());

		// A stop token source with a shared state should generate a stop token that reflects the state of the source.
		StopToken stopToken = stopTokenSource.getToken();
		PTF_ASSERT_TRUE(stopToken.stopPossible());
		PTF_ASSERT_FALSE(stopToken.stopRequested());

		// Request a stop and check if the stop token reflects the change.
		PTF_ASSERT_TRUE(stopTokenSource.requestStop());
		PTF_ASSERT_TRUE(stopTokenSource.stopRequested());
		PTF_ASSERT_TRUE(stopToken.stopRequested());

		// Requesting a stop again should not change the state
		PTF_ASSERT_FALSE(stopTokenSource.requestStop());
		PTF_ASSERT_TRUE(stopTokenSource.stopRequested());
		PTF_ASSERT_TRUE(stopToken.stopRequested());

		// Creating a new stop token should reflect the state of the source.
		StopToken stopToken2 = stopTokenSource.getToken();
		PTF_ASSERT_TRUE(stopToken2.stopRequested());
	}
}