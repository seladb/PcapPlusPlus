#ifndef PCPP_TEST_FRAMEWORK_RUN
#define PCPP_TEST_FRAMEWORK_RUN

#include <vector>
#include <string>
#include <sstream>
#include "../../3rdParty/MemPlumber/MemPlumber/memplumber.h"
#include "PcppTestFrameworkCommon.h"

static void __ptfSplitString(const std::string& input, std::vector<std::string>& result)
{
	std::istringstream ss(input);
	std::string token;

	while(std::getline(ss, token, ';'))
	{
		result.push_back(token);
	}
}

static bool __ptfCheckTags(std::string tagSet, std::string tagSetToCompareWith, bool emptyTagSetMeansAll)
{
	std::vector<std::string> tagSetVec, tagSetToCompareWithVec;

	if (tagSetToCompareWith == "")
	{
		return emptyTagSetMeansAll;
	}

	__ptfSplitString(tagSet, tagSetVec);
	__ptfSplitString(tagSetToCompareWith, tagSetToCompareWithVec);

	for (std::vector<std::string>::const_iterator tagSetToCompareWithIter = tagSetToCompareWithVec.begin(); tagSetToCompareWithIter != tagSetToCompareWithVec.end(); tagSetToCompareWithIter++)
	{
		for (std::vector<std::string>::const_iterator tagSetIter = tagSetVec.begin(); tagSetIter != tagSetVec.end(); tagSetIter++)
		{
			if (*tagSetIter == *tagSetToCompareWithIter)
			{
				return true;
			}
		}
	}

	return false;
}

#define PTF_START_RUNNING_TESTS(userTags, configTags) \
	bool allTestsPassed = true; \
	int testsPassed = 0; \
	int testsFailed = 0; \
	int testsSkipped = 0; \
	std::string userTagsToRun = userTags; \
	std::string configTagsToRun = configTags; \
	printf("Start running tests...\n\n")

#define PTF_RUN_TEST(TestName, tags) \
	std::string TestName##_tags = std::string(#TestName) + ";" + tags; \
	int TestName##_result = PTF_RESULT_PASSED; \
	if (!__ptfCheckTags(TestName##_tags, userTagsToRun, true)) \
	{ \
		if (showSkippedTests) \
		{ \
			printf("%-30s: SKIPPED (tags don't match)\n", #TestName ""); \
		} \
		TestName##_result = PTF_RESULT_SKIPPED; \
	} \
	else \
	{ \
		bool runMemLeakCheck = !__ptfCheckTags("skip_mem_leak_check", configTagsToRun, false) && !__ptfCheckTags(TestName##_tags, "skip_mem_leak_check", false); \
		if (runMemLeakCheck) \
		{ \
			bool memAllocVerbose = __ptfCheckTags("mem_leak_check_verbose", configTagsToRun, false); \
			MemPlumber::start(memAllocVerbose); \
		} \
		TestName(TestName##_result, verboseMode, showSkippedTests); \
		if (runMemLeakCheck) \
		{ \
			if (TestName##_result != PTF_RESULT_PASSED) \
			{ \
				MemPlumber::stopAndFreeAllMemory(); \
			} \
			else \
			{ \
				size_t memLeakCount = 0; \
				uint64_t memLeakSize = 0; \
				MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true); \
				MemPlumber::stopAndFreeAllMemory(); \
				if (memLeakCount > 0 || memLeakSize > 0) \
				{ \
					TestName##_result = PTF_RESULT_FAILED; \
					printf("%-30s: FAILED. Memory leak found! %d objects and %d[bytes] leaked\n", #TestName, (int)memLeakCount, (int)memLeakSize); \
				} \
			} \
		} \
		if (TestName##_result == PTF_RESULT_PASSED) \
		{ \
			printf("%-30s: PASSED\n", #TestName ""); \
		} \
	} \
	if (TestName##_result == PTF_RESULT_PASSED) testsPassed++; \
	if (TestName##_result == PTF_RESULT_FAILED) testsFailed++; \
	if (TestName##_result == PTF_RESULT_SKIPPED) testsSkipped++; \
	allTestsPassed &= (TestName##_result != PTF_RESULT_FAILED)


#define PTF_END_RUNNING_TESTS \
	if (allTestsPassed) \
	{ \
		printf("\nALL TESTS PASSED!!\n"); \
		printf("Test cases: %d, Passed: %d, Failed: %d, Skipped: %d\n", testsPassed + testsFailed + testsSkipped, testsPassed, testsFailed, testsSkipped); \
		return 0; \
	} \
	else \
	{ \
		printf("\nNOT ALL TESTS PASSED!!\n"); \
		printf("Test cases: %d, Passed: %d, Failed: %d, Skipped: %d\n", testsPassed + testsFailed + testsSkipped, testsPassed, testsFailed, testsSkipped); \
		return 1; \
	}

static bool verboseMode = false;

#define PTF_SET_VERBOSE_MODE(flag) verboseMode = flag

static bool showSkippedTests = false;

#define PTF_SHOW_SKIPPED_TESTS(flag) showSkippedTests = flag

#endif // PCPP_TEST_FRAMEWORK_RUN