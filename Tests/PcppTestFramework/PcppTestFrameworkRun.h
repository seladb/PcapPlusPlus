#pragma once

#include <algorithm>
#include <vector>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include "memplumber.h"
#include "PcppTestFrameworkCommon.h"

static void __ptfSplitString(const std::string& input, std::vector<std::string>& result)
{
	std::istringstream ss(input);
	std::string token;

	while (std::getline(ss, token, ';'))
	{
		result.push_back(token);
	}
}

static bool __ptfCheckTags(const std::string& tagSet, const std::string& tagSetToCompareWith, bool emptyTagSetMeansAll)
{
	std::vector<std::string> tagSetVec, tagSetToCompareWithVec;

	if (tagSetToCompareWith == "")
	{
		return emptyTagSetMeansAll;
	}

	__ptfSplitString(tagSet, tagSetVec);
	__ptfSplitString(tagSetToCompareWith, tagSetToCompareWithVec);

	for (const auto& tagSetToCompareWithIter : tagSetToCompareWithVec)
	{
		if (std::any_of(tagSetVec.begin(), tagSetVec.end(),
		                [tagSetToCompareWithIter](const std::string& val) { return val == tagSetToCompareWithIter; }))
		{
			return true;
		}
	}

	return false;
}

#define PTF_START_RUNNING_TESTS(userIncludeTags, userExcludeTags, configTags)                                          \
	bool allTestsPassed = true;                                                                                        \
	int testsPassed = 0;                                                                                               \
	int testsFailed = 0;                                                                                               \
	int testsSkipped = 0;                                                                                              \
	std::string ptfUserIncludeTags = userIncludeTags;                                                                  \
	std::string ptfUserExcludeTags = userExcludeTags;                                                                  \
	std::string configTagsToRun = configTags;                                                                          \
	std::cout << "Start running tests..." << std::endl << std::endl

#define PTF_RUN_TEST(TestName, tags)                                                                                   \
	std::string TestName##_tags = std::string(#TestName) + ";" + tags;                                                 \
	int TestName##_result = PTF_RESULT_PASSED;                                                                         \
	if (!__ptfCheckTags(TestName##_tags, ptfUserIncludeTags, true) ||                                                  \
	    __ptfCheckTags(TestName##_tags, ptfUserExcludeTags, false))                                                    \
	{                                                                                                                  \
		if (showSkippedTests)                                                                                          \
		{                                                                                                              \
			std::cout << std::left << std::setw(35) << #TestName << ": SKIPPED (tags don't match)" << std::endl;       \
		}                                                                                                              \
		TestName##_result = PTF_RESULT_SKIPPED;                                                                        \
	}                                                                                                                  \
	else                                                                                                               \
	{                                                                                                                  \
		bool runMemLeakCheck = !__ptfCheckTags("skip_mem_leak_check", configTagsToRun, false) &&                       \
		                       !__ptfCheckTags(TestName##_tags, "skip_mem_leak_check", false);                         \
		if (runMemLeakCheck)                                                                                           \
		{                                                                                                              \
			bool memAllocVerbose = __ptfCheckTags("mem_leak_check_verbose", configTagsToRun, false);                   \
			MemPlumber::start(memAllocVerbose);                                                                        \
		}                                                                                                              \
		try                                                                                                            \
		{                                                                                                              \
			TestName(TestName##_result, verboseMode, showSkippedTests);                                                \
		}                                                                                                              \
		catch (std::exception const& e)                                                                                \
		{                                                                                                              \
			TestName##_result = PTF_RESULT_FAILED;                                                                     \
			std::cout << std::left << std::setw(35) << #TestName << ": FAILED. Unhandled exception occurred! "         \
			          << "Exception: " << e.what() << std::endl;                                                       \
		}                                                                                                              \
		if (runMemLeakCheck)                                                                                           \
		{                                                                                                              \
			if (TestName##_result != PTF_RESULT_PASSED)                                                                \
			{                                                                                                          \
				MemPlumber::stopAndFreeAllMemory();                                                                    \
			}                                                                                                          \
			else                                                                                                       \
			{                                                                                                          \
				size_t memLeakCount = 0;                                                                               \
				uint64_t memLeakSize = 0;                                                                              \
				MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true);                                             \
				MemPlumber::stopAndFreeAllMemory();                                                                    \
				if (memLeakCount > 0 || memLeakSize > 0)                                                               \
				{                                                                                                      \
					TestName##_result = PTF_RESULT_FAILED;                                                             \
					std::cout << std::left << std::setw(35) << #TestName << ": FAILED. Memory leak found! "            \
					          << memLeakCount << " objects and " << memLeakSize << "[bytes] leaked" << std::endl;      \
				}                                                                                                      \
			}                                                                                                          \
		}                                                                                                              \
		if (TestName##_result == PTF_RESULT_PASSED)                                                                    \
		{                                                                                                              \
			std::cout << std::left << std::setw(35) << #TestName << ": PASSED" << std::endl;                           \
		}                                                                                                              \
	}                                                                                                                  \
	if (TestName##_result == PTF_RESULT_PASSED)                                                                        \
		testsPassed++;                                                                                                 \
	if (TestName##_result == PTF_RESULT_FAILED)                                                                        \
		testsFailed++;                                                                                                 \
	if (TestName##_result == PTF_RESULT_SKIPPED)                                                                       \
		testsSkipped++;                                                                                                \
	allTestsPassed &= (TestName##_result != PTF_RESULT_FAILED)

#define PTF_END_RUNNING_TESTS                                                                                          \
	std::string message = (allTestsPassed ? "ALL TESTS PASSED!!" : "NOT ALL TESTS PASSED!!");                          \
	std::cout << std::endl                                                                                             \
	          << message << std::endl                                                                                  \
	          << "Test cases: " << testsPassed + testsFailed + testsSkipped << ", "                                    \
	          << "Passed: " << testsPassed << ", "                                                                     \
	          << "Failed: " << testsFailed << ", "                                                                     \
	          << "Skipped: " << testsSkipped << std::endl;                                                             \
	return (allTestsPassed ? 0 : 1);

static bool verboseMode = false;

#define PTF_SET_VERBOSE_MODE(flag) verboseMode = flag

static bool showSkippedTests = false;

#define PTF_SHOW_SKIPPED_TESTS(flag) showSkippedTests = flag
