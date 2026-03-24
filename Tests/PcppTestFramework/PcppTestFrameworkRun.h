#pragma once

#include <algorithm>
#include <vector>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <functional>
#include "memplumber.h"
#include "PcppTestFrameworkCommon.h"

static bool verboseMode = false;
static bool showSkippedTests = false;

namespace ptf
{
	static void ptfSplitString(const std::string& input, std::vector<std::string>& result)
	{
		std::istringstream ss(input);
		std::string token;

		while (std::getline(ss, token, ';'))
		{
			result.push_back(token);
		}
	}

	static bool ptfCheckTags(const std::string& tagSet, const std::string& tagSetToCompareWith,
	                         bool emptyTagSetMeansAll)
	{
		std::vector<std::string> tagSetVec, tagSetToCompareWithVec;

		if (tagSetToCompareWith == "")
		{
			return emptyTagSetMeansAll;
		}

		ptfSplitString(tagSet, tagSetVec);
		ptfSplitString(tagSetToCompareWith, tagSetToCompareWithVec);

		for (const auto& tagSetToCompareWithIter : tagSetToCompareWithVec)
		{
			if (std::any_of(tagSetVec.begin(), tagSetVec.end(), [tagSetToCompareWithIter](const std::string& val) {
				    return val == tagSetToCompareWithIter;
			    }))
			{
				return true;
			}
		}

		return false;
	}

	class TestRunner
	{
	public:
		using TestFunc = std::function<void(int& result, bool verboseMode, bool showSkippedTests)>;

		TestRunner(std::string userIncludeTags, std::string userExcludeTags, std::string configTags)
		    : m_UserIncludeTags(std::move(userIncludeTags)), m_UserExcludeTags(std::move(userExcludeTags)),
		      m_ConfigTagsToRun(std::move(configTags))
		{}

		int runTest(TestFunc testFn, std::string const& testName, std::string const& additionalTestTags)
		{
			std::string allTestTags = testName + ";" + additionalTestTags;
			int result = PTF_RESULT_PASSED;

			if (!ptfCheckTags(allTestTags, m_UserIncludeTags, true) ||
			    ptfCheckTags(allTestTags, m_UserExcludeTags, false))
			{
				if (showSkippedTests)
				{
					std::cout << std::left << std::setw(35) << testName << ": SKIPPED (tags don't match)" << std::endl;
				}
				result = PTF_RESULT_SKIPPED;
			}
			else
			{
				bool runMemLeakCheck = !ptfCheckTags("skip_mem_leak_check", m_ConfigTagsToRun, false) &&
				                       !ptfCheckTags(allTestTags, "skip_mem_leak_check", false);
				if (runMemLeakCheck)
				{
					bool memAllocVerbose = ptfCheckTags("mem_leak_check_verbose", m_ConfigTagsToRun, false);
					MemPlumber::start(memAllocVerbose);
				}
				try
				{
					testFn(result, verboseMode, showSkippedTests);
				}
				catch (std::exception const& e)
				{
					result = PTF_RESULT_FAILED;
					std::cout << std::left << std::setw(35) << testName << ": FAILED. Unhandled exception occurred! "
					          << "Exception: " << e.what() << std::endl;
				}
				if (runMemLeakCheck)
				{
					if (result != PTF_RESULT_PASSED)
					{
						MemPlumber::stopAndFreeAllMemory();
					}
					else
					{
						size_t memLeakCount = 0;
						uint64_t memLeakSize = 0;
						MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true);
						MemPlumber::stopAndFreeAllMemory();
						if (memLeakCount > 0 || memLeakSize > 0)
						{
							result = PTF_RESULT_FAILED;
							std::cout << std::left << std::setw(35) << testName << ": FAILED. Memory leak found! "
							          << memLeakCount << " objects and " << memLeakSize << "[bytes] leaked"
							          << std::endl;
						}
					}
				}
				if (result == PTF_RESULT_PASSED)
				{
					std::cout << std::left << std::setw(35) << testName << ": PASSED" << std::endl;
				}
			}
			if (result == PTF_RESULT_PASSED)
				testsPassed++;
			if (result == PTF_RESULT_FAILED)
				testsFailed++;
			if (result == PTF_RESULT_SKIPPED)
				testsSkipped++;

			return result;
		}

		int finalizeResults()
		{
			std::string message = (!hasFailures() ? "ALL TESTS PASSED!!" : "NOT ALL TESTS PASSED!!");
			std::cout << std::endl
			          << message << std::endl
			          << "Test cases: " << testsPassed + testsFailed + testsSkipped << ", "
			          << "Passed: " << testsPassed << ", "
			          << "Failed: " << testsFailed << ", "
			          << "Skipped: " << testsSkipped << std::endl;
			return hasFailures();
		}

	private:
		bool hasFailures(bool ignoreSkipped = true) const
		{
			if (ignoreSkipped)
				return testsFailed != 0;
			return testsFailed + testsSkipped != 0;
		}

		std::string m_UserIncludeTags;
		std::string m_UserExcludeTags;
		std::string m_ConfigTagsToRun;
		int testsPassed = 0;
		int testsFailed = 0;
		int testsSkipped = 0;
	};
}  // namespace ptf

#define PTF_START_RUNNING_TESTS(userIncludeTags, userExcludeTags, configTags)                                          \
	ptf::TestRunner testRunner(userIncludeTags, userExcludeTags, configTags);                                          \
	std::cout << "Start running tests..." << std::endl << std::endl

#define PTF_RUN_TEST(TestName, tags) testRunner.runTest(TestName, #TestName, tags)

#define PTF_END_RUNNING_TESTS return testRunner.finalizeResults();

#define PTF_SET_VERBOSE_MODE(flag) verboseMode = flag
#define PTF_SHOW_SKIPPED_TESTS(flag) showSkippedTests = flag
