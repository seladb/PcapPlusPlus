#ifndef PCPP_TEST_FRAMEWORK_RUN
#define PCPP_TEST_FRAMEWORK_RUN

#include <vector>
#include <string>
#include <sstream>
#include "../../3rdParty/MemPlumber/MemPlumber/memplumber.h"

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
    std::string userTagsToRun = userTags; \
    std::string configTagsToRun = configTags; \
    printf("Start running tests...\n\n")

#define PTF_RUN_TEST(TestName, tags) \
    std::string TestName##_tags = std::string(#TestName) + ";" + tags; \
    int TestName##_result = 1; \
    if (!__ptfCheckTags(TestName##_tags, userTagsToRun, true)) \
    { \
        printf("%-30s: SKIPPED (tags don't match)\n", #TestName ""); \
    } \
    else \
    { \
        bool runMemLeakCheck = !__ptfCheckTags("skip_mem_leak_check", configTagsToRun, false) && !__ptfCheckTags(TestName##_tags, "skip_mem_leak_check", false); \
        if (runMemLeakCheck) \
        { \
            bool memAllocVerbose = __ptfCheckTags("mem_leak_check_verbose", configTagsToRun, false); \
            MemPlumber::start(memAllocVerbose); \
        } \
        TestName(TestName##_result, verboseMode); \
        if (runMemLeakCheck) \
        { \
            size_t memLeakCount = 0; \
            uint64_t memLeakSize = 0; \
            MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true); \
            MemPlumber::stopAndFreeAllMemory(); \
            if (memLeakCount > 0 || memLeakSize > 0) \
            { \
                TestName##_result = 0; \
                printf("%-30s: FAILED. Memory leak found! %d objects and %d[bytes] leaked\n", #TestName, (int)memLeakCount, (int)memLeakSize); \
            } \
        } \
        if (TestName##_result == 1) \
        { \
            printf("%-30s: PASSED\n", #TestName ""); \
        } \
    } \
    allTestsPassed &= (TestName##_result != 0)

#define PTF_SKIP_TEST(why) \
    printf("%-30s: SKIPPED (%s)\n", __FUNCTION__, why); \
    ptfResult = -1; \
    return

#define PTF_END_RUNNING_TESTS \
    if (allTestsPassed) \
    { \
        printf("ALL TESTS PASSED!!\n\n\n"); \
        return 0; \
    } \
    else \
    { \
        printf("NOT ALL TESTS PASSED!!\n\n\n"); \
        return 1; \
    }

static bool verboseMode = false;

#define PTF_SET_VERBOSE_MODE(flag) verboseMode = flag

#define PTF_IS_VERBOSE_MODE verboseMode

#endif // PCPP_TEST_FRAMEWORK_RUN