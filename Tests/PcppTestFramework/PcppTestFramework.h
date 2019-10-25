#ifndef PCPP_TEST_FRAMEWORK
#define PCPP_TEST_FRAMEWORK

#include "memplumber.h"
#include <string>
#include <vector>
#include <sstream>

void __ptfSplitString(const std::string& input, std::vector<std::string>& result)
{
    std::istringstream ss(input);
    std::string token;

	while(std::getline(ss, token, ';')) 
    {
		result.push_back(token);
	}    
}

bool __ptfCheckTags(std::string tagSet, std::string tagSetToCompareWith, bool emptyTagSetMeansAll)
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

#define int_PTF_PRINT_FORMAT "%d"
#define int_PTF_PRINT_TYPE(val) (int)(val)

#define u8_PTF_PRINT_FORMAT "%u"
#define u8_PTF_PRINT_TYPE(val) (uint8_t)(val)

#define u16_PTF_PRINT_FORMAT "%u"
#define u16_PTF_PRINT_TYPE(val) (uint16_t)(val)

#define u32_PTF_PRINT_FORMAT "%u"
#define u32_PTF_PRINT_TYPE(val) (uint32_t)(val)

#ifndef PCAPPP_MINGW_ENV
#define size_PTF_PRINT_FORMAT "%zu"
#else
#define size_PTF_PRINT_FORMAT "%u"
#endif
#define size_PTF_PRINT_TYPE(val) (size_t)(val)

#define string_PTF_PRINT_FORMAT "%s"
#define string_PTF_PRINT_TYPE(val) std::string(val).c_str()

#define hex_PTF_PRINT_FORMAT "0x%X"
#define hex_PTF_PRINT_TYPE(val) val 

#define enum_PTF_PRINT_FORMAT "%d"
#define enum_PTF_PRINT_TYPE(val) (int)(val)

#define object_PTF_PRINT_FORMAT "%s"
#define object_PTF_PRINT_TYPE(val) #val


#define PTF_TEST_CASE(TestName) void TestName(int& ptfResult)

#define PTF_TEST_CASE_PASSED \
    ptfResult = 1; \
    return

#define PTF_ASSERT(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		ptfResult = 0; \
        return; \
	}

#define PTF_ASSERT_AND_RUN_COMMAND(exp, command, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		command; \
		ptfResult = 0; \
        return; \
	}

#define PTF_ASSERT_EQUAL(actual, expected, type) \
    if (actual != expected) { \
		printf("%-30s: FAILED (line: %d). assert equal failed: actual: " type##_PTF_PRINT_FORMAT " != expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_BUF_COMPARE(buf1, buf2, size) \
    if (memcmp(buf1, buf2, size) != 0) { \
		printf("%-30s: FAILED (line: %d). assert buffer compare failed: %s != %s\n", __FUNCTION__, __LINE__, #buf1, #buf2); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_TRUE(exp) \
    if (!(exp)) { \
		printf("%-30s: FAILED (line: %d). assert true failed: %s\n", __FUNCTION__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_FALSE(exp) \
    if (exp) { \
		printf("%-30s: FAILED (line: %d). assert false failed: %s\n", __FUNCTION__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }


#define PTF_ASSERT_NOT_NULL(exp) \
    if ((exp) == NULL) \
    { \
		printf("%-30s: FAILED (line: %d). assert not null failed: %s is NULL\n", __FUNCTION__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_NULL(exp) \
    if ((exp) != NULL) \
    { \
		printf("%-30s: FAILED (line: %d). assert null failed: %s is NULL\n", __FUNCTION__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_TRY(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%s, NON-CRITICAL: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
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
        TestName(TestName##_result); \
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

bool verboseMode = false;

#define PTF_SET_VERBOSE_MODE(flag) verboseMode = flag

#define PTF_IS_VERBOSE_MODE verboseMode

#define PTF_PRINT_VERBOSE(format, ...) do { \
		if(verboseMode) { \
			printf(format "\n", ## __VA_ARGS__); \
		} \
} while(0)

#endif // PCPP_TEST_FRAMEWORK