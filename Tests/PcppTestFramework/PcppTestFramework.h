#ifndef PCPP_TEST_FRAMEWORK
#define PCPP_TEST_FRAMEWORK

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

bool __ptfCheckTags(std::string testTags, std::string configTags)
{
    std::vector<std::string> testTagsVec, configTagsVec;

    if (configTags == "")
    {
        return true;
    }
    
    __ptfSplitString(testTags, testTagsVec);
    __ptfSplitString(configTags, configTagsVec);

    for (std::vector<std::string>::const_iterator configTagIter = configTagsVec.begin(); configTagIter != configTagsVec.end(); configTagIter++)
    {
        for (std::vector<std::string>::const_iterator testTagIter = testTagsVec.begin(); testTagIter != testTagsVec.end(); testTagIter++)
        {
            if (*testTagIter == *configTagIter)
            {
                return true;
            }
        }
    }

    return false;
}

#define PTF_TEST_CASE(TestName) void TestName(bool& result)

#define PTF_ASSERT(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		result = false; \
        return; \
	}

#define PTF_ASSERT_AND_RUN_COMMAND(exp, command, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		command; \
		result = false; \
        return; \
	}

#define PTF_TRY(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%s, NON-CRITICAL: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
	}

#define PTF_START_RUNNING_TESTS(tags) \
    bool allTestsPassed = true; \
    std::string tagsToRun = tags; \
    printf("Start running tests...\n\n")

#define PTF_RUN_TEST(TestName, tags) \
    std::string TestName##_tags = std::string(#TestName) + ";" + tags; \
    bool TestName##_result = true; \
    if (!__ptfCheckTags(TestName##_tags, tagsToRun)) \
    { \
        printf("%-30s: SKIPPED (tags not match)\n", #TestName ""); \
    } \
    else \
    { \
        TestName(TestName##_result); \
        if (TestName##_result) \
        { \
            printf("%-30s: PASSED\n", #TestName ""); \
        } \
    } \
    allTestsPassed &= TestName##_result

#define PTF_SKIP_TEST(TestName, why) \
    printf("%-30s: SKIPPED (%s)\n", #TestName "", why); \

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