// general test macros

#include <stdio.h>

#define TEST_CASE(TestName) void TestName(bool& result)

#define TEST_ASSERT_EQUAL(actual, expected) \
    if (actual != expected) { \
		printf("%s:%d: FAILED. assert equal failed: actual: %d != expected: %d\n", __FUNCTION__, __LINE__, (int)(actual), (int)(expected)); \
		result = false; \
        return; \
    }

#define START_RUNNING_TESTS bool allTestsPassed = true

#define RUN_TEST(TestName) \
    bool TestName##_result = true; \
    TestName(TestName##_result); \
    if (TestName##_result) { \
        printf("%-30s: PASSED\n", #TestName ""); \
    } \
    allTestsPassed &= TestName##_result

#define SKIP_TEST(TestName, why) \
    printf("%-30s: SKIPPED (%s)\n", #TestName "", why); \

#define END_RUNNING_TESTS \
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

// memplumber specific macros

#ifdef TEST_VERBOSE
#define TEST_VERBOSE_INNER true
#else
#define TEST_VERBOSE_INNER false
#endif //TEST_VERBOSE

#ifdef MEM_CHECK_VERBOSE
#define MEM_CHECK_VERBOSE_INNER true
#else
#define MEM_CHECK_VERBOSE_INNER false
#endif //MEM_CHECK_VERBOSE

#define START_TEST \
    size_t memLeakCount; \
    uint64_t memLeakSize; \
    MemPlumber::start(TEST_VERBOSE_INNER)

#define START_TEST_DUMP_TO_FILE(fileName, append) \
    size_t memLeakCount; \
    uint64_t memLeakSize; \
    MemPlumber::start(true, fileName, append)


#define STOP_TEST MemPlumber::stopAndFreeAllMemory()

#define CHECK_MEM_LEAK(expectedLeakCount, expectedLeakSize) \
    MemPlumber::memLeakCheck(memLeakCount, memLeakSize, MEM_CHECK_VERBOSE_INNER); \
    TEST_ASSERT_EQUAL(memLeakCount, expectedLeakCount); \
    TEST_ASSERT_EQUAL(memLeakSize, expectedLeakSize)
