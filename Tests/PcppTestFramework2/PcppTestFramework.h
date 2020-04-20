#ifndef PCPP_TEST_FRAMEWORK
#define PCPP_TEST_FRAMEWORK

#include <stdio.h>
#include "../../3rdParty/MemPlumber/MemPlumber/memplumber.h"

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
		printf("%-30s: FAILED (%s:%d). assert equal failed: actual: " type##_PTF_PRINT_FORMAT " != expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_BUF_COMPARE(buf1, buf2, size) \
    if (memcmp(buf1, buf2, size) != 0) { \
		printf("%-30s: FAILED (%s:%d). assert buffer compare failed: %s != %s\n", __FUNCTION__, __FILE__, __LINE__, #buf1, #buf2); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_TRUE(exp) \
    if (!(exp)) { \
		printf("%-30s: FAILED (%s:%d). assert true failed: %s\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_FALSE(exp) \
    if (exp) { \
		printf("%-30s: FAILED (%s:%d). assert false failed: %s\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_NOT_NULL(exp) \
    if ((exp) == NULL) \
    { \
		printf("%-30s: FAILED (%s:%d). assert not null failed: %s is NULL\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_ASSERT_NULL(exp) \
    if ((exp) != NULL) \
    { \
		printf("%-30s: FAILED (%s:%d). assert null failed: %s is NULL\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = 0; \
        return; \
    }

#define PTF_TRY(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%s, NON-CRITICAL: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
	}

#endif // PCPP_TEST_FRAMEWORK