#ifndef PCPP_TEST_FRAMEWORK
#define PCPP_TEST_FRAMEWORK

#include <stdio.h>
#include "../../3rdParty/MemPlumber/MemPlumber/memplumber.h"
#include "PcppTestFrameworkCommon.h"

#ifdef PCAPPP_MINGW_ENV
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif // PCAPPP_MINGW_ENV

#define int_PTF_PRINT_FORMAT "%d"
#define int_PTF_PRINT_TYPE(val) (int)(val)

#define u8_PTF_PRINT_FORMAT "%u"
#define u8_PTF_PRINT_TYPE(val) (uint8_t)(val)

#define u16_PTF_PRINT_FORMAT "%u"
#define u16_PTF_PRINT_TYPE(val) (uint16_t)(val)

#define u32_PTF_PRINT_FORMAT "%u"
#define u32_PTF_PRINT_TYPE(val) (uint32_t)(val)

#if defined(PCAPPP_MINGW_ENV) || defined(_MSC_VER)
#define u64_PTF_PRINT_FORMAT "%I64u"
#elif __APPLE__
#define u64_PTF_PRINT_FORMAT "%llu"
#else
#define u64_PTF_PRINT_FORMAT "%lu"
#endif
#define u64_PTF_PRINT_TYPE(val) (uint64_t)(val)

#ifdef PCAPPP_MINGW_ENV
#define size_PTF_PRINT_FORMAT "%u"
#else
#define size_PTF_PRINT_FORMAT "%zu"
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


#define PTF_TEST_CASE(TestName) void TestName(int& ptfResult, bool printVerbose, bool showSkipped)

#define PTF_INTERNAL_RUN(TestName) \
	TestName(ptfResult, printVerbose, showSkipped); \
	if (ptfResult == PTF_RESULT_FAILED) { \
		printf("%-30s: FAILED (%s:%d). Internal test '%s' failed\n", __FUNCTION__, __FILE__, __LINE__, #TestName); \
		return; \
	} \
	else { \
		ptfResult = PTF_RESULT_PASSED; \
	}

#define PTF_IS_VERBOSE_MODE printVerbose

#define PTF_TEST_CASE_PASSED \
	ptfResult = PTF_RESULT_PASSED; \
	return

#define PTF_ASSERT_EQUAL(actual, expected, type) \
	if (actual != expected) { \
		printf("%-30s: FAILED (%s:%d). assert equal failed: actual: " type##_PTF_PRINT_FORMAT " != expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_NOT_EQUAL(actual, expected, type) \
	if (actual == expected) { \
		printf("%-30s: FAILED (%s:%d). assert not equal failed: actual: " type##_PTF_PRINT_FORMAT " == expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_GREATER_THAN(actual, expected, type) \
	if (actual <= expected) { \
		printf("%-30s: FAILED (%s:%d). assert greater than failed: actual: " type##_PTF_PRINT_FORMAT " <= expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_GREATER_OR_EQUAL_THAN(actual, expected, type) \
	if (actual < expected) { \
		printf("%-30s: FAILED (%s:%d). assert greater or equal than failed: actual: " type##_PTF_PRINT_FORMAT " < expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_LOWER_THAN(actual, expected, type) \
	if (actual >= expected) { \
		printf("%-30s: FAILED (%s:%d). assert lower than failed: actual: " type##_PTF_PRINT_FORMAT " >= expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_LOWER_OR_EQUAL_THAN(actual, expected, type) \
	if (actual > expected) { \
		printf("%-30s: FAILED (%s:%d). assert lower or equal than failed: actual: " type##_PTF_PRINT_FORMAT " > expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}


#define PTF_ASSERT_BUF_COMPARE(buf1, buf2, size) \
	if (memcmp(buf1, buf2, size) != 0) { \
		printf("%-30s: FAILED (%s:%d). assert buffer compare failed: %s != %s\n", __FUNCTION__, __FILE__, __LINE__, #buf1, #buf2); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_TRUE(exp) \
	if (!(exp)) { \
		printf("%-30s: FAILED (%s:%d). assert true failed: %s\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_FALSE(exp) \
	if (exp) { \
		printf("%-30s: FAILED (%s:%d). assert false failed: %s\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_NOT_NULL(exp) \
	if ((exp) == NULL) { \
		printf("%-30s: FAILED (%s:%d). assert not null failed: %s is NULL\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_NULL(exp) \
	if ((exp) != NULL) { \
		printf("%-30s: FAILED (%s:%d). assert null failed: %s is not NULL\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_NON_CRITICAL_EQUAL(actual, expected, type) \
	if (actual != expected) { \
		printf("%s: NON-CRITICAL: (%s:%d). actual: " type##_PTF_PRINT_FORMAT " != expected: " type##_PTF_PRINT_FORMAT "\n", __FUNCTION__, __FILE__, __LINE__, type##_PTF_PRINT_TYPE(actual), type##_PTF_PRINT_TYPE(expected)); \
	}

#define PTF_NON_CRITICAL_TRUE(exp) \
	if (!exp) { \
		printf("%s: NON-CRITICAL: (%s:%d). expression is not true: %s\n", __FUNCTION__, __FILE__, __LINE__, #exp); \
	}

#define PTF_PRINT_VERBOSE(format, ...) do { \
		if(printVerbose) { \
			printf("%-30s: [VERBOSE] " format "\n", __FUNCTION__, ## __VA_ARGS__); \
		} \
} while(0)

#define PTF_SKIP_TEST(why) \
	if (showSkipped) { \
		printf("%-30s: SKIPPED (%s)\n", __FUNCTION__, why); \
	} \
	ptfResult = PTF_RESULT_SKIPPED; \
	return

#endif // PCPP_TEST_FRAMEWORK