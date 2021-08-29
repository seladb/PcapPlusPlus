#ifndef PCPP_TEST_FRAMEWORK
#define PCPP_TEST_FRAMEWORK

#include <iomanip>
#include <iostream>
#include "memplumber.h"
#include "PcppTestFrameworkCommon.h"

#define _PTF_PRINT_TYPE(val) val
#define object_PTF_PRINT_TYPE(val) "'" << val.toString() << "'"
#define object_no_str_PTF_PRINT_TYPE(val) "'" << #val << "'"
#define string_PTF_PRINT_TYPE(val) "'" << val << "'"
#define hex_PTF_PRINT_TYPE(val) "0x" << std::hex << val
#define enum_PTF_PRINT_TYPE(val) #val << "[" << val << "]"
#define ptr_PTF_PRINT_TYPE(val) #val << "[" << val << "]"

#define PTF_TEST_CASE(TestName) void TestName(int& ptfResult, bool printVerbose, bool showSkipped)

#define PTF_INTERNAL_RUN(TestName) \
	TestName(ptfResult, printVerbose, showSkipped); \
	if (ptfResult == PTF_RESULT_FAILED) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Internal test '" << #TestName << "' failed" \
		<< std::endl; \
		return; \
	} \
	else { \
		ptfResult = PTF_RESULT_PASSED; \
	}

#define PTF_IS_VERBOSE_MODE printVerbose

#define PTF_TEST_CASE_PASSED \
	ptfResult = PTF_RESULT_PASSED; \
	return

#define PTF_ASSERT_EQUAL(actual, expected, ...) \
	{ \
		if (actual != expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert EQUAL failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " != " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}


#define PTF_ASSERT_NOT_EQUAL(actual, expected, ...) \
	{ \
		if (actual == expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert NOT EQUAL failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " == " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}

#define PTF_ASSERT_GREATER_THAN(actual, expected, ...) \
	{ \
		if (actual <= expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert GREATER THAN failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " <= " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}

#define PTF_ASSERT_GREATER_OR_EQUAL_THAN(actual, expected, ...) \
	{ \
		if (actual < expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert GREATER OR EQUAL THAN failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " < " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}

#define PTF_ASSERT_LOWER_THAN(actual, expected, ...) \
	{ \
		if (actual >= expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert LOWER THAN failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " >= " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}

#define PTF_ASSERT_LOWER_OR_EQUAL_THAN(actual, expected, ...) \
	{ \
		if (actual > expected) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
			<< "Assert LOWER OR EQUAL THAN failed: " \
			<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
			<< " > " \
			<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
			<< std::endl; \
			ptfResult = PTF_RESULT_FAILED; \
			return; \
		} \
	}

#define PTF_ASSERT_BUF_COMPARE(buf1, buf2, size) \
	if (memcmp(buf1, buf2, size) != 0) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "Assert BUFFER COMPARE failed: " \
		<< #buf1 << " != " << #buf2 \
		<< std::endl; \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_TRUE(exp) \
	if (!(exp)) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Assert TRUE failed: " << #exp \
		<< std::endl; \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_FALSE(exp) \
	if (exp) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Assert FALSE failed: " << #exp \
		<< std::endl; \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_NOT_NULL(exp) \
	if ((exp) == NULL) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Assert NOT NULL failed: " \
		<< #exp << " is NULL" \
		<< std::endl; \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_ASSERT_NULL(exp) \
	if ((exp) != NULL) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "FAILED (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Assert NULL failed: " \
		<< #exp << " is not NULL" \
		<< std::endl; \
		ptfResult = PTF_RESULT_FAILED; \
		return; \
	}

#define PTF_NON_CRITICAL_EQUAL(actual, expected, ...) \
	if (actual != expected) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "NON-CRITICAL (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Assert EQUAL failed: " \
		<< "actual: " << __VA_ARGS__##_PTF_PRINT_TYPE(actual) \
		<< " != " \
		<< "expected: " << __VA_ARGS__##_PTF_PRINT_TYPE(expected) \
		<< std::endl; \
	}


#define PTF_NON_CRITICAL_TRUE(exp) \
	if (!exp) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "NON-CRITICAL (" << __FILE__ << ":" << __LINE__ << "). " \
		<< "Expression is not TRUE: " << #exp \
		<< std::endl; \
	}

#define PTF_PRINT_VERBOSE(data) \
	if(printVerbose) { \
		std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
		<< "[VERBOSE] " \
		<< data \
		<< std::endl; \
	} \

#define PTF_SKIP_TEST(why) \
	{ \
		if (showSkipped) { \
			std::cout << std::left << std::setw(30) << __FUNCTION__ << ": " \
			<< "SKIPPED (" << why << ")" \
			<< std::endl; \
		} \
		ptfResult = PTF_RESULT_SKIPPED; \
		return; \
	}

#endif // PCPP_TEST_FRAMEWORK
