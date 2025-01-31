#pragma once

#include <iomanip>
#include <cstring>
#include <iostream>
#include "memplumber.h"
#include "PcppTestFrameworkCommon.h"

#ifdef _MSC_VER
#	define _PTF_MSVC_SUPPRESS_C26444 _Pragma("warning(suppress: 26444)");
#else
#	define _PTF_MSVC_SUPPRESS_C26444
#endif  // _MSC_VER

#define _PTF_PRINT_TYPE_ACTUAL(exp, val) val
#define _PTF_PRINT_TYPE_EXPECTED(exp, val) val
#define hex_PTF_PRINT_TYPE_ACTUAL(exp, val) "0x" << std::hex << +val << std::dec
#define hex_PTF_PRINT_TYPE_EXPECTED(exp, val) "0x" << std::hex << +val << std::dec
#define enum_PTF_PRINT_TYPE_ACTUAL(exp, val) "enum[" << val << "]"
#define enum_PTF_PRINT_TYPE_EXPECTED(exp, val) exp << "[" << val << "]"
#define ptr_PTF_PRINT_TYPE_ACTUAL(exp, val) exp << "[ptr: " << val << "]"
#define ptr_PTF_PRINT_TYPE_EXPECTED(exp, val) exp << "[ptr: " << val << "]"
#define enumclass_PTF_PRINT_TYPE_ACTUAL(exp, val)                                                                      \
	"enum[" << +static_cast<std::underlying_type<decltype(val)>::type>(val) << "]"
#define enumclass_PTF_PRINT_TYPE_EXPECTED(exp, val)                                                                    \
	exp << "[" << +static_cast<std::underlying_type<decltype(val)>::type>(val) << "]"
#define BUFFER_PRINT(buffer, size)                                                                                     \
	for (size_t currentByteId = 0; currentByteId < static_cast<size_t>(size); ++currentByteId)                         \
	{                                                                                                                  \
		std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex                                       \
		          << static_cast<int>(*(buffer + currentByteId)) << " ";                                               \
	}                                                                                                                  \
	std::cout << std::setfill(' ') << std::setw(0) << std::left << std::dec;                                           \
	std::cout << std::endl

#define PTF_PRINT_ASSERTION(severity, op)                                                                              \
	std::cout << std::left << std::setw(35) << __FUNCTION__ << ": " << severity << " (" << __FILE__ << ":" << __LINE__ \
	          << "). "                                                                                                 \
	          << "Assert " << op << " failed:" << std::endl

#define PTF_PRINT_COMPARE_ASSERTION(severity, op, actualExp, actualVal, expectedExp, expectedVal, objType)             \
	PTF_PRINT_ASSERTION(severity, op) << "   Actual:   " << objType##_PTF_PRINT_TYPE_ACTUAL(actualExp, actualVal)      \
	                                  << std::endl                                                                     \
	                                  << "   Expected: "                                                               \
	                                  << objType##_PTF_PRINT_TYPE_EXPECTED(expectedExp, expectedVal) << std::endl

#define PTF_PRINT_COMPARE_ASSERTION_FAILED(op, actualExp, actualVal, expectedExp, expectedVal, objType)                \
	PTF_PRINT_COMPARE_ASSERTION("FAILED", op, actualExp, actualVal, expectedExp, expectedVal, objType)

#define PTF_PRINT_COMPARE_ASSERTION_NON_CRITICAL(op, actualExp, actualVal, expectedExp, expectedVal, objType)          \
	PTF_PRINT_COMPARE_ASSERTION("NON-CRITICAL", op, actualExp, actualVal, expectedExp, expectedVal, objType)

#define PTF_TEST_CASE(TestName) void TestName(int& ptfResult, bool printVerbose, bool showSkipped)

#define PTF_INTERNAL_RUN(TestName)                                                                                     \
	TestName(ptfResult, printVerbose, showSkipped);                                                                    \
	if (ptfResult == PTF_RESULT_FAILED)                                                                                \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "INTERNAL TEST")                                                                 \
		    << "   Internal test '" << #TestName << "' failed" << std::endl;                                           \
		return;                                                                                                        \
	}                                                                                                                  \
	else                                                                                                               \
	{                                                                                                                  \
		ptfResult = PTF_RESULT_PASSED;                                                                                 \
	}

#define PTF_IS_VERBOSE_MODE printVerbose

#define PTF_TEST_CASE_PASSED                                                                                           \
	ptfResult = PTF_RESULT_PASSED;                                                                                     \
	return

#define PTF_ASSERT_EQUAL(actual, expected, ...)                                                                        \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual != ptfExpected)                                                                                  \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("EQUAL", #actual, ptfActual, #expected, ptfExpected, __VA_ARGS__);      \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_VECTORS_EQUAL(actual, expected, ...)                                                                \
	{                                                                                                                  \
		if (actual != expected)                                                                                        \
		{                                                                                                              \
			std::ostringstream actualOss, expectedOss;                                                                 \
			bool first = true;                                                                                         \
			for (const auto& elem : actual)                                                                            \
			{                                                                                                          \
				if (!first)                                                                                            \
					actualOss << ", ";                                                                                 \
				actualOss << elem;                                                                                     \
				first = false;                                                                                         \
			}                                                                                                          \
			first = true;                                                                                              \
			for (const auto& elem : expected)                                                                          \
			{                                                                                                          \
				if (!first)                                                                                            \
					expectedOss << ", ";                                                                               \
				expectedOss << elem;                                                                                   \
				first = false;                                                                                         \
			}                                                                                                          \
			std::string actualValues = "[" + actualOss.str() + "]";                                                    \
			std::string expectedValues = "[" + expectedOss.str() + "]";                                                \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("VECTORS EQUAL", #actual, actualValues, #expected, expectedValues,      \
			                                   __VA_ARGS__);                                                           \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_NOT_EQUAL(actual, expected, ...)                                                                    \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual == ptfExpected)                                                                                  \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("NOT EQUAL", #actual, ptfActual, #expected, ptfExpected, __VA_ARGS__);  \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_GREATER_THAN(actual, expected, ...)                                                                 \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual <= ptfExpected)                                                                                  \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("GREATER THAN", #actual, ptfActual, #expected, ptfExpected,             \
			                                   __VA_ARGS__);                                                           \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_GREATER_OR_EQUAL_THAN(actual, expected, ...)                                                        \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual < ptfExpected)                                                                                   \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("GREATER OR EQUAL THAN", #actual, ptfActual, #expected, ptfExpected,    \
			                                   __VA_ARGS__);                                                           \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_LOWER_THAN(actual, expected, ...)                                                                   \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual >= ptfExpected)                                                                                  \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("LOWER THAN", #actual, ptfActual, #expected, ptfExpected, __VA_ARGS__); \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_LOWER_OR_EQUAL_THAN(actual, expected, ...)                                                          \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual > ptfExpected)                                                                                   \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_FAILED("LOWER OR EQUAL THAN", #actual, ptfActual, #expected, ptfExpected,      \
			                                   __VA_ARGS__);                                                           \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_ASSERT_BUF_COMPARE(buf1, buf2, size)                                                                       \
	if (memcmp(buf1, buf2, size) != 0)                                                                                 \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "BUFFER COMPARE") << "   Actual   " << std::endl;                                \
		BUFFER_PRINT(buf1, size) << "   Expected   " << std::endl;                                                     \
		BUFFER_PRINT(buf2, size);                                                                                      \
		ptfResult = PTF_RESULT_FAILED;                                                                                 \
		return;                                                                                                        \
	}

#define PTF_ASSERT_TRUE(exp)                                                                                           \
	if (!(exp))                                                                                                        \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "TRUE") << "   [" << #exp << "]" << std::endl;                                   \
		ptfResult = PTF_RESULT_FAILED;                                                                                 \
		return;                                                                                                        \
	}

#define PTF_ASSERT_FALSE(exp)                                                                                          \
	if (exp)                                                                                                           \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "FALSE") << "   [" << #exp << "]" << std::endl;                                  \
		ptfResult = PTF_RESULT_FAILED;                                                                                 \
		return;                                                                                                        \
	}

#define PTF_ASSERT_NOT_NULL(exp)                                                                                       \
	if ((exp) == NULL)                                                                                                 \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "NOT NULL") << "   [" << #exp << "] is NULL" << std::endl;                       \
		ptfResult = PTF_RESULT_FAILED;                                                                                 \
		return;                                                                                                        \
	}

#define PTF_ASSERT_NULL(exp)                                                                                           \
	if ((exp) != NULL)                                                                                                 \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("FAILED", "NULL") << "   [" << #exp << "] is not NULL" << std::endl;                       \
		ptfResult = PTF_RESULT_FAILED;                                                                                 \
		return;                                                                                                        \
	}

#define PTF_ASSERT_RAISES(expression, exception_type, message)                                                         \
	{                                                                                                                  \
		auto rightExceptionCaught = false;                                                                             \
		std::string messageCaught = "";                                                                                \
		try                                                                                                            \
		{                                                                                                              \
			_PTF_MSVC_SUPPRESS_C26444                                                                                  \
			expression;                                                                                                \
		}                                                                                                              \
		catch (const exception_type& e)                                                                                \
		{                                                                                                              \
			rightExceptionCaught = true;                                                                               \
			messageCaught = e.what();                                                                                  \
		}                                                                                                              \
		catch (...)                                                                                                    \
		{ /* do nothing */                                                                                             \
		}                                                                                                              \
		if (!rightExceptionCaught)                                                                                     \
		{                                                                                                              \
			PTF_PRINT_ASSERTION("FAILED", "EXCEPTION RAISED")                                                          \
			    << "   " << #exception_type << " not raised" << std::endl;                                             \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
		if (messageCaught != std::string(message))                                                                     \
		{                                                                                                              \
			PTF_PRINT_ASSERTION("FAILED", "EXCEPTION RAISED")                                                          \
			    << "   "                                                                                               \
			    << "Expected message: " << std::string(message) << std::endl                                           \
			    << "   "                                                                                               \
			    << "Message caught  : " << messageCaught << std::endl;                                                 \
			ptfResult = PTF_RESULT_FAILED;                                                                             \
			return;                                                                                                    \
		}                                                                                                              \
	}

#define PTF_NON_CRITICAL_EQUAL(actual, expected, ...)                                                                  \
	{                                                                                                                  \
		auto ptfActual = actual;                                                                                       \
		auto ptfExpected = static_cast<decltype(ptfActual)>(expected);                                                 \
		if (ptfActual != ptfExpected)                                                                                  \
		{                                                                                                              \
			PTF_PRINT_COMPARE_ASSERTION_NON_CRITICAL("EQUAL", #actual, ptfActual, #expected, ptfExpected,              \
			                                         __VA_ARGS__);                                                     \
		}                                                                                                              \
	}

#define PTF_NON_CRITICAL_TRUE(exp)                                                                                     \
	if (!exp)                                                                                                          \
	{                                                                                                                  \
		PTF_PRINT_ASSERTION("NON-CRITICAL", "TRUE") << "   [" << #exp << "]" << std::endl;                             \
	}

#define PTF_PRINT_VERBOSE(data)                                                                                        \
	if (printVerbose)                                                                                                  \
	{                                                                                                                  \
		std::cout << std::left << std::setw(35) << __FUNCTION__ << ": "                                                \
		          << "[VERBOSE] " << data << std::endl;                                                                \
	}

#define PTF_SKIP_TEST(why)                                                                                             \
	{                                                                                                                  \
		if (showSkipped)                                                                                               \
		{                                                                                                              \
			std::cout << std::left << std::setw(35) << __FUNCTION__ << ": "                                            \
			          << "SKIPPED (" << why << ")" << std::endl;                                                       \
		}                                                                                                              \
		ptfResult = PTF_RESULT_SKIPPED;                                                                                \
		return;                                                                                                        \
	}
