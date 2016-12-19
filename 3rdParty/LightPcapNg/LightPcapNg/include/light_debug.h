// light_debug.h
// Created on: Jul 23, 2016

// Copyright (c) 2016 Radu Velea

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef INCLUDE_LIGHT_DEBUG_H_
#define INCLUDE_LIGHT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#ifdef _LIGHT_DEBUG_MODE
#define light_stop          getchar()
#define DPRINT_HERE(symbol) fprintf(stderr, "%s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)
#else
#define light_stop          (void)0
#define DPRINT_HERE(symbol) (void)#symbol
#endif

// XXX: Warning: I should not use these macros with functions!!! Undefined for Release.

#define DCHECK_INT(x, y, other)	do { \
		int x_ret = (int)(x); \
		int y_ret = (int)(y); \
		if (x_ret <= y_ret) { \
			fprintf(stderr, "ERROR at %s::%s::%d: %d <= %d\n", \
					__FILE__, __FUNCTION__, __LINE__, x_ret, y_ret); \
			other; \
		} \
	} while (0)

#define DCHECK_ASSERT(x, y, other)	do { \
		int x_ret = (int)(x); \
		int y_ret = (int)(y); \
		if (x_ret != y_ret) { \
			fprintf(stderr, "ERROR at %s::%s::%d: %d != %d\n", \
					__FILE__, __FUNCTION__, __LINE__, x_ret, y_ret); \
			other; \
		} \
	} while (0)

#define DCHECK_ASSERT_EXP(expression, err_message, other) do { \
		if (!(expression)) {\
			fprintf(stderr, "ERROR at %s::%s::%d: %s\n", \
					__FILE__, __FUNCTION__, __LINE__, err_message); \
			other; \
		} \
	} while (0)

#define DCHECK_NULLP(x, other)	do { \
		void *x_ret = (void *)(x); \
		if (x_ret == NULL) { \
			fprintf(stderr, "NULL pointer ERROR at %s::%s::%d\n", \
					__FILE__, __FUNCTION__, __LINE__); \
			other; \
		} \
	} while (0)

#define PCAPNG_WARNING(symbol) fprintf(stderr, "Warning at: %s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)
#define PCAPNG_ERROR(symbol)   fprintf(stderr, "Error at: %s::%s::%d, %s\n", __FILE__, __FUNCTION__, __LINE__, #symbol)

#ifdef  _MSC_VER
#define __attribute__(x)
#endif //  _MSC_VER

#define PCAPNG_ATTRIBUTE_SLOW __attribute__((warning ("slow for large traces")))
#define PCAPNG_ATTRIBUTE_DEPRECATED __attribute__((warning ("deprecated function")))
#define PCAPNG_ATTRIBUTE_UNTESTED __attribute__((warning ("unit test required")))
#define PCAPNG_ATTRIBUTE_REFACTOR __attribute__((warning ("should be refactored")))

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_LIGHT_DEBUGs_H_ */
