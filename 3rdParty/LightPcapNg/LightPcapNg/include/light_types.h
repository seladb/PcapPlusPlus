// light_types.h
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

#ifndef INCLUDE_LIGHT_TYPES_H_
#define INCLUDE_LIGHT_TYPES_H_

typedef enum {
	LIGHT_FALSE = 0,
	LIGHT_TRUE = 1,
//	LIGHT_MAYBE = 2,
} light_boolean;

typedef enum {
	LIGHT_INFO_TYPE = 0,
	LIGHT_INFO_LENGTH = 1,
	LIGHT_INFO_BODY = 2,
	LIGHT_INFO_OPTIONS = 3,
	LIGHT_INFO_MAX = 4,
} light_info;

#endif /* INCLUDE_LIGHT_TYPES_H_ */
