// light_compression.h
// Created on: Aug 16, 2019

// Copyright (c) 2019 TMEIC Corporation - Robert Kriener

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

#ifndef INCLUDE_LIGHT_COMPRESSION_FUNCTIONS_H_
#define INCLUDE_LIGHT_COMPRESSION_FUNCTIONS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct light_file_t;

extern _compression_t * (*get_compression_context_ptr)(int);
extern void(*free_compression_context_ptr)(_compression_t*);
extern _decompression_t * (*get_decompression_context_ptr)();
extern void(*free_decompression_context_ptr)(_decompression_t*);
extern int(*is_compressed_file)(const char*);
extern size_t(*read_compressed)(struct light_file_t *, void *, size_t);
extern size_t(*write_compressed)(struct light_file_t *, const void *, size_t);
extern int(*close_compressed)(struct light_file_t *);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_LIGHT_COMPRESSION_FUNCTIONS_H_ */
