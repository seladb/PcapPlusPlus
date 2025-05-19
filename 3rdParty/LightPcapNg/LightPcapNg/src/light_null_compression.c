// light_null_compression.c
// Created on: Aug 13, 2019

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

#include "light_compression.h"
#include "light_null_compression.h"
#include "light_compression_functions.h"
#include "light_file.h"


#if defined(USE_NULL_COMPRESSION)

_compression_t * (*get_compression_context_ptr)(int) = NULL;
void(*free_compression_context_ptr)(_compression_t*) = NULL;
_decompression_t * (*get_decompression_context_ptr)() = NULL;
void(*free_decompression_context_ptr)(_decompression_t*) = NULL;
int(*is_compressed_file)(const char*) = NULL;
size_t(*read_compressed)(struct light_file_t *, void *, size_t) = NULL;
size_t(*write_compressed)(struct light_file_t *, const void *, size_t) = NULL;
int(*close_compressed)(struct light_file_t *) = NULL;

#endif
