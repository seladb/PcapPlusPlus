// light_compression.c
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

#ifndef __cplusplus

#include "light_compression.h"
#include "light_compression_functions.h"
#include "light_file.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

_compression_t * light_get_compression_context(int compression_level)
{
	if (compression_level == 0)
		return NULL;

	if (get_compression_context_ptr != NULL)
		return get_compression_context_ptr(compression_level);
	else
		return NULL;
}

void light_free_compression_context(_compression_t* context)
{
	if (!context)
		return;

	if (free_compression_context_ptr != NULL)
		free_compression_context_ptr(context);

	free(context);
}

_decompression_t * light_get_decompression_context()
{
	if (get_decompression_context_ptr != NULL)
		return get_decompression_context_ptr();
	else
		return NULL;
}

void light_free_decompression_context(_decompression_t* context)
{
	if (!context)
		return;

	if (free_decompression_context_ptr != NULL)
		free_decompression_context_ptr(context);

	free(context);
}


int light_is_compressed_file(const char* file_path)
{
	if (is_compressed_file != NULL)
		return is_compressed_file(file_path);
	else
		return 0;
}

size_t light_read_compressed(light_file fd, void *buf, size_t count)
{
	if (read_compressed != NULL)
		return read_compressed(fd,buf,count);
	return 0;
}

size_t light_write_compressed(light_file fd, const void *buf, size_t count)
{
	if (write_compressed != NULL)
		return write_compressed(fd,buf,count);
	return 0;
}

int light_close_compressed(light_file fd)
{
	int result = 0;
	if (close_compressed != NULL)
		result = close_compressed(fd);

	light_free_compression_context(fd->compression_context);
	light_free_decompression_context(fd->decompression_context);

	return result;
}

#endif
