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
#include "light_file.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

//I really wanted to define these as extern funciton pointers and then declare them inside the C
//File for the compression implementation, but that doesn't seem to work (atleast when this is a lib)
//So I am hacking it into here for now
#if defined(USE_Z_STD)
_compression_t * (*get_compression_context_ptr)(int) = &get_zstd_compression_context;
void(*free_compression_context_ptr)(_compression_t*) = &free_zstd_compression_context;
_compression_t * (*get_decompression_context_ptr)() = &get_zstd_decompression_context;
void(*free_decompression_context_ptr)(_decompression_t*) = &free_zstd_decompression_context;
int(*is_compressed_file)(const char*) = &is_zstd_compressed_file;
size_t(*read_compressed)(struct light_file_t *, void *, size_t) = &read_zstd_compressed;
size_t(*write_compressed)(struct light_file_t *, const void *, size_t) = &write_zstd_compressed;
int(*close_compressed)(struct light_file_t *) = &close_zstd_compresssed;

#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#else
_compression_t * (*get_compression_context_ptr)(int) = NULL;
void(*free_compression_context_ptr)(_compression_t*) = NULL;
_compression_t * (*get_decompression_context_ptr)() = NULL;
void(*free_decompression_context_ptr)(_decompression_t*) = NULL;
int(*is_compressed_file)(const char*) = NULL;
size_t(*read_compressed)(struct light_file_t *, void *, size_t) = NULL;
size_t(*write_compressed)(struct light_file_t *, const void *, size_t) = NULL;
int(*close_compressed)(struct light_file_t *) = NULL;

#endif

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

int light_close_compresssed(light_file fd)
{
	int result = 0;
	if (close_compressed != NULL)
		result = close_compressed(fd);

	light_free_compression_context(fd->compression_context);
	light_free_decompression_context(fd->decompression_context);

	return result;
}

#endif