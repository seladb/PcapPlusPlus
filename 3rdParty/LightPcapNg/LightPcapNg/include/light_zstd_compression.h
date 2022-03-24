// light_zstd_compression.h
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

#ifndef INCLUDE_LIGHT_ZSTD_COMPRESSION_H_
#define INCLUDE_LIGHT_ZSTD_COMPRESSION_H_
#if defined(USE_Z_STD)

#include <stdint.h>
#include <zstd.h>      // presumes zstd library is installed


//An ethernet packet should only ever be up to 1500 bytes + some header crap
//We also expect some ovehead for the pcapng blocks which contain the ethernet packets
//so allocate 1700 bytes as the max input size we expect in a single shot
#define COMPRESSION_BUFFER_IN_MAX_SIZE 1700

//This is the z-std compression type I would call it z-std type and realias
//2x but compiler won't let me do that across bounds it seems
//So I gave it a generic "light" name....
struct zstd_compression_t
{
	uint32_t* buffer_in;
	uint32_t* buffer_out;
	size_t buffer_in_max_size;
	size_t buffer_out_max_size;
	int compression_level;
	ZSTD_CCtx* cctx;
};

struct zstd_decompression_t
{
	uint32_t* buffer_in;
	uint32_t* buffer_out;
	size_t buffer_in_max_size;
	size_t buffer_out_max_size;
	ZSTD_DCtx* dctx;
	int outputReady;
	ZSTD_outBuffer output;
	ZSTD_inBuffer input;
};


typedef struct zstd_compression_t _compression_t;
typedef struct zstd_decompression_t _decompression_t;

struct light_file_t;

_compression_t * get_zstd_compression_context(int compression_level);
void free_zstd_compression_context(_compression_t* context);

_decompression_t * get_zstd_decompression_context();
void free_zstd_decompression_context(_decompression_t* context);

int is_zstd_compressed_file(const char* file_path);

size_t read_zstd_compressed(struct light_file_t *fd, void *buf, size_t count);

size_t write_zstd_compressed(struct light_file_t *fd, const void *buf, size_t count);

int close_zstd_compressed(struct light_file_t *fd);

#endif //USE_Z_STD
#endif /* INCLUDE_LIGHT_ZSTD_COMPRESSION_H_ */
