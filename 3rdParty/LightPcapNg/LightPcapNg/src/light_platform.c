// light_platform.c
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

#include "light_platform.h"
#include "light_internal.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef UNIVERSAL

light_file light_open(const char *file_name, const __read_mode_t mode)
{
	light_file fd = calloc(1,sizeof(light_file_t));
	fd->file = INVALID_FILE;
	fd->compression_context = NULL;
	fd->decompression_context = NULL;

	switch (mode) {
	case LIGHT_OREAD:
		fd->file = fopen(file_name, "rb");
		break;
	case LIGHT_OWRITE:
		fd->file = fopen(file_name, "wb");
		break;
	case LIGHT_OAPPEND:
		fd->file = fopen(file_name, "ab");
		break;
	}

	return fd;
}

light_file light_open_compression(const char *file_name, const __read_mode_t mode, int compression_level)
{
	light_file fd = calloc(1, sizeof(light_file_t));
	fd->file = INVALID_FILE;

	assert(0 <= compression_level && 10 >= compression_level);
	compression_level = max(0, compression_level);
	compression_level = min(compression_level, 10);

	fd->compression_context = light_get_compression_context(compression_level);

	switch (mode)
	{
		case LIGHT_OWRITE:
			fd->file = fopen(file_name, "wb");
			break;
			//TODO Not so sure about allowing appends... I think you can get away with this in Zstd 
			//but i dont know about other compression algorithms!
		case LIGHT_OAPPEND:
			fd->file = fopen(file_name, "ab");
			break;
	}

	return fd;
}

light_file light_open_decompression(const char *file_name, const __read_mode_t mode)
{
	light_file fd = calloc(1, sizeof(light_file_t));
	fd->file = INVALID_FILE;
	fd->decompression_context = light_get_decompression_context();

	switch (mode)
	{
		case LIGHT_OREAD:
			fd->file = fopen(file_name, "rb");
			break;
	}

	return fd;
}

size_t light_read(light_file fd, void *buf, size_t count)
{
	size_t bytes_read = fread(buf, 1, count, fd->file);
	return  bytes_read != count ? -1 : bytes_read;
}

size_t light_write(light_file fd, const void *buf, size_t count)
{
	if (fd->compression_context == NULL)
	{
		size_t bytes_written = fwrite(buf, 1, count, fd->file);
		return  bytes_written != count ? -1 : bytes_written;
	}
	else
	{
		//Do compression here
		/* Set the input buffer to what we just read.
		* We compress until the input buffer is empty, each time flushing the
		* output.
		*/
		ZSTD_inBuffer input = { buf, count, 0 };
		int finished;
		do
		{
			/* Compress into the output buffer and write all of the output to
			* the file so we can reuse the buffer next iteration.
			*/
			ZSTD_outBuffer output = { fd->compression_context->buffer_out, fd->compression_context->buffer_out_max_size, 0 };
			size_t const remaining = ZSTD_compressStream2(fd->compression_context->cctx, &output, &input, ZSTD_e_continue);
			assert(!ZSTD_isError(remaining));
			fwrite(output.dst, 1, output.pos, fd->file);
			/* If we're on the last chunk we're finished when zstd returns 0,
			 * We're finished when we've consumed all the input.
			 */
			finished = (input.pos == input.size);
		} while (!finished);
	}

	return count;
}

size_t light_size(light_file fd)
{
	size_t size = 0;
	size_t current = ftell(fd->file);

	fseek(fd->file, 0, SEEK_END);
	size = ftell(fd->file);
	fseek(fd->file, current, SEEK_SET);

	return size;
}

int light_close(light_file fd)
{
	//Wrap up the compression here
	if (fd->compression_context)
	{
		ZSTD_inBuffer input = { 0,0,0 };

		int remaining = 1;

		while (remaining != 0)
		{
			ZSTD_outBuffer output = { fd->compression_context->buffer_out, fd->compression_context->buffer_out_max_size, 0 };
			remaining = ZSTD_compressStream2(fd->compression_context->cctx, &output, &input, ZSTD_e_end);
			fwrite(output.dst, 1, output.pos, fd->file);
		}
	}
	light_free_compression_context(fd->compression_context);

	return fclose(fd->file);
}

int light_flush(light_file fd)
{
	return fflush(fd->file);
}

int light_eof(light_file fd)
{
	return feof(fd->file);
}

light_file_pos_t light_get_pos(light_file fd)
{
	return ftell(fd->file);
}

int light_set_pos(light_file fd, light_file_pos_t pos)
{
	return fseek(fd->file, pos, SEEK_SET);
}

#else

#error UNIMPLEMENRTED

#endif
