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
#include "light_compression.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Visual studio gives us min + max for free, but other OS does not....
#if !defined(_MSC_VER) || (!defined(max) && !defined(min))
#define max(a,b) (((a) > (b)) ? (a) : (b))
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define UNDEF_MAX_MIN
#endif


#ifdef UNIVERSAL

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

		default:
			break;
	}

	if (fd->file)
	{
		return fd;
	}
	else
	{
		return NULL;
	}
}

light_file light_open(const char *file_name, const __read_mode_t mode)
{
	light_file fd = calloc(1,sizeof(light_file_t));
	fd->file = INVALID_FILE;
	fd->compression_context = NULL;
	fd->decompression_context = NULL;

	switch (mode) {
	case LIGHT_OREAD:
	{
		if (light_is_compressed_file(file_name))
		{
			free(fd);  // PCPP PATCH
			return light_open_decompression(file_name, mode);
		}
		fd->file = fopen(file_name, "rb");
		break;
	}
	case LIGHT_OWRITE:
		fd->file = fopen(file_name, "wb");
		break;
	case LIGHT_OAPPEND:
		fd->file = fopen(file_name, "ab");
		break;
	}

	if (fd->file)
	{
		return fd;
	}
	else
	{
		return NULL;
	}
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
		/*case LIGHT_OAPPEND:
			fd->file = fopen(file_name, "ab");
			break;*/
		default:
			break;
	}

	if (fd->file)
	{
		return fd;
	}
	else
	{
		return NULL;
	}
}



size_t light_read(light_file fd, void *buf, size_t count)
{
	if (fd->decompression_context == NULL)
	{
		size_t bytes_read = fread(buf, 1, count, fd->file);
		return  bytes_read != count ? -1 : bytes_read;
	}
	else
	{
		return light_read_compressed(fd, buf, count);
	}
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
		return light_write_compressed(fd, buf, count);
	}
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
	light_close_compressed(fd);
	int rc = fclose(fd->file);

	free(fd);

	return rc;
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

light_file_pos_t light_set_pos(light_file fd, light_file_pos_t pos)
{
	return fseek(fd->file, pos, SEEK_SET);
}

#else

#error UNIMPLEMENRTED

#endif

#if defined(UNDEF_MAX_MIN)
#undef max
#undef min
#undef UNDEF_MAX_MIN
#endif
