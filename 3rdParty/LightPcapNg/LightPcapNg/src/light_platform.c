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

#include <stdio.h>

#ifdef UNIVERSAL

__fd_t light_open(const char *file_name, const __read_mode_t mode)
{
	__fd_t fd = (__fd_t)INVALID_FILE;

	switch (mode) {
	case LIGHT_OREAD:
		fd = fopen(file_name, "rb");
		break;
	case LIGHT_OWRITE:
		fd = fopen(file_name, "wb");
		break;
	case LIGHT_OAPPEND:
		fd = fopen(file_name, "ab");
		break;
	}

	return fd;
}

int light_read(__fd_t fd, void *buf, size_t count)
{
	size_t bytes_read = fread(buf, 1, count, fd);
	return  bytes_read != count ? -1 : bytes_read;
}

int light_write(__fd_t fd, const void *buf, size_t count)
{
	size_t bytes_written = fwrite(buf, 1, count, fd);
	return  bytes_written != count ? -1 : bytes_written;
}

size_t light_size(__fd_t fd)
{
	size_t size = 0;
	size_t current = ftell(fd);

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, current, SEEK_SET);

	return size;
}

int light_close(__fd_t fd)
{
	return fclose(fd);
}

int light_flush(__fd_t fd)
{
	return fflush(fd);
}

#else

#error UNIMPLEMENRTED

#endif
