// light_platform.h
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

#ifndef INCLUDE_LIGHT_PLATFORM_H_
#define INCLUDE_LIGHT_PLATFORM_H_

#ifndef UNIVERSAL
#define UNIVERSAL
#endif // UNIVERSAL

#include <stddef.h>
#include "light_internal.h"
#include "light_file.h"

typedef enum {
	LIGHT_OREAD,
	LIGHT_OWRITE,
	LIGHT_OAPPEND,
} __read_mode_t;

#ifdef UNIVERSAL

typedef long light_file_pos_t;
#define INVALID_FILE NULL

#else

#error UNIMPLEMENRTED

#endif

light_file light_open(const char *file_name, const __read_mode_t mode);
light_file light_open_compression(const char *file_name, const __read_mode_t mode, int compression_level);
size_t light_read(light_file fd, void *buf, size_t count);
size_t light_write(light_file fd, const void *buf, size_t count);
size_t light_size(light_file fd);
int light_close(light_file fd);
int light_flush(light_file fd);
int light_eof(light_file fd);
light_file_pos_t light_get_pos(light_file fd);
light_file_pos_t light_set_pos(light_file fd, light_file_pos_t);

#endif /* INCLUDE_LIGHT_PLATFORM_H_ */
