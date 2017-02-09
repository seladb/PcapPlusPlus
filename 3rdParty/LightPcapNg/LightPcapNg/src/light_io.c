// light_io.c
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

#include "light_debug.h"
#include "light_internal.h"
#include "light_pcapng.h"
#include "light_platform.h"

#include <stdio.h>
#include <stdlib.h>

light_pcapng light_read_from_path(const char *file_name)
{
	light_pcapng head;
	uint32_t *memory;
	size_t size = 0;
	__fd_t fd = light_open(file_name, LIGHT_OREAD);
	DCHECK_ASSERT_EXP(fd != NULL, "could not open file", return NULL);

	size = light_size(fd);
	DCHECK_INT(size, 0, light_stop);

	memory = calloc(size, 1);

	DCHECK_INT(light_read(fd, memory, size), size - 1, light_stop);

	head = light_read_from_memory(memory, size);

	light_close(fd);
	free(memory);

	return head;
}

int light_pcapng_to_file(const char *file_name, const light_pcapng pcapng)
{
	size_t size;
	uint32_t *data = light_pcapng_to_memory(pcapng, &size);
	__fd_t fd = light_open(file_name, LIGHT_OWRITE);

	light_write(fd, data, size);
	light_close(fd);
	free(data);
	return LIGHT_SUCCESS;
}
