// test_mem.c
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

#include "light_pcapng.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct _light_pcapng_mem;
extern int light_pcapng_validate(light_pcapng p0, uint32_t *p1);
extern struct _light_pcapng_mem *light_no_copy_from_memory(uint32_t *memory, size_t size, int is_owner);
extern void light_pcapng_mem_release(struct _light_pcapng_mem *pcapng);

int read_file(const char *file, uint8_t **data, size_t *size)
{
	size_t tmp;
	struct stat info;
	FILE *f;

	f = fopen(file, "rb");
	stat(file, &info);
	*data = calloc(info.st_size, 1);
	tmp = fread(*data, 1, info.st_size, f);
	if (tmp != info.st_size) {
		free(*data);
		return -1;
	}

	fclose(f);
	*size = info.st_size;
	return 0;
}

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		uint8_t *data;
		size_t size;
		if (read_file(file, &data, &size) == 0) {
			light_pcapng pcapng0 = light_read_from_memory((uint32_t *)data, size);
			struct _light_pcapng_mem *pcapng1 = light_no_copy_from_memory((uint32_t *)data, size, 1);
			int status = light_pcapng_validate(pcapng0, *(uint32_t **)pcapng1);
			uint32_t **sec = (uint32_t **)(((uint32_t **)pcapng1)[1]);

			status &= light_pcapng_validate(pcapng0, sec[0]);

			printf("Internal structure comparison returned %d\n", status);

			light_pcapng_release(pcapng0);
			light_pcapng_mem_release(pcapng1);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return 0;
}

