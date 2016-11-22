// test_read_write.c
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define TMP_FILE	"/tmp/pcapng.tmp"

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			FILE *tmp = fopen(TMP_FILE, "wb");
			size_t size;
			uint32_t *data = light_pcapng_to_memory(pcapng, &size);
			struct stat f_info;
			FILE *f_check = fopen(file, "rb");
			uint8_t *data_check;
			int status = 0;

			stat(file, &f_info);
			if (size != f_info.st_size) {
				fprintf(stderr, "Memory size mismatch %zu != %zu\n", size, f_info.st_size);
				goto EARLY_FAILURE;
			}
			printf("Data for %s: %zu bytes\n", file, size);

			data_check = calloc(size, 1);
			if (fread(data_check, 1, size, f_check) != size) {
				fprintf(stderr, "Error reading %s!\n", file);
				free(data_check);
				goto EARLY_FAILURE;
			}

			status = memcmp(data, data_check, size);

			if (status == 0) {
				printf("SUCCESS for %s\n\n", file);
			}
			else {
				fprintf(stderr, "FAILURE for %s\n\n", file);
			}

			fwrite(data, size, 1, tmp);

			free(data_check);
EARLY_FAILURE:
			fclose(f_check);
			fclose(tmp);
			free(data);
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	// unlink(TMP_FILE);

	return EXIT_SUCCESS;
}
