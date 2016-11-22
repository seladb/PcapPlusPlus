// test_histogram.c
// Created on: Sep 30, 2016

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

static uint32_t key_master(const light_pcapng pcapng)
{
	uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;
	light_get_block_info(pcapng, LIGHT_INFO_TYPE, &type, NULL);
	return type;
}

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			light_pair *histogram;
			size_t length = 0;
			size_t uncounted = 0;
			size_t i;
			light_pcapng_historgram(pcapng, key_master, &histogram, &length, &uncounted);

			printf("Histogram for %s: %zu classes, %zu items rejected. See <key, value> bellow:\n", file, length, uncounted);
			for (i = 0; i < length; ++i) {
				printf("<0x%8X, %12u>\n", histogram[i].key, histogram[i].val);
			}
			printf("\n");

			free(histogram);
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return 0;
}
