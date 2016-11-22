// test_subcapture.c
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static light_boolean subcapture_predicate(const light_pcapng pcapng)
{
	uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;
	uint32_t length = 0;

	light_get_block_info(pcapng, LIGHT_INFO_TYPE, &type, NULL);
	light_get_block_info(pcapng, LIGHT_INFO_LENGTH, &length, NULL);

	return (type != LIGHT_ENHANCED_PACKET_BLOCK) || (length > 512);
}

int main(int argc, const char **args) {
	int i;
	char comment[] = "This pcapng file was created using LightPcapNg subcapture functionality.";
	light_option option = light_create_option(0xB00B, strlen(comment), comment);

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			light_pcapng subcapture = NULL;
			uint32_t *subcapture_mem;
			size_t subcapture_size;
			FILE *subcapture_file;
			char subcapture_name[PATH_MAX] = {0,};
			const char *file_name = file;
			char *offset;

			while ((offset = strstr(file_name, "/")) != NULL)
				file_name = offset + 1;

			light_subcapture(pcapng, subcapture_predicate, &subcapture);
			light_add_option(subcapture, subcapture, option, LIGHT_TRUE);
			subcapture_mem = light_pcapng_to_memory(subcapture, &subcapture_size);

			sprintf(subcapture_name, "subcapture_%s", file_name);
			printf("Write subcapture to %s\n", subcapture_name);
			subcapture_file = fopen(subcapture_name, "wb");
			fwrite(subcapture_mem, 1, subcapture_size, subcapture_file);
			fclose(subcapture_file);

			free(subcapture_mem);
			light_pcapng_release(subcapture);
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	light_free_option(option);
	return 0;
}
