// test_flow.c
// Created on: Oct 23, 2016

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

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		char *core_file_name = strdup(file);
		char *dot = strrchr(core_file_name, '.');
		light_pcapng pcapng = light_read_from_path(file);
		light_pcapng current_section = pcapng;
		int flow_index = 0;

		if (dot != NULL) {
			*dot = 0;
		}

		while (current_section != NULL) {
			light_pcapng *flows = NULL;
			size_t flow_count = 0;
			size_t dropped = 0;
			size_t i;
			int ret = light_ip_flow(&current_section, &flows, &flow_count, &dropped);

			if (ret != LIGHT_SUCCESS) {
				fprintf(stderr, "Error while computing for %s\n", file);
				break;
			}

			printf("Found %zu flows, dropped %zu packages for %s\n", flow_count, dropped, file);
			for (i = 0; i < flow_count; ++i) {
				light_pcapng current_flow = flows[i];
				size_t block_count = light_get_block_count(current_flow);
				uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;
				char flow_file_name[256] = {0,};
				light_option options = NULL;

				light_get_block_info(pcapng, LIGHT_INFO_TYPE, &type, NULL);
#if 0
				printf("Write flow %zu out of %zu, with block count = %zu and type = 0x%X\n",
						i, flow_count, block_count, type);
#else
				(void)block_count;
#endif

				light_get_block_info(current_flow, LIGHT_INFO_OPTIONS, &options, NULL);
				while (options != NULL) {
					if (light_get_option_code(options) == LIGHT_CUSTOM_OPTION_ADDRESS_INFO) {
						break;
					}
					options = light_get_next_option(options);
				}

				if (options != NULL) {
					uint8_t *label = (uint8_t *)light_get_option_data(options);
					if (*label == 4) {
						uint8_t source[4], destination[4];
						memcpy(source, label + 1, sizeof(uint32_t));
						memcpy(destination, label + 5, sizeof(uint32_t));
						sprintf(flow_file_name, "%s_flow_[%d]_%u.%u.%u.%u-%u.%u.%u.%u.pcapng",
								core_file_name, flow_index,
								source[0], source[1], source[2], source[3],
								destination[0], destination[1], destination[2], destination[3]);
					}
					else {
						// TODO: handle IPv6 info.
						printf("Protocol type = %u\n", *label);
						sprintf(flow_file_name, "%s_flow_%d.pcapng", core_file_name, flow_index);
					}
				}
				else {
					sprintf(flow_file_name, "%s_flow_%d.pcapng", core_file_name, flow_index);
				}

				if (light_pcapng_to_file(flow_file_name, current_flow) != LIGHT_SUCCESS) {
					fprintf(stderr, "Failed to write flow %d for %s\n", flow_index, file);
				}
				light_pcapng_release(current_flow);
				flow_index++;
			}

			free(flows);
		}

		if (pcapng != NULL) {
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}

		free(core_file_name);
	}

	return 0;
}
