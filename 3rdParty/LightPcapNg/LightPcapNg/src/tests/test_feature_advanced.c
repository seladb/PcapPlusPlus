// test_feature_advanced.c
// Created on: Nov 1, 2016

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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#define MAX_FEATURES 64

typedef uint64_t (*extractor_fn)(const light_pcapng);
static extractor_fn features[MAX_FEATURES] = {0,};
static char *feature_names[MAX_FEATURES] = {0,};
static int feature_count = 0;
static void *feature_lib_handle = NULL;

static int compile_features()
{
	int ret = system("make -C features");
	return ret;
}

static int extract_features()
{
	feature_lib_handle = dlopen("./features/libfeatures.so", RTLD_LAZY);
	if (!feature_lib_handle) {
		fprintf(stderr, "dlerror: %s\n", dlerror());
		return -1;
	}

	FILE *feature_list = fopen("features/feature_list.txt", "r");
	if (!feature_list) {
		perror("Unable to open feature_list.txt");
		return -1;
	}

	char line[256] = {0,};
	while (fgets(line, sizeof(line), feature_list) != NULL) {
		if (line[strlen(line) - 1] == '\n') {
			line[strlen(line) - 1] = 0;
		}

		extractor_fn function = (extractor_fn)dlsym(feature_lib_handle, line);
		if (!function) {
			fprintf(stderr, "Unable to find symbol %s\n", line);
		}
		else {
			features[feature_count] = function;
			feature_names[feature_count] = strdup(line);
			feature_count++;
		}
		memset(line, 0, sizeof(line));
	}

	fclose(feature_list);

	return 0;
}

static void cleanup()
{
	int i;

	for (i = 0; i < feature_count; ++i) {
		free(feature_names[i]);
	}

	dlclose(feature_lib_handle);
	feature_lib_handle = NULL;
}

int main(int argc, const char **args) {
	int i, j;
	FILE *features_csv = fopen("features/unscaled.csv", "w");
	FILE *features_raw = fopen("features/raw.dat", "w");
	uint64_t *min_features = NULL;
	uint64_t *max_features = NULL;
	uint64_t **feature_table = NULL;

	if (compile_features() != 0) {
		fprintf(stderr, "Unable to compile features!\n");
		return EXIT_FAILURE;
	}

	if (extract_features() != 0) {
		fprintf(stderr, "Unable to extract function pointers!\n");
		return EXIT_FAILURE;
	}

	min_features = calloc(feature_count, sizeof(uint64_t));
	memset(min_features, -1, feature_count * sizeof(uint64_t));

	max_features = calloc(feature_count, sizeof(uint64_t));
	feature_table = calloc(argc - 1, sizeof(uint64_t *));
	for (i = 0; i < argc - 1; ++i) {
		feature_table[i] = calloc(feature_count, sizeof(uint64_t));
	}

	fprintf(features_csv, "address1, address2");
	for (i = 0; i < feature_count; ++i) {
		fprintf(features_csv, ", %s", feature_names[i]);
	}
	fprintf(features_csv, "\n");

	printf("Running feature extraction with %d functions and %d traces\n", feature_count, argc - 1);

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			uint64_t feature_values[MAX_FEATURES];
			light_option feature_option;
			light_option address_option;

			address_option = light_get_option(pcapng, LIGHT_CUSTOM_OPTION_ADDRESS_INFO);
			if (address_option != NULL) {
				uint8_t *label = (uint8_t *)light_get_option_data(address_option);
				if (*label == 4) {
					uint8_t source[4], destination[4];
					memcpy(source, label + 1, sizeof(uint32_t));
					memcpy(destination, label + 5, sizeof(uint32_t));
					fprintf(features_csv, "%u.%u.%u.%u, %u.%u.%u.%u",
							source[0], source[1], source[2], source[3],
							destination[0], destination[1], destination[2], destination[3]);
				}
				else if (*label == 6) {
					fprintf(features_csv, "ipv6, ipv6");
				}
				else {
					fprintf(features_csv, "unknown, unknown");
				}
			}
			else {
				fprintf(features_csv, "unknown, unknown");
			}

			printf("Extract features for %s\n", file);

			// Write output to file.
			for (j = 0; j < feature_count; ++j) {
				feature_values[j] = features[j](pcapng);
				fprintf(features_csv, ", %lu", feature_values[j]);

				// Save for later.
				feature_table[i - 1][j] = feature_values[j];

				if (feature_values[j] == -1) {
					// Invalid value.
					continue;
				}

				if (min_features[j] > feature_table[i - 1][j]) {
					min_features[j] = feature_table[i - 1][j];
				}
				if (max_features[j] < feature_table[i - 1][j]) {
					max_features[j] = feature_table[i - 1][j];
				}
			}
			fprintf(features_csv, "\n");

			// Update .pcapng traces with computed metrics.
			feature_option = light_create_option(LIGHT_CUSTOM_OPTION_FEATURE_U64, feature_count * sizeof(uint64_t), feature_values);
			light_update_option(pcapng, pcapng, feature_option);
			light_pcapng_to_file(file, pcapng);

			light_free_option(feature_option);
			light_pcapng_release(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	fclose(features_csv);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	printf("Start exporting double features!\n");

	fprintf(features_raw, "%% %d features\n", feature_count);
	fprintf(features_raw, "%% %d items\n", argc - 1);

	for (i = 0; i < argc - 1; ++i) {
		for (j = 0; j < feature_count; ++j) {
			if (feature_table[i][j] == -1) {
				// Invalid feature.
				fprintf(features_raw, "%.6lf ", 0.0);
			}
			else {
				double f = (double)(feature_table[i][j] - min_features[j]) / (max_features[j] - min_features[j]);
				fprintf(features_raw, "%.6lf ", f);
			}
		}
		fprintf(features_raw, "\n");
	}
	fclose(features_raw);

	cleanup();

	return EXIT_SUCCESS;
}
