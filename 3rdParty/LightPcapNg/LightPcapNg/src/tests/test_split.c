#include "light_pcapng.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_split_count(int argc, char *const *argv)
{
	while (*argv != NULL) {
		if (access(*argv, F_OK | R_OK) == 0) {
			light_pcapng_stream stream = light_open_stream(*argv);
			unsigned int count = 0;

			if (stream == NULL) {
				fprintf(stderr, "Failed to open %s\n", *argv);
			}
			else {
				light_pcapng pcapng = NULL;
				do {
					count++;
					pcapng = light_read_stream(stream);
				} while (pcapng != NULL);
			}

			light_close_stream(stream);
			printf("--> %s has %u blocks\n", *argv, count);
		}
		argv++;
	}
}

static void test_split_trace(int n, const char *file)
{
	uint32_t *current_section = NULL;
	uint32_t **current_interface_list = calloc(1, sizeof(uint32_t *));
	int current_interface_list_size = 1;
	int current_interface_count = 0;

	int current_data_block_index = 0;
	int current_trace_index = 0;

	char trace_path[PATH_MAX] = {0};
	int first_fd = -1;
	int current_fd = -1;

	char *raw_file = strdup(file);
	char *tmp = strrchr(raw_file, '.');
	*tmp = 0;

	light_pcapng_stream stream = light_open_stream(file);
	if (stream == NULL) {
		free(current_interface_list);
		free(raw_file);
		return;
	}

	sprintf(trace_path, "%s_%04d.pcapng", raw_file, current_trace_index);
	first_fd = current_fd = open(trace_path, O_CREAT | O_RDWR, 0666);

	if (current_fd == -1) {
		fprintf(stderr, "Unable to open file for write: %s\n", trace_path);
		free(current_interface_list);
		free(raw_file);
		light_close_stream(stream);
		return;
	}

	do {
		int reusable = 0;
		size_t current_block_size = 0;
		uint32_t *current_block = light_pcapng_to_memory(light_read_stream(stream), &current_block_size);

		if (current_block == NULL) {
			break;
		}

		switch (current_block[0]) {
		case LIGHT_SECTION_HEADER_BLOCK:
			if (current_section) {
				int i;
				for (i = 0; i < current_interface_count; ++i) {
					free(current_interface_list[i]);
					current_interface_list[i] = NULL;
				}
				current_interface_count = 0;
				free(current_section);
			}
			current_section = current_block;
			((uint64_t *)current_section)[2] = (uint64_t)-1; // Don't use section length for split-traces.
			reusable = 1;
			break;
		case LIGHT_INTERFACE_BLOCK:
			if (current_interface_count == current_interface_list_size) {
				current_interface_list_size *= 2;
				current_interface_list = realloc(current_interface_list, current_interface_list_size);
			}
			current_interface_list[current_interface_count] = current_block;
			current_interface_count++;
			reusable = 1;
			break;
		default:
			current_data_block_index++;
			break;
		}

		if (write(current_fd, current_block, current_block_size) != current_block_size) {
			fprintf(stderr, "Warning: write error occurred for %s: failed to write %zu bytes\n.", trace_path, current_block_size);
		}

		if (!reusable) {
			free(current_block);
		}

		if (current_data_block_index == n) {
			int i;

			close(current_fd);

			current_trace_index++;
			sprintf(trace_path, "%s_%04d.pcapng", raw_file, current_trace_index);
			current_fd = open(trace_path, O_CREAT | O_RDWR, 0666);
			if (write(current_fd, current_section, current_section[1]) != current_section[1]) {
				fprintf(stderr, "Warning: write error occurred for %s: failed to write %u bytes\n.", trace_path, current_section[1]);
			}

			for (i = 0; i < current_interface_count; ++i) {
				if (write(current_fd, current_interface_list[i], current_interface_list[i][1]) != current_interface_list[i][1]) {
					fprintf(stderr, "Warning: write error occurred for %s: failed to write %u bytes\n.", trace_path, current_interface_list[i][1]);
				}
			}
			current_data_block_index = 0;
		}
	} while (1);

	printf("Split %s into %d files.\n", file, current_fd - first_fd + 1);
	free(raw_file);

	close(current_fd);
	{
		int i;
		for (i = 0; i < current_interface_count; ++i) {
			free(current_interface_list[i]);
		}
		free(current_interface_list);
		free(current_section);
	}
	light_close_stream(stream);
}

int main(int argc, char * const argv[]) {
	// TODO: split trace in N intervals.
	// TODO: split trace in N bytes size.
	// ...
	// TODO: split trace using histogram function.
	int option = 0;
	int n = 0;

	while ((option = getopt(argc, argv, "n:t:b:f:c")) != -1) {
		switch (option) {
		case 'n':
			n = atoi(optarg);
			printf("Set packet limit to %d\n", n);
			break;
		case 't':
			break;
		case 'b':
			break;
		case 'f':
			break;
		case 'c':
			test_split_count(argc - optind, &argv[optind]);
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (n != 0) {
		int i;
		for (i = 1; i < argc; ++i) {
			if (access(argv[i], F_OK | R_OK) == 0) {
				test_split_trace(n, argv[i]);
			}
		}
	}

	return 0;
}
