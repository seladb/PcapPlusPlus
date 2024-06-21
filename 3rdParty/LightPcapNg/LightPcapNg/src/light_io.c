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
	light_file fd = light_open(file_name, LIGHT_OREAD);
	DCHECK_ASSERT_EXP(fd != NULL, "could not open file", return NULL);

	size = light_size(fd);
	// DCHECK_INT(size, 0, light_stop);

	memory = calloc(size, 1);
	if (memory == NULL) {
		fprintf(stderr, "Unable to alloc %zu bytes\n", size);
		light_close(fd);
		return NULL;
	}

	// DCHECK_INT(light_read(fd, memory, size), size - 1, light_stop);
	light_read(fd, memory, size);

	head = light_read_from_memory(memory, size);

	light_close(fd);
	free(memory);

	return head;
}

int light_pcapng_to_file(const char *file_name, const light_pcapng pcapng)
{
	light_file fd = light_open(file_name, LIGHT_OWRITE);
	size_t written = 0;
	if (fd)
	{
		written = light_pcapng_to_file_stream(pcapng, fd);
		light_close(fd);
	}
	return written > 0 ? LIGHT_SUCCESS : LIGHT_FAILURE;
}

int light_pcapng_to_compressed_file(const char *file_name, const light_pcapng pcapng, int compression_level)
{
	light_file fd = light_open_compression(file_name, LIGHT_OWRITE, compression_level);
	size_t written = 0;

	if (fd)
	{
		written = light_pcapng_to_file_stream(pcapng, fd);
		light_close(fd);
	}

	return written > 0 ? LIGHT_SUCCESS : LIGHT_FAILURE;
}


light_pcapng_stream light_open_stream(const char *file_name)
{
	light_pcapng_stream pcapng = calloc(1, sizeof(struct _light_pcapng_stream));
	pcapng->file = light_open(file_name, LIGHT_OREAD); // PCPP patch

	if (pcapng->file == NULL) { // PCPP patch
		free(pcapng);
		return NULL;
	}

	pcapng->valid = 1;
	return pcapng;
}

light_pcapng light_read_stream(light_pcapng_stream pcapng)
{
	uint32_t block_type = 0;
	uint32_t block_total_length = 0;
	uint32_t *block_data = NULL;

	if (pcapng == NULL || !pcapng->valid) {
		return NULL;
	}

	if (pcapng->current_block) {
		light_pcapng_release(pcapng->current_block);
		pcapng->current_block = NULL;
	}

	// PCPP patch
	if (light_read(pcapng->file, &block_type, sizeof(block_type)) == -1 ||
			light_read(pcapng->file, &block_total_length, sizeof(block_total_length)) == -1) {
		pcapng->valid = 0;
		return NULL;
	}

	block_data = malloc(block_total_length);
	if (block_data == NULL) {
		pcapng->valid = 0;
		return NULL;
	}

	block_data[0] = block_type;
	block_data[1] = block_total_length;

	// PCPP patch
	if (light_read(pcapng->file, &block_data[2], block_total_length - 2 * sizeof(uint32_t)) == -1) {
		free(block_data);
		pcapng->valid = 0;
		return NULL;
	}

	pcapng->current_block = light_read_from_memory(block_data, block_total_length);
	free(block_data);

	return pcapng->current_block;
}

int light_close_stream(light_pcapng_stream pcapng)
{
	if (pcapng == NULL) {
		return LIGHT_BAD_STREAM;
	}

	if (pcapng->current_block) {
		light_pcapng_release(pcapng->current_block);
		pcapng->current_block = NULL;
	}

	light_close(pcapng->file); // PCPP patch
	pcapng->valid = 0;
	free(pcapng);

	return LIGHT_SUCCESS;
}
