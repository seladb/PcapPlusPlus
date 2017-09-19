// light_internal.c
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

#include "light_internal.h"

#include "light_debug.h"
#include "light_pcapng.h"
#include "light_util.h"

#include <stdlib.h>
#include <string.h>

struct _light_option *__copy_option(const struct _light_option *option)
{
	if (option == NULL) {
		return NULL;
	}

	size_t current_size = 0;
	struct _light_option *copy = calloc(1, sizeof(struct _light_option));

	PADD32(option->option_length, &current_size);

	copy->custom_option_code = option->custom_option_code;
	copy->option_length = option->option_length;
	copy->data = calloc(1, current_size);
	memcpy(copy->data, option->data, option->option_length);

	copy->next_option = __copy_option(option->next_option);

	return copy;
}

struct _light_pcapng *__copy_block(const struct _light_pcapng *pcapng, const light_boolean recursive)
{
	if (pcapng == NULL) {
		return NULL;
	}

	size_t body_length = pcapng->block_total_lenght - 2 * sizeof(pcapng->block_total_lenght) - sizeof(pcapng->block_type);
	struct _light_pcapng *pcopy = calloc(1, sizeof(struct _light_pcapng));
	size_t option_length = 0;

	pcopy->block_type = pcapng->block_type;
	pcopy->block_total_lenght = pcapng->block_total_lenght;
	pcopy->options = __copy_option(pcapng->options);
	option_length = __get_option_total_size(pcopy->options);
	body_length -= option_length;

	pcopy->block_body = calloc(body_length, 1);
	memcpy(pcopy->block_body, pcapng->block_body, body_length);

	if (recursive == LIGHT_TRUE) {
		pcopy->next_block = __copy_block(pcapng->next_block, recursive);
	}
	else {
		pcopy->next_block = NULL;
	}

	return pcopy;
}

size_t __get_option_total_size(const struct _light_option *option)
{
	size_t size = 0;

	while (option != NULL) {
		uint16_t actual_length;
		PADD32(option->option_length, &actual_length);
		size += 4 + actual_length;
		option = option->next_option;
	}

	return size;
}

uint32_t *__get_option_size(const struct _light_option *option, size_t *size)
{
	if (option == NULL) {
		*size = 0;
		return NULL;
	}

	size_t next_size;
	uint32_t *next_option = __get_option_size(option->next_option, &next_size);
	uint32_t *current_mem;
	size_t current_size = 0;

	PADD32(option->option_length, &current_size);

	current_mem = calloc(sizeof(uint32_t) + current_size + next_size, 1);
	current_mem[0] = option->custom_option_code | (option->option_length << 16);
	memcpy(&current_mem[1], option->data, current_size);
	memcpy(&current_mem[1 + current_size / 4], next_option, next_size);

	current_size += sizeof(option->custom_option_code) + sizeof(option->option_length) + next_size;
	*size = current_size;

	free(next_option);

	return current_mem;
}

light_boolean __is_section_header(const struct _light_pcapng * section)
{
	if (section != NULL) {
		if (section->block_type != LIGHT_SECTION_HEADER_BLOCK) {
			return LIGHT_FALSE;
		}
		else {
			return LIGHT_TRUE;
		}
	}

	return LIGHT_FALSE;
}

int __validate_section(struct _light_pcapng *section)
{
	if (__is_section_header(section) != LIGHT_TRUE) {
		return LIGHT_INVALID_SECTION;
	}

	struct _light_section_header *shb = (struct _light_section_header *)section->block_body;
	uint64_t size = section->block_total_lenght;
	struct _light_pcapng *next_block = section->next_block;

	while (next_block != NULL) {
		if (__is_section_header(next_block) == LIGHT_TRUE) {
			shb->section_length = size;
			return __validate_section(next_block);
		}
		else {
			size += next_block->block_total_lenght;
			next_block = next_block->next_block;
		}
	}

	shb->section_length = size;
	return LIGHT_SUCCESS;
}
