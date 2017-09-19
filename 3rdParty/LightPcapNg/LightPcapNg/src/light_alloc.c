// light_alloc.c
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

#include "light_internal.h"
#include "light_util.h"

#include <stdlib.h>
#include <string.h>

light_option light_alloc_option(uint16_t option_length)
{
	struct _light_option *option = calloc(1, sizeof(struct _light_option));
	uint16_t actual_size = 0;

	option->option_length = option_length;

	PADD32(option_length, &actual_size);
	if (actual_size != 0) {
		option->data = calloc(1, actual_size);
	}

	return option;
}

light_pcapng light_alloc_block(uint32_t block_type, const uint32_t *block_body, uint32_t block_body_length)
{
	struct _light_pcapng *pcapng_block = calloc(1, sizeof(struct _light_pcapng));
	uint32_t actual_size = 0;
	int32_t block_body_size;

	pcapng_block->block_type = block_type;

	PADD32(block_body_length, &actual_size);

	pcapng_block->block_total_lenght = actual_size; // This value MUST be a multiple of 4.
	block_body_size = actual_size - 2 * sizeof(pcapng_block->block_total_lenght) - sizeof(pcapng_block->block_type);

	if (block_body_size > 0) {
		pcapng_block->block_body = calloc(1, block_body_size);
		memcpy(pcapng_block->block_body, block_body, block_body_size);
	}

	pcapng_block->next_block = NULL;
	pcapng_block->options = NULL;

	return pcapng_block;
}

void light_free_option(light_option option)
{
	free(option->data);
	free(option);
}

void light_free_block(light_pcapng pcapng)
{
	free(pcapng);
	free(pcapng->block_body);
}


