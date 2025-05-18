// light_pcapng_cont.c
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

#include "light_debug.h"
#include "light_internal.h"

#include <stdlib.h>
#include <string.h>

static void __parse_mem_inplace(struct _light_pcapng_mem *head, uint32_t *memory, size_t size, int is_owner)
{
	uint32_t tmp_block_len;
	size_t tmp_size = size;
	uint32_t *iterator = memory;;
	size_t i;

	head->mem = memory;
	head->mem_size = size;
	head->owner = is_owner;

	head->block_count = 0;
	while (tmp_size > 0) {
		head->block_count++;
		tmp_block_len = iterator[1];
		tmp_size -= tmp_block_len;
		iterator += tmp_block_len / sizeof(iterator[0]);
	}

	head->mem_blocks = calloc(head->block_count, sizeof(uint32_t *));
	iterator = memory;
	for (i = 0; i < head->block_count; ++i) {
		head->mem_blocks[i] = iterator;
		iterator += iterator[1] / sizeof(iterator[0]);
	}
}

struct _light_pcapng_mem *light_no_copy_from_memory(uint32_t *memory, size_t size, int is_owner)
{
	struct _light_pcapng_mem *head = NULL;
	head = calloc(1, sizeof(struct _light_pcapng_mem));
	__parse_mem_inplace(head, memory, size, is_owner);
	return head;
}

void light_pcapng_mem_release(struct _light_pcapng_mem *pcapng)
{
	if (pcapng != NULL) {
		free(pcapng->mem_blocks);

		if (pcapng->owner != 0)
			free(pcapng->mem);

		free(pcapng);
	}
}
