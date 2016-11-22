// light_internal.h
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

#ifndef INCLUDE_LIGHT_INTERNAL_H_
#define INCLUDE_LIGHT_INTERNAL_H_

#include "light_types.h"

#include <stddef.h>
#include <stdint.h>

struct _light_pcapng {
	uint32_t block_type;
	uint32_t block_total_lenght;
	uint32_t *block_body;
	struct _light_option *options;
	struct _light_pcapng *next_block;
};

struct _light_option {
	uint16_t custom_option_code;
	uint16_t option_length;
	// uint32_t PEN;
	uint32_t *data;
	struct _light_option *next_option;
};

struct _light_pcapng_mem {
	uint32_t *mem;
	uint32_t **mem_blocks;
	size_t mem_size;
	size_t block_count;
	int owner;
};

// Private Functions
struct _light_pcapng *__copy_block(const struct _light_pcapng *pcapng, const light_boolean recursive);
struct _light_option *__copy_option(const struct _light_option *option);
size_t __get_option_total_size(const struct _light_option *option);
uint32_t *__get_option_size(const struct _light_option *option, size_t *size);
light_boolean __is_section_header(const struct _light_pcapng *section);
int __validate_section(struct _light_pcapng *section);

#endif /* INCLUDE_LIGHT_INTERNAL_H_ */
