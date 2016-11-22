// light_pcapng.c
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
#include "light_util.h"

#include <stdlib.h>
#include <string.h>

// Documentation from: https://github.com/pcapng/pcapng

static struct _light_option *__parse_options(uint32_t **memory, const int32_t max_len)
{
	if (max_len <= 0) {
		return NULL;
	}
	else {
		struct _light_option *opt = calloc(1, sizeof(struct _light_option));
		uint16_t actual_length;
		uint16_t allignment = sizeof(uint32_t);

		uint16_t *local_memory = (uint16_t*)*memory;
		uint16_t remaining_size;

		opt->custom_option_code = *local_memory++;
		opt->option_length = *local_memory++;

		actual_length = (opt->option_length % allignment) == 0 ?
				opt->option_length :
				(opt->option_length / allignment + 1) * allignment;

		if (actual_length > 0) {
			opt->data = calloc(1, actual_length);
			memcpy(opt->data, local_memory, actual_length);
			local_memory += (sizeof(**memory) / sizeof(*local_memory)) * (actual_length / allignment);
		}

		*memory = (uint32_t*)local_memory;
		remaining_size = max_len - actual_length - 2 * sizeof(*local_memory);

		if (opt->custom_option_code == 0) {
			DCHECK_ASSERT(opt->option_length, 0, light_stop);
			DCHECK_ASSERT(remaining_size, 0, light_stop);

			if (remaining_size) {
				// XXX: Treat the remaining data as garbage and discard it form the trace.
				*memory += remaining_size / sizeof(uint32_t);
			}
		}
		else {
			opt->next_option = __parse_options(memory, remaining_size);
		}

		return opt;
	}
}

// Parse memory and allocate _light_pcapng array.
static size_t __parse_mem_copy(struct _light_pcapng **iter, const uint32_t *memory, const size_t size)
{
	struct _light_pcapng *current = NULL;
	size_t bytes_read = 0;
	size_t remaining = size;
	size_t block_count = 0;

	*iter = NULL;

	while (remaining > 12) {
		const uint32_t *local_data = (const uint32_t *)(memory);

		if (current == NULL) {
			current = calloc(1, sizeof(struct _light_pcapng));
			DCHECK_NULLP(current, return block_count);

			if (*iter == NULL) {
				*iter = current;
			}
		}
		else {
			current->next_block = calloc(1, sizeof(struct _light_pcapng));
			DCHECK_NULLP(current->next_block, return block_count);

			current = current->next_block;
		}

		current->block_type = *local_data++;
		current->block_total_lenght = *local_data++;
		DCHECK_INT(((current->block_total_lenght % 4) == 0), 0, light_stop);

		switch (current->block_type)
		{
		case LIGHT_SECTION_HEADER_BLOCK:
		{
			DPRINT_HERE(LIGHT_SECTION_HEADER_BLOCK);
			struct _light_section_header *shb = calloc(1, sizeof(struct _light_section_header));
			struct _light_option *opt = NULL;
			uint32_t version;
			int32_t local_offset;

			shb->byteorder_magic = *local_data++;
			// TODO check byte order.
			version = *local_data++;
			shb->major_version = version & 0xFFFF;
			shb->minor_version = (version >> 16) & 0xFFFF;
			shb->section_length = *((uint64_t*)local_data);
			local_data += 2;

			current->block_body = (uint32_t*)shb;
			local_offset = (size_t)local_data - (size_t)memory;
			opt = __parse_options((uint32_t **)&local_data, current->block_total_lenght - local_offset - sizeof(current->block_total_lenght));
			current->options = opt;
		}
		break;

		case LIGHT_INTERFACE_BLOCK:
		{
			DPRINT_HERE(LIGHT_INTERFACE_BLOCK);
			struct _light_interface_description_block *idb = calloc(1, sizeof(struct _light_interface_description_block));
			struct _light_option *opt = NULL;
			uint32_t link_reserved = *local_data++;
			int32_t local_offset;

			idb->link_type = link_reserved & 0xFFFF;
			idb->reserved = (link_reserved >> 16) & 0xFFFF;
			idb->snapshot_length = *local_data++;
			current->block_body = (uint32_t*)idb;
			local_offset = (size_t)local_data - (size_t)memory;
			opt = __parse_options((uint32_t **)&local_data, current->block_total_lenght - local_offset - sizeof(current->block_total_lenght));
			current->options = opt;
		}
		break;

		case LIGHT_ENHANCED_PACKET_BLOCK:
		{
			DPRINT_HERE(LIGHT_ENHANCED_PACKET_BLOCK);
			struct _light_enhanced_packet_block *epb = NULL;
			struct _light_option *opt = NULL;
			uint32_t interface_id = *local_data++;
			uint32_t timestamp_high = *local_data++;
			uint32_t timestamp_low = *local_data++;
			uint32_t captured_packet_length = *local_data++;
			uint32_t original_packet_length = *local_data++;
			int32_t local_offset;
			uint32_t actual_len = 0;

			PADD32(captured_packet_length, &actual_len);

			epb = calloc(1, sizeof(struct _light_enhanced_packet_block) + actual_len);
			epb->interface_id = interface_id;
			epb->timestamp_high = timestamp_high;
			epb->timestamp_low = timestamp_low;
			epb->capture_packet_length = captured_packet_length;
			epb->original_capture_length = original_packet_length;

			memcpy(epb->packet_data, local_data, captured_packet_length); // Maybe actual_len?
			local_data += actual_len / sizeof(uint32_t);
			current->block_body = (uint32_t*)epb;
			local_offset = (size_t)local_data - (size_t)memory;
			opt = __parse_options((uint32_t **)&local_data, current->block_total_lenght - local_offset - sizeof(current->block_total_lenght));
			current->options = opt;
		}
		break;

		case LIGHT_SIMPLE_PACKET_BLOCK:
		{
			DPRINT_HERE(LIGHT_SIMPLE_PACKET_BLOCK);
			struct _light_simple_packet_block *spb = NULL;
			uint32_t original_packet_length = *local_data++;
			uint32_t actual_len = current->block_total_lenght - 2 * sizeof(current->block_total_lenght) - sizeof(current->block_type) - sizeof(original_packet_length);

			spb = calloc(1, sizeof(struct _light_enhanced_packet_block) + actual_len);
			spb->original_packet_length = original_packet_length;

			memcpy(spb->packet_data, local_data, actual_len);
			local_data += actual_len / sizeof(uint32_t);
			current->block_body = (uint32_t*)spb;
			current->options = NULL; // No options defined by the standard for this block type.
		}
		break;

		case LIGHT_CUSTOM_DATA_BLOCK:
		{
			DPRINT_HERE(LIGHT_CUSTOM_DATA_BLOCK);
			struct _light_custom_nonstandard_block *cnb = NULL;
			struct _light_option *opt = NULL;
			uint32_t len = *local_data++;
			uint32_t reserved0 = *local_data++;
			uint32_t reserved1 = *local_data++;
			int32_t local_offset;
			uint32_t actual_len = 0;

			PADD32(len, &actual_len);
			cnb = calloc(1, sizeof(struct _light_custom_nonstandard_block) + actual_len);
			cnb->data_length = len;
			cnb->reserved0 = reserved0;
			cnb->reserved1 = reserved1;

			memcpy(cnb->packet_data, local_data, len); // Maybe actual_len?
			local_data += actual_len / sizeof(uint32_t);
			current->block_body = (uint32_t*)cnb;
			local_offset = (size_t)local_data - (size_t)memory;
			opt = __parse_options((uint32_t **)&local_data, current->block_total_lenght - local_offset - sizeof(current->block_total_lenght));
			current->options = opt;
		}
		break;

		default: // Could not find registered block type. Copying data as RAW.
		{
			DPRINT_HERE(default);
			uint32_t raw_size = current->block_total_lenght - 2 * sizeof(current->block_total_lenght) - sizeof(current->block_type);
			if (raw_size > 0) {
				current->block_body = calloc(raw_size, 1);
				memcpy(current->block_body, local_data, raw_size);
				local_data += raw_size / (sizeof(*local_data));
			}
			else {
				current->block_body = NULL;
			}
		}
		break;
		}

		// Compute offset and return new link.
		// Block total length.
		DCHECK_ASSERT((bytes_read = *local_data++), current->block_total_lenght, light_stop);

		bytes_read = current->block_total_lenght;
		remaining -= bytes_read;
		memory += bytes_read / sizeof(*memory);
		block_count++;
	}

	return block_count;
}

light_pcapng light_read_from_memory(const uint32_t *memory, size_t size)
{
	struct _light_pcapng *head = NULL;
	__parse_mem_copy(&head, memory, size);
	return head;
}

static void __free_option(struct _light_option *option)
{
	if (option == NULL)
		return;

	__free_option(option->next_option);

	option->next_option = NULL;
	free(option->data);
	free(option);
}

void light_pcapng_release(light_pcapng pcapng)
{
	light_pcapng iter = pcapng;
	uint32_t block_count = light_get_block_count(pcapng);
	light_pcapng *block_pointers = calloc(block_count, sizeof(light_pcapng));
	uint32_t i = 0;

	while (iter != NULL) {
		block_pointers[i] = iter;
		i++;
		iter = iter->next_block;
	}

	for (i = 0; i < block_count; ++i) {
		__free_option(block_pointers[i]->options);
		free(block_pointers[i]->block_body);
		free(block_pointers[i]);
	}

	free(block_pointers);
}

static int __option_count(struct _light_option *option)
{
	if (option == NULL)
		return 0;

	return 1 + __option_count(option->next_option);
}

char *light_pcapng_to_string(light_pcapng pcapng)
{
	if (pcapng == NULL)
		return NULL;

	light_pcapng iter = pcapng;
	uint32_t block_count = light_get_block_count(pcapng);
	size_t buffer_size = 128 * block_count;
	char *string = calloc(buffer_size, sizeof(char));
	char *offset = string;
	DCHECK_NULLP(offset, return NULL);

	while (iter != NULL) {
		char *next = calloc(128, 1);

		sprintf(next, "---\nType = 0x%X\nLength = %u\nData Pointer = %p\nOption count = %d\n---\n",
				iter->block_type, iter->block_total_lenght, (void*)iter->block_body, __option_count(iter->options));

		memcpy(offset, next, strlen(next));
		offset += strlen(next);
		free(next);
		iter = iter->next_block;
	}

	return string;
}

uint32_t *light_pcapng_to_memory(const light_pcapng pcapng, size_t *size)
{
	light_pcapng iterator = pcapng;
	size_t bytes = light_get_size(pcapng);
	uint32_t *block_mem = calloc(bytes, 1);
	uint32_t *block_offset = block_mem;
	DCHECK_NULLP(block_offset, return NULL);

	*size = 0;
	while (iterator != NULL && bytes > 0) {
		size_t body_length = iterator->block_total_lenght - 2 * sizeof(iterator->block_total_lenght) - sizeof(iterator->block_type);
		size_t option_length;
		uint32_t *option_mem = __get_option_size(iterator->options, &option_length);
		body_length -= option_length;

		block_offset[0] = iterator->block_type;
		block_offset[1] = iterator->block_total_lenght;
		memcpy(&block_offset[2], iterator->block_body, body_length);
		memcpy(&block_offset[2 + body_length / 4], option_mem, option_length);
		block_offset[iterator->block_total_lenght / 4 - 1] = iterator->block_total_lenght;

		DCHECK_ASSERT(iterator->block_total_lenght, body_length + option_length + 3 * sizeof(uint32_t), light_stop);
		block_offset += iterator->block_total_lenght / 4;
		bytes -= iterator->block_total_lenght;
		*size += iterator->block_total_lenght;

		free(option_mem);
		iterator = iterator->next_block;
	}

	return block_mem;
}

int light_pcapng_validate(light_pcapng p0, uint32_t *p1)
{
	light_pcapng iterator0 = p0;
	uint32_t *iterator1 = p1;
	int block_count = 0;

	while (iterator0 != NULL && iterator1 != NULL) { // XXX find a better stop condition.
		if (iterator0->block_type != iterator1[0] ||
				iterator0->block_total_lenght != iterator1[1]) {
			fprintf(stderr, "Block type or length mismatch at block %d!\n", block_count);
			fprintf(stderr, "Expected type: 0x%X == 0x%X and expected length: %u == %u\n",
					iterator0->block_type, iterator1[0], iterator0->block_total_lenght, iterator1[1]);
			return 0;
		}
		size_t size = 0;
		light_pcapng next_block = iterator0->next_block;
		iterator0->next_block = NULL; // This might be quite intrusive.
		uint32_t *mem = light_pcapng_to_memory(iterator0, &size);
		if (memcmp(mem, iterator1, size) != 0) {
			iterator0->next_block = next_block;
			free(mem);
			fprintf(stderr, "Block contents mismatch!\n");
			return 0;
		}

		free(mem);
		iterator0->next_block = next_block;
		iterator0 = iterator0->next_block;

		iterator1 += iterator1[1] / sizeof(uint32_t);
		block_count++;
	}

	return 1;
}

uint32_t light_get_block_count(const light_pcapng pcapng)
{
	uint32_t count = 0;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		count++;
		iterator = iterator->next_block;
	}

	return count;
}

light_pcapng light_get_block(const light_pcapng pcapng, uint32_t index)
{
	light_pcapng iterator = pcapng;
	while (iterator != NULL && index != 0) {
		index--;
		iterator = iterator->next_block;
	}

	return iterator;
}

light_pcapng light_next_block(const light_pcapng pcapng)
{
	return pcapng == NULL ? NULL : pcapng->next_block;
}

void light_pcapng_historgram(const light_pcapng pcapng, uint32_t (*key_master)(const light_pcapng),
		light_pair **hist, size_t *size, size_t *rejected)
{
	light_pcapng iterator = pcapng;
	size_t dropped = 0;
	size_t sz = 0;
	size_t i;

	*hist = NULL;

	while (iterator != NULL) {
		uint32_t key = key_master(iterator);
		if (key != LIGHT_KEY_REJECTED) {
			int found = 0;
			for (i = 0; i < sz; ++i) {
				if ((*hist)[i].key == key) {
					found = 1;
					(*hist)[i].val++;
					break;
				}
			}

			if (found == 0) {
				*hist = realloc(*hist, (sz + 1) * sizeof(light_pair));
				(*hist)[sz].key = key;
				(*hist)[sz].val = 1;
				sz++;
			}
		}
		else {
			dropped++;
		}
		iterator = iterator->next_block;
	}

	*size = sz;

	if (rejected != NULL)
		*rejected = dropped;
}

size_t light_get_size(const light_pcapng pcapng)
{
	light_pcapng iterator = pcapng;
	size_t size = 0;

	while (iterator != NULL) {
		size += iterator->block_total_lenght;
		iterator = iterator->next_block;
	}

	return size;
}

int light_iterate(const light_pcapng pcapng, light_boolean (*stop_fn)(const light_pcapng, void *), void *args)
{
	int iterations = 0;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		if (stop_fn(iterator, args) == LIGHT_FALSE) {
			break;
		}
		iterations++;
		iterator = iterator->next_block;
	}

	return iterations;
}

int light_get_block_info(const light_pcapng pcapng, light_info info_flag, void *info_data, size_t *data_size)
{
	if (pcapng == NULL || info_flag < 0 || info_flag > LIGHT_INFO_MAX) {
		return LIGHT_INVALID_ARGUMENT;
	}

	switch (info_flag) {
	case LIGHT_INFO_TYPE:
	{
		uint32_t *type = (uint32_t *)info_data;
		if (type)
			*type = pcapng->block_type;
		if (data_size)
			*data_size = sizeof(*type);
		break;
	}
	case LIGHT_INFO_LENGTH:
	{
		uint32_t *length = (uint32_t *)info_data;
		if (length)
			*length = pcapng->block_total_lenght;
		if (data_size)
			*data_size = sizeof(*length);
		break;
	}
	case LIGHT_INFO_BODY:
	{
		uint32_t **body = (uint32_t **)info_data;
		if (body)
			*body = pcapng->block_body;
		if (data_size)
			*data_size = sizeof(*body);
		break;
	}
	case LIGHT_INFO_OPTIONS:
	{
		light_option *body = (light_option *)info_data;
		if (body)
			*body = pcapng->options;
		if (data_size)
			*data_size = sizeof(*body);
		break;
	}
	default:
		break;
	}

	return LIGHT_SUCCESS;
}
