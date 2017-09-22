// light_manipulate.c
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


#if BYTE_ORDER == BIG_ENDIAN

#define LIGHT_HTONS(n) (n)
#define LIGHT_NTOHS(n) (n)
#define LIGHT_HTONL(n) (n)
#define LIGHT_NTOHL(n) (n)

#elif BYTE_ORDER == LITTLE_ENDIAN

#define LIGHT_HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define LIGHT_NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define LIGHT_HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define LIGHT_NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#else
#error "Both BIG_ENDIAN or LITTLE_ENDIAN are not #defined"
#endif


light_option light_create_option(const uint16_t option_code, uint16_t option_length, void *option_value)
{
	uint16_t size = 0;
	light_option option = calloc(1, sizeof(struct _light_option));

	PADD32(option_length, &size);
	option->custom_option_code = option_code;
	option->option_length = option_length;

	option->data = calloc(size, sizeof(uint8_t));
	memcpy(option->data, option_value, option_length);

	return option;
}

int light_add_option(light_pcapng section, light_pcapng pcapng, light_option option, light_boolean copy)
{
	size_t option_size = 0;
	light_option option_list = NULL;

	if (option == NULL) {
		return LIGHT_INVALID_ARGUMENT;
	}

	if (copy == LIGHT_TRUE) {
		option_list = __copy_option(option);
	}
	else {
		option_list = option;
	}

	option_size = __get_option_total_size(option_list);

	if (pcapng->options == NULL) {
		light_option iterator = option_list;
		while (iterator->next_option != NULL) {
			iterator = iterator->next_option;
		}

		if (iterator->custom_option_code != 0) {
			// Add terminator option.
			iterator->next_option = calloc(1, sizeof(struct _light_option));
			option_size += 4;
		}
		pcapng->options = option_list;
	}
	else {
		light_option current = pcapng->options;
		while (current->next_option && current->next_option->custom_option_code != 0) {
			current = current->next_option;
		}

		light_option opt_endofopt = current->next_option;
		current->next_option = option_list;
		option_list->next_option = opt_endofopt;
	}

	pcapng->block_total_lenght += option_size;

	if (__is_section_header(section) == 1) {
		struct _light_section_header *shb = (struct _light_section_header *)section->block_body;
		shb->section_length += option_size;
	}
	else if (section != NULL) {
		PCAPNG_WARNING("PCAPNG block is not section header!");
	}

	return LIGHT_SUCCESS;
}

int light_update_option(light_pcapng section, light_pcapng pcapng, light_option option)
{
	light_option iterator = pcapng->options;
	uint16_t old_data_size, new_data_size;

	while (iterator != NULL) {
		if (iterator->custom_option_code == option->custom_option_code) {
			break;
		}
		iterator = iterator->next_option;
	}

	if (iterator == NULL) {
		return light_add_option(section, pcapng, option, LIGHT_TRUE);
	}

	if (iterator->option_length != option->option_length) {
		PADD32(option->option_length, &new_data_size);
		PADD32(iterator->option_length, &old_data_size);

		int data_size_diff = (int)new_data_size - (int)old_data_size;
		pcapng->block_total_lenght += data_size_diff;

		if (__is_section_header(section) == 1) {
			struct _light_section_header *shb = (struct _light_section_header *)section->block_body;
			shb->section_length += data_size_diff;
		}
		else {
			PCAPNG_WARNING("PCAPNG block is not section header!");
		}

		iterator->option_length = option->option_length;
		free(iterator->data);
		iterator->data = calloc(new_data_size, sizeof(uint8_t));
	}

	memcpy(iterator->data, option->data, iterator->option_length);

	return LIGHT_SUCCESS;
}

int light_add_block(light_pcapng block, light_pcapng next_block)
{
	block->next_block = next_block;
	return LIGHT_SUCCESS;
}

int light_subcapture(const light_pcapng section, light_boolean (*predicate)(const light_pcapng), light_pcapng *subcapture)
{
	if (__is_section_header(section) == 0) {
		PCAPNG_ERROR("Invalid section header");
		return LIGHT_INVALID_SECTION;
	}

	// Root section header is automatically included into the subcapture.
	light_pcapng root = __copy_block(section, LIGHT_FALSE);
	light_pcapng iterator = root;
	light_pcapng next_block = section->next_block;

	while (next_block != NULL) {
		// Predicate functions applies to all block types, including section header blocks.
		if (!!predicate(next_block) == LIGHT_TRUE) {
			iterator->next_block = __copy_block(next_block, LIGHT_FALSE);
			iterator = iterator->next_block;
		}
		next_block = next_block->next_block;
	}

	*subcapture = root;
	return __validate_section(*subcapture);

}

typedef union {
	union {
	uint32_t raw;
	uint8_t bytes[4];
	} ipv4;
	union {
	uint64_t raw[2];
	uint16_t words[8];
	} ipv6;
} address_t;

typedef struct _flow_address {
	address_t source;
	address_t destination;
} flow_address_t;

typedef struct _flow_information {
	uint8_t version;
	flow_address_t address;
	light_pcapng section; // Deep copy.
	light_pcapng interface; // Deep copy.
	light_pcapng last_block;
	struct _flow_information *next;
} flow_information_t;

static void __extract_ipv4_address(const uint8_t *payload, flow_address_t *address)
{
	const uint8_t *address_offest = payload + 12;
	int i;

	for (i = 0; i < 4; ++i) {
		address->source.ipv4.bytes[i] = address_offest[i];
	}

	address_offest += 4;
	for (i = 0; i < 4; ++i) {
		address->destination.ipv4.bytes[i] = address_offest[i];
	}
}

static void __extract_ipv6_address(const uint8_t *payload, flow_address_t *address)
{
	const uint8_t *address_offest = payload + 8;
	int i;

	for (i = 0; i < 16; i += 2) {
		address->source.ipv6.words[i / 2] = LIGHT_NTOHS(*(uint16_t*)(&address_offest[i]));
	}

	address_offest += 16;
	for (i = 0; i < 16; i += 2) {
		address->destination.ipv6.words[i / 2] = LIGHT_NTOHS(*(uint16_t*)(&address_offest[i]));
	}
}

static light_boolean __get_ip_address(const uint8_t *payload, flow_address_t *address, uint8_t *protocol_version)
{
	uint16_t ethernet_type = LIGHT_NTOHS(*(uint16_t*)(payload + 12));
	payload += 14; // MAC address is 6 bytes long. ==> 2 x 6 + 2

	switch (ethernet_type) {
	case 0x0800: // Internet Protocol v4
	case 0x86DD: // Internet Protocol v6
		break;
	case 0x8100: // 802.1Q Virtual LAN
		payload += 4;
		break;
	case 0x9100: // 802.1Q DoubleTag
		payload += 6;
		break;
	default:
		// PCAPNG_WARNING("Unhandled Ethernet type(len)");
		return LIGHT_FALSE;
	}

	*protocol_version = (*payload >> 4) & 0b1111;

	if (*protocol_version == 4) {
		__extract_ipv4_address(payload, address);
	}
	else if (*protocol_version == 6) {
		__extract_ipv6_address(payload, address);
	}
	else {
		// PCAPNG_WARNING("Unknown protocol version");
		// fprintf(stderr, "Unknown protocol version %u for ether type 0x%X\n", *protocol_version, ethernet_type);
		return LIGHT_FALSE;
	}

	return LIGHT_TRUE;
}

static light_boolean __get_address(const light_pcapng pcapng, flow_address_t *address, uint8_t *protocol_version)
{
	uint32_t type = pcapng->block_type;

	if (type == LIGHT_ENHANCED_PACKET_BLOCK) {
		struct _light_enhanced_packet_block *epb = (struct _light_enhanced_packet_block *)pcapng->block_body;
		uint8_t *bytes = (uint8_t *)epb->packet_data;
		return __get_ip_address(bytes, address, protocol_version);
	}
	else if (type == LIGHT_SIMPLE_PACKET_BLOCK) {
		struct _light_simple_packet_block *epb = (struct _light_simple_packet_block *)pcapng->block_body;
		uint8_t *bytes = (uint8_t *)epb->packet_data;
		return __get_ip_address(bytes, address, protocol_version);
	}

	return LIGHT_FALSE;
}

static flow_information_t *__create_flow(const light_pcapng section, const light_pcapng interface, const flow_address_t *key, const uint8_t protocol_version)
{
	flow_information_t *flow = calloc(1, sizeof(flow_information_t));

	flow->version = protocol_version;
	memcpy(&flow->address, key, sizeof(flow->address));
	flow->section = __copy_block(section, LIGHT_FALSE);
	flow->interface = __copy_block(interface, LIGHT_FALSE);;
	flow->last_block = flow->interface;

	flow->section->next_block = flow->interface;

	return flow;
}

// Could be better.
static flow_information_t *__find_flow(flow_information_t *start, const flow_address_t *key, const uint8_t protocol_version)
{
	while (start != NULL) {
		if (start->version == protocol_version) {
			if (start->address.source.ipv6.raw[0] == key->source.ipv6.raw[0] && start->address.source.ipv6.raw[1] == key->source.ipv6.raw[1] &&
					start->address.destination.ipv6.raw[0] == key->destination.ipv6.raw[0] && start->address.destination.ipv6.raw[1] == key->destination.ipv6.raw[1]) {
				return start;
			}

			if (start->address.source.ipv6.raw[0] == key->destination.ipv6.raw[0] && start->address.source.ipv6.raw[1] == key->destination.ipv6.raw[1] &&
					start->address.destination.ipv6.raw[0] == key->source.ipv6.raw[0] && start->address.destination.ipv6.raw[1] == key->source.ipv6.raw[1]) {
				return start;
			}
		}
		start = start->next;
	}

	return NULL;
}

static void __append_address_information(light_pcapng section, const flow_information_t *info)
{
	light_option flow_option;
	uint8_t *option_data;
	uint16_t option_length = 1;

	if (info->version == 4) {
		option_length += 2 * sizeof(info->address.source.ipv4);
	}
	else if (info->version == 6) {
		option_length += 2 * sizeof(info->address.source.ipv6);
	}

	// Maybe I could use light_create_option instead of light_alloc_option.
	flow_option = light_alloc_option(option_length);
	flow_option->custom_option_code = LIGHT_CUSTOM_OPTION_ADDRESS_INFO;
	option_data = (uint8_t *)flow_option->data;

	memcpy(option_data, &info->version, sizeof(info->version));
	option_data += sizeof(info->version);
	if (info->version == 4) {
		memcpy(option_data, &info->address.source.ipv4, sizeof(info->address.source.ipv4));
		option_data += sizeof(info->address.source.ipv4);
		memcpy(option_data, &info->address.destination.ipv4, sizeof(info->address.destination.ipv4));
	}
	else if (info->version == 6) {
		memcpy(option_data, &info->address.source.ipv6, sizeof(info->address.source.ipv6));
		option_data += sizeof(info->address.source.ipv6);
		memcpy(option_data, &info->address.destination.ipv6, sizeof(info->address.destination.ipv6));
	}
	light_add_option(section, info->section, flow_option, LIGHT_FALSE);
}

int light_ip_flow(light_pcapng *sectionp, light_pcapng **flows, size_t *flow_count, size_t *dropped)
{
	light_pcapng section = *sectionp;
	size_t progress = 0;
	size_t limit = light_get_block_count(*sectionp);
	size_t skipped = 0;

	if (__is_section_header(section) == 0) {
		PCAPNG_ERROR("Invalid section header");
		return LIGHT_INVALID_SECTION;
	}

	light_pcapng current_section = section;
	light_pcapng current_interface = NULL;
	light_pcapng *interface_list = NULL;
	uint32_t interface_list_size = 0;

	flow_information_t *current_flow = NULL;
	flow_information_t *last_flow = NULL;
	light_pcapng current_block = section->next_block;

	*flow_count = 0;

	while (current_block != NULL) {
		uint32_t type = current_block->block_type;
		if (type == LIGHT_SECTION_HEADER_BLOCK) {
			// current_section = current_block;
			*sectionp = current_block;
			break;
		}
		else if (type == LIGHT_INTERFACE_BLOCK) {
			current_interface = current_block;
			interface_list = realloc(interface_list, (interface_list_size + 1) * sizeof(light_pcapng));
			interface_list[interface_list_size] = current_interface;
			interface_list_size++;
		}
		else if (type == LIGHT_ENHANCED_PACKET_BLOCK || type == LIGHT_SIMPLE_PACKET_BLOCK) {
			flow_address_t flow_key = {0};
			uint8_t protocol_version;
			flow_information_t *match = NULL;

			if (__get_address(current_block, &flow_key, &protocol_version) == LIGHT_FALSE) {
				skipped++;
				goto iterate;
			}

			if (current_flow == NULL) { // Beginning of the trace.
				if (type == LIGHT_SIMPLE_PACKET_BLOCK) {
					current_flow = __create_flow(current_section, current_interface, &flow_key, protocol_version);
				}
				else {
					struct _light_enhanced_packet_block *epb = (struct _light_enhanced_packet_block *)current_block->block_body;
					current_flow = __create_flow(current_section, interface_list[epb->interface_id], &flow_key, protocol_version);
				}
				match = current_flow;
				last_flow = current_flow;
				*flow_count = 1;
			}
			else {
				match = __find_flow(current_flow, &flow_key, protocol_version);
			}

			if (match == NULL) {
				if (type == LIGHT_SIMPLE_PACKET_BLOCK) {
					match = __create_flow(current_section, current_interface, &flow_key, protocol_version);
				}
				else {
					struct _light_enhanced_packet_block *epb = (struct _light_enhanced_packet_block *)current_block->block_body;
					match = __create_flow(current_section, interface_list[epb->interface_id], &flow_key, protocol_version);
				}

				last_flow->next = match;
				last_flow = match;
				*flow_count += 1;
			}
			else {
				match->last_block->next_block = __copy_block(current_block, LIGHT_FALSE);
				match->last_block = match->last_block->next_block;
			}
		}
		else {
			// TODO: Append other blocks to all flows accordingly.
		}

iterate:
		progress++;
		if (progress % 10000 == 0) {
			printf("Flow extraction progress: %.2lf [%d / %d]\n", (double)progress / limit * 100.0, (int)progress, (int)limit);
		}
		current_block = current_block->next_block;
	}

	if (dropped != NULL) {
		*dropped = skipped;
	}

	// End of trace.
	if (current_block == NULL) {
		*sectionp = NULL;
	}

	*flows = calloc(*flow_count, sizeof(light_pcapng));
	uint32_t index = 0;
	flow_information_t *iterator = current_flow;

	while (iterator != NULL) {
		(*flows)[index] = iterator->section;
		__validate_section((*flows)[index]);
		__append_address_information(iterator->section, iterator);
		index++;
		iterator = iterator->next;
	}

	while (current_flow != NULL) {
		flow_information_t *to_be_deleted = current_flow;
		current_flow = current_flow->next;
		free(to_be_deleted);
	}

	free(interface_list);

	return LIGHT_SUCCESS;
}
