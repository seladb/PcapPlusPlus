// light_pcapng_ext.h
// Created on: Nov 14, 2016

// Copyright (c) 2016

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

#ifndef LIGHT_PCAPNG_EXT_H_
#define LIGHT_PCAPNG_EXT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "light_types.h"

#include <stddef.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <Winsock2.h>
#else
#include <sys/time.h>
#endif

#ifndef NULL
#define NULL   ((void *) 0)
#endif

#define MAX_SUPPORTED_INTERFACE_BLOCKS 32

struct _light_pcapng_t;
typedef struct _light_pcapng_t light_pcapng_t;

typedef struct _light_packet_header {
	uint32_t interface_id;
	struct timeval timestamp;
	uint32_t captured_length;
	uint32_t original_length;
	uint16_t data_link;
	char* comment;
	uint16_t comment_length;
} light_packet_header;

typedef struct _light_pcapng_file_info {
	uint16_t major_version;
	uint16_t minor_version;
	char *file_comment;
	size_t file_comment_size;
	char *hardware_desc;
	size_t hardware_desc_size;
	char *os_desc;
	size_t os_desc_size;
	char *user_app_desc;
	size_t user_app_desc_size;
	size_t interface_block_count;
	uint16_t link_types[MAX_SUPPORTED_INTERFACE_BLOCKS];
	double timestamp_resolution[MAX_SUPPORTED_INTERFACE_BLOCKS];

} light_pcapng_file_info;


light_pcapng_t *light_pcapng_open_read(const char* file_path, light_boolean read_all_interfaces);

light_pcapng_t *light_pcapng_open_write(const char* file_path, light_pcapng_file_info *file_info);

light_pcapng_t *light_pcapng_open_append(const char* file_path);

light_pcapng_file_info *light_create_default_file_info();

light_pcapng_file_info *light_create_file_info(const char *os_desc, const char *hardware_desc, const char *user_app_desc, const char *file_comment);

void light_free_file_info(light_pcapng_file_info *info);

light_pcapng_file_info *light_pcang_get_file_info(light_pcapng_t *pcapng);

int light_get_next_packet(light_pcapng_t *pcapng, light_packet_header *packet_header, const uint8_t **packet_data);

void light_write_packet(light_pcapng_t *pcapng, const light_packet_header *packet_header, const uint8_t *packet_data);

void light_pcapng_close(light_pcapng_t *pcapng);

#ifdef __cplusplus
}
#endif

#endif /* LIGHT_PCAPNG_EXT_H_ */
