// light_pcapng.h
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

#ifndef LIGHT_PCAPNG_H_
#define LIGHT_PCAPNG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "light_special.h"
#include "light_types.h"

#define LIGHT_SECTION_HEADER_BLOCK  0x0A0D0D0A
#define LIGHT_INTERFACE_BLOCK       0x00000001
#define LIGHT_ENHANCED_PACKET_BLOCK 0x00000006
#define LIGHT_SIMPLE_PACKET_BLOCK   0x00000003

#define LIGHT_CUSTOM_DATA_BLOCK     0xB16B00B5
#define LIGHT_UNKNOWN_DATA_BLOCK    0xDEADBEEF

// "Official" option codes
#define LIGHT_OPTION_IF_TSRESOL            0x0009
#define LIGHT_OPTION_COMMENT               0x0001
#define LIGHT_OPTION_SHB_HARDWARE          0x0002
#define LIGHT_OPTION_SHB_OS                0x0003
#define LIGHT_OPTION_SHB_USERAPPL          0x0004
#define LIGHT_OPTION_IF_TSRESOL            0x0009

// Custom option codes
#define LIGHT_CUSTOM_OPTION_ADDRESS_INFO   0xADD4
#define LIGHT_CUSTOM_OPTION_FEATURE_U64    0x0064

#define BYTE_ORDER_MAGIC            0x1A2B3C4D

#define LIGHT_KEY_REJECTED          0xFFFFFFFF

/////////////////////////////// /////////// ERROR CODES //////////////////////////////////////////////

#define LIGHT_SUCCESS           0
#define LIGHT_INVALID_SECTION  -1
#define LIGHT_OUT_OF_MEMORY    -2
#define LIGHT_INVALID_ARGUMENT -3
#define LIGHT_NOT_FOUND        -4

/////////////////////////////// STANDARD PCAPNG STRUCTURES & FUNCTIONS ///////////////////////////////

typedef struct _light_pcapng *light_pcapng;
typedef struct _light_option *light_option;

typedef struct _light_pair {
	uint32_t key;
	uint32_t val;
} light_pair;

// Read/Write Functions
light_pcapng light_read_from_path(const char *file_name);
light_pcapng light_read_from_memory(const uint32_t *memory, size_t size);
uint32_t *light_pcapng_to_memory(const light_pcapng pcapng, size_t *size);
int light_pcapng_to_file(const char *file_name, const light_pcapng pcapng);
void light_pcapng_release(light_pcapng pcapng);

// For Debugging Purposes
char *light_pcapng_to_string(light_pcapng pcapng);
uint32_t light_get_block_count(const light_pcapng pcapng);
light_pcapng light_get_block(const light_pcapng pcapng, uint32_t index);
light_pcapng light_next_block(const light_pcapng pcapng);
size_t light_get_size(const light_pcapng pcapng);
void light_pcapng_historgram(const light_pcapng pcapng, uint32_t (*key_master)(const light_pcapng),
		light_pair **hist, size_t *size, size_t *rejected);
int light_get_block_info(const light_pcapng pcapng, light_info info_flag, void *info_data, size_t *data_size);
light_option light_get_option(const light_pcapng pcapng, uint16_t option_code);
uint16_t light_get_option_code(const light_option option);
const light_option light_get_next_option(const light_option option);
uint32_t *light_get_option_data(const light_option option);
uint16_t light_get_option_length(const light_option option);

// Manipulation Functions
light_option light_create_option(const uint16_t option_code, const uint16_t option_length, void *option_value);
int light_add_option(light_pcapng section, light_pcapng pcapng, light_option option, light_boolean copy);
int light_update_option(light_pcapng section, light_pcapng pcapng, light_option option);
int light_add_block(light_pcapng block, light_pcapng next_block);
int light_subcapture(const light_pcapng section, light_boolean (*predicate)(const light_pcapng), light_pcapng *subcapture);
int light_iterate(const light_pcapng pcapng, light_boolean (*stop_fn)(const light_pcapng, void *), void *args);
int light_ip_flow(light_pcapng *sectionp, light_pcapng **flows, size_t *flow_count, size_t *dropped);

// Allocation and free functions
light_option light_alloc_option(uint16_t option_length);
light_pcapng light_alloc_block(uint32_t block_type, const uint32_t *block_body, uint32_t block_body_length);
void light_free_option(light_option option);
void light_free_block(light_pcapng pcapng);

// Advanced Interaction
typedef enum {
	LIGHT_FEATURE_BITMASK = 0,
	LIGHT_FEATURE_BYTE = 1,
	LIGHT_FEATURE_SHORT = 2,
	LIGHT_FEATURE_FLOAT = 4,
	LIGHT_FEATURE_DOUBLE = 5,
} light_feature_t;
int light_section_feature_extraction(const light_pcapng section, int (*extractor)(const light_pcapng, void *, size_t),
		void **feature_vector, const size_t feature_vector_size, const light_feature_t type);

/////////////////////////////// CONTINUOUS MEMORY BLOCK STRUCTURES & FUNCTIONS ///////////////////////////////

typedef struct _light_pcapng_mem *light_pcapng_mem;

// Continuous Memory Functions
struct _light_pcapng_mem *light_no_copy_from_memory(uint32_t *memory, size_t size, int is_owner);
void light_pcapng_mem_release(struct _light_pcapng_mem *pcapng);

#ifdef __cplusplus
}
#endif

#endif /* LIGHT_PCAPNG_H_ */
