// light_special.h
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

#ifndef INCLUDE_LIGHT_SPECIAL_H_
#define INCLUDE_LIGHT_SPECIAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef NULL
#define NULL   ((void *) 0)
#endif

struct _light_section_header {
	uint32_t byteorder_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
};

struct _light_interface_description_block {
	uint16_t link_type;
	uint16_t reserved;
	uint32_t snapshot_length;
};

struct _light_enhanced_packet_block {
	uint32_t interface_id;
	uint32_t timestamp_high, timestamp_low;
	uint32_t capture_packet_length;
	uint32_t original_capture_length;
	uint32_t packet_data[0];
};

struct _light_simple_packet_block {
	uint32_t original_packet_length;
	uint32_t packet_data[0];
};

struct _light_custom_nonstandard_block {
	uint32_t data_length;
	uint32_t reserved0, reserved1;
	uint32_t packet_data[0];
};

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_LIGHT_SPECIAL_H_ */
