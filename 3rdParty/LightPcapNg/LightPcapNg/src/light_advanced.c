// light_advanced.c
// Created on: Aug 19, 2016

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
#include "light_pcapng.h"

#include <stdlib.h>

int light_section_feature_extraction(const light_pcapng section, int (*extractor)(const light_pcapng, void *, size_t),
		void **feature_vector, const size_t feature_vector_size, const light_feature_t type)
{
	light_pcapng iterator;

	if (__is_section_header(section) != LIGHT_TRUE) {
		return LIGHT_INVALID_SECTION;
	}

	switch(type) {
	case LIGHT_FEATURE_BITMASK:
		*feature_vector = calloc(1, sizeof(uint64_t));
		break;
	case LIGHT_FEATURE_BYTE:
		*feature_vector = calloc(feature_vector_size, sizeof(uint8_t));
		break;
	case LIGHT_FEATURE_SHORT:
		*feature_vector = calloc(feature_vector_size, sizeof(uint16_t));
		break;
	case LIGHT_FEATURE_FLOAT:
		*feature_vector = calloc(feature_vector_size, sizeof(float));
		break;
	case LIGHT_FEATURE_DOUBLE:
		*feature_vector = calloc(feature_vector_size, sizeof(double));
		break;
	}

	if (*feature_vector == NULL) {
		return LIGHT_OUT_OF_MEMORY;
	}

	extractor(section, *feature_vector, feature_vector_size);
	iterator = section->next_block;
	while (iterator != NULL && __is_section_header(iterator) != LIGHT_TRUE) {
		extractor(iterator, *feature_vector, feature_vector_size);
		iterator = iterator->next_block;
	}

	return LIGHT_SUCCESS;
}
