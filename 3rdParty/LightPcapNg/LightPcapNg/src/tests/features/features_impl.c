/*
 * feature_impl.c
 *
 *  Created on: Nov 1, 2016
 *      Author: rvelea
 */

#include "features.h"

#include <light_pcapng.h>

#include <stdio.h>

static uint64_t my_pow(uint32_t base, uint32_t exponent)
{
	uint64_t result = 1;

	while (exponent-- > 0) {
		result = result * base;
	}

	return result;
}

feature_type_t _f_data_transfered(const light_pcapng pcapng)
{
	feature_type_t bytes = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			bytes += epb->original_capture_length;
		}
		else if (block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &spb, NULL);
			bytes += spb->original_packet_length;
		}

		iterator = light_next_block(iterator);
	}

	return bytes;
}

feature_type_t _f_trace_duration(const light_pcapng pcapng)
{
	feature_type_t duration;
	uint64_t resolution = 1000; // Microsecond resolution.
	int first_block = 1;
	uint64_t first_timestamp = 0;
	uint64_t current_timestamp = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_INTERFACE_BLOCK) {
			light_option timestamp_resolution = light_get_option(iterator, LIGHT_OPTION_IF_TSRESOL);
			if (timestamp_resolution != NULL) {
				uint8_t *interface_resolution = (uint8_t *)light_get_option_data(timestamp_resolution);
				uint8_t value = *interface_resolution & 0x7F;

				if ((*interface_resolution & 0x80) == 0) { // Resolution is negative power of 10.
					resolution = 1000000000 / my_pow(10, value);
				}
				else { // Resolution is negative power of 2.
					resolution = 1000000000 / my_pow(2, value);
				}

				if (resolution == 0) {
					fprintf(stderr, "Invalid resolution: %u\n", value);
					resolution = 1000;
				}
			}
		}
		else if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			current_timestamp = ((uint64_t)epb->timestamp_high << 32) + epb->timestamp_low;
			if (first_block == 1) {
				first_timestamp = current_timestamp;
				first_block = 0;
			}
			else if (first_timestamp > current_timestamp) {
				fprintf(stderr, "We are going back in time!\n");
				first_timestamp = current_timestamp;
			}
		}
		/*
		else if (pcapng->block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb = (struct _light_simple_packet_block *)pcapng->block_body;
		}
		*/

		iterator = light_next_block(iterator);
	}

	// Returning the duration in nanoseconds.
	duration = (current_timestamp - first_timestamp) * resolution;
	return duration;
}
