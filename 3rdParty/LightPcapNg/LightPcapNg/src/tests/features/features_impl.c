/*
 * feature_impl.c
 *
 *  Created on: Nov 1, 2016
 *      Author: rvelea
 */

#include "features.h"

#include <light_pcapng.h>

#include <stdio.h>
#include <stdio.h>
#include <string.h>


static uint64_t my_pow(uint32_t base, uint32_t exponent)
{
	uint64_t result = 1;

	while (exponent-- > 0) {
		result = result * base;
	}

	return result;
}

feature_type_t _f_data_transferred(const light_pcapng pcapng)
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


feature_type_t _f_avg_packet_interval(const light_pcapng pcapng)
{
	feature_type_t duration;
	uint64_t resolution = 1000; // Microsecond resolution.
	int first_block = 1;
	uint64_t first_timestamp = 0;
	uint64_t current_timestamp = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;
	uint32_t enhanced_block_count = 0;

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
			enhanced_block_count++;
		}
		/*
		else if (pcapng->block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb = (struct _light_simple_packet_block *)pcapng->block_body;
		}
		*/

		iterator = light_next_block(iterator);
	}

	// Returning the duration in nanoseconds.
	if (enhanced_block_count) {
		duration = (current_timestamp - first_timestamp) * resolution / enhanced_block_count;
		return duration;
	}
	else {
		return -1;
	}
}

feature_type_t _f_address_relation(const light_pcapng pcapng)
{
	feature_type_t ret = -1;
	int i;

	light_option address_option = light_get_option(pcapng, LIGHT_CUSTOM_OPTION_ADDRESS_INFO);

	if (address_option != NULL) {
		uint8_t *label = (uint8_t *)light_get_option_data(address_option);
		if (*label == 4) {
			uint8_t source[4], destination[4];
			memcpy(source, label + 1, sizeof(uint32_t));
			memcpy(destination, label + 5, sizeof(uint32_t));

			ret = 0;
			for (i = 0; i < 4; ++i) {
				uint32_t match = !!(source[i] == destination[i]);

				if (match == 0) {
					break;
				}
				ret = (ret << 1) + match;
			}
		}
	}

	return ret;
}

#define LIGHT_HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define LIGHT_NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

static feature_type_t __solve_port(const uint8_t *payload)
{
	uint8_t protocol = payload[9];
	if (protocol != 6 && protocol != 17) {
		return 0;
	}

	uint8_t ip_header_length = (*payload) & 0b1111;
	const uint8_t *tcp_offset = payload + ip_header_length * 4;
	uint16_t source_port = LIGHT_NTOHS(((uint16_t *)tcp_offset)[0]);
	uint16_t destination_port = LIGHT_NTOHS(((uint16_t *)tcp_offset)[1]);

	return ((uint32_t)source_port << 16 | destination_port);
}

static feature_type_t __solve_protocol(const uint8_t *payload)
{
	uint8_t protocol = payload[9];
	switch (protocol)
	{
	case 1: // ICMP
		return 1;
	case 2: // IGMP
		return 2;
	case 6: // TCP
		return 64;
	case 17: // UDP
		return 32;
	default:
		return 0;
	}
}

static feature_type_t __ip_level(const uint8_t *payload, feature_type_t (*fn)(const uint8_t *))
{
	uint32_t protocol_version;
	feature_type_t result = 0;
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
		return 0;
	}

	protocol_version = (*payload >> 4) & 0b1111;

	if (protocol_version == 4) {
		// IPv4
		result = fn(payload);
	}
	else if (protocol_version == 6) {
		// IPv6
	}
	else {
		// PCAPNG_WARNING("Unknown protocol version");
		return 0;
	}

	return result;
}

feature_type_t _f_protocol(const light_pcapng pcapng)
{
	feature_type_t ret = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			ret |= __ip_level((uint8_t *)epb->packet_data, __solve_protocol);
		}
		else if (block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &spb, NULL);
			ret |= __ip_level((uint8_t *)spb->packet_data, __solve_protocol);
		}

		iterator = light_next_block(iterator);
	}

	return ret;
}

feature_type_t _f_packet_count(const light_pcapng pcapng)
{
	feature_type_t ret = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_ENHANCED_PACKET_BLOCK || block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			ret++;
		}
		iterator = light_next_block(iterator);
	}

	return ret;
}

static feature_type_t _f_application_port(const light_pcapng pcapng, uint16_t port)
{
	feature_type_t ret = 0;
	uint32_t block_type;
	light_pcapng iterator = pcapng;

	while (iterator != NULL) {
		light_get_block_info(iterator, LIGHT_INFO_TYPE, &block_type, NULL);
		if (block_type == LIGHT_ENHANCED_PACKET_BLOCK) {
			struct _light_enhanced_packet_block *epb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &epb, NULL);
			ret = __ip_level((uint8_t *)epb->packet_data, __solve_port);
		}
		else if (block_type == LIGHT_SIMPLE_PACKET_BLOCK) {
			struct _light_simple_packet_block *spb;
			light_get_block_info(iterator, LIGHT_INFO_BODY, &spb, NULL);
			ret = __ip_level((uint8_t *)spb->packet_data, __solve_port);
		}
		else {
			ret = 0;
		}

		uint16_t source = (ret >> 16);
		uint16_t destination = (ret & 0xFFFF);

		if (port == source || port == destination) {
			return 1;
		}

		iterator = light_next_block(iterator);
	}

	return 0;
}

feature_type_t _f_application_port_https(const light_pcapng pcapng)
{
	return _f_application_port(pcapng, 443);
}

feature_type_t _f_application_port_http(const light_pcapng pcapng)
{
	return _f_application_port(pcapng, 80) + _f_application_port(pcapng, 8080) + _f_application_port(pcapng, 8008);
}
