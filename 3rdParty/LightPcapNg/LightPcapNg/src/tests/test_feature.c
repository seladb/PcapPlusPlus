// test_feature.c
// Created on: Oct 12, 2016

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

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

enum feature_description {
	FEATURE_PROTOCOL = 0,
	FEATURE_LENGTH = 1,
};

static void print_interface(const struct _light_interface_description_block *idb)
{
	printf("Interface link type = 0x%X\n", idb->link_type);
	printf("Interface snapshot length = %u\n", idb->snapshot_length);
}

static void __handle_tcp(uint8_t *packet_data)
{
	uint16_t source_port = ntohs(((uint16_t *)packet_data)[0]);
	uint16_t destination_port = ntohs(((uint16_t *)packet_data)[1]);
	printf("TCP source: %u, destination: %u\n", source_port, destination_port);
}

static void __handle_ipv4(uint8_t *packet_data, uint8_t header_len)
{
	uint16_t total_length = ntohs(((uint16_t *)packet_data)[1]);
	uint8_t protocol = packet_data[9];
	int i = 12;

	printf("Packet total length = %u, protocol = %u\n", total_length, protocol);

	printf("Source address: ");
	for (; i < 16; ++i) {
		printf("%u.", packet_data[i]);
	}
	printf("\n");

	printf("Destination address: ");
	for (; i < 20; ++i) {
		printf("%u.", packet_data[i]);
	}
	printf("\n");

	if (protocol == 6) {
		__handle_tcp(packet_data + header_len * 4);
	}
}

static int extractor(const light_pcapng packet, void *data, size_t feature_count)
{
	float *features = (float *)data;
	uint32_t *body = NULL;
	size_t body_size = 0;
	uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;
	uint8_t protocol_version;
	uint8_t ip_header_length;
	uint16_t ethernet_type;
	struct _light_enhanced_packet_block *epb;
	uint8_t *octets;
	int i;

	light_get_block_info(packet, LIGHT_INFO_BODY, &body, &body_size);
	light_get_block_info(packet, LIGHT_INFO_TYPE, &type, NULL);

	if (type == LIGHT_INTERFACE_BLOCK) {
		struct _light_interface_description_block *idb = (struct _light_interface_description_block *)body;
		print_interface(idb);
		return 0;
	}
	else if (type != LIGHT_ENHANCED_PACKET_BLOCK /*&& type != LIGHT_SIMPLE_PACKET_BLOCK*/) {
		return 0;
	}

	epb = (struct _light_enhanced_packet_block *)body;
	octets = (uint8_t *)epb->packet_data;

	printf("HWaddr0: "); // Print destination address.
	for (i = 0; i < 6; ++i) {
		uint8_t byte = *octets++;
		printf("%x:", byte);
	}
	printf("\n");

	printf("HWaddr1: "); // Print host address.
	for (i = 0; i < 6; ++i) {
		uint8_t byte = *octets++;
		printf("%x:", byte);
	}
	printf("\n");

	ethernet_type = ntohs(*(uint16_t*)(octets));
	octets += 2; // Skip rest of Ethernet header.

	switch (ethernet_type) {
	case 0x0800: // Internet Protocol v4
	case 0x86DD: // Internet Protocol v6
		break;
	case 0x8100: // 802.1Q Virtual LAN
		octets += 4;
		break;
	case 0x9100: // 802.1Q DoubleTag
		octets += 6;
		break;
	default:
		printf("Unhandled Ethernet type(len) 0x%X\n", ethernet_type);
		return 0;
	}

	ip_header_length = (*octets) & 0b1111;
	protocol_version = (*octets >> 4) & 0b1111;

	if (protocol_version == 4) {
		__handle_ipv4(octets, ip_header_length);
		features[FEATURE_PROTOCOL] = 1.0;
	}
	else {
		// TODO;
		printf("Protocol version = %u\n", protocol_version);
	}

	printf("\n");
	return 0;
}

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng pcapng = light_read_from_path(file);
		if (pcapng != NULL) {
			float *features = NULL;
			int ret = light_section_feature_extraction(pcapng, extractor, (void **)&features, FEATURE_LENGTH, LIGHT_FEATURE_FLOAT);

			if (ret != LIGHT_SUCCESS) {
				fprintf(stderr, "Error while extracting features for %s\n", file);
				goto release;
			}

			// TODO: Print or handle features.
release:
			light_pcapng_release(pcapng);
			free(features);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return 0;
}
