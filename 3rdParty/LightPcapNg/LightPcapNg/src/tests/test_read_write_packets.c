// test_read_write_packets.c
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

#include "light_pcapng_ext.h"

#include <stdio.h>
#include <stdlib.h>

void copy_file(const char *src_path, const char *dst_path) {
	FILE *src_fd = fopen(src_path, "rb");
	FILE *dst_fd = fopen(dst_path, "wb");
	size_t n, m;
	unsigned char buff[8192];
	do {
	    n = fread(buff, 1, 8192, src_fd);
	    if (n)
	    	m = fwrite(buff, 1, n, dst_fd);
	    else
	    	m = 0;
	} while ((n > 0) && (n == m));

	fflush(dst_fd);
    fclose(src_fd);
    fclose(dst_fd);
}

int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng_t *pcapng_read = light_pcapng_open_read(file, LIGHT_FALSE);
		if (pcapng_read != NULL) {
			const char* file_append = "output_append.pcapng";
			copy_file(file, file_append);

			light_pcapng_file_info *info = light_pcang_get_file_info(pcapng_read);
			printf("file version is %d.%d\n", info->major_version, info->minor_version);
			if (info->file_comment != NULL)
				printf("file comment is: %s\n", info->file_comment);
			if (info->os_desc != NULL)
				printf("os is: %s\n", info->os_desc);
			if (info->hardware_desc != NULL)
				printf("hardware description is: %s\n", info->hardware_desc);
			if (info->user_app_desc != NULL)
				printf("user app is: %s\n", info->user_app_desc);

			const char *file_write = "output.pcapng";
			light_pcapng_t *pcapng_write = light_pcapng_open_write(file_write, light_create_default_file_info());

			light_pcapng_t *pcapng_append = light_pcapng_open_append(file_append);
			//light_pcapng_t *pcapng_write = light_pcapng_open_write(file_write, info);
			if (pcapng_write == NULL)
			{
				printf("Error occurred in opening write file\n");
				exit(1);
			}

			if (pcapng_append == NULL)
			{
				printf("Error occurred in opening append file\n");
				exit(1);
			}

			int index = 1;

			while (1) {
				light_packet_header pkt_header;
				const uint8_t *pkt_data = NULL;
				int res = 0;

				res = light_get_next_packet(pcapng_read, &pkt_header, &pkt_data);
				if (!res)
					break;

				if (pkt_data != NULL) {
					printf("packet #%d: orig_len=%d, cap_len=%d, iface_id=%d, data_link=%d, timestamp=%d.%06d\n",
							index,
							pkt_header.original_length,
							pkt_header.captured_length,
							pkt_header.interface_id,
							pkt_header.data_link,
							(int)pkt_header.timestamp.tv_sec,
							(int)pkt_header.timestamp.tv_usec);

					uint16_t comment_len = 15;
					char comment[comment_len];
					sprintf(comment, "Packet #%d", index);
					pkt_header.comment = comment;
					pkt_header.comment_length = comment_len;

					light_write_packet(pcapng_write, &pkt_header, pkt_data);
					light_write_packet(pcapng_append, &pkt_header, pkt_data);

					index++;
				}
			}

			printf("interface count in file: %d\n", info->interface_block_count);

			light_pcapng_close(pcapng_read);
			light_pcapng_close(pcapng_write);
			light_pcapng_close(pcapng_append);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return 0;
}
