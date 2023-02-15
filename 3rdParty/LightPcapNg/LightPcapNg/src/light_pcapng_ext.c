// light_pcapng_ext.c
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
#include "light_pcapng.h"
#include "light_platform.h"
#include "light_debug.h"
#include "light_util.h"
#include "light_internal.h"
#include "light_debug.h"

#include <stdlib.h>
#include <string.h>


struct _light_pcapng_t
{
	light_pcapng pcapng;
	light_pcapng_file_info *file_info;
	light_file file;
};

static light_pcapng_file_info *__create_file_info(light_pcapng pcapng_head)
{
	uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;

	if (pcapng_head == NULL)
		return NULL;

	light_pcapng iter = pcapng_head;

	light_get_block_info(iter, LIGHT_INFO_TYPE, &type, NULL);

	if (type != LIGHT_SECTION_HEADER_BLOCK)
		return NULL;

	light_pcapng_file_info *file_info = calloc(1, sizeof(light_pcapng_file_info));

	struct _light_section_header* section_header;

	light_get_block_info(iter, LIGHT_INFO_BODY, &section_header, NULL);
	file_info->major_version = section_header->major_version;
	file_info->minor_version = section_header->minor_version;

	light_option opt = light_get_option(iter, LIGHT_OPTION_SHB_HARDWARE);
	if (opt != NULL)
	{
		file_info->hardware_desc_size = light_get_option_length(opt);
		file_info->hardware_desc = calloc(file_info->hardware_desc_size+1, sizeof(char));
		memcpy(file_info->hardware_desc, (char*)light_get_option_data(opt), file_info->hardware_desc_size);
		file_info->hardware_desc[file_info->hardware_desc_size] = '\0';
	}
	else
	{
		file_info->hardware_desc_size = 0;
		file_info->hardware_desc = NULL;
	}

	opt = light_get_option(iter, LIGHT_OPTION_SHB_OS);
	if (opt != NULL)
	{
		file_info->os_desc_size = light_get_option_length(opt);
		file_info->os_desc = calloc(file_info->os_desc_size+1, sizeof(char));
		memcpy(file_info->os_desc, (char*)light_get_option_data(opt), file_info->os_desc_size);
		file_info->os_desc[file_info->os_desc_size] = '\0';
	}
	else
	{
		file_info->os_desc_size = 0;
		file_info->os_desc = NULL;
	}

	opt = light_get_option(iter, LIGHT_OPTION_SHB_USERAPPL);
	if (opt != NULL)
	{
		file_info->user_app_desc_size = light_get_option_length(opt);
		file_info->user_app_desc = calloc(file_info->user_app_desc_size+1, sizeof(char));
		memcpy(file_info->user_app_desc, (char*)light_get_option_data(opt), file_info->user_app_desc_size);
		file_info->user_app_desc[file_info->user_app_desc_size] = '\0';
	}
	else
	{
		file_info->user_app_desc_size = 0;
		file_info->user_app_desc = NULL;
	}

	opt = light_get_option(iter, LIGHT_OPTION_COMMENT);
	if (opt != NULL)
	{
		file_info->file_comment_size = light_get_option_length(opt);
		file_info->file_comment = calloc(file_info->file_comment_size+1, sizeof(char));
		memcpy(file_info->file_comment, (char*)light_get_option_data(opt), file_info->file_comment_size);
		file_info->file_comment[file_info->file_comment_size] = '\0';
	}
	else
	{
		file_info->file_comment_size = 0;
		file_info->file_comment = NULL;
	}

	file_info->interface_block_count = 0;

	return file_info;
}

static double __power_of(int x, int y)
{
	int i;
	double res = 1;

	if (y < 0)
		return 1 / __power_of(x, -y);

	for (i = 0; i < y; i++)
		res *= x;

	return res;
}

static void __append_interface_block_to_file_info(const light_pcapng interface_block, light_pcapng_file_info* info)
{
	struct _light_interface_description_block* interface_desc_block;
	light_option ts_resolution_option = NULL;

	if (info->interface_block_count >= MAX_SUPPORTED_INTERFACE_BLOCKS)
		return;

	light_get_block_info(interface_block, LIGHT_INFO_BODY, &interface_desc_block, NULL);

	ts_resolution_option = light_get_option(interface_block, LIGHT_OPTION_IF_TSRESOL);
	if (ts_resolution_option == NULL)
	{
		info->timestamp_resolution[info->interface_block_count] = __power_of(10,-6);
	}
	else
	{
		uint8_t* raw_ts_data = (uint8_t*)light_get_option_data(ts_resolution_option);
		if (*raw_ts_data < 128)
			info->timestamp_resolution[info->interface_block_count] = __power_of(10, (-1)*(*raw_ts_data));
		else
			info->timestamp_resolution[info->interface_block_count] = __power_of(2, (-1)*((*raw_ts_data)-128));
	}

	info->link_types[info->interface_block_count++] = interface_desc_block->link_type;
}

static light_boolean __is_open_for_write(const struct _light_pcapng_t* pcapng)
{
	if (pcapng->file != NULL)
		return LIGHT_TRUE;

	return LIGHT_FALSE;
}

// if timestamp of the packet contains number of seconds, which exceeds a limit, with which it will be possible to
// write it with nsec precision, we invalidate that timestamp, but still write the packet; this makes sense, as
// such timestamps (> 18446744073) refer to year (> 2554), so we can allow ourselves not to support them for now
static const uint64_t MAXIMUM_PACKET_SECONDS_VALUE = UINT64_MAX / 1000000000;

light_pcapng_t *light_pcapng_open_read(const char* file_path, light_boolean read_all_interfaces)
{
	DCHECK_NULLP(file_path, return NULL);

	light_pcapng_t *pcapng = calloc(1, sizeof(struct _light_pcapng_t));
	pcapng->file = light_open(file_path, LIGHT_OREAD);
	DCHECK_ASSERT_EXP(pcapng->file != NULL, "could not open file", return NULL);

	//The first thing inside an NG capture is the section header block
	//When the file is opened we need to go ahead and read that out
	light_read_record(pcapng->file,&pcapng->pcapng);
	//Prase stuff out of the section header
	pcapng->file_info = __create_file_info(pcapng->pcapng);

	//If they requested to read all interfaces we must fast forward through file and find them all up front
	if (read_all_interfaces)
	{
		//Bookmark our current location
		light_file_pos_t currentPos = light_get_pos(pcapng->file);
		while (pcapng->pcapng != NULL)
		{
			light_read_record(pcapng->file, &pcapng->pcapng);
			uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;
			light_get_block_info(pcapng->pcapng, LIGHT_INFO_TYPE, &type, NULL);
			if (type == LIGHT_INTERFACE_BLOCK)
				__append_interface_block_to_file_info(pcapng->pcapng, pcapng->file_info);
		}
		//Should be at and of file now, if not something broke!!!
		if (!light_eof(pcapng->file))
		{
			light_pcapng_release(pcapng->pcapng);
			return NULL;
		}
		//Ok got to end of file so reset back to bookmark
		light_set_pos(pcapng->file, currentPos);
	}

	light_pcapng_release(pcapng->pcapng);
	pcapng->pcapng = NULL;

	return pcapng;
}

light_pcapng_t *light_pcapng_open_write(const char* file_path, light_pcapng_file_info *file_info, int compression_level)
{
	DCHECK_NULLP(file_info, return NULL);
	DCHECK_NULLP(file_path, return NULL);

	light_pcapng_t *pcapng = calloc(1, sizeof(struct _light_pcapng_t));

	pcapng->file = light_open_compression(file_path, LIGHT_OWRITE, compression_level);
	pcapng->file_info = file_info;

	DCHECK_ASSERT_EXP(pcapng->file != NULL, "could not open output file", return NULL);

	pcapng->pcapng = NULL;

	struct _light_section_header section_header;
	section_header.byteorder_magic = BYTE_ORDER_MAGIC;
	section_header.major_version = file_info->major_version;
	section_header.minor_version = file_info->minor_version;
	section_header.section_length = 0xFFFFFFFFFFFFFFFFULL;
	light_pcapng blocks_to_write = light_alloc_block(LIGHT_SECTION_HEADER_BLOCK, (const uint32_t*)&section_header, sizeof(section_header)+3*sizeof(uint32_t));

	if (file_info->file_comment_size > 0)
	{
		light_option new_opt = light_create_option(LIGHT_OPTION_COMMENT, file_info->file_comment_size, file_info->file_comment);
		light_add_option(blocks_to_write, blocks_to_write, new_opt, LIGHT_FALSE);
	}

	if (file_info->hardware_desc_size > 0)
	{
		light_option new_opt = light_create_option(LIGHT_OPTION_SHB_HARDWARE, file_info->hardware_desc_size, file_info->hardware_desc);
		light_add_option(blocks_to_write, blocks_to_write, new_opt, LIGHT_FALSE);
	}

	if (file_info->os_desc_size > 0)
	{
		light_option new_opt = light_create_option(LIGHT_OPTION_SHB_OS, file_info->os_desc_size, file_info->os_desc);
		light_add_option(blocks_to_write, blocks_to_write, new_opt, LIGHT_FALSE);
	}

	if (file_info->user_app_desc_size > 0)
	{
		light_option new_opt = light_create_option(LIGHT_OPTION_SHB_USERAPPL, file_info->user_app_desc_size, file_info->user_app_desc);
		light_add_option(blocks_to_write, blocks_to_write, new_opt, LIGHT_FALSE);
	}

	light_pcapng next_block = blocks_to_write;
	int i = 0;
	for (i = 0; i < file_info->interface_block_count; i++)
	{
		struct _light_interface_description_block interface_block;
		interface_block.link_type = file_info->link_types[i];
		interface_block.reserved = 0;
		interface_block.snapshot_length = 0;

		light_pcapng iface_block_pcapng = light_alloc_block(LIGHT_INTERFACE_BLOCK, (const uint32_t*)&interface_block, sizeof(struct _light_interface_description_block)+3*sizeof(uint32_t));
		light_add_block(next_block, iface_block_pcapng);
		next_block = iface_block_pcapng;
	}

	light_pcapng_to_file_stream(blocks_to_write, pcapng->file);


	light_pcapng_release(blocks_to_write);

	return pcapng;
}

light_pcapng_t *light_pcapng_open_append(const char* file_path)
{
	DCHECK_NULLP(file_path, return NULL);

	light_pcapng_t *pcapng = light_pcapng_open_read(file_path, LIGHT_TRUE);
	DCHECK_NULLP(pcapng, return NULL);
	light_close(pcapng->file);

	pcapng->file = light_open(file_path, LIGHT_OAPPEND);
	DCHECK_NULLP(pcapng->file, return NULL);

	light_pcapng_release(pcapng->pcapng);
	pcapng->pcapng = NULL;

	return pcapng;
}

light_pcapng_file_info *light_create_default_file_info()
{
	light_pcapng_file_info *default_file_info = calloc(1, sizeof(light_pcapng_file_info));
	memset(default_file_info, 0, sizeof(light_pcapng_file_info));
	default_file_info->major_version = 1;
	return default_file_info;
}

light_pcapng_file_info *light_create_file_info(const char *os_desc, const char *hardware_desc, const char *user_app_desc, const char *file_comment)
{
	light_pcapng_file_info *info = light_create_default_file_info();

	if (os_desc != NULL && strlen(os_desc) > 0)
	{
		size_t os_len = strlen(os_desc);
		info->os_desc = calloc(os_len, sizeof(char));
		memcpy(info->os_desc, os_desc, os_len);
		info->os_desc_size = os_len;
	}

	if (hardware_desc != NULL && strlen(hardware_desc) > 0)
	{
		size_t hw_len = strlen(hardware_desc);
		info->hardware_desc = calloc(hw_len, sizeof(char));
		memcpy(info->hardware_desc, hardware_desc, hw_len);
		info->hardware_desc_size = hw_len;
	}

	if (user_app_desc != NULL && strlen(user_app_desc) > 0)
	{
		size_t app_len = strlen(user_app_desc);
		info->user_app_desc = calloc(app_len, sizeof(char));
		memcpy(info->user_app_desc, user_app_desc, app_len);
		info->user_app_desc_size = app_len;
	}

	if (file_comment != NULL && strlen(file_comment) > 0)
	{
		size_t comment_len = strlen(file_comment);
		info->file_comment = calloc(comment_len, sizeof(char));
		memcpy(info->file_comment, file_comment, comment_len);
		info->file_comment_size = comment_len;
	}

	return info;
}

void light_free_file_info(light_pcapng_file_info *info)
{
	if (info->user_app_desc != NULL)
		free(info->user_app_desc);

	if (info->file_comment != NULL)
		free(info->file_comment);

	if (info->hardware_desc != NULL)
		free(info->hardware_desc);

	if (info->os_desc != NULL)
		free(info->os_desc);

	free(info);
}

light_pcapng_file_info *light_pcang_get_file_info(light_pcapng_t *pcapng)
{
	DCHECK_NULLP(pcapng, return NULL);
	return pcapng->file_info;
}

int light_get_next_packet(light_pcapng_t *pcapng, light_packet_header *packet_header, const uint8_t **packet_data)
{
	uint32_t type = LIGHT_UNKNOWN_DATA_BLOCK;

	light_read_record(pcapng->file, &pcapng->pcapng);

	//End of file or something is broken!
	if (pcapng == NULL)
		return 0;

	light_get_block_info(pcapng->pcapng, LIGHT_INFO_TYPE, &type, NULL);

	while (pcapng->pcapng != NULL && type != LIGHT_ENHANCED_PACKET_BLOCK && type != LIGHT_SIMPLE_PACKET_BLOCK)
	{
		if (type == LIGHT_INTERFACE_BLOCK)
			__append_interface_block_to_file_info(pcapng->pcapng, pcapng->file_info);

		light_read_record(pcapng->file, &pcapng->pcapng);
		if (pcapng->pcapng== NULL)
			break;
		light_get_block_info(pcapng->pcapng, LIGHT_INFO_TYPE, &type, NULL);
	}

	*packet_data = NULL;

	if (pcapng->pcapng == NULL)
		return 0;

	if (type == LIGHT_ENHANCED_PACKET_BLOCK)
	{
		struct _light_enhanced_packet_block *epb = NULL;

		light_get_block_info(pcapng->pcapng, LIGHT_INFO_BODY, &epb, NULL);

		packet_header->interface_id = epb->interface_id;
		packet_header->captured_length = epb->capture_packet_length;
		packet_header->original_length = epb->original_capture_length;
		uint64_t timestamp = epb->timestamp_high;
		timestamp = timestamp << 32;
		timestamp += epb->timestamp_low;
		double timestamp_res = pcapng->file_info->timestamp_resolution[epb->interface_id];
		uint64_t packet_secs = timestamp * timestamp_res;
		if (packet_secs <= MAXIMUM_PACKET_SECONDS_VALUE)
		{
			packet_header->timestamp.tv_sec = packet_secs;
			packet_header->timestamp.tv_nsec =
					(timestamp - (packet_secs / timestamp_res))	// number of time units less than seconds
					* timestamp_res								// shift . to the left to get 0.{previous_number}
					* 1000000000;								// get the nanoseconds
		}
		else
		{
			packet_header->timestamp.tv_sec = 0;
			packet_header->timestamp.tv_nsec = 0;
		}

		if (epb->interface_id < pcapng->file_info->interface_block_count)
			packet_header->data_link = pcapng->file_info->link_types[epb->interface_id];

		*packet_data = (uint8_t*)epb->packet_data;
	}

	else if (type == LIGHT_SIMPLE_PACKET_BLOCK)
	{
		struct _light_simple_packet_block *spb = NULL;

		light_get_block_info(pcapng->pcapng, LIGHT_INFO_BODY, &spb, NULL);

		packet_header->interface_id = 0;
		packet_header->captured_length = spb->original_packet_length;
		packet_header->original_length = spb->original_packet_length;
		packet_header->timestamp.tv_sec = 0;
		packet_header->timestamp.tv_nsec = 0;
		if (pcapng->file_info->interface_block_count > 0)
			packet_header->data_link = pcapng->file_info->link_types[0];

		*packet_data = (uint8_t*)spb->packet_data;
	}

	packet_header->comment = NULL;
	packet_header->comment_length = 0;

	light_option option = light_get_option(pcapng->pcapng, 1); // get comment
	if (option != NULL)
	{
		packet_header->comment_length = light_get_option_length(option);
		packet_header->comment = (char*)light_get_option_data(option);
	}

	return 1;
}

static const uint8_t NSEC_PRECISION = 9;

void light_write_packet(light_pcapng_t *pcapng, const light_packet_header *packet_header, const uint8_t *packet_data)
{
	DCHECK_NULLP(pcapng, return);
	DCHECK_NULLP(packet_header, return);
	DCHECK_NULLP(packet_data, return);
	DCHECK_ASSERT_EXP(__is_open_for_write(pcapng) == LIGHT_TRUE, "file not open for writing", return);

	size_t iface_id = 0;
	for (iface_id = 0; iface_id < pcapng->file_info->interface_block_count; iface_id++)
	{
		if (pcapng->file_info->link_types[iface_id] == packet_header->data_link)
			break;
	}

	light_pcapng blocks_to_write = NULL;

	// TODO: most probably, this section should be removed as soon as possibility to write interface blocks
	// is added, as all this section does is basically creating "mock" interface blocks with default parameters
	// in case interface ID of packet block to be written does not exist - was not read previously
	if (iface_id >= pcapng->file_info->interface_block_count)
	{
		struct _light_interface_description_block interface_block;
		interface_block.link_type = packet_header->data_link;
		interface_block.reserved = 0;
		interface_block.snapshot_length = 0;

		light_pcapng iface_block_pcapng = light_alloc_block(LIGHT_INTERFACE_BLOCK, (const uint32_t*)&interface_block, sizeof(struct _light_interface_description_block)+3*sizeof(uint32_t));

		// let all written packets has a timestamp resolution in nsec - this way we will not loose the precision;
		// when a possibility to write interface blocks is added, the precision should be taken from them
		light_option resolution_option = light_create_option(LIGHT_OPTION_IF_TSRESOL, sizeof(NSEC_PRECISION), (uint8_t*)&NSEC_PRECISION);
		light_add_option(NULL, iface_block_pcapng, resolution_option, LIGHT_FALSE);

		blocks_to_write = iface_block_pcapng;
		__append_interface_block_to_file_info(iface_block_pcapng, pcapng->file_info);
	}

	size_t option_size = sizeof(struct _light_enhanced_packet_block) + packet_header->captured_length;
	PADD32(option_size, &option_size);
	uint8_t *epb_memory = calloc(1, option_size);
	//memset(epb_memory, 0, option_size); should be redundant with calloc
	struct _light_enhanced_packet_block *epb = (struct _light_enhanced_packet_block *)epb_memory;
	epb->interface_id = iface_id;

	uint64_t timestamp, packet_secs = (uint64_t)packet_header->timestamp.tv_sec;
	if (sizeof(packet_header->timestamp.tv_sec) < sizeof(packet_secs))
		packet_secs = 0x00000000FFFFFFFF & packet_secs;

	if (packet_secs <= MAXIMUM_PACKET_SECONDS_VALUE)
		timestamp = packet_secs * (uint64_t)1000000000 + (uint64_t)packet_header->timestamp.tv_nsec;
	else
		timestamp = 0;
	epb->timestamp_high = timestamp >> 32;
	epb->timestamp_low = timestamp & 0xFFFFFFFF;

	epb->capture_packet_length = packet_header->captured_length;
	epb->original_capture_length = packet_header->original_length;

	memcpy(epb->packet_data, packet_data, packet_header->captured_length);

	light_pcapng packet_block_pcapng = light_alloc_block(LIGHT_ENHANCED_PACKET_BLOCK, (const uint32_t*)epb_memory, option_size+3*sizeof(uint32_t));
	free(epb_memory);

	if (packet_header->comment_length > 0)
	{
		light_option packet_comment_opt = light_create_option(LIGHT_OPTION_COMMENT, packet_header->comment_length, packet_header->comment);
		light_add_option(NULL, packet_block_pcapng, packet_comment_opt, LIGHT_FALSE);
	}

	if (blocks_to_write == NULL)
		blocks_to_write = packet_block_pcapng;
	else
		light_add_block(blocks_to_write, packet_block_pcapng);

	light_pcapng_to_file_stream(blocks_to_write, pcapng->file);

	light_pcapng_release(blocks_to_write);
}

void light_pcapng_close(light_pcapng_t *pcapng)
{
	DCHECK_NULLP(pcapng, return);

	light_pcapng_release(pcapng->pcapng);
	pcapng->pcapng = NULL;
	if (pcapng->file != NULL)
	{
		light_flush(pcapng->file);
		light_close(pcapng->file);
	}
	light_free_file_info(pcapng->file_info);
	free(pcapng);
}

void light_pcapng_flush(light_pcapng_t *pcapng)
{
	light_flush(pcapng->file);
}
