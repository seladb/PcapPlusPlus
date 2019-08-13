// light_compression.c
// Created on: Aug 13, 2019

// Copyright (c) 2019 TMEIC Corporation - Robert Kriener

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

#include "light_compression.h"
#include "light_file.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

_compression_t * light_get_compression_context(int compression_level)
{
	if (compression_level == 0)
		return NULL;

#if defined(USE_Z_STD)
	struct zstd_compression_t *context = calloc(1, sizeof(struct zstd_compression_t));
	context->cctx = ZSTD_createCCtx();
	//Enough to handle a whole packet
	context->buffer_in_max_size = COMPRESSION_BUFFER_IN_MAX_SIZE;
	//If we don't compress to a smaller or equal size then we are we compressing at all!
	context->buffer_out_max_size = max(ZSTD_CStreamOutSize(), COMPRESSION_BUFFER_IN_MAX_SIZE);
	context->buffer_in = malloc(context->buffer_in_max_size);
	context->buffer_out = malloc(context->buffer_out_max_size);
	context->compression_level = compression_level * 2; //Input is scale 0-10 but zstd goes 0 - 20!
	assert(!ZSTD_isError(ZSTD_CCtx_setParameter(context->cctx, ZSTD_c_compressionLevel, compression_level)));

	return context;
#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#else
	return NULL;

#endif 
}

void light_free_compression_context(_compression_t* context)
{
	if (!context)
		return;

#if defined(USE_Z_STD)
	if (context->cctx)
		ZSTD_freeCCtx(context->cctx);
	if (context->buffer_out)
		free(context->buffer_out);
	if (context->buffer_in)
		free(context->buffer_in);
#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#endif

	free(context);
}

_decompression_t * light_get_decompression_context()
{
#if defined(USE_Z_STD)
	struct zstd_decompression_t *context = calloc(1, sizeof(struct zstd_decompression_t));
	context->dctx = ZSTD_createDCtx();
	//Enough to handle a whole packet
	context->buffer_in_max_size = ZSTD_DStreamInSize();;
	//ZSTD_DStreamOutSize() is big enough to hold atleast 1 full frame, but we can go bigger
	context->buffer_out_max_size = max(ZSTD_DStreamOutSize(), COMPRESSION_BUFFER_IN_MAX_SIZE);
	context->buffer_in = malloc(context->buffer_in_max_size);
	context->buffer_out = malloc(context->buffer_out_max_size);

	context->output.dst = context->buffer_out;
	context->output.size = context->buffer_out_max_size;
	context->output.pos = 0;
	context->outputReady = 0;

	return context;
#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#else
	return NULL;

#endif 
}

void light_free_decompression_context(_decompression_t* context)
{
	if (!context)
		return;

#if defined(USE_Z_STD)
	if (context->dctx)
		ZSTD_freeDCtx(context->dctx);
	if (context->buffer_out)
		free(context->buffer_out);
	if (context->buffer_in)
		free(context->buffer_in);
#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#endif 

	free(context);
}


int light_is_compressed_file(const char* file_path)
{
#if defined(USE_Z_STD)
	if (strstr(file_path, ".zstd"))
	{
		return 1;
	}
#elif defined(USE_THIS_COMPRESSION_INSTEAD)

#else
	return 0;
#endif 
}

size_t light_read_compressed(light_file fd, void *buf, size_t count)
{
#if defined(USE_Z_STD)
	{
		//Decompression is a little more complex
		//Need to manage reading bytes from orignal file
		//Decompressing those into a buffer
		//Then reading the selected number of bytes from the buffer
		//Once whole buffer is consumed we need to read and decompress next chunk from file

		size_t bytes_read = 0;

		while (bytes_read < count)
		{
			if (fd->decompression_context->outputReady == 0)
			{
				//Check if we need to grab a new chunk from the actual file
				//If we read all the input then yes, we need to do that
				if (fd->decompression_context->input.pos >= fd->decompression_context->input.size)
				{
					//Read a decompress a chunk
					size_t bytes_read_file = fread(fd->decompression_context->buffer_in, 1, fd->decompression_context->buffer_in_max_size, fd->file);
					if (bytes_read_file < fd->decompression_context->buffer_in_max_size && bytes_read_file == 0 && feof(fd->file))
						return EOF;
					fd->decompression_context->input.src = fd->decompression_context->buffer_in;
					fd->decompression_context->input.size = bytes_read_file;
					fd->decompression_context->input.pos = 0;
				}
				//Decompress into the output buffer and use this buffer to actually get our results
				fd->decompression_context->output.dst = fd->decompression_context->buffer_out;
				fd->decompression_context->output.size = fd->decompression_context->buffer_out_max_size;
				fd->decompression_context->output.pos = 0;

				size_t const remaining = ZSTD_decompressStream(fd->decompression_context->dctx, &fd->decompression_context->output, &fd->decompression_context->input);
				assert(!ZSTD_isError(remaining));

				//Re-use the output class to track our own consumption
				fd->decompression_context->output.size = fd->decompression_context->output.pos;
				fd->decompression_context->output.pos = 0;
				fd->decompression_context->outputReady = 1;
			}

			//Now get bytes from our output buffer

			//Case we need everything or less than that which was decoded
			int needToRead = count - bytes_read;
			int remaining = (fd->decompression_context->output.size - fd->decompression_context->output.pos);
			if (needToRead <= remaining)
			{
				memcpy((uint8_t*)buf + bytes_read, (uint8_t*)fd->decompression_context->output.dst + fd->decompression_context->output.pos, needToRead);
				fd->decompression_context->output.pos += needToRead;
				bytes_read += needToRead;
			}

			//Case we need more than that which was decoded
			if (needToRead > remaining)
			{
				memcpy((uint8_t*)buf + bytes_read, (uint8_t*)fd->decompression_context->output.dst + fd->decompression_context->output.pos, remaining);
				bytes_read += remaining;
				fd->decompression_context->output.pos += remaining;
			}

			//We have consumed everything - set next call to decompress a new chunk
			if (fd->decompression_context->output.pos == fd->decompression_context->output.size)
				fd->decompression_context->outputReady = 0;

		}


		return bytes_read;
	}
#endif 
}

size_t light_write_compressed(light_file fd, const void *buf, size_t count)
{

#if defined(USE_Z_STD)
	{
		//Do compression here!
		/* Set the input buffer to what we just read.
		* We compress until the input buffer is empty, each time flushing the
		* output.
		*/
		ZSTD_inBuffer input = { buf, count, 0 };
		int finished;
		do
		{
			/* Compress into the output buffer and write all of the output to
			* the file so we can reuse the buffer next iteration.
			*/
			ZSTD_outBuffer output = { fd->compression_context->buffer_out, fd->compression_context->buffer_out_max_size, 0 };
			size_t const remaining = ZSTD_compressStream2(fd->compression_context->cctx, &output, &input, ZSTD_e_continue);
			assert(!ZSTD_isError(remaining));
			fwrite(output.dst, 1, output.pos, fd->file);
			/* If we're on the last chunk we're finished when zstd returns 0,
			 * We're finished when we've consumed all the input.
			 */
			finished = (input.pos == input.size);
		} while (!finished);

		return count;
	}
#endif 
}

int light_close_compresssed(light_file fd)
{
#if defined(USE_Z_STD)
	//Wrap up the compression here
	if (fd->compression_context)
	{
		ZSTD_inBuffer input = { 0,0,0 };

		int remaining = 1;

		while (remaining != 0)
		{
			ZSTD_outBuffer output = { fd->compression_context->buffer_out, fd->compression_context->buffer_out_max_size, 0 };
			remaining = ZSTD_compressStream2(fd->compression_context->cctx, &output, &input, ZSTD_e_end);
			fwrite(output.dst, 1, output.pos, fd->file);
		}
	}
#endif
	light_free_compression_context(fd->compression_context);
}