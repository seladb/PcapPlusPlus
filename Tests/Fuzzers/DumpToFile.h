#pragma once

#include <iostream>

// This function is created as PcapPlusPlus doesn't seem to offer a way of
// parsing Pcap files directly from memory
static int dumpDataToPcapFile(const uint8_t* data, size_t size, const char* path)
{
	FILE* fd;
	int written = 0;

	fd = fopen(path, "wb");
	if (fd == NULL)
	{
		std::cerr << "Error opening pcap file for writing\n";
		return -1;
	}

	written = fwrite(data, 1, size, fd);
	if (static_cast<size_t>(written) != size)
	{
		std::cerr << "Error writing pcap file\n";
		fclose(fd);
		return -1;
	}

	fclose(fd);
	return 0;
}
