#include <iostream>

#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

#include "Logger.h"

#define TMP_FILEPATH "/tmp/fuzz_sample.pcap"

// This function is created as PcapPlusPlus doesn't seem to offer a way of
// parsing Pcap files directly from memory
int dumpDataToPcapFile(const uint8_t *data, size_t size)
{
	FILE *fd;
	int written = 0;

	fd = fopen(TMP_FILEPATH, "wb");
	if (fd == NULL)
	{
		std::cerr << "Error opening pcap file for writing\n";
		return -1;
	}

	written = fwrite(data, 1, size, fd);
	if (written != size)
	{
		std::cerr << "Error writing pcap file\n";
		fclose(fd);
		return -1;
	}

	fclose(fd);

	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if (dumpDataToPcapFile(Data, Size) < 0)
	{
		std::cerr << "Can't Dump buffer to a PCAP file!!!!\n";
		return 0;
	}

	// Disable logs
	pcpp::Logger::getInstance().suppressLogs();

	// open a pcap file for reading
	pcpp::PcapFileReaderDevice reader(TMP_FILEPATH);
	if (!reader.open())
	{
		std::cerr << "Error opening the pcap file\n";
		return 0;
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader.getNextPacket(rawPacket))
	{
		std::cerr << "Couldn't read the first packet in the file\n";
		return 0;
	}

	do
	{
		// parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// verify the packet is IPv4
		if (parsedPacket.isPacketOfType(pcpp::IPv4))
		{
			// extract source and dest IPs
			pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
			pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

			// print source and dest IPs
			std::cout << "Source IP is '" << srcIP.toString() << "'; Dest IP is '" << destIP.toString() << "'"
					  << std::endl;
		}
	} while (reader.getNextPacket(rawPacket));

	// close the file
	reader.close();

	return 0;
}
