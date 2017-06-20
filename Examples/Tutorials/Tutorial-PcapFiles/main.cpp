#include "stdlib.h"
#include "PcapFileDevice.h"

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("input.pcap");

	// verify that a reader interface was indeed created
	if (reader == NULL)
	{
		printf("Cannot determine reader for file type\n");
		exit(1);
	}

	// open the reader for reading
	if (!reader->open())
	{
		printf("Cannot open input.pcap for reading\n");
		exit(1);
	}

	// create a pcap file writer. Specify file name and link type of all packets that
	// will be written to it
	pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);

	// try to open the file for writing
	if (!pcapWriter.open())
	{
		printf("Cannot open output.pcap for writing\n");
		exit(1);
	}

	// create a pcap-ng file writer. Specify file name. Link type is not necessary because
	// pcap-ng files can store multiple link types in the same file
	pcpp::PcapNgFileWriterDevice pcapNgWriter("output.pcapng");

	// try to open the file for writing
	if (!pcapNgWriter.open())
	{
		printf("Cannot open output.pcapng for writing\n");
		exit(1);
	}

	// set a BPF filter for the reader - only packets that match the filter will be read
	if (!reader->setFilter("net 98.138.19.88"))
	{
		printf("Cannot set filter for file reader\n");
		exit(1);
	}

	// the packet container
	pcpp::RawPacket rawPacket;

	// a while loop that will continue as long as there are packets in the input file
	// matching the BPF filter
	while (reader->getNextPacket(rawPacket))
	{
		// write each packet to both writers
		pcapWriter.writePacket(rawPacket);
		pcapNgWriter.writePacket(rawPacket);
	}

	// create the stats object
	pcap_stat stats;

	// read stats from reader and print them
	reader->getStatistics(stats);
	printf("Read %d packets successfully and %d packets could not be read\n", stats.ps_recv, stats.ps_drop);

	// read stats from pcap writer and print them
	pcapWriter.getStatistics(stats);
	printf("Written %d packets successfully to pcap writer and %d packets could not be written\n", stats.ps_recv, stats.ps_drop);

	// read stats from pcap-ng writer and print them
	pcapNgWriter.getStatistics(stats);
	printf("Written %d packets successfully to pcap-ng writer and %d packets could not be written\n", stats.ps_recv, stats.ps_drop);

	// close reader
	reader->close();

	// close writers
	pcapWriter.close();
	pcapNgWriter.close();

	// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
	delete reader;
}
