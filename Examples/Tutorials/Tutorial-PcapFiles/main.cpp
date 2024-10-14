#include <memory>
#include <iostream>
#include "PcapFileDevice.h"

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("input.pcap"));

	// verify that a reader interface was indeed created
	if (reader == nullptr)
	{
		std::cerr << "Cannot determine reader for file type" << std::endl;
		return 1;
	}

	// open the reader for reading
	if (!reader->open())
	{
		std::cerr << "Cannot open input.pcap for reading" << std::endl;
		return 1;
	}

	// create a pcap file writer. Specify file name and link type of all packets that
	// will be written to it
	pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);

	// try to open the file for writing
	if (!pcapWriter.open())
	{
		std::cerr << "Cannot open output.pcap for writing" << std::endl;
		return 1;
	}

	// create a pcap-ng file writer. Specify file name. Link type is not necessary because
	// pcap-ng files can store multiple link types in the same file
	pcpp::PcapNgFileWriterDevice pcapNgWriter("output.pcapng");

	// try to open the file for writing
	if (!pcapNgWriter.open())
	{
		std::cerr << "Cannot open output.pcapng for writing" << std::endl;
		return 1;
	}

	// set a BPF filter for the reader - only packets that match the filter will be read
	if (!reader->setFilter("net 98.138.19.88"))
	{
		std::cerr << "Cannot set filter for file reader" << std::endl;
		return 1;
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

	// Use lambda to simplify statistics output
	auto printStats = [](const std::string& writerName, const pcpp::IPcapDevice::PcapStats& stats) {
		std::cout << "Written " << stats.packetsRecv << " packets successfully to " << writerName << " and "
		          << stats.packetsDrop << " packets could not be written" << std::endl;
	};

	// create the stats object
	pcpp::IPcapDevice::PcapStats stats;

	// read stats from reader and print them
	reader->getStatistics(stats);
	std::cout << "Read " << stats.packetsRecv << " packets successfully and " << stats.packetsDrop
	          << " packets could not be read" << std::endl;

	// read stats from pcap writer and print them
	pcapWriter.getStatistics(stats);
	printStats("pcap writer", stats);

	// read stats from pcap-ng writer and print them
	pcapNgWriter.getStatistics(stats);
	printStats("pcap-ng writer", stats);

	// close reader
	reader->close();

	// close writers
	pcapWriter.close();
	pcapNgWriter.close();

	return 0;
}
