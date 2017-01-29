/**
 * PcapPrinter application
 * =======================
 * This simple application takes a pcap file, parses its packets using Packet++ and output each layer in each packet
 * as a readable string (quite similar to the way Wireshark shows packets).
 * The result is printed to stdout (by default) or to a file (if specified). It can also print only the
 * first X packets of a file
 *
 * For more details about modes of operation and parameters run PcapPrinter -h
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <getopt.h>

using namespace pcpp;

static struct option PcapPrinterOptions[] =
{
	{"input-file",  required_argument, 0, 'f'},
	{"output-file", required_argument, 0, 'o'},
	{"packet-count", required_argument, 0, 'c'},
	{"filter", required_argument, 0, 'i'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)



/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"-------\n"
			"PcapPrinter [-h] [-o output_file] [-c packet_count] [-i filter] -f pcap_file\n"
			"\nOptions:\n\n"
			"    -f pcap_file   : Input pcap file name\n"
			"    -o output_file : Save output to text file (default output is stdout)\n"
			"    -c packet_count: Print only first packet_count number of packet\n"
			"    -i filter      : Apply a BPF filter, meaning only filtered packets will be printed\n"
			"    -h             : Displays this help message and exits\n");
	exit(0);
}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	std::string inputPcapFileName = "";
	std::string outputPcapFileName = "";

	std::string filter = "";

	int packetCount = -1;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "f:o:c:i:h", PcapPrinterOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'f':
				inputPcapFileName = optarg;
				break;
			case 'o':
				outputPcapFileName = optarg;
				break;
			case 'c':
				packetCount = atoi(optarg);
				break;
			case 'i':
				filter = optarg;
				break;
			case 'h':
				printUsage();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	if (inputPcapFileName == "")
	{
		EXIT_WITH_ERROR("Input file name was not given");
	}

	// write to output file if provided, otherwise output to cout

	std::ofstream of;
	std::ostream* out = &std::cout;

	if (outputPcapFileName != "")
	{
		of.open(outputPcapFileName.c_str());
		out = &of;
	}

	// open a pcap file for reading
	PcapFileReaderDevice reader(inputPcapFileName.c_str());

	if (!reader.open())
	{
		EXIT_WITH_ERROR("Error opening input pcap file\n");
	}

	// set a filter if provided
	if (filter != "")
	{
		if (!reader.setFilter(filter))
			EXIT_WITH_ERROR("Couldn't set filter '%s'", filter.c_str());
	}

	// read the first (and only) packet from the file
	int packetCountSoFar = 0;
	RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket) && packetCountSoFar != packetCount)
	{
		// parse the raw packet into a parsed packet
		Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << parsedPacket.printToString() << std::endl;

		packetCountSoFar++;
	}

	(*out) << "Finished. Printed " << packetCountSoFar << " packets" << std::endl;

	// close the file
	reader.close();

	return 0;
}
