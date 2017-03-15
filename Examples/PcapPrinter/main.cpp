/**
 * PcapPrinter application
 * =======================
 * This application takes a pcap or pcapng file, parses its packets using Packet++ and output each layer in each packet
 * as a readable string (quite similar to the way Wireshark shows packets).
 * In addition it prints a short summary of the file (with details such as file name, size, etc.)
 * The result is printed to stdout (by default) or to a file (if specified). It can also print only the
 * first X packets of a file
 *
 * For more details about modes of operation and parameters run PcapPrinter -h
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
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
	{"summary", no_argument, 0, 's'},
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
			"PcapPrinter [-h] [-o output_file] [-c packet_count] [-i filter] [-s] -f pcap_file\n"
			"\nOptions:\n\n"
			"    -f pcap_file   : Input pcap/pcapng file name\n"
			"    -o output_file : Save output to text file (default output is stdout)\n"
			"    -c packet_count: Print only first packet_count number of packet\n"
			"    -i filter      : Apply a BPF filter, meaning only filtered packets will be printed\n"
			"    -s             : Print only file summary and exit\n"
			"    -h             : Displays this help message and exits\n");
	exit(0);
}


/**
* print file summary based on the reader type
*/
std::string printFileSummary(IFileReaderDevice* reader)
{
	std::ostringstream stream;
	stream << "File summary:" << std::endl;
	stream << "~~~~~~~~~~~~~" << std::endl;
	stream << "   File name: " << reader->getFileName() << std::endl;
	stream << "   File size: " << reader->getFileSize() << " bytes" << std::endl;
	
	if (dynamic_cast<PcapFileReaderDevice*>(reader) != NULL)
	{
		PcapFileReaderDevice* pcapReader = dynamic_cast<PcapFileReaderDevice*>(reader);
		LinkLayerType linkLayer = pcapReader->getLinkLayerType();
		if (linkLayer == LINKTYPE_ETHERNET)
			stream << "   Link layer type: Ethernet" << std::endl;
		else if (linkLayer == LINKTYPE_LINUX_SLL)
			stream << "   Link layer type: Linux cooked capture" << std::endl;
		else if (linkLayer == LINKTYPE_NULL)
			stream << "   Link layer type: Null/Loopback" << std::endl;
		else if (linkLayer == LINKTYPE_RAW)
			stream << "   Link layer type: Raw IP" << std::endl;
		else
			stream << "   Link layer type: " << (int)linkLayer << std::endl;
	}
	else if (dynamic_cast<PcapNgFileReaderDevice*>(reader) != NULL)
	{ 
		PcapNgFileReaderDevice* pcapNgReader = dynamic_cast<PcapNgFileReaderDevice*>(reader);
		if (pcapNgReader->getOS() != "")
			stream << "   OS: " << pcapNgReader->getOS() << std::endl;

		if (pcapNgReader->getCaptureApplication() != "")
			stream << "   Capture application: " << pcapNgReader->getCaptureApplication() << std::endl;

		if (pcapNgReader->getCaptureFileComment() != "")
			stream << "   File comment: " << pcapNgReader->getCaptureFileComment() << std::endl;

		if (pcapNgReader->getHardware() != "")
			stream << "   Capture hardware: " << pcapNgReader->getHardware() << std::endl;
	}

	stream << std::endl;

	return stream.str();
}


/**
* print all requested packets in a pcap file
*/
int printPcapPackets(PcapFileReaderDevice* reader, std::ostream* out, int packetCount)
{
	// read packets from the file until end-of-file or until reached user requested packet count
	int packetCountSoFar = 0;
	RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket) && packetCountSoFar != packetCount)
	{
		// parse the raw packet into a parsed packet
		Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << parsedPacket.printToString() << std::endl;

		packetCountSoFar++;
	}
	
	// return the nubmer of packets that were printed
	return packetCountSoFar;
}


/**
* print all requested packets in a pcap-ng file
*/
int printPcapNgPackets(PcapNgFileReaderDevice* reader, std::ostream* out, int packetCount)
{
	// read packets from the file until end-of-file or until reached user requested packet count
	int packetCountSoFar = 0;
	RawPacket rawPacket;
	std::string packetComment = "";
	while (reader->getNextPacket(rawPacket, packetComment) && packetCountSoFar != packetCount)
	{
		// print packet comment if exists
		if (packetComment != "")
			(*out) << "Packet Comment: " << packetComment << std::endl;

		// parse the raw packet into a parsed packet
		Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << parsedPacket.printToString() << std::endl;

		packetCountSoFar++;
	}

	// return the nubmer of packets that were printed
	return packetCountSoFar;
}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	std::string inputPcapFileName = "";
	std::string outputPcapFileName = "";

	std::string filter = "";

	bool printOnlySummary = false;

	int packetCount = -1;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "f:o:c:i:sh", PcapPrinterOptions, &optionIndex)) != -1)
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
			case 's':
				printOnlySummary = true;
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

	// open a pcap/pcapng file for reading
	IFileReaderDevice* reader = IFileReaderDevice::getReader(inputPcapFileName.c_str());

	if (!reader->open())
	{
		delete reader;
		EXIT_WITH_ERROR("Error opening input pcap file\n");
	}

	// set a filter if provided
	if (filter != "")
	{
		if (!reader->setFilter(filter))
		{
			delete reader;
			EXIT_WITH_ERROR("Couldn't set filter '%s'", filter.c_str());
		}
			
	}

	// print file summary
	(*out) << printFileSummary(reader);

	// if requested to print only file summary - exit
	if (printOnlySummary)
	{
		delete reader;
		exit(0);
	}

	int printedPacketCount = 0;

	// if the file is a pcap file
	if (dynamic_cast<PcapFileReaderDevice*>(reader) != NULL)
	{
		// print all requested packets in the pcap file
		PcapFileReaderDevice* pcapReader = dynamic_cast<PcapFileReaderDevice*>(reader);
		printedPacketCount = printPcapPackets(pcapReader, out, packetCount);
	}
	// if the file is a pcap-ng file
	else if (dynamic_cast<PcapNgFileReaderDevice*>(reader) != NULL)
	{
		// print all requested packets in the pcap-ng file
		PcapNgFileReaderDevice* pcapNgReader = dynamic_cast<PcapNgFileReaderDevice*>(reader);
		printedPacketCount = printPcapNgPackets(pcapNgReader, out, packetCount);
	}
	
	(*out) << "Finished. Printed " << printedPacketCount << " packets" << std::endl;

	// close the file
	reader->close();

	// free reader memory
	delete reader;

	return 0;
}
