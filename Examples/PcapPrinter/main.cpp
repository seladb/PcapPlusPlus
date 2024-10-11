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

#include <iostream>
#include <fstream>
#include <sstream>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <getopt.h>

static struct option PcapPrinterOptions[] = {
	{ "output-file",  required_argument, nullptr, 'o' },
	{ "packet-count", required_argument, nullptr, 'c' },
	{ "filter",       required_argument, nullptr, 'i' },
	{ "summary",      no_argument,       nullptr, 's' },
	{ "help",         no_argument,       nullptr, 'h' },
	{ "version",      no_argument,       nullptr, 'v' },
	{ nullptr,        0,                 nullptr, 0   }
};

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get() << " pcap_file [-h] [-v] [-o output_file] [-c packet_count] [-i filter] [-s]"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    pcap_file      : Input pcap/pcapng file name" << std::endl
	          << "    -o output_file : Save output to text file (default output is stdout)" << std::endl
	          << "    -c packet_count: Print only first packet_count number of packet" << std::endl
	          << "    -i filter      : Apply a BPF filter, meaning only filtered packets will be printed" << std::endl
	          << "    -s             : Print only file summary and exit" << std::endl
	          << "    -v             : Display the current version and exit" << std::endl
	          << "    -h             : Display this help message and exit" << std::endl
	          << std::endl;
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}

std::string linkLayerToString(pcpp::LinkLayerType linkLayer)
{

	if (linkLayer == pcpp::LINKTYPE_ETHERNET)
		return "Ethernet";
	if (linkLayer == pcpp::LINKTYPE_IEEE802_5)
		return "IEEE 802.5 Token Ring";
	else if (linkLayer == pcpp::LINKTYPE_LINUX_SLL)
		return "Linux cooked capture";
	else if (linkLayer == pcpp::LINKTYPE_LINUX_SLL2)
		return "Linux cooked capture v2";
	else if (linkLayer == pcpp::LINKTYPE_NULL)
		return "Null/Loopback";
	else if (linkLayer == pcpp::LINKTYPE_RAW || linkLayer == pcpp::LINKTYPE_DLT_RAW1 ||
	         linkLayer == pcpp::LINKTYPE_DLT_RAW2)
	{
		std::ostringstream stream;
		stream << "Raw IP (" << linkLayer << ")";
		return stream.str();
	}

	std::ostringstream stream;
	stream << (int)linkLayer;
	return stream.str();
}

/**
 * print file summary based on the reader type
 */
std::string printFileSummary(pcpp::IFileReaderDevice* reader)
{
	std::ostringstream stream;
	stream << "File summary:" << std::endl;
	stream << "~~~~~~~~~~~~~" << std::endl;
	stream << "   File name: " << reader->getFileName() << std::endl;
	stream << "   File size: " << reader->getFileSize() << " bytes" << std::endl;

	if (dynamic_cast<pcpp::PcapFileReaderDevice*>(reader) != nullptr)
	{
		pcpp::PcapFileReaderDevice* pcapReader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);
		pcpp::LinkLayerType linkLayer = pcapReader->getLinkLayerType();
		stream << "   Link layer type: " << linkLayerToString(linkLayer) << std::endl;
	}
	else if (dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader) != nullptr)
	{
		pcpp::SnoopFileReaderDevice* snoopReader = dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader);
		pcpp::LinkLayerType linkLayer = snoopReader->getLinkLayerType();
		stream << "   Link layer type: " << linkLayerToString(linkLayer) << std::endl;
	}
	else if (dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader) != nullptr)
	{
		pcpp::PcapNgFileReaderDevice* pcapNgReader = dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader);
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
 * print all requested packets in a pcap/snoop file
 */
int printPcapPackets(pcpp::IFileReaderDevice* reader, std::ostream* out, int packetCount)
{
	// read packets from the file until end-of-file or until reached user requested packet count
	int packetCountSoFar = 0;
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket) && packetCountSoFar != packetCount)
	{
		// parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << parsedPacket.toString() << std::endl;

		packetCountSoFar++;
	}

	// return the number of packets that were printed
	return packetCountSoFar;
}

/**
 * print all requested packets in a pcap-ng file
 */
int printPcapNgPackets(pcpp::PcapNgFileReaderDevice* reader, std::ostream* out, int packetCount)
{
	// read packets from the file until end-of-file or until reached user requested packet count
	int packetCountSoFar = 0;
	pcpp::RawPacket rawPacket;
	std::string packetComment = "";
	while (reader->getNextPacket(rawPacket, packetComment) && packetCountSoFar != packetCount)
	{
		// print packet comment if exists
		if (packetComment != "")
			(*out) << "Packet Comment: " << packetComment << std::endl;

		// parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << "Link layer type: " << linkLayerToString(rawPacket.getLinkLayerType()) << std::endl;
		(*out) << parsedPacket.toString() << std::endl;

		packetCountSoFar++;
	}

	// return the number of packets that were printed
	return packetCountSoFar;
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string inputPcapFileName = "";
	std::string outputPcapFileName = "";

	std::string filter = "";

	bool printOnlySummary = false;

	int packetCount = -1;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "o:c:i:svh", PcapPrinterOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
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
			exit(0);
			break;
		case 'v':
			printAppVersion();
			break;
		default:
			printUsage();
			exit(-1);
		}
	}

	if (optind < argc)
	{
		inputPcapFileName = argv[optind];
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
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(inputPcapFileName);

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
			EXIT_WITH_ERROR("Couldn't set filter '" << filter << "'");
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
	if (dynamic_cast<pcpp::PcapFileReaderDevice*>(reader) != nullptr)
	{
		// print all requested packets in the pcap file
		pcpp::PcapFileReaderDevice* pcapReader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);
		printedPacketCount = printPcapPackets(pcapReader, out, packetCount);
	}
	else if (dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader) != nullptr)
	{
		// print all requested packets in the pcap file
		pcpp::SnoopFileReaderDevice* snoopReader = dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader);
		printedPacketCount = printPcapPackets(snoopReader, out, packetCount);
	}
	// if the file is a pcap-ng file
	else if (dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader) != nullptr)
	{
		// print all requested packets in the pcap-ng file
		pcpp::PcapNgFileReaderDevice* pcapNgReader = dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader);
		printedPacketCount = printPcapNgPackets(pcapNgReader, out, packetCount);
	}

	(*out) << "Finished. Printed " << printedPacketCount << " packets" << std::endl;

	// close the file
	reader->close();

	// free reader memory
	delete reader;

	return 0;
}
