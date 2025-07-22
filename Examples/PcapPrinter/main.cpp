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
		std::cout << '\n' << "ERROR: " << reason << '\n' << '\n';                                                      \
		exit(1);                                                                                                       \
	} while (0)

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << '\n'
	          << "Usage:" << '\n'
	          << "------" << '\n'
	          << pcpp::AppName::get() << " pcap_file [-h] [-v] [-o output_file] [-c packet_count] [-i filter] [-s]"
	          << '\n'
	          << '\n'
	          << "Options:" << '\n'
	          << '\n'
	          << "    pcap_file      : Input pcap/pcapng file name" << '\n'
	          << "    -o output_file : Save output to text file (default output is stdout)" << '\n'
	          << "    -c packet_count: Print only first packet_count number of packet" << '\n'
	          << "    -i filter      : Apply a BPF filter, meaning only filtered packets will be printed" << '\n'
	          << "    -s             : Print only file summary and exit" << '\n'
	          << "    -v             : Display the current version and exit" << '\n'
	          << "    -h             : Display this help message and exit" << '\n'
	          << '\n';
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << '\n'
	          << "Built: " << pcpp::getBuildDateTime() << '\n'
	          << "Built from: " << pcpp::getGitInfo() << '\n';
	exit(0);
}

std::string linkLayerToString(pcpp::LinkLayerType linkLayer)
{

	if (linkLayer == pcpp::LINKTYPE_ETHERNET)
	{
		return "Ethernet";
	}
	if (linkLayer == pcpp::LINKTYPE_IEEE802_5)
	{
		return "IEEE 802.5 Token Ring";
	}
	if (linkLayer == pcpp::LINKTYPE_LINUX_SLL)
	{
		return "Linux cooked capture";
	}
	if (linkLayer == pcpp::LINKTYPE_LINUX_SLL2)
	{
		return "Linux cooked capture v2";
	}
	if (linkLayer == pcpp::LINKTYPE_NULL)
	{
		return "Null/Loopback";
	}
	if (linkLayer == pcpp::LINKTYPE_RAW || linkLayer == pcpp::LINKTYPE_DLT_RAW1 || linkLayer == pcpp::LINKTYPE_DLT_RAW2)
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
	stream << "File summary:" << '\n';
	stream << "~~~~~~~~~~~~~" << '\n';
	stream << "   File name: " << reader->getFileName() << '\n';
	stream << "   File size: " << reader->getFileSize() << " bytes" << '\n';

	if (dynamic_cast<pcpp::PcapFileReaderDevice*>(reader) != nullptr)
	{
		auto* pcapReader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);
		const pcpp::LinkLayerType linkLayer = pcapReader->getLinkLayerType();
		stream << "   Link layer type: " << linkLayerToString(linkLayer) << '\n';
	}
	else if (dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader) != nullptr)
	{
		auto* snoopReader = dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader);
		const pcpp::LinkLayerType linkLayer = snoopReader->getLinkLayerType();
		stream << "   Link layer type: " << linkLayerToString(linkLayer) << '\n';
	}
	else if (dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader) != nullptr)
	{
		auto* pcapNgReader = dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader);
		if (!pcapNgReader->getOS().empty())
		{
			stream << "   OS: " << pcapNgReader->getOS() << '\n';
		}

		if (!pcapNgReader->getCaptureApplication().empty())
		{
			stream << "   Capture application: " << pcapNgReader->getCaptureApplication() << '\n';
		}

		if (!pcapNgReader->getCaptureFileComment().empty())
		{
			stream << "   File comment: " << pcapNgReader->getCaptureFileComment() << '\n';
		}

		if (!pcapNgReader->getHardware().empty())
		{
			stream << "   Capture hardware: " << pcapNgReader->getHardware() << '\n';
		}
	}

	stream << '\n';

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
		const pcpp::Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << parsedPacket.toString() << '\n';

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
	std::string packetComment;
	while (reader->getNextPacket(rawPacket, packetComment) && packetCountSoFar != packetCount)
	{
		// print packet comment if exists
		if (!packetComment.empty())
		{
			(*out) << "Packet Comment: " << packetComment << '\n';
		}

		// parse the raw packet into a parsed packet
		const pcpp::Packet parsedPacket(&rawPacket);

		// print packet to string
		(*out) << "Link layer type: " << linkLayerToString(rawPacket.getLinkLayerType()) << '\n';
		(*out) << parsedPacket.toString() << '\n';

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

	std::string inputPcapFileName;
	std::string outputPcapFileName;

	std::string filter;

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
			packetCount = std::stoi(optarg);
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

	if (inputPcapFileName.empty())
	{
		EXIT_WITH_ERROR("Input file name was not given");
	}

	// write to output file if provided, otherwise output to cout

	std::ofstream ofs;
	std::ostream* out = &std::cout;

	if (!outputPcapFileName.empty())
	{
		ofs.open(outputPcapFileName.c_str());
		out = &ofs;
	}

	// open a pcap/pcapng file for reading
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(inputPcapFileName);

	if (!reader->open())
	{
		delete reader;
		EXIT_WITH_ERROR("Error opening input pcap file\n");
	}

	// set a filter if provided
	if (!filter.empty())
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
		auto* pcapReader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);
		printedPacketCount = printPcapPackets(pcapReader, out, packetCount);
	}
	else if (dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader) != nullptr)
	{
		// print all requested packets in the pcap file
		auto* snoopReader = dynamic_cast<pcpp::SnoopFileReaderDevice*>(reader);
		printedPacketCount = printPcapPackets(snoopReader, out, packetCount);
	}
	// if the file is a pcap-ng file
	else if (dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader) != nullptr)
	{
		// print all requested packets in the pcap-ng file
		auto* pcapNgReader = dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader);
		printedPacketCount = printPcapNgPackets(pcapNgReader, out, packetCount);
	}

	(*out) << "Finished. Printed " << printedPacketCount << " packets" << '\n';

	// close the file
	reader->close();

	// free reader memory
	delete reader;

	return 0;
}
