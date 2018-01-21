/**
 * PcapSplitter application
 * ========================
 * An application that splits a pcap file into smaller pcap files by a user-defined criteria:
 *
 * 1) File-size - splits the pcap file to smaller pcap files, each file with a certain size defined by the user
 * 2) Packet-count - splits the pcap file to smaller pcap files, each with number of packets defined by the user
 * 3) Client-IP - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections
 *    initiated by a certain client-ip, for example: file#1 will contain connections initiated by 1.1.1.1, file#2
 *    will contain connections initiated by 1.2.3.4, and so on. The user can limit the number of output files, in
 *    this case multiple client-ips will be written to the same file. If the user doesn't set such limit - each file
 *    will contain one client-ip
 * 4) Server-IP - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections
 *    to a certain server-ip, for example: file#1 will contain connections to 8.8.8.8, file#2 will contain connections
 *    to 10.12.13.14, and so on. The user can limit the number of output files, in this case multiple server-ips will
 *    be written to the same file. If the user doesn't set such limit - each file will contain one server-ip
 * 5) Server-port - splits the pcap file to smaller pcap files so each file contains all TCP/UDP connections
 *    to a certain server port, for example: file#1 will contain all port 80 connections (HTTP), file#2 will contain
 *    all port 25 (SMTP) connections, and so on. The user can limit the number of output files, in this case connections
 *    to multiple server ports will be written to the same file. If the user doesn't set such limit - each file will
 *    contain connection to one server port only
 * 6) IP source and IP dest - splits the pcap file to smaller pcap files so each file contains all connections made
 *    between two IP addresses. The user can limit the number of output files, in this case multiple pairs of IP source
 *    and dest will be written to the same file. If the user doesn't set such limit - all connection of one pair of
 *    source and dest IP will be written to each file
 * 7) Connection - splits a pcap file to smaller pcap files by TCP/UDP connection meaning each connection will be written
 *    to a certain file. The user can limit the number of output files, in this case an equal number of connections will
 *    be written to the same file. If the user doesn't set such limit - each file will contain one connection
 * 8) BPF filter - splits the pcap file into two files: one that contains all packets matching the input BPF filter
 *    and the other one with the rest of the packets
 *
 * Remarks:
 * - Options 3-7 supports both IPv4 and IPV6
 * - Number of output files isn't limited, unless the user set such limit in options 3-7
 * - There is no limit on the size of the input file, the number of packets it contains or the number of connections it
 *   contains
 * - The user can also set a BPF filter to instruct the application to handle only packets filtered by the filter. The rest
 *   of the packets in the input file will be ignored
 * - In options 3-5 & 7 all packets which aren't UDP or TCP (hence don't belong to any connection) will be written to
 *   one output file, separate from the other output files (usually file#0)
 * - Works only on files of the pcap (TCPDUMP) format
 *
 */


#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <map>
#include <RawPacket.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include "SimpleSplitters.h"
#include "IPPortSplitters.h"
#include "ConnectionSplitters.h"
#include <getopt.h>
#include <SystemUtils.h>
#include <PcapPlusPlusVersion.h>


using namespace pcpp;

static struct option PcapSplitterOptions[] =
{
	{"input-file",  required_argument, 0, 'f'},
	{"output-file", required_argument, 0, 'o'},
	{"method", required_argument, 0, 'm'},
	{"param", required_argument, 0, 'p'},
	{"filter", required_argument, 0, 'i'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};


#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#define SPLIT_BY_FILE_SIZE     "file-size"
#define SPLIT_BY_PACKET_COUNT  "packet-count"
#define SPLIT_BY_IP_CLIENT     "client-ip"
#define SPLIT_BY_IP_SERVER     "server-ip"
#define SPLIT_BY_SERVER_PORT   "server-port"
#define SPLIT_BY_2_TUPLE       "ip-src-dst"
#define SPLIT_BY_5_TUPLE       "connection"
#define SPLIT_BY_BPF_FILTER    "bpf-filter"
#define SPLIT_BY_ROUND_ROBIN   "round-robin"

#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif

/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"-------\n"
			"%s [-h] [-v] [-i filter] -f pcap_file -o output_dir -m split_method [-p split_param]\n"
			"\nOptions:\n\n"
			"    -f pcap_file    : Input pcap file name\n"
			"    -o output_dir   : The directory where the output files shall be written\n"
			"    -m split_method : The method to split with. Can take one of the following params:\n"
			"                      'file-size'    - split files by size in bytes\n"
			"                      'packet-count' - split files by packet count\n"
			"                      'client-ip'    - split files by client IP, meaning all connections with\n"
			"                                       the same client IP will be in the same file\n"
			"                      'server-ip'    - split files by server IP, meaning all connections with\n"
			"                                       the same server IP will be in the same file\n"
			"                      'server-port'  - split files by server port, meaning all connections with\n"
			"                                       the same server port will be in the same file\n"
			"                      'ip-src-dst'   - split files by IP src and dst (2-tuple), meaning all connections\n"
			"                                       with the same IPs will be in the same file\n"
			"                      'connection'   - split files by connection (5-tuple), meaning all packets\n"
			"                                       of a connection will be in the same file\n"
			"                      'bpf-filter'   - split file into two files: one that contains all packets\n"
			"                                       matching the given BPF filter (file #0) and one that contains\n"
			"                                       the rest of the packets (file #1)\n"
			"                      'round-robin'  - split the file in a round-robin manner - each packet to a\n"
			"                                       different file\n"
			"    -p split-param  : The relevant parameter for the split method:\n"
			"                      'method = file-size'    => split-param is the max size per file (in bytes).\n"
			"                                                 split-param is required for this method\n"
			"                      'method = packet-count' => split-param is the number of packet per file.\n"
			"                                                 split-param is required for this method\n"
			"                      'method = client-ip'    => split-param is max number of files to open.\n"
			"                                                 If not provided the default is unlimited number of files\n"
			"                      'method = server-ip'    => split-param is max number of files to open.\n"
			"                                                 If not provided the default is unlimited number of files\n"
			"                      'method = server-port'  => split-param is max number of files to open.\n"
			"                                                 If not provided the default is unlimited number of files\n"
			"                      'method = ip-src-dst'   => split-param is max number of files to open.\n"
			"                                                 If not provided the default is unlimited number of files\n"
			"                      'method = connection'   => split-param is max number of files to open.\n"
			"                                                 If not provided the default is unlimited number of files\n"
			"                      'method = bpf-filter'   => split-param is the BPF filter to match upon\n"
			"                      'method = round-robin'  => split-param is number of files to round-robin packets between\n"
			"    -i filter       : Apply a BPF filter, meaning only filtered packets will be counted in the split\n"
			"    -v              : Displays the current version and exists\n"
			"    -h              : Displays this help message and exits\n", AppName::get().c_str());
	exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}


/**
 * An auxiliary method for extracting the file name without the extension from a file path,
 * for example: for the input '/home/myuser/mypcap.pcap' -> return value will be 'mypcap'
 */
std::string getFileNameWithoutExtension(const std::string& path)
{
	// if path is empty, return an empty string
	if (path == "")
		return "";

	// find the last "\\" or "/" (depends on the os) - where path ends and filename starts
	size_t i = path.rfind(SEPARATOR, path.length());
	if (i != std::string::npos)
	{
		// extract filename from path
		std::string fileNameWithExtension = path.substr(i+1, path.length() - i);

		// from the file name - remove the extension (the part after the ".")
		i = fileNameWithExtension.rfind('.', fileNameWithExtension.length());
		if (i != std::string::npos)
			return fileNameWithExtension.substr(0, i);

		return fileNameWithExtension;
	}
	// filename without a path
	else
	{
		// from the file name - remove the extension (the part after the ".")
		i = path.rfind('.', path.length());
		if (i != std::string::npos)
			return path.substr(0, i);

		// filename doesn't have an extension
		return path;
	}

	return("");
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string inputPcapFileName = "";
	std::string outputPcapDir = "";

	std::string filter = "";

	std::string method = "";

	char param[1000];
	memset(param, 0, 1000);

	bool paramWasSet = false;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "f:o:m:p:i:vh", PcapSplitterOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'f':
				inputPcapFileName = optarg;
				break;
			case 'o':
				outputPcapDir = optarg;
				break;
			case 'm':
				method = optarg;
				break;
			case 'p':
				strncpy(param, optarg, 1000);
				paramWasSet = true;
				break;
			case 'i':
				filter = optarg;
				break;
			case 'h':
				printUsage();
				break;
			case 'v':
				printAppVersion();
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

	if (outputPcapDir == "")
	{
		EXIT_WITH_ERROR("Output directory name was not given");
	}

	if (!pcpp::directoryExists(outputPcapDir))
	{
		EXIT_WITH_ERROR("Output directory doesn't exist");
	}

	if (method == "")
	{
		EXIT_WITH_ERROR("Split method was not given");
	}

	Splitter* splitter = NULL;

	// decide of the splitter to use, according to the user's choice
	if (method == SPLIT_BY_FILE_SIZE)
	{
		uint64_t paramAsUint64 = (paramWasSet ? strtoull(param, NULL, 10) : 0);
		splitter = new FileSizeSplitter(paramAsUint64);
	}
	else if (method == SPLIT_BY_PACKET_COUNT)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : 0);
		splitter = new PacketCountSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_IP_CLIENT)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : SplitterWithMaxFiles::UNLIMITED_FILES_MAGIC_NUMBER);
		splitter = new ClientIPSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_IP_SERVER)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : SplitterWithMaxFiles::UNLIMITED_FILES_MAGIC_NUMBER);
		splitter = new ServerIPSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_SERVER_PORT)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : SplitterWithMaxFiles::UNLIMITED_FILES_MAGIC_NUMBER);
		splitter = new ServerPortSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_2_TUPLE)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : SplitterWithMaxFiles::UNLIMITED_FILES_MAGIC_NUMBER);
		splitter = new TwoTupleSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_5_TUPLE)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : SplitterWithMaxFiles::UNLIMITED_FILES_MAGIC_NUMBER);
		splitter = new FiveTupleSplitter(paramAsInt);
	}
	else if (method == SPLIT_BY_BPF_FILTER)
	{
		splitter = new BpfCriteriaSplitter(std::string(param));
	}
	else if (method == SPLIT_BY_ROUND_ROBIN)
	{
		int paramAsInt = (paramWasSet ? atoi(param) : 0);
		splitter = new RoundRobinSplitter(paramAsInt);
	}
	else
		EXIT_WITH_ERROR("Unknown method '%s'", method.c_str());


	// verify splitter param is legal, otherwise return an error
	std::string errorStr;
	if (!splitter->isSplitterParamLegal(errorStr))
	{
		EXIT_WITH_ERROR("%s", errorStr.c_str());
	}

	// prepare the output file format: /requested-path/original-file-name-[4-digit-number-starting-at-0000].pcap
	std::string outputPcapFileName = outputPcapDir + std::string(1, SEPARATOR) + getFileNameWithoutExtension(inputPcapFileName) + "-";

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

	printf("Started...\n");

	int packetCountSoFar = 0;
	int numOfFiles = 0;
	RawPacket rawPacket;

	// prepare a map of file number to PcapFileWriterDevice
	std::map<int, PcapFileWriterDevice*> outputFiles;

	// read all packets from input file, for each packet do:
	while (reader.getNextPacket(rawPacket))
	{
		// parse the raw packet into a parsed packet
		Packet parsedPacket(&rawPacket);

		std::vector<int> filesToClose;

		// call the splitter to get the file number to write the current packet to
		int fileNum = splitter->getFileNumber(parsedPacket, filesToClose);

		// if file number is seen for the first time (meaning it's the first packet written to it)
		if (outputFiles.find(fileNum) == outputFiles.end())
		{
			// get file name from the splitter and add the .pcap extension
			std::string fileName = splitter->getFileName(parsedPacket, outputPcapFileName, fileNum) + ".pcap";

			// create a new PcapFileWriterDevice for this file
			outputFiles[fileNum] = new PcapFileWriterDevice(fileName.c_str(), reader.getLinkLayerType());

			// open the writer
			if (!outputFiles[fileNum]->open())
				break;

			numOfFiles++;
		}

		// if file number exists in the map but PcapFileWriterDevice is null it means this file was open once and
		// then closed. In this case we need to re-open the PcapFileWriterDevice in append mode
		else if (outputFiles[fileNum] == NULL)
		{
			// get file name from the splitter and add the .pcap extension
			std::string fileName = splitter->getFileName(parsedPacket, outputPcapFileName, fileNum) + ".pcap";

			// re-create the PcapFileWriterDevice
			outputFiles[fileNum] = new PcapFileWriterDevice(fileName.c_str());

			// open the writer in __append__ mode
			if (!outputFiles[fileNum]->open(true))
				break;
		}

		// write the packet to the writer
		outputFiles[fileNum]->writePacket(*parsedPacket.getRawPacket());

		// if splitter wants us to close files - go over the file numbers and close them
		for (std::vector<int>::iterator it = filesToClose.begin(); it != filesToClose.end(); it++)
		{
			// check if that file number is in the map
			if (outputFiles.find(*it) != outputFiles.end())
			{
				// close the writer
				outputFiles[*it]->close();

				// free the writer memory and put null in the map record
				delete outputFiles[*it];
				outputFiles[*it] = NULL;
			}
		}

		packetCountSoFar++;
	}

	std::cout << "Finished. Read and written " << packetCountSoFar << " packets to " << numOfFiles << " files" << std::endl;

	// close the reader file
	reader.close();

	// close the writer files which are still open
	for(std::map<int, PcapFileWriterDevice*>::iterator it = outputFiles.begin(); it != outputFiles.end(); ++it)
	{
		if (it->second != NULL)
			it->second->close();
	}

	return 0;
}
