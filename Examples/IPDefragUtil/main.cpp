#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include "PcapPlusPlusVersion.h"
#include "IPv4Layer.h"
#include "IPv4Reassembly.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "getopt.h"

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)

static struct option DefragUtilOptions[] =
{
	{"output-file", required_argument, 0, 'o'},
	{"filter-by-ipid", required_argument, 0, 'd'},
	{"bpf-filter", required_argument, 0, 'f'},
	{"copy-all-packets", no_argument, 0, 'a'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};

/**
 * A struct for collecting stats during the de-fragmentation process
 */
struct DefragStats
{
	int totalPacketsRead;
	int ipv4Packets;
	int ipv4PacketsMatchIpIDs;
	int ipv4PacketsMatchBpfFilter;
	int ipv4FragmentsMatched;
	int ipv4PacketsDefragmented;
	int totalPacketsWritten;

	void clear() { memset(this, 0, sizeof(DefragStats)); }
	DefragStats() { clear(); }
};


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"-------\n"
			"%s input_file -o output_file [-d ip_ids] [-f bpf_filter] [-a] [-h] [-v]\n"
			"\nOptions:\n\n"
			"    input_file      : Input pcap/pcapng file\n"
			"    -o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type\n"
			"    -d ip_ids       : De-fragment only fragments that match this comma-separated list of IP IDs in decimal format\n"
			"    -f bpf_filter   : De-fragment only fragments that match bpf_filter. Filter should be provided in Berkeley Packet Filter (BPF)\n"
			"                      syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'\n"
			"    -a              : Copy all packets (those who were de-fragmented and those who weren't) to output file\n"
			"    -v              : Displays the current version and exits\n"
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
 * This method reads packets from the input file, decided which fragments pass the filters set by the user, de-fragment the fragments
 * who pass them, and writes the result packets to the output file
 */
void processPackets(IFileReaderDevice* reader, IFileWriterDevice* writer,
		bool filterByBpf, std::string bpfFilter,
		bool filterByIpID, std::map<uint16_t, bool> ipIDs,
		bool copyAllPacketsToOutputFile,
		DefragStats& stats)
{
	RawPacket rawPacket;

	// create an instance of IPv4Reassembly
	IPv4Reassembly ipv4Reassembly;

	IPv4Reassembly::ReassemblyStatus status;

	// read all packet from input file
	while (reader->getNextPacket(rawPacket))
	{
		bool defragPacket = true;

		stats.totalPacketsRead++;

		// if user requested to filter by BPF
		if (filterByBpf)
		{
			// check if packet matches the BPF filter supplied by the user
			if (IPcapDevice::matchPakcetWithFilter(bpfFilter, &rawPacket))
			{
				stats.ipv4PacketsMatchBpfFilter++;
			}
			else // if not - set the packet as not marked for de-fragmentation
			{
				defragPacket = false;
			}
		}

		// check if packet is of type IPv4
		Packet parsedPacket(&rawPacket);
		if (parsedPacket.isPacketOfType(IPv4))
		{
			stats.ipv4Packets++;
		}
		else // if not - set the packet as not marked for de-fragmentation
		{
			defragPacket = false;
		}

		// if user requested to filter by IP ID
		if (filterByIpID)
		{
			// get the IPv4 layer
			IPv4Layer* ipLayer = parsedPacket.getLayerOfType<IPv4Layer>();
			if (ipLayer != NULL)
			{
				// check if packet ID matches one of the IP IDs requested by the user
				if (ipIDs.find(ntohs(ipLayer->getIPv4Header()->ipId)) != ipIDs.end())
				{
					stats.ipv4PacketsMatchIpIDs++;
				}
				else // if not - set the packet as not marked for de-fragmentation
				{
					defragPacket = false;
				}
			}
		}

		// if fragment is marked for de-fragmentation
		if (defragPacket)
		{
			// process the packet in the IPv4 reassembly mechanism
			Packet* result = ipv4Reassembly.processPacket(&parsedPacket, status);

			// write fragment/packet to file if:
			// - packet is fully reassembled (status of REASSEMBLED)
			// - packet isn't a fragment or isn't an IPv4 packet and the user asked to write all packets to output
			if (status == IPv4Reassembly::REASSEMBLED ||
					((status == IPv4Reassembly::NON_IP_PACKET || status == IPv4Reassembly::NON_FRAGMENT) && copyAllPacketsToOutputFile))
			{
				writer->writePacket(*result->getRawPacket());
				stats.totalPacketsWritten++;
			}

			// update statistics if packet is fully reassembled (status of REASSEMBLED)
			if (status == IPv4Reassembly::REASSEMBLED)
			{
				stats.ipv4PacketsDefragmented++;
				delete result;
			}

			// update statistics if packet if packet isn't full reassembled
			if (status == IPv4Reassembly::FIRST_FRAGMENT ||
					status == IPv4Reassembly::FRAGMENT ||
					status == IPv4Reassembly::OUT_OF_ORDER_FRAGMENT ||
					status == IPv4Reassembly::MALFORMED_FRAGMENT ||
					status == IPv4Reassembly::REASSEMBLED)
			{
				stats.ipv4FragmentsMatched++;
			}
		}
		// if packet isn't marked for de-fragmentation but the user asked to write all packets to output file
		else if (copyAllPacketsToOutputFile)
		{
			writer->writePacket(rawPacket);
			stats.totalPacketsWritten++;
		}

	}
}


/**
 * A method for printing fragmentation process stats
 */
void printStats(const DefragStats& stats, bool filterByIpID, bool filterByBpf)
{
	std::ostringstream stream;
	stream << "Summary:\n";
	stream << "========\n";
	stream << "Total packets read:                      " << stats.totalPacketsRead << std::endl;
	stream << "IPv4 packets read:                       " << stats.ipv4Packets << std::endl;
	if (filterByIpID)
		stream << "IPv4 packets match IP ID list:           " << stats.ipv4PacketsMatchIpIDs << std::endl;
	if (filterByBpf)
		stream << "IPv4 packets match BPF filter:           " << stats.ipv4PacketsMatchBpfFilter << std::endl;
	stream << "IPv4 total fragments matched:            " << stats.ipv4FragmentsMatched << std::endl;
	stream << "IPv4 packets de-fragmented:              " << stats.ipv4PacketsDefragmented << std::endl;
	stream << "Total packets written to output file:    " << stats.totalPacketsWritten << std::endl;

	std::cout << stream.str();
}


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	int optionIndex = 0;
	char opt = 0;

	std::string outputFile = "";
	bool filterByBpfFilter = false;
	std::string bpfFilter = "";
	bool filterByIpID = false;
	std::map<uint16_t, bool> ipIDMap;
	bool copyAllPacketsToOutputFile = false;


	while((opt = getopt_long (argc, argv, "o:d:f:ahv", DefragUtilOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
			{
				break;
			}
			case 'o':
			{
				outputFile = optarg;
				break;
			}
			case 'd':
			{
				filterByIpID = true;
				// read the IP ID list into the map
				ipIDMap.clear();
				std::string ipIDsAsString = std::string(optarg);
				std::stringstream stream(ipIDsAsString);
				std::string ipIDStr;
				// break comma-separated string into string list
				while(std::getline(stream, ipIDStr, ','))
				{
					// convert the IP ID to uint16_t
					uint16_t ipID = (uint16_t)atoi(ipIDStr.c_str());
					// add the IP ID into the map if it doesn't already exist
					if (ipIDMap.find(ipID) == ipIDMap.end())
						ipIDMap[ipID] = true;
				}

				// verify list is not empty
				if (ipIDMap.empty())
				{
					EXIT_WITH_ERROR("Couldn't parse IP ID list");
				}
				break;
			}
			case 'f':
			{
				filterByBpfFilter = true;
				bpfFilter = optarg;
				if (!IPcapDevice::verifyFilter(bpfFilter))
					EXIT_WITH_ERROR("Illegal BPF filter");
				break;
			}
			case 'a':
			{
				copyAllPacketsToOutputFile = true;
				break;
			}
			case 'h':
			{
				printUsage();
				exit(0);
			}
			case 'v':
			{
				printAppVersion();
				break;
			}
		}
	}

	std::string inputFile = "";

	int expectedParams = 1;
	int paramIndex = -1;

    for (int i = optind; i < argc; i++)
    {
    	paramIndex++;
    	if (paramIndex > expectedParams)
    		EXIT_WITH_ERROR("Unexpected parameter: %s", argv[i]);

    	switch (paramIndex)
    	{
			case 0:
			{
				inputFile = argv[i];
				break;
			}

			default:
				EXIT_WITH_ERROR("Unexpected parameter: %s", argv[i]);
    	}
    }

    if (inputFile == "")
    {
    	EXIT_WITH_ERROR("Input file name was not given");
    }

    if (outputFile == "")
    {
    	EXIT_WITH_ERROR("Output file name was not given");
    }

    // create a reader device from input file
    IFileReaderDevice* reader = IFileReaderDevice::getReader(inputFile.c_str());

	if (!reader->open())
	{
		EXIT_WITH_ERROR("Error opening input file\n");
	}


	// create a writer device for output file in the same file type as input file
	IFileWriterDevice* writer = NULL;

	if (dynamic_cast<PcapFileReaderDevice*>(reader) != NULL)
	{
		writer = new PcapFileWriterDevice(outputFile.c_str(), ((PcapFileReaderDevice*)reader)->getLinkLayerType());
	}
	else if (dynamic_cast<PcapNgFileReaderDevice*>(reader) != NULL)
	{
		writer = new PcapNgFileWriterDevice(outputFile.c_str());
	}
	else
	{
		EXIT_WITH_ERROR("Cannot determine input file type");
	}

	if (!writer->open())
	{
		EXIT_WITH_ERROR("Error opening output file\n");
	}

	// run the de-fragmentation process
	DefragStats stats;
	processPackets(reader, writer, filterByBpfFilter, bpfFilter, filterByIpID, ipIDMap, copyAllPacketsToOutputFile, stats);

	// close files
	reader->close();
	writer->close();

	// print summary stats to console
	printStats(stats, filterByIpID, filterByBpfFilter);

	delete reader;
	delete writer;
}
