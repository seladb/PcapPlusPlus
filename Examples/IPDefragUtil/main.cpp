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
#include "IPv6Layer.h"
#include "IPReassembly.h"
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
	int ipv6Packets;
	int ipv4PacketsMatchIpIDs;
	int ipv6PacketsMatchFragIDs;
	int ipPacketsMatchBpfFilter;
	int ipv4FragmentsMatched;
	int ipv6FragmentsMatched;
	int ipv4PacketsDefragmented;
	int ipv6PacketsDefragmented;
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
			"%s input_file -o output_file [-d frag_ids] [-f bpf_filter] [-a] [-h] [-v]\n"
			"\nOptions:\n\n"
			"    input_file      : Input pcap/pcapng file\n"
			"    -o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type\n"
			"    -d frag_ids     : De-fragment only fragments that match this comma-separated list of IP IDs (for IPv4) or\n"
			"                      fragment IDs (for IPv6) in decimal format\n"
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
		bool filterByIpID, std::map<uint32_t, bool> fragIDs,
		bool copyAllPacketsToOutputFile,
		DefragStats& stats)
{
	RawPacket rawPacket;

	// create an instance of IPReassembly
	IPReassembly ipReassembly;

	IPReassembly::ReassemblyStatus status;

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
				stats.ipPacketsMatchBpfFilter++;
			}
			else // if not - set the packet as not marked for de-fragmentation
			{
				defragPacket = false;
			}
		}

		bool isIPv4Packet = false;
		bool isIPv6Packet = false;

		// check if packet is of type IPv4 or IPv6
		Packet parsedPacket(&rawPacket);
		if (parsedPacket.isPacketOfType(IPv4))
		{
			stats.ipv4Packets++;
			isIPv4Packet = true;
		}
		else if (parsedPacket.isPacketOfType(IPv6))
		{
			stats.ipv6Packets++;
			isIPv6Packet = true;
		}
		else // if not - set the packet as not marked for de-fragmentation
		{
			defragPacket = false;
		}

		// if user requested to filter by IP ID
		if (filterByIpID)
		{
			// get the IPv4 layer
			IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
			if (ipv4Layer != NULL)
			{
				// check if packet ID matches one of the IP IDs requested by the user
				if (fragIDs.find((uint32_t)ntohs(ipv4Layer->getIPv4Header()->ipId)) != fragIDs.end())
				{
					stats.ipv4PacketsMatchIpIDs++;
				}
				else // if not - set the packet as not marked for de-fragmentation
				{
					defragPacket = false;
				}
			}

			// get the IPv6 layer
			IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<IPv6Layer>();
			if (ipv6Layer != NULL && ipv6Layer->isFragment())
			{
				// if this packet is a fragment, get the fragmentation header
				IPv6FragmentationHeader* fragHdr = ipv6Layer->getExtensionOfType<IPv6FragmentationHeader>();

				// check if fragment ID matches one of the fragment IDs requested by the user
				if (fragIDs.find(ntohl(fragHdr->getFragHeader()->id)) != fragIDs.end())
				{
					stats.ipv6PacketsMatchFragIDs++;
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
			// process the packet in the IP reassembly mechanism
			Packet* result = ipReassembly.processPacket(&parsedPacket, status);

			// write fragment/packet to file if:
			// - packet is fully reassembled (status of REASSEMBLED)
			// - packet isn't a fragment or isn't an IP packet and the user asked to write all packets to output
			if (status == IPReassembly::REASSEMBLED ||
					((status == IPReassembly::NON_IP_PACKET || status == IPReassembly::NON_FRAGMENT) && copyAllPacketsToOutputFile))
			{
				writer->writePacket(*result->getRawPacket());
				stats.totalPacketsWritten++;
			}

			// update statistics if packet is fully reassembled (status of REASSEMBLED) and
			if (status == IPReassembly::REASSEMBLED)
			{
				if (isIPv4Packet)
					stats.ipv4PacketsDefragmented++;
				else if (isIPv6Packet)
					stats.ipv6PacketsDefragmented++;

				// free packet
				delete result;
			}

			// update statistics if packet isn't fully reassembled
			if (status == IPReassembly::FIRST_FRAGMENT ||
					status == IPReassembly::FRAGMENT ||
					status == IPReassembly::OUT_OF_ORDER_FRAGMENT ||
					status == IPReassembly::MALFORMED_FRAGMENT ||
					status == IPReassembly::REASSEMBLED)
			{
				if (isIPv4Packet)
					stats.ipv4FragmentsMatched++;
				else if (isIPv6Packet)
					stats.ipv6FragmentsMatched++;
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
	stream << "IPv6 packets read:                       " << stats.ipv6Packets << std::endl;
	if (filterByIpID)
	{
		stream << "IPv4 packets match fragment ID list:     " << stats.ipv4PacketsMatchIpIDs << std::endl;
		stream << "IPv6 packets match fragment ID list:     " << stats.ipv6PacketsMatchFragIDs << std::endl;
	}
	if (filterByBpf)
		stream << "IP packets match BPF filter:             " << stats.ipPacketsMatchBpfFilter << std::endl;
	stream << "Total fragments matched:                 " << (stats.ipv4FragmentsMatched + stats.ipv6FragmentsMatched) << std::endl;
	stream << "IPv4 fragments matched:                  " << stats.ipv4FragmentsMatched << std::endl;
	stream << "IPv6 fragments matched:                  " << stats.ipv6FragmentsMatched << std::endl;
	stream << "Total packets reassembled:               " << (stats.ipv4PacketsDefragmented + stats.ipv6PacketsDefragmented) << std::endl;
	stream << "IPv4 packets reassembled:                " << stats.ipv4PacketsDefragmented << std::endl;
	stream << "IPv6 packets reassembled:                " << stats.ipv6PacketsDefragmented << std::endl;
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
	bool filterByFragID = false;
	std::map<uint32_t, bool> fragIDMap;
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
				filterByFragID = true;
				// read the IP ID / Frag ID list into the map
				fragIDMap.clear();
				std::string ipIDsAsString = std::string(optarg);
				std::stringstream stream(ipIDsAsString);
				std::string ipIDStr;
				// break comma-separated string into string list
				while(std::getline(stream, ipIDStr, ','))
				{
					// convert the IP ID to uint16_t
					uint32_t fragID = (uint32_t)atoi(ipIDStr.c_str());
					// add the frag ID into the map if it doesn't already exist
					if (fragIDMap.find(fragID) == fragIDMap.end())
						fragIDMap[fragID] = true;
				}

				// verify list is not empty
				if (fragIDMap.empty())
				{
					EXIT_WITH_ERROR("Couldn't parse fragment ID list");
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
	processPackets(reader, writer, filterByBpfFilter, bpfFilter, filterByFragID, fragIDMap, copyAllPacketsToOutputFile, stats);

	// close files
	reader->close();
	writer->close();

	// print summary stats to console
	printStats(stats, filterByFragID, filterByBpfFilter);

	delete reader;
	delete writer;
}
