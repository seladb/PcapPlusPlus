#include <iostream>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <cmath>
#include "PcapPlusPlusVersion.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "getopt.h"

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

static struct option FragUtilOptions[] = {
	{ "output-file",      required_argument, nullptr, 'o' },
	{ "frag-size",        required_argument, nullptr, 's' },
	{ "filter-by-ipid",   required_argument, nullptr, 'd' },
	{ "bpf-filter",       required_argument, nullptr, 'f' },
	{ "copy-all-packets", no_argument,       nullptr, 'a' },
	{ "help",             no_argument,       nullptr, 'h' },
	{ "version",          no_argument,       nullptr, 'v' },
	{ nullptr,            0,                 nullptr, 0   }
};

/**
 * A struct for collecting stats during the fragmentation process
 */
struct FragStats
{
	int totalPacketsRead;
	int ipv4Packets;
	int ipv6Packets;
	int ipv4PacketsMatchIpIDs;
	int ipPacketsMatchBpfFilter;
	int ipPacketsUnderSize;
	int ipv4PacketsFragmented;
	int ipv6PacketsFragmented;
	int totalPacketsWritten;

	void clear()
	{
		memset(this, 0, sizeof(FragStats));
	}
	FragStats()
	{
		clear();
	}
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout
	    << std::endl
	    << "Usage:" << std::endl
	    << "------" << std::endl
	    << pcpp::AppName::get() << " input_file -s frag_size -o output_file [-d ip_ids] [-f bpf_filter] [-a] [-h] [-v]"
	    << std::endl
	    << std::endl
	    << "Options:" << std::endl
	    << std::endl
	    << "    input_file      : Input pcap/pcapng file" << std::endl
	    << "    -s frag_size    : Size of each fragment" << std::endl
	    << "    -o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type"
	    << std::endl
	    << "    -d ip_ids       : Fragment only packets that match this comma-separated list of IP IDs in decimal "
	       "format"
	    << std::endl
	    << "    -f bpf_filter   : Fragment only packets that match bpf_filter. Filter should be provided in Berkeley "
	       "Packet Filter (BPF)"
	    << std::endl
	    << "                      syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'" << std::endl
	    << "    -a              : Copy all packets (those who were fragmented and those who weren't) to output file"
	    << std::endl
	    << "    -v              : Displays the current version and exits" << std::endl
	    << "    -h              : Displays this help message and exits" << std::endl
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

/**
 * Set fragment parameters in an IPv4 fragment packet
 */
void setIPv4FragmentParams(pcpp::IPv4Layer* fragIpLayer, size_t fragOffset, bool lastFrag)
{
	// calculate the fragment offset field
	uint16_t fragOffsetValue = pcpp::hostToNet16((uint16_t)(fragOffset / 8));

	// set the fragment flags bits to zero
	fragOffsetValue &= (uint16_t)0xff1f;

	// if this is not the last fragment, set a "more fragments" flag
	if (!lastFrag)
		fragOffsetValue |= (uint16_t)0x20;

	// write fragment flags + fragment offset to packet
	fragIpLayer->getIPv4Header()->fragmentOffset = fragOffsetValue;
}

/**
 * Add IPv6 fragmentation extension to an IPv6 fragment packet and set fragmentation parameters
 */
void setIPv6FragmentParams(pcpp::IPv6Layer* fragIpLayer, size_t fragOffset, bool lastFrag, uint32_t fragId)
{
	pcpp::IPv6FragmentationHeader fragHeader(fragId, fragOffset, lastFrag);
	fragIpLayer->addExtension<pcpp::IPv6FragmentationHeader>(fragHeader);
}

/**
 * Generate a 4-byte positive random number. Used for generating IPv6 fragment ID
 */
uint32_t generateRandomNumber()
{
	uint32_t result = 0;
	for (int i = 4; i > 0; i--)
	{
		uint8_t randomNum = (uint8_t)rand() % 256;
		result += (uint32_t)pow(randomNum, i);
	}

	return result;
}

/**
 * A method that takes a raw packet and a requested fragment size and splits the packet into fragments.
 * Fragments are written to a  RawPacketVector instance supplied by the user.
 * The input packet isn't modified in any way.
 * If the packet isn't of type IPv4 or IPv6, nothing happens and the result vector remains empty.
 * If the packet payload size is smaller or equal than the request fragment size the packet isn't fragmented, but the
 * packet is copied and pushed into the result vector
 */
void splitIPPacketToFragmentsBySize(pcpp::RawPacket* rawPacket, size_t fragmentSize,
                                    pcpp::RawPacketVector& resultFragments)
{
	// parse raw packet
	pcpp::Packet packet(rawPacket);

	// check if IPv4/6
	pcpp::ProtocolType ipProto = pcpp::UnknownProtocol;
	if (packet.isPacketOfType(pcpp::IPv4))
		ipProto = pcpp::IPv4;
	else if (packet.isPacketOfType(pcpp::IPv6))
		ipProto = pcpp::IPv6;
	else
		return;

	pcpp::Layer* ipLayer = nullptr;
	if (ipProto == pcpp::IPv4)
		ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
	else  // ipProto == IPv6
		ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();

	// if packet payload size is less than the requested fragment size, don't fragment and return
	if (ipLayer->getLayerPayloadSize() <= fragmentSize)
	{
		pcpp::RawPacket* copyOfRawPacket = new pcpp::RawPacket(*rawPacket);
		resultFragments.pushBack(copyOfRawPacket);
		return;
	}

	// generate a random number for IPv6 fragment ID (not used in IPv4 packets)
	uint32_t randomNum = generateRandomNumber();

	// go over the payload and create fragments until reaching the end of the payload
	size_t curOffset = 0;
	while (curOffset < ipLayer->getLayerPayloadSize())
	{
		bool lastFrag = false;
		size_t curFragSize = fragmentSize;

		// check if this is the last fragment by comparing the size of the rest of the payload to the requested fragment
		// size
		if (ipLayer->getLayerPayloadSize() - curOffset <= fragmentSize)
		{
			curFragSize = ipLayer->getLayerPayloadSize() - curOffset;
			lastFrag = true;
		}

		// create the fragment packet
		// first, duplicate the input packet and create a new parsed packet out of it
		pcpp::RawPacket* newFragRawPacket = new pcpp::RawPacket(*packet.getRawPacket());
		pcpp::Packet newFrag(newFragRawPacket);

		// find the IPv4/6 layer of the new fragment
		pcpp::Layer* fragIpLayer = nullptr;
		if (ipProto == pcpp::IPv4)
			fragIpLayer = newFrag.getLayerOfType<pcpp::IPv4Layer>();
		else  // ipProto == IPv6
			fragIpLayer = newFrag.getLayerOfType<pcpp::IPv6Layer>();

		// delete all layers above IP layer
		newFrag.removeAllLayersAfter(fragIpLayer);

		// create a new PayloadLayer with the fragmented data and add it to the new fragment packet
		pcpp::PayloadLayer newPayload(ipLayer->getLayerPayload() + curOffset, curFragSize);
		newFrag.addLayer(&newPayload);

		// set fragment parameters in IPv4/6 layer
		if (ipProto == pcpp::IPv4)
			setIPv4FragmentParams((pcpp::IPv4Layer*)fragIpLayer, curOffset, lastFrag);
		else  // ipProto == IPv6
			setIPv6FragmentParams((pcpp::IPv6Layer*)fragIpLayer, curOffset, lastFrag, randomNum);

		// compute all calculated fields of the new fragment
		newFrag.computeCalculateFields();

		// add fragment to result list
		resultFragments.pushBack(newFrag.getRawPacket());

		// increment offset pointer
		curOffset += curFragSize;
	}
}

/**
 * This method reads packets from the input file, decided which packets pass the filters set by the user, fragment
 * packets who pass them, and write the result packets to the output file
 */
void processPackets(pcpp::IFileReaderDevice* reader, pcpp::IFileWriterDevice* writer, int fragSize, bool filterByBpf,
                    const std::string& bpfFilter, bool filterByIpID, std::unordered_map<uint16_t, bool> ipIDs,
                    bool copyAllPacketsToOutputFile, FragStats& stats)
{
	stats.clear();

	pcpp::RawPacket rawPacket;
	pcpp::BPFStringFilter filter(bpfFilter);

	// read all packet from input file
	while (reader->getNextPacket(rawPacket))
	{
		stats.totalPacketsRead++;

		// as default - set the packet as marked for fragmentation
		bool fragPacket = true;

		// if user requested to filter by BPF
		if (filterByBpf)
		{
			// check if packet matches the BPF filter supplied by the user
			if (pcpp::IPcapDevice::matchPacketWithFilter(filter, &rawPacket))
			{
				stats.ipPacketsMatchBpfFilter++;
			}
			else  // if not - set the packet as not marked for fragmentation
			{
				fragPacket = false;
			}
		}

		pcpp::ProtocolType ipProto = pcpp::UnknownProtocol;

		// check if packet is of type IPv4
		pcpp::Packet parsedPacket(&rawPacket);
		if (parsedPacket.isPacketOfType(pcpp::IPv4))
		{
			ipProto = pcpp::IPv4;
			stats.ipv4Packets++;
		}
		else if (parsedPacket.isPacketOfType(pcpp::IPv6))  // check if packet is of type IPv6
		{
			ipProto = pcpp::IPv6;
			stats.ipv6Packets++;
		}
		else  // if not - set the packet as not marked for fragmentation
		{
			fragPacket = false;
		}

		// if user requested to filter by IP ID (relevant only for IPv4 packets)
		if (filterByIpID)
		{
			// get the IPv4 layer
			pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipLayer != nullptr)
			{
				// check if packet ID matches one of the IP IDs requested by the user
				if (ipIDs.find(pcpp::netToHost16(ipLayer->getIPv4Header()->ipId)) != ipIDs.end())
				{
					stats.ipv4PacketsMatchIpIDs++;
				}
				else  // if not - set the packet as not marked for fragmentation
				{
					fragPacket = false;
				}
			}
		}

		// if packet passed all filters and marked for fragmentation
		if (fragPacket)
		{
			// call the method who splits the packet into fragments
			pcpp::RawPacketVector resultFrags;
			splitIPPacketToFragmentsBySize(&rawPacket, (size_t)fragSize, resultFrags);

			// if result list contains only 1 packet it means packet wasn't fragmented - update stats accordingly
			if (resultFrags.size() == 1)
			{
				stats.ipPacketsUnderSize++;
			}
			else if (resultFrags.size() > 1)  // packet was fragmented
			{
				if (ipProto == pcpp::IPv4)
					stats.ipv4PacketsFragmented++;
				else  // ipProto == IPv6
					stats.ipv6PacketsFragmented++;
			}

			// write the result fragments if either: (1) packet was indeed fragmented,
			// or (2) user requested to write all packet to output file
			if (resultFrags.size() > 1 || copyAllPacketsToOutputFile)
			{
				writer->writePackets(resultFrags);
				stats.totalPacketsWritten += resultFrags.size();
			}
		}
		// even if packet didn't pass the filters but user requested to write all packet to output file, write it
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
void printStats(const FragStats& stats, bool filterByIpID, bool filterByBpf)
{
	std::ostringstream stream;
	stream << "Summary:\n";
	stream << "========\n";
	stream << "Total packets read:                      " << stats.totalPacketsRead << std::endl;
	stream << "IPv4 packets read:                       " << stats.ipv4Packets << std::endl;
	stream << "IPv6 packets read:                       " << stats.ipv6Packets << std::endl;
	if (filterByIpID)
		stream << "IPv4 packets match IP ID list:           " << stats.ipv4PacketsMatchIpIDs << std::endl;
	if (filterByBpf)
		stream << "IP packets match BPF filter:             " << stats.ipPacketsMatchBpfFilter << std::endl;
	stream << "IP packets smaller than fragment size:   " << stats.ipPacketsUnderSize << std::endl;
	stream << "IPv4 packets fragmented:                 " << stats.ipv4PacketsFragmented << std::endl;
	stream << "IPv6 packets fragmented:                 " << stats.ipv6PacketsFragmented << std::endl;
	stream << "Total packets written to output file:    " << stats.totalPacketsWritten << std::endl;

	std::cout << stream.str();
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	std::string outputFile = "";
	int fragSize = -1;
	bool filterByBpfFilter = false;
	std::string bpfFilter = "";
	bool filterByIpID = false;
	std::unordered_map<uint16_t, bool> ipIDMap;
	bool copyAllPacketsToOutputFile = false;

	while ((opt = getopt_long(argc, argv, "o:s:d:f:ahv", FragUtilOptions, &optionIndex)) != -1)
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
		case 's':
		{
			fragSize = atoi(optarg);
			if (fragSize < 1)
				EXIT_WITH_ERROR("Fragment size must be a positive integer");
			if (fragSize % 8 != 0)
				EXIT_WITH_ERROR("Fragment size must divide by 8");
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
			while (std::getline(stream, ipIDStr, ','))
			{
				// convert the IP ID to uint16_t
				uint16_t ipID = (uint16_t)atoi(ipIDStr.c_str());
				// add the IP ID into the map if it doesn't already exist
				ipIDMap.emplace(ipID, true);
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
			pcpp::BPFStringFilter filter(bpfFilter);
			if (!filter.verifyFilter())
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

	// go over user params and look the input file
	for (int i = optind; i < argc; i++)
	{
		paramIndex++;
		if (paramIndex > expectedParams)
			EXIT_WITH_ERROR("Unexpected parameter: " << argv[i]);

		switch (paramIndex)
		{
		case 0:
		{
			inputFile = argv[i];
			break;
		}

		default:
			EXIT_WITH_ERROR("Unexpected parameter: " << argv[i]);
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

	if (fragSize < 0)
	{
		EXIT_WITH_ERROR("Need to choose fragment size using the '-s' flag");
	}

	// create a reader device from input file
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(inputFile);

	if (!reader->open())
	{
		EXIT_WITH_ERROR("Error opening input file");
	}

	// create a writer device for output file in the same file type as input file
	pcpp::IFileWriterDevice* writer = nullptr;

	if (dynamic_cast<pcpp::PcapFileReaderDevice*>(reader) != nullptr)
	{
		writer = new pcpp::PcapFileWriterDevice(outputFile, ((pcpp::PcapFileReaderDevice*)reader)->getLinkLayerType());
	}
	else if (dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader) != nullptr)
	{
		writer = new pcpp::PcapNgFileWriterDevice(outputFile);
	}
	else
	{
		EXIT_WITH_ERROR("Cannot determine input file type");
	}

	if (!writer->open())
	{
		EXIT_WITH_ERROR("Error opening output file");
	}

	// run the fragmentation process
	FragStats stats;
	processPackets(reader, writer, fragSize, filterByBpfFilter, bpfFilter, filterByIpID, ipIDMap,
	               copyAllPacketsToOutputFile, stats);

	// close files
	reader->close();
	writer->close();

	// print summary stats to console
	printStats(stats, filterByIpID, filterByBpfFilter);

	delete reader;
	delete writer;
}
