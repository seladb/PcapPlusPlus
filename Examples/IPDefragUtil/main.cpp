#include "GreLayer.h"
#include "IPReassembly.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "IpAddress.h"
#include "L2tpLayer.h"
#include "LRUList.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PcapPlusPlusVersion.h"
#include "ProtocolType.h"
#include "Reassembly.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include "getopt.h"
#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <string>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#if defined(_WIN32)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif

// unless the user chooses otherwise - default number of concurrent used file descl2tptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500

std::string getTupleName(pcpp::IPAddress src, pcpp::IPAddress dst, uint16_t srcPort, uint16_t dstPort,
						 std::string protocol_name)
{
	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol_name;

	// return the name
	return stream.str();
}
/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the
 * application
 */
class GlobalConfig
{
  private:
	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig()
	{
		writeMetadata = false;
		writeToConsole = false;
		maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
		m_RecentFilesWithActivity = NULL;
	}

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key.
	// This LRU list is used to decide which connection was seen least recently in case we reached max number of open
	// file descl2tptors and we need to decide which files to close
	pcpp::LRUList<std::string> *m_RecentFilesWithActivity;

  public:
	// calculate processed packet numbers
	int PacketNum;

	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a flag indicating whether to write L2TP data to actual files or to console
	bool writeToConsole;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;

	std::string getFileName(std::string name)
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return
		// value
		if (!outputDir.empty())
			stream << outputDir << SEPARATOR;

		stream << name;

		// return the file path
		return stream.str();
	}

	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file
	 * or overwrite it. Return value is a pointer to the new file stream
	 */
	std::ostream *openFileStream(std::string fileName, bool reopen)
	{
		// if the user chooses to write only to console, don't open anything and return std::cout
		if (writeToConsole)
			return &std::cout;

		// open the file on the disk (with append or overwrite mode)
		if (reopen)
			return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
		else
			return new std::ofstream(fileName.c_str(), std::ios_base::binary);
	}

	/**
	 * Close a file stream
	 */
	void closeFileSteam(std::ostream *fileStream)
	{
		// if the user chooses to write only to console - do nothing and return
		if (!writeToConsole)
		{
			// close the file stream
			std::ofstream *fstream = (std::ofstream *)fileStream;
			fstream->close();

			// free the memory of the file stream
			delete fstream;
		}
	}

	pcpp::LRUList<std::string> *getRecentFilesWithActivity()
	{
		// This is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default
		// is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES but the user can choose another number
		if (m_RecentFilesWithActivity == NULL)
			m_RecentFilesWithActivity = new pcpp::LRUList<std::string>(maxOpenFiles);

		// return the pointer
		return m_RecentFilesWithActivity;
	}

	/**
	 * The singleton implementation of this class
	 */
	static GlobalConfig &getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
};

// 存储某一五元组的数据包
/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats
 * data on the connection
 */
struct ReassemblyData
{
	std::ostream *fileStream;

	// flags indicating whether the file was already opened before. If the answer is yes, next time it'll
	// be opened in append mode (and not in overwrite mode)
	bool reopenFileStream;

	// stats data: num of data packets, bytes
	int numOfDataPackets;
	int bytes;

	/**
	 * the default c'tor
	 */
	ReassemblyData()
	{
		fileStream = NULL;
		clear();
	}

	/**
	 * The default d'tor
	 */
	~ReassemblyData()
	{
		// close files on both sides if open
		if (fileStream != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStream);
	}

	/**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
	void clear()
	{
		// for the file stream - close them if they're not null
		if (fileStream != NULL)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStream);
			fileStream = NULL;
		}

		reopenFileStream = false;
		numOfDataPackets = 0;
		bytes = 0;
	}
};

// 五元组->数据统计的map
// typedef representing the manager and its iterator
typedef std::map<std::string, ReassemblyData> ReassemblyMgr;
typedef std::map<std::string, ReassemblyData>::iterator ReassemblyMgrIter;

static void OnMessageReadyCallback(std::string *data, std::string tuplename, void *userCookie)
{
	/* 	1. manager 存 ReassemblyData   									yes
		2. manager 的指定 ReassemblyData 里边fileStream 是否为NULL
			2.1 将当前（指传入的参数）的名称加入opened列表
			2.2 如果打开的文件已达上限，关闭目前的
			2.3 设置文件名
			2.4 打开文件， 模式由之前2.2设置的reopenFileStreams决定
		3. 更改ReassemblyData里的统计值
		4. 将数据写入打开的文件里
	 */

	// 1.

	// extract the manager from the user cookie
	ReassemblyMgr *mgr = (ReassemblyMgr *)userCookie;

	// check if this tuple already appears in the manager. If not add it
	ReassemblyMgrIter iter = mgr->find(tuplename);
	if (iter == mgr->end())
	{
		mgr->insert(std::make_pair(tuplename, ReassemblyData()));
		iter = mgr->find(tuplename);
	}

	// 2.

	//  if filestream isn't open yet
	if (iter->second.fileStream == NULL)
	{
		// 2.1

		std::string nameToCloseFile;
		int result = GlobalConfig::getInstance().getRecentFilesWithActivity()->put(tuplename, &nameToCloseFile);

		// 2.2

		// 等于1，需要关闭最近未使用
		if (result == 1)
		{
			ReassemblyMgrIter iter2 = mgr->find(nameToCloseFile);
			if (iter2 != mgr->end())
			{
				if (iter2->second.fileStream != NULL)
				{
					// close the file
					GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStream);
					iter2->second.fileStream = NULL;

					// set the reopen flag to true to indicate that next time this file will be opened it will be opened
					// in append mode (and not overwrite mode)
					iter2->second.reopenFileStream = true;
				}
			}
		}

		// 2.3

		// get the file name according to the 5-tuple etc.
		std::string name = tuplename + ".txt";
		std::string fileName = GlobalConfig::getInstance().getFileName(name);

		// 2.4

		// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was
		// already opened before)
		iter->second.fileStream = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStream);
	}

	// 3.

	// count number of packets and bytes
	iter->second.numOfDataPackets++;

	// set new processed packet number
	GlobalConfig::getInstance().PacketNum++;

	// 4.

	// write the new data to the file
	*iter->second.fileStream << *data << std::endl;
}

static struct option DefragUtilOptions[] = {{"output-file", required_argument, 0, 'o'},
											{"filter-by-ipid", required_argument, 0, 'd'},
											{"bpf-filter", required_argument, 0, 'f'},
											{"copy-all-packets", no_argument, 0, 'a'},
											{"help", no_argument, 0, 'h'},
											{"version", no_argument, 0, 'v'},
											{0, 0, 0, 0}};

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

	void clear()
	{
		memset(this, 0, sizeof(DefragStats));
	}
	DefragStats()
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
		<< pcpp::AppName::get() << " input_file -o output_file [-d frag_ids] [-f bpf_filter] [-a] [-h] [-v]"
		<< std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    input_file      : Input pcap/pcapng file" << std::endl
		<< "    -o output_file  : Output file. Output file type (pcap/pcapng) will match the input file type"
		<< std::endl
		<< "    -d frag_ids     : De-fragment only fragments that match this comma-separated list of IP IDs (for IPv4) "
		   "or"
		<< std::endl
		<< "                      fragment IDs (for IPv6) in decimal format" << std::endl
		<< "    -f bpf_filter   : De-fragment only fragments that match bpf_filter. Filter should be provided in "
		   "Berkeley Packet Filter (BPF)"
		<< std::endl
		<< "                      syntax (http://biot.com/capstats/bpf.html) i.e: 'ip net 1.1.1.1'" << std::endl
		<< "    -a              : Copy all packets (those who were de-fragmented and those who weren't) to output file"
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
 * This method reads packets from the input file, decided which fragments pass the filters set by the user, de-fragment
 * the fragments who pass them, and writes the result packets to the output file
 */
void processPackets(pcpp::IFileReaderDevice *reader, bool filterByBpf, std::string bpfFilter, bool filterByIpID,
					std::map<uint32_t, bool> fragIDs, DefragStats &stats, void *UserCookie)
{
	pcpp::RawPacket rawPacket;
	pcpp::BPFStringFilter filter(bpfFilter);

	// create an instance of IPReassembly
	pcpp::IPReassembly ipReassembly;

	pcpp::IPReassembly::ReassemblyStatus status;

	// read all packet from input file
	while (reader->getNextPacket(rawPacket))
	{
		bool defragPacket = true;

		stats.totalPacketsRead++;

		// if user requested to filter by BPF
		if (filterByBpf)
		{
			// check if packet matches the BPF filter supplied by the user
			if (pcpp::IPcapDevice::matchPacketWithFilter(filter, &rawPacket))
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
		pcpp::Packet parsedPacket(&rawPacket);
		if (parsedPacket.isPacketOfType(pcpp::IPv4))
		{
			stats.ipv4Packets++;
			isIPv4Packet = true;
		}
		else if (parsedPacket.isPacketOfType(pcpp::IPv6))
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
			pcpp::IPv4Layer *ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipv4Layer != NULL)
			{
				// check if packet ID matches one of the IP IDs requested by the user
				if (fragIDs.find((uint32_t)pcpp::netToHost16(ipv4Layer->getIPv4Header()->ipId)) != fragIDs.end())
				{
					stats.ipv4PacketsMatchIpIDs++;
				}
				else // if not - set the packet as not marked for de-fragmentation
				{
					defragPacket = false;
				}
			}

			// get the IPv6 layer
			pcpp::IPv6Layer *ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
			if (ipv6Layer != NULL && ipv6Layer->isFragment())
			{
				// if this packet is a fragment, get the fragmentation header
				pcpp::IPv6FragmentationHeader *fragHdr = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();

				// check if fragment ID matches one of the fragment IDs requested by the user
				if (fragIDs.find(pcpp::netToHost32(fragHdr->getFragHeader()->id)) != fragIDs.end())
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
			pcpp::Packet *result = ipReassembly.processPacket(&parsedPacket, status);

			// write fragment/packet to file if:
			// - packet is fully reassembled (status of REASSEMBLED)
			// - packet isn't a fragment or isn't an IP packet and the user asked to write all packets to output
			if (status == pcpp::IPReassembly::REASSEMBLED ||
				((status == pcpp::IPReassembly::NON_IP_PACKET || status == pcpp::IPReassembly::NON_FRAGMENT)))
			{
				// @ycyaoxdu:
				// we do not write it here, we parse next layer in loop until Payload Layer is parsed.
				stats.totalPacketsWritten++;

				// TupleName is used to identify which file the packet will store in
				std::string TupleName = "";
				// the protocol name of "current" layer
				std::string protoname = "ip";
				// ip
				pcpp::IPAddress IpSrc, IpDst;

				pcpp::Layer *ipLayer;

				if (isIPv4Packet)
				{
					pcpp::IPv4Layer *ipv4Layer = result->getLayerOfType<pcpp::IPv4Layer>();
					IpSrc = ipv4Layer->getSrcIPAddress();
					IpDst = ipv4Layer->getDstIPAddress();
					ipLayer = ipv4Layer;
				}
				else
				{
					pcpp::IPv6Layer *ipv6Layer = result->getLayerOfType<pcpp::IPv6Layer>();
					IpSrc = ipv6Layer->getSrcIPAddress();
					IpDst = ipv6Layer->getDstIPAddress();
					ipLayer = ipv6Layer;
				}

				// parse next layer
				ipLayer->parseNextLayer();
				auto nextLayer = ipLayer->getNextLayer();
				// TODO(ycyaoxdu)
				// maybe interface here: handle, needs to be implement to handle packets for every submodules.
				// code logic:
				// if next layer is payload layer, just print all messages.
				// else parseNextLayer and call next module

				// switch statement
				switch (nextLayer->getProtocol())
				{
				case pcpp::OSPF:
					// ospf handle
					break;
				case pcpp::GRE:
					// gre handle
					break;
				case pcpp::ESP:
					// esp handle
					break;
				case pcpp::TCP:
					// tcp handle
					break;
				case pcpp::UDP:
					// udp handle
					protoname = "udp";

					pcpp::UdpLayer udp(nextLayer->getData(), nextLayer->getDataLen(), ipLayer, result);
					// pcpp::UdpLayer *udp = reinterpret_cast<pcpp::UdpLayer *>(nextLayer);

					uint16_t PortSrc = udp.getSrcPort();
					uint16_t PortDst = udp.getDstPort();

					// next layer
					udp.parseNextLayer();
					nextLayer = udp.getNextLayer();
					if (nextLayer->getProtocol() == pcpp::L2TP)
					{
						protoname = "l2tp";
						TupleName = getTupleName(IpSrc, IpDst, PortSrc, PortDst, protoname);

						pcpp::L2tpLayer l2tp(nextLayer->getData(), nextLayer->getDataLen(), &udp, result);
						// pcpp::L2tpLayer *l2tp = reinterpret_cast<pcpp::L2tpLayer *>(nextLayer);

						l2tp.parseNextLayer();
						nextLayer = l2tp.getNextLayer();
						if (nextLayer->getProtocol() == pcpp::PPP_PPTP)
						{
							pcpp::PPP_PPTPLayer ppp(nextLayer->getData(), nextLayer->getDataLen(), &l2tp, result);
							// pcpp::PPP_PPTPLayer *ppp = reinterpret_cast<pcpp::PPP_PPTPLayer *>(nextLayer);

							ReassembleMessage(&ppp, TupleName, UserCookie, OnMessageReadyCallback);
						}
						else
						{
							// should have ppp protocol message, if not, discard
						}
					}
					else if (nextLayer->getProtocol() == pcpp::RIP)
					{
						protoname = "rip";
					}
					else if (nextLayer->getProtocol() == pcpp::GTP)
					{
						protoname = "gtp";
					}
					else if (nextLayer->getProtocol() == pcpp::GenericPayload)
					{
						// print & save
					}
					else
					{
						// discard packet
					}

					break;
					// TODO: add SCTP in Packet++/header/ProtocolType.h, then uncomment the below 3 lines.
					// case pcpp::SCTP :
					// // sctp handle
					// break;
					// case pcpp::GenericPayload:
					// 	break;
					// default:
					// 	// drop packet
					// 	break;
				}
			}

			// update statistics if packet is fully reassembled (status of REASSEMBLED) and
			if (status == pcpp::IPReassembly::REASSEMBLED)
			{
				if (isIPv4Packet)
					stats.ipv4PacketsDefragmented++;
				else if (isIPv6Packet)
					stats.ipv6PacketsDefragmented++;

				// free packet
				delete result;
			}

			// update statistics if packet isn't fully reassembled
			if (status == pcpp::IPReassembly::FIRST_FRAGMENT || status == pcpp::IPReassembly::FRAGMENT ||
				status == pcpp::IPReassembly::OUT_OF_ORDER_FRAGMENT ||
				status == pcpp::IPReassembly::MALFORMED_FRAGMENT || status == pcpp::IPReassembly::REASSEMBLED)
			{
				if (isIPv4Packet)
					stats.ipv4FragmentsMatched++;
				else if (isIPv6Packet)
					stats.ipv6FragmentsMatched++;
			}
		}
		// if packet isn't marked for de-fragmentation but the user asked to write all packets to output file
		else
		{
			stats.totalPacketsWritten++;
		}
	}
}

/**
 * A method for printing fragmentation process stats
 */
void printStats(const DefragStats &stats, bool filterByIpID, bool filterByBpf)
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
	stream << "Total fragments matched:                 " << (stats.ipv4FragmentsMatched + stats.ipv6FragmentsMatched)
		   << std::endl;
	stream << "IPv4 fragments matched:                  " << stats.ipv4FragmentsMatched << std::endl;
	stream << "IPv6 fragments matched:                  " << stats.ipv6FragmentsMatched << std::endl;
	stream << "Total packets reassembled:               "
		   << (stats.ipv4PacketsDefragmented + stats.ipv6PacketsDefragmented) << std::endl;
	stream << "IPv4 packets reassembled:                " << stats.ipv4PacketsDefragmented << std::endl;
	stream << "IPv6 packets reassembled:                " << stats.ipv6PacketsDefragmented << std::endl;
	stream << "Total packets written to output file:    " << stats.totalPacketsWritten << std::endl;

	std::cout << stream.str();
}

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
	std::string outputDir = "";

	std::string outputFile = "";
	bool filterByBpfFilter = false;
	std::string bpfFilter = "";
	bool filterByFragID = false;
	std::map<uint32_t, bool> fragIDMap;

	while ((opt = getopt_long(argc, argv, "o:d:f:hv", DefragUtilOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0: {
			break;
		}
		case 'o': {
			outputDir = optarg;
			break;
		}
		case 'd': {
			filterByFragID = true;
			// read the IP ID / Frag ID list into the map
			fragIDMap.clear();
			std::string ipIDsAsString = std::string(optarg);
			std::stringstream stream(ipIDsAsString);
			std::string ipIDStr;
			// break comma-separated string into string list
			while (std::getline(stream, ipIDStr, ','))
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
		case 'f': {
			filterByBpfFilter = true;
			bpfFilter = optarg;
			pcpp::BPFStringFilter filter(bpfFilter);
			if (!filter.verifyFilter())
				EXIT_WITH_ERROR("Illegal BPF filter");
			break;
		}
		case 'h': {
			printUsage();
			exit(0);
		}
		case 'v': {
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
			EXIT_WITH_ERROR("Unexpected parameter: " << argv[i]);

		switch (paramIndex)
		{
		case 0: {
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

	// verify output dir exists
	if (!outputDir.empty() && !pcpp::directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info
	ReassemblyMgr mgr;

	// create a reader device from input file
	pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(inputFile);

	if (!reader->open())
	{
		EXIT_WITH_ERROR("Error opening input file");
	}

	// run the de-fragmentation process
	DefragStats stats;
	processPackets(reader, filterByBpfFilter, bpfFilter, filterByFragID, fragIDMap, stats, &mgr);

	// close files
	reader->close();

	// print summary stats to console
	printStats(stats, filterByFragID, filterByBpfFilter);

	delete reader;
}
