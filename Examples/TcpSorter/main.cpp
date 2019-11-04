/**
 * TcpSorter application
 * =========================
 * This is an application that captures packets transmitted as part of TCP connections, organizes the packet and stores it in a way that is convenient for protocol analysis and debugging.
 * This application reconstructs the TCP packets by order and stores each connection in a separate file(s). TcpSorter understands TCP sequence numbers and will correctly reorder
 * packets regardless of retransmissions, out-of-order delivery or data loss.
 *
 * The main purpose of it is to demonstrate the TCP packet sorting capabilities in PcapPlusPlus.
 *
 * Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpSorter -h
 */


#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "TcpSorter.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "LRUList.h"
#include <getopt.h>

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


// unless the user chooses otherwise - default number of concurrent used file descriptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500
#define DEFAULT_UNLIMITED_NUMBEROF_OF_CAPTURED_PACKET 0
#define DEFAULT_MAX_IDEL_TIMEOUT 180
#define DEFAULT_MAX_NUMBER_OF_INACTIVE_CONNECTION_SCAN 100
#define DEFAULT_CLEAN_UP_INACTIVE_CONNECTION_PERIOD 60
#define DEFAULT_MAX_SEGMENT_LIFE_TIME 60

typedef std::shared_ptr<pcpp::PcapFileWriterDevice> SPPcapFileWriterDevice;

static struct option TcpSorterOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'r'},
	{"output-dir", required_argument, 0, 'o'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"filter", required_argument, 0, 'e'},
	{"max-file-desc", required_argument, 0, 'f'},
	{"max-captured-packet", required_argument, 0, 'p'},
	{"max-idle-timeout", required_argument, 0, 't'},
	{"max-inactive-connection-scan", required_argument, 0, 'n'},
	{"clean-up-inactive-connection-period", required_argument, 0, 'd'},
	{"max-segment-lifetime", required_argument, 0, 'g'},

	{"write-metadata", no_argument, 0, 'm'},
	{"write-to-console", no_argument, 0, 'c'},
	{"separate-sides", no_argument, 0, 's'},
	{"should-include-empty-segment", no_argument, 0, 'x'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{0, 0, 0, 0}
};


/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig
{
private:

	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig() { writeMetadata = false; outputDir = ""; separateSides = false; maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES; m_RecentConnsWithActivity = nullptr; }

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key. This LRU list is used to decide which connection was seen least
	// recently in case we reached max number of open file descriptors and we need to decide which files to close
	LRUList<uint32_t>* m_RecentConnsWithActivity;

public:

	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a flag indicating whether to write both side of a connection to the same file (which is the default) or write each side to a separate file
	bool separateSides;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;


	/**
	 * A method getting connection parameters as input and returns a filename and file path as output.
	 * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
	 */
	std::string getFileName(ConnectionData connData, int side, bool separareSides)
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return value
		if (outputDir != "")
			stream << outputDir << SEPARATOR;

		std::string sourceIP = connData.srcIP->toString();
		std::string destIP = connData.dstIP->toString();

		// for IPv6 addresses, replace ':' with '_'
		std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
		std::replace(destIP.begin(), destIP.end(), ':', '_');

		// side == 0 means data is sent from client->server
		if (side <= 0 || separareSides == false)
			stream << sourceIP << "." << connData.srcPort << "-" << destIP << "." << connData.dstPort;
		else // side == 1 means data is sent from server->client
			stream << destIP << "." << connData.dstPort << "-" << sourceIP << "." << connData.srcPort;

		// return the file path
		return stream.str();
	}


	/**
	 * Open a file writer. Inputs are the filename to open and a flag indicating whether to append to an existing file or overwrite it.
	 * Return value is a pointer to the new file stream
	 */
	SPPcapFileWriterDevice openFileWriter(std::string fileName, bool reopen)
	{
		// open the file on the disk (with append or overwrite mode)
		SPPcapFileWriterDevice spFileWriter = std::make_shared<PcapFileWriterDevice>(fileName.c_str());
		spFileWriter->open(reopen);
		return spFileWriter;
	}


	/**
	 * Close a file writer
	 */
	void closeFileWriter(SPPcapFileWriterDevice fileWriter)
	{
		if (nullptr != fileWriter)
		{
			fileWriter->close();
			// free the memory
			fileWriter.reset();
		}
	}


	/**
	 * Return a pointer to the least-recently-used (LRU) list of connections
	 */
	LRUList<uint32_t>* getRecentConnsWithActivity()
	{
		// this is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES
		// but the user can choose another number
		if (m_RecentConnsWithActivity == nullptr)
			m_RecentConnsWithActivity = new LRUList<uint32_t>(maxOpenFiles);

		// return the pointer
		return m_RecentConnsWithActivity;
	}


	/**
	 * The singleton implementation of this class
	 */
	static GlobalConfig& getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
};

/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats data on the connection
 */
struct TcpSorterData
{
	// shared pointer to the Pcap file writer for both sides
	SPPcapFileWriterDevice pcapFileWriterSide[2];

	// flags indicating whether the file in each side was already opened before. If the answer is yes, next time it'll be opened in append mode (and not in overwrite mode)
	bool reopenFileWriter[2];

	// a flag indicating on which side was the latest message on this connection
	int curSide;

	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];

	/**
	 * the default c'tor
	 */
	TcpSorterData() { pcapFileWriterSide[0] = nullptr; pcapFileWriterSide[1] = nullptr; clear(); }

	/**
	 * The default d'tor
	 */
	~TcpSorterData()
	{
		// close files on both sides if open
		for (int side = 0; side < 2; side++)
		{
			if (pcapFileWriterSide[side] != nullptr)
				GlobalConfig::getInstance().closeFileWriter(pcapFileWriterSide[side]);
		}
	}

	/**
	 * Clear all data (put 0, false or nullptr - whatever relevant for each field)
	 */
	void clear()
	{
		for (int side = 0; side < 2; side++)
		{
			if (pcapFileWriterSide[side] != nullptr)
			{
				GlobalConfig::getInstance().closeFileWriter(pcapFileWriterSide[side]);
				pcapFileWriterSide[side] = nullptr;
			}

			reopenFileWriter[side] = false;
			numOfDataPackets[side] = 0;
			numOfMessagesFromSide[side] = 0;
		}


		curSide = -1;
	}
};

// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, TcpSorterData> TcpSorterConnMgr;
typedef std::map<uint32_t, TcpSorterData>::iterator TcpSorterConnMgrIter;

/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvlcms] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]\n"
			"\nOptions:\n\n"
			"    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
			"    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface\n"
			"    -o output_dir : Specify output directory (default is '.')\n"
			"    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP sorter will only work on filtered packets\n"
			"    -f max_files  : Maximum number of file descriptors to use (default: 500)\n"
			"    -p max_packet : Maximum number of captured packets from both sides in each TCP connection (default: 0 = unlimited)\n"
			"    -t time_out   : Maximum idle timeout in seconds for inactive TCP connection (default: 180. The value 0 = unlimited)\n"
			"    -n max_scan   : Maximum number of inactive TCP connection scan in each batch (default: 100. The value 0 = scan all)\n"
			"    -d clean_prd  : Time period in seconds to trigger clean up inactive TCP connection (default: 60)\n"
			"    -g max_slt    : Maximum sgement lifetime. In TIME_WAIT state, TCP state machine wait for twice the MSS until transist to closed state. (default: 60)\n"
			"    -x            : Exclude empty TCP packet (default: false)\n"
			"    -m            : Write a metadata file for each connection\n"
			"    -s            : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)\n"
			"    -l            : Print the list of interfaces and exit\n"
			"    -v            : Displays the current version and exists\n"
			"    -h            : Display this help message and exit\n\n", AppName::get().c_str());
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
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}


/*********************************************************************
 *
 * TcpSorter callback functions begins
 *
 * ******************************************************************/

/**
 * The callback being called by the TCP sorter module whenever new data arrives on a certain connection
 */

static void tcpPacketReadyCallback(int sideIndex, ConnectionData connData, TcpSorter::SPRawPacket spRawPacket, void* userCookie)
{
	// extract the connection manager from the user cookie
	TcpSorterConnMgr* connMgr = (TcpSorterConnMgr*)userCookie;

	uint32_t flowKey = connData.flowKey;
	// check if this flow already appears in the connection manager. If not add it
	TcpSorterConnMgrIter iter = connMgr->find(flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert({flowKey, TcpSorterData()});
		iter = connMgr->find(flowKey);
	}

	int side;

	// if the user wants to write each side in a different file - set side as the sideIndex, otherwise write everything to the same file ("side 0")
	if (GlobalConfig::getInstance().separateSides)
		side = sideIndex;
	else
		side = 0;

	// if the file writer on the relevant side isn't open yet (meaning it's the first data on this connection)
	if (iter->second.pcapFileWriterSide[side] == nullptr)
	{
		// add the flow key of this connection to the list of open connections. If the return value isn't NULL it means that there are too many open files
		// and we need to close the connection with least recently used file(s) in order to open a new one.
		// The connection with the least recently used file is the return value
		uint32_t flowKeyToCloseFiles;
		int result = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(flowKey, &flowKeyToCloseFiles);

		// if result equals to 1 it means we need to close the open files in this connection (the one with the least recently used files)
		if (result == 1)
		{
			// find the connection from the flow key
			TcpSorterConnMgrIter iter2 = connMgr->find(flowKeyToCloseFiles);
			if (iter2 != connMgr->end())
			{
				// close files on both sides (if they're open)
				for (int index = 0; index < 1; index++)
				{
					if (iter2->second.pcapFileWriterSide[index] != nullptr)
					{
						// close the file
						GlobalConfig::getInstance().closeFileWriter(iter2->second.pcapFileWriterSide[index]);
						iter2->second.pcapFileWriterSide[index] = nullptr;
						// set the reopen flag to true to indicate that next time this file will be opened it will be opened in append mode (and not overwrite mode)
						iter2->second.reopenFileWriter[index] = true;
					}
				}
			}
		}

		// get the file name according to the 5-tuple etc.
		std::string fileName = GlobalConfig::getInstance().getFileName(connData, sideIndex, GlobalConfig::getInstance().separateSides) + ".pcap";

		// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was already opened before)
		iter->second.pcapFileWriterSide[side] = GlobalConfig::getInstance().openFileWriter(fileName, iter->second.reopenFileWriter[side]);
	}
	// if this messages comes on a different side than previous message seen on this connection
	if (sideIndex != iter->second.curSide)
	{
		// count number of message in each side
		iter->second.numOfMessagesFromSide[sideIndex]++;

		// set side index as the current active side
		iter->second.curSide = sideIndex;
	}

	// count number of packets and bytes in each side of the connection
	iter->second.numOfDataPackets[sideIndex]++;

	// write the new packet to the file
	iter->second.pcapFileWriterSide[side]->writePacket(*spRawPacket);
}

/**
 * The callback being called by the TCP sorter module whenever missing packet is found in capture
 */
static void tcpPacketMissingCallback(int sideIndex, ConnectionData connData, uint32_t seq, uint32_t length, void* userCookie)
{
	std::string sourceIP = connData.srcIP->toString();
	std::string destIP = connData.dstIP->toString();
	std::string dir = sideIndex == 0? " => " : " <= ";
	std::cout<< "Found missing packet: " << "side(" << sideIndex <<"), "
				<< sourceIP << ":" << connData.srcPort
				<< dir
				<< destIP <<":" << connData.dstPort
				<< ", seq(" << seq <<"), len(" << length <<")"
				<< std::endl;
}

/*********************************************************************
 *
 * TcpSorter callback functions ends
 *
 * ******************************************************************/

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(RawPacket* packet, PcapLiveDevice* dev, void* tcpSorterCookie)
{
	// get a pointer to the TCP sorter instance and feed the packet arrived to it
	TcpSorter* tcpSorter = (TcpSorter*)tcpSorterCookie;

	// The libpcap engine might release the packet data after the callback function.
	// Clone a copy of raw packet by the copy c'tor.
	TcpSorter::SPRawPacket spRawPacket = std::make_shared<RawPacket>(*packet);
	tcpSorter->sortPacket(spRawPacket);
}

void printSummary(TcpSorterConnMgr* connMgr)
{
	uint64_t numTotalConn = connMgr->size();
	uint64_t numTotalPackets = 0;
	uint64_t numTotalMsgs = 0;
	for (auto iter = connMgr->begin(); iter != connMgr->end(); iter++)
	{
		numTotalPackets += iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1];
		numTotalMsgs += iter->second.numOfMessagesFromSide[0] + iter->second.numOfMessagesFromSide[1];
	}

	printf("\nSummary:\n"
			 "----------\n");
	printf("Total Number of Connections    : %lu\n", numTotalConn);
	printf("Total Number of Packets        : %lu\n", numTotalPackets);
	printf("Total Number of Messages       : %lu\n", numTotalMsgs);
}

/**
 * The method responsible for TCP sorter on pcap/pcapng files
 */
void doTcpSorterOnPcapFile(std::string fileName, TcpSorter& tcpSorter, TcpSorterConnMgr* connMgr, std::string bpfFiler = "")
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	// set BPF filter if set by the user
	if (bpfFiler != "")
	{
		if (!reader->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
	}

	printf("Starting reading '%s'...\n", fileName.c_str());

	// run in a loop that reads one packet from the file in each iteration and feeds it to the TCP sorter instance
	RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		TcpSorter::SPRawPacket spRawPacket = std::make_shared<RawPacket>(rawPacket);
		tcpSorter.sortPacket(spRawPacket);
	}

	// after all packets have been read - close the connections which are still opened
	tcpSorter.closeAllConnections();

	// close the reader and free its memory
	reader->close();
	delete reader;

	printSummary(connMgr);

	printf("Done!\n");
}


/**
 * The method responsible for TCP sorter on live traffic
 */
void doTcpSorterOnLiveTraffic(PcapLiveDevice* dev, TcpSorter& tcpSorter, TcpSorterConnMgr* connMgr, std::string bpfFiler = "")
{
	// try to open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open interface");

	// set BPF filter if set by the user
	if (bpfFiler != "")
	{
		if (!dev->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to interface");
	}

	printf("Starting packet capture on '%s'...\n", dev->getIPv4Address().toString().c_str());

	// start capturing packets. Each packet arrived will be handled by onPacketArrives method
	dev->startCapture(onPacketArrives, &tcpSorter);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user presses ctrl+c
	while(!shouldStop)
		PCAP_SLEEP(1);

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// close all connections which are still opened
	tcpSorter.closeAllConnections();

	printSummary(connMgr);

	printf("Done!\n");
}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	std::string inputPcapFileName = "";
	std::string bpfFilter = "";
	std::string outputDir = "";
	bool writeMetadata = false;
	bool separateSides = false;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;
	uint64_t maxNumCapturedPacket = DEFAULT_UNLIMITED_NUMBEROF_OF_CAPTURED_PACKET;
	uint32_t maxIdleTimeout = DEFAULT_MAX_IDEL_TIMEOUT;
	uint32_t maxNumInactiveConnScan = DEFAULT_MAX_NUMBER_OF_INACTIVE_CONNECTION_SCAN;
	uint32_t cleanUpInactiveConnPeriod = DEFAULT_CLEAN_UP_INACTIVE_CONNECTION_PERIOD;
	uint32_t maxSegmentLifeTime = DEFAULT_MAX_SEGMENT_LIFE_TIME;
	bool shouldIncludeEmptySegments = true;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:r:o:e:f:p:t:n:d:g:mcsvhlx", TcpSorterOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'r':
				inputPcapFileName = optarg;
				break;
			case 'o':
				outputDir = optarg;
				break;
			case 'e':
				bpfFilter = optarg;
				break;
			case 's':
				separateSides = true;
				break;
			case 'm':
				writeMetadata = true;
				break;
			case 'x':
				shouldIncludeEmptySegments = false;
				break;
			case 'f':
				if(sscanf(optarg, "%lu", &maxOpenFiles) != 1) {
					printf("Invalid argument for maxOpenFiles!");
					exit(-1);
				}
				break;
			case 'p':
				if(sscanf(optarg, "%lu", &maxNumCapturedPacket) != 1) {
					printf("Invalid argument for maxNumCapturedPacket!");
					exit(-1);
				}
				break;
			case 't':
				if(sscanf(optarg, "%u", &maxIdleTimeout) != 1) {
					printf("Invalid argument for maxIdelTimeout!");
					exit(-1);
				}
				break;
			case 'n':
				if(sscanf(optarg, "%u", &maxNumInactiveConnScan) != 1) {
					printf("Invalid argument for maxNumInactiveConnScan!");
					exit(-1);
				}
				break;
			case 'd':
				if(sscanf(optarg, "%u", &cleanUpInactiveConnPeriod) != 1) {
					printf("Invalid argument for cleanUpInactiveConnPeriod!");
					exit(-1);
				}
				break;
			case 'g':
				if(sscanf(optarg, "%u", &maxSegmentLifeTime) != 1) {
					printf("Invalid argument for maxSegmentLifeTime!");
					exit(-1);
				}
				break;
			case 'h':
				printUsage();
				break;
			case 'v':
				printAppVersion();
				break;
			case 'l':
				listInterfaces();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	// if no interface nor input pcap file were provided - exit with error
	if (inputPcapFileName == "" && interfaceNameOrIP == "")
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// verify output dir exists
	if (outputDir != "" && !directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().separateSides = separateSides;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info on all connections
	TcpSorterConnMgr connMgr;

	TcpSorterConfiguration cfg(maxNumCapturedPacket, maxIdleTimeout,
														 maxNumInactiveConnScan, cleanUpInactiveConnPeriod,
														 maxSegmentLifeTime, shouldIncludeEmptySegments);

	// create the TCP sorter instance
	TcpSorter tcpSorter(tcpPacketReadyCallback, tcpPacketMissingCallback, &connMgr, cfg);

	// analyze in pcap file mode
	if (inputPcapFileName != "")
	{
		doTcpSorterOnPcapFile(inputPcapFileName, tcpSorter, &connMgr, bpfFilter);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		PcapLiveDevice* dev = nullptr;
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == nullptr)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == nullptr)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}

		// start capturing packets and do TCP sorting
		doTcpSorterOnLiveTraffic(dev, tcpSorter, &connMgr, bpfFilter);
	}
}
