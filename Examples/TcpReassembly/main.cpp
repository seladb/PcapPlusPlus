/**
 * TcpReassembly application
 * =========================
 * This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in
 * a way that is convenient for protocol analysis and debugging. This application reconstructs the TCP data streams and
 * stores each connection in a separate file(s). TcpReassembly understands TCP sequence numbers and will correctly
 * reconstruct data streams regardless of retransmissions, out-of-order delivery or data loss. TcpReassembly works more
 * or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options. The main purpose
 * of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus. Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Limit the max number of open files in each point in time (to avoid running out of file descriptors for large
 *     files / heavy traffic)
 *   - Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in
 *     each side + total), number of TCP messages (in each side + total), number of bytes (in each side + total)
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpReassembly -h
 */

#include <unordered_map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "TcpReassembly.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "LRUList.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#if defined(_WIN32)
#	define SEPARATOR '\\'
#else
#	define SEPARATOR '/'
#endif

// unless the user chooses otherwise - default number of concurrent used file descriptors is 500
constexpr int DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES = 500;

static struct option TcpAssemblyOptions[] = {
	{ "interface",        required_argument, nullptr, 'i' },
	{ "input-file",       required_argument, nullptr, 'r' },
	{ "output-dir",       required_argument, nullptr, 'o' },
	{ "list-interfaces",  no_argument,       nullptr, 'l' },
	{ "filter",           required_argument, nullptr, 'e' },
	{ "write-metadata",   no_argument,       nullptr, 'm' },
	{ "write-to-console", no_argument,       nullptr, 'c' },
	{ "separate-sides",   no_argument,       nullptr, 's' },
	{ "max-file-desc",    required_argument, nullptr, 'f' },
	{ "help",             no_argument,       nullptr, 'h' },
	{ "version",          no_argument,       nullptr, 'v' },
	{ nullptr,            0,                 nullptr, 0   }
};

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
	    : m_RecentConnsWithActivity(nullptr), writeMetadata(false), writeToConsole(false), separateSides(false),
	      maxOpenFiles(DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES)
	{}

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key.
	// This LRU list is used to decide which connection was seen least recently in case we reached max number of open
	// file descriptors and we need to decide which files to close
	pcpp::LRUList<uint32_t>* m_RecentConnsWithActivity;

public:
	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a flag indicating whether to write TCP data to actual files or to console
	bool writeToConsole;

	// a flag indicating whether to write both side of a connection to the same file (which is the default) or write
	// each side to a separate file
	bool separateSides;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;

	/**
	 * A method getting connection parameters as input and returns a filename and file path as output.
	 * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
	 */
	std::string getFileName(pcpp::ConnectionData connData, int side, bool useSeparateSides) const
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return
		// value
		if (!outputDir.empty())
			stream << outputDir << SEPARATOR;

		std::string sourceIP = connData.srcIP.toString();
		std::string destIP = connData.dstIP.toString();

		// for IPv6 addresses, replace ':' with '_'
		std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
		std::replace(destIP.begin(), destIP.end(), ':', '_');

		// side == 0 means data is sent from client->server
		if (side <= 0 || !useSeparateSides)
			stream << sourceIP << '.' << connData.srcPort << '-' << destIP << '.' << connData.dstPort;
		else  // side == 1 means data is sent from server->client
			stream << destIP << '.' << connData.dstPort << '-' << sourceIP << '.' << connData.srcPort;

		// return the file path
		return stream.str();
	}

	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file
	 * or overwrite it. Return value is a pointer to the new file stream
	 */
	std::ostream* openFileStream(const std::string& fileName, bool reopen) const
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
	void closeFileSteam(std::ostream* fileStream) const
	{
		// if the user chooses to write only to console - do nothing and return
		if (!writeToConsole)
		{
			// close the file stream
			auto fstream = (std::ofstream*)fileStream;
			fstream->close();

			// free the memory of the file stream
			delete fstream;
		}
	}

	/**
	 * Return a pointer to the least-recently-used (LRU) list of connections
	 */
	pcpp::LRUList<uint32_t>* getRecentConnsWithActivity()
	{
		// This is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of allowed open files at any point in time. Default
		// is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES but the user can choose another number
		if (m_RecentConnsWithActivity == nullptr)
			m_RecentConnsWithActivity = new pcpp::LRUList<uint32_t>(maxOpenFiles);

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

	/**
	 * d'tor
	 */
	~GlobalConfig()
	{
		delete m_RecentConnsWithActivity;
	}
};

/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats
 * data on the connection
 */
struct TcpReassemblyData
{
	// pointer to 2 file stream - one for each side of the connection. If the user chooses to write both sides to the
	// same file (which is the default), only one file stream is used (index 0)
	std::ostream* fileStreams[2];

	// flags indicating whether the file in each side was already opened before. If the answer is yes, next time it'll
	// be opened in append mode (and not in overwrite mode)
	bool reopenFileStreams[2];

	// a flag indicating on which side was the latest message on this connection
	int8_t curSide;

	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];
	int bytesFromSide[2];

	/**
	 * the default c'tor
	 */
	TcpReassemblyData()
	{
		fileStreams[0] = nullptr;
		fileStreams[1] = nullptr;
		clear();
	}

	/**
	 * The default d'tor
	 */
	~TcpReassemblyData()
	{
		// close files on both sides if open
		if (fileStreams[0] != nullptr)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);

		if (fileStreams[1] != nullptr)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
	}

	/**
	 * Clear all data (put 0, false or nullptr - whatever relevant for each field)
	 */
	void clear()
	{
		// for the file stream - close them if they're not null
		if (fileStreams[0] != nullptr)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);
			fileStreams[0] = nullptr;
		}

		if (fileStreams[1] != nullptr)
		{
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);
			fileStreams[1] = nullptr;
		}

		reopenFileStreams[0] = false;
		reopenFileStreams[1] = false;
		numOfDataPackets[0] = 0;
		numOfDataPackets[1] = 0;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		bytesFromSide[0] = 0;
		bytesFromSide[1] = 0;
		curSide = -1;
	}
};

// typedef representing the connection manager
typedef std::unordered_map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get()
	          << " [-hvlcms] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file"
	          << std::endl
	          << "    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 "
	             "address. Required argument for capturing from live interface"
	          << std::endl
	          << "    -o output_dir : Specify output directory (default is '.')" << std::endl
	          << "    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly "
	             "will only work on filtered packets"
	          << std::endl
	          << "    -f max_files  : Maximum number of file descriptors to use" << std::endl
	          << "    -c            : Write all output to console (nothing will be written to files)" << std::endl
	          << "    -m            : Write a metadata file for each connection" << std::endl
	          << "    -s            : Write each side of each connection to a separate file (default is writing both "
	             "sides of each connection to the same file)"
	          << std::endl
	          << "    -l            : Print the list of interfaces and exit" << std::endl
	          << "    -v            : Display the current version and exit" << std::endl
	          << "    -h            : Display this help message and exit" << std::endl
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
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	auto const& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;

	for (auto dev : devList)
	{
		std::cout << "    -> Name: '" << dev->getName() << "'   IP address: " << dev->getIPv4Address().toString()
		          << std::endl;
	}
	exit(0);
}

/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie)
{
	// extract the connection manager from the user cookie
	auto connMgr = (TcpReassemblyConnMgr*)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	auto flow = connMgr->find(tcpData.getConnectionData().flowKey);
	if (flow == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		flow = connMgr->find(tcpData.getConnectionData().flowKey);
	}

	int8_t side;

	// if the user wants to write each side in a different file - set side as the sideIndex, otherwise write everything
	// to the same file ("side 0")
	if (GlobalConfig::getInstance().separateSides)
		side = sideIndex;
	else
		side = 0;

	// if the file stream on the relevant side isn't open yet (meaning it's the first data on this connection)
	if (flow->second.fileStreams[side] == nullptr)
	{
		// add the flow key of this connection to the list of open connections. If the return value isn't nullptr it
		// means that there are too many open files and we need to close the connection with least recently used file(s)
		// in order to open a new one. The connection with the least recently used file is the return value
		uint32_t flowKeyToCloseFiles;
		int result = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(tcpData.getConnectionData().flowKey,
		                                                                           &flowKeyToCloseFiles);

		// if result equals to 1 it means we need to close the open files in this connection (the one with the least
		// recently used files)
		if (result == 1)
		{
			// find the connection from the flow key
			auto flow2 = connMgr->find(flowKeyToCloseFiles);
			if (flow2 != connMgr->end())
			{
				// close files on both sides (if they're open)
				for (int index = 0; index < 2; index++)
				{
					if (flow2->second.fileStreams[index] != nullptr)
					{
						// close the file
						GlobalConfig::getInstance().closeFileSteam(flow2->second.fileStreams[index]);
						flow2->second.fileStreams[index] = nullptr;

						// set the reopen flag to true to indicate that next time this file will be opened it will be
						// opened in append mode (and not overwrite mode)
						flow2->second.reopenFileStreams[index] = true;
					}
				}
			}
		}

		// clang-format off
		// get the file name according to the 5-tuple etc.
		std::string fileName = GlobalConfig::getInstance().getFileName(tcpData.getConnectionData(), sideIndex, GlobalConfig::getInstance().separateSides)
		                       + ".txt";
		// clang-format on

		// open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was
		// already opened before)
		flow->second.fileStreams[side] =
		    GlobalConfig::getInstance().openFileStream(fileName, flow->second.reopenFileStreams[side]);
	}

	// if this messages comes on a different side than previous message seen on this connection
	if (sideIndex != flow->second.curSide)
	{
		// count number of message in each side
		flow->second.numOfMessagesFromSide[sideIndex]++;

		// set side index as the current active side
		flow->second.curSide = sideIndex;
	}

	// count number of packets and bytes in each side of the connection
	flow->second.numOfDataPackets[sideIndex]++;
	flow->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	// write the new data to the file
	flow->second.fileStreams[side]->write((char*)tcpData.getData(), tcpData.getDataLength());
}

/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the
 * connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
	// get a pointer to the connection manager
	auto connMgr = (TcpReassemblyConnMgr*)userCookie;

	// look for the connection in the connection manager
	auto connectionMngr = connMgr->find(connectionData.flowKey);

	// assuming it's a new connection
	if (connectionMngr == connMgr->end())
	{
		// add it to the connection manager
		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
	}
}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the
 * connection from the connection manager and writes the metadata file if requested by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData,
                                               pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	// get a pointer to the connection manager
	auto connMgr = (TcpReassemblyConnMgr*)userCookie;

	// find the connection in the connection manager by the flow key
	auto connection = connMgr->find(connectionData.flowKey);

	// connection wasn't found - shouldn't get here
	if (connection == connMgr->end())
		return;

	// write a metadata file if required by the user
	if (GlobalConfig::getInstance().writeMetadata)
	{
		std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.txt";
		std::ofstream metadataFile(fileName.c_str());
		metadataFile << "Number of data packets in side 0:  " << connection->second.numOfDataPackets[0] << std::endl;
		metadataFile << "Number of data packets in side 1:  " << connection->second.numOfDataPackets[1] << std::endl;
		metadataFile << "Total number of data packets:      "
		             << (connection->second.numOfDataPackets[0] + connection->second.numOfDataPackets[1]) << std::endl;
		metadataFile << std::endl;
		metadataFile << "Number of bytes in side 0:         " << connection->second.bytesFromSide[0] << std::endl;
		metadataFile << "Number of bytes in side 1:         " << connection->second.bytesFromSide[1] << std::endl;
		metadataFile << "Total number of bytes:             "
		             << (connection->second.bytesFromSide[0] + connection->second.bytesFromSide[1]) << std::endl;
		metadataFile << std::endl;
		metadataFile << "Number of messages in side 0:      " << connection->second.numOfMessagesFromSide[0]
		             << std::endl;
		metadataFile << "Number of messages in side 1:      " << connection->second.numOfMessagesFromSide[1]
		             << std::endl;
		metadataFile.close();
	}

	// remove the connection from the connection manager
	connMgr->erase(connection);
}

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
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* tcpReassemblyCookie)
{
	// get a pointer to the TCP reassembly instance and feed the packet arrived to it
	auto tcpReassembly = (pcpp::TcpReassembly*)tcpReassemblyCookie;
	tcpReassembly->reassemblePacket(packet);
}

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFile(const std::string& fileName, pcpp::TcpReassembly& tcpReassembly,
                               const std::string& bpfFilter = "")
{
	// open input file (pcap or pcapng file)
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName);

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	// set BPF filter if set by the user
	if (!bpfFilter.empty())
	{
		if (!reader->setFilter(bpfFilter))
			EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
	}

	std::cout << "Starting reading '" << fileName << "'..." << std::endl;

	// run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		tcpReassembly.reassemblePacket(&rawPacket);
	}

	// extract number of connections before closing all of them
	size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

	// after all packets have been read - close the connections which are still opened
	tcpReassembly.closeAllConnections();

	// close the reader and free its memory
	reader->close();
	delete reader;

	std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;
}

/**
 * The method responsible for TCP reassembly on live traffic
 */
void doTcpReassemblyOnLiveTraffic(pcpp::PcapLiveDevice* dev, pcpp::TcpReassembly& tcpReassembly,
                                  const std::string& bpfFilter = "")
{
	// try to open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open interface");

	// set BPF filter if set by the user
	if (!bpfFilter.empty())
	{
		if (!dev->setFilter(bpfFilter))
			EXIT_WITH_ERROR("Cannot set BPF filter to interface");
	}

	std::cout << "Starting packet capture on '" << dev->getIPv4Address() << "'..." << std::endl;

	// start capturing packets. Each packet arrived will be handled by onPacketArrives method
	dev->startCapture(onPacketArrives, &tcpReassembly);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user presses ctrl+c
	while (!shouldStop)
		std::this_thread::sleep_for(std::chrono::seconds(1));

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// close all connections which are still opened
	tcpReassembly.closeAllConnections();

	std::cout << "Done! processed " << tcpReassembly.getConnectionInformation().size() << " connections" << std::endl;
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP;
	std::string inputPcapFileName;
	std::string bpfFilter;
	std::string outputDir;
	bool writeMetadata = false;
	bool writeToConsole = false;
	bool separateSides = false;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;

	int optionIndex = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, "i:r:o:e:f:mcsvhl", TcpAssemblyOptions, &optionIndex)) != -1)
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
		case 'c':
			writeToConsole = true;
			break;
		case 'f':
			maxOpenFiles = (size_t)atoi(optarg);
			break;
		case 'h':
			printUsage();
			exit(0);
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
	if (inputPcapFileName.empty() && interfaceNameOrIP.empty())
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// verify output dir exists
	if (!outputDir.empty() && !pcpp::directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().writeToConsole = writeToConsole;
	GlobalConfig::getInstance().separateSides = separateSides;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	// create the TCP reassembly instance
	pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback,
	                                  tcpReassemblyConnectionEndCallback);

	// analyze in pcap file mode
	if (!inputPcapFileName.empty())
	{
		doTcpReassemblyOnPcapFile(inputPcapFileName, tcpReassembly, bpfFilter);
	}
	else  // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

		// start capturing packets and do TCP reassembly
		doTcpReassemblyOnLiveTraffic(dev, tcpReassembly, bpfFilter);
	}
}
