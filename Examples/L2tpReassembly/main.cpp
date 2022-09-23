
#include "LRUList.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PcapPlusPlusVersion.h"
#include "L2tpLayer.h"
#include "L2tpReassembly.h"
#include "SystemUtils.h"
#include <algorithm>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>

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

static struct option L2tpAssemblyOptions[] = {{"interface", required_argument, 0, 'i'},
											 {"input-file", required_argument, 0, 'r'},
											 {"output-dir", required_argument, 0, 'o'},
											 {"list-interfaces", no_argument, 0, 'l'},
											 {"filter", required_argument, 0, 'e'},
											 {"write-metadata", no_argument, 0, 'm'},
											 {"write-to-console", no_argument, 0, 'c'},
											 {"max-file-desc", required_argument, 0, 'f'},
											 {"help", no_argument, 0, 'h'},
											 {"version", no_argument, 0, 'v'},
											 {0, 0, 0, 0}};

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
struct L2tpReassemblyData
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
	L2tpReassemblyData()
	{
		fileStream = NULL;
		clear();
	}

	/**
	 * The default d'tor
	 */
	~L2tpReassemblyData()
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
typedef std::map<std::string, L2tpReassemblyData> L2tpReassemblyMgr;
typedef std::map<std::string, L2tpReassemblyData>::iterator L2tpReassemblyMgrIter;

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
			  << "Usage:" << std::endl
			  << "------" << std::endl
			  << pcpp::AppName::get()
			  << " [-hvlcm] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]" << std::endl
			  << std::endl
			  << "Options:" << std::endl
			  << std::endl
			  << "    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file"
			  << std::endl
			  << "    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 "
				 "address. Required argument for capturing from live interface"
			  << std::endl
			  << "    -o output_dir : Specify output directory (default is '.')" << std::endl
			  << "    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning L2TP reassembly "
				 "will only work on filtered packets"
			  << std::endl
			  << "    -f max_files  : Maximum number of file descl2tptors to use" << std::endl
			  << "    -c            : Write all output to console (nothing will be written to files)" << std::endl
			  << "    -m            : Write a metadata file for each file" << std::endl
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
	const std::vector<pcpp::PcapLiveDevice *> &devList =
		pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (std::vector<pcpp::PcapLiveDevice *>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		std::cout << "    -> Name: '" << (*iter)->getName()
				  << "'   IP address: " << (*iter)->getIPv4Address().toString() << std::endl;
	}
	exit(0);
}

static void OnL2tpMessageReadyCallback(pcpp::L2tpPacketData *l2tpData, void *userCookie)
{
	/* 	1. manager 存 L2tpReassemblyData   									yes
		2. manager 的指定 L2tpReassemblyData 里边fileStream 是否为NULL
			2.1 将当前（指传入的参数）的名称加入opened列表
			2.2 如果打开的文件已达上限，关闭目前的
			2.3 设置文件名
			2.4 打开文件， 模式由之前2.2设置的reopenFileStreams决定
		3. 更改L2tpReassemblyData里的统计值
		4. 将数据写入打开的文件里
	 */

	// 1.

	// extract the manager from the user cookie
	L2tpReassemblyMgr *mgr = (L2tpReassemblyMgr *)userCookie;

	// check if this tuple already appears in the manager. If not add it
	L2tpReassemblyMgrIter iter = mgr->find(l2tpData->getTupleName());
	if (iter == mgr->end())
	{
		mgr->insert(std::make_pair(l2tpData->getTupleName(), L2tpReassemblyData()));
		iter = mgr->find(l2tpData->getTupleName());
	}

	// 2.

	//  if filestream isn't open yet
	if (iter->second.fileStream == NULL)
	{
		// 2.1

		std::string nameToCloseFile;
		int result =
			GlobalConfig::getInstance().getRecentFilesWithActivity()->put(l2tpData->getTupleName(), &nameToCloseFile);

		// 2.2

		// 等于1，需要关闭最近未使用
		if (result == 1)
		{
			L2tpReassemblyMgrIter iter2 = mgr->find(nameToCloseFile);
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
		std::string name = l2tpData->getTupleName() + ".txt";
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
	l2tpData->getLayer()->ToStructuredOutput(*iter->second.fileStream);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void *cookie)
{
	bool *shouldStop = (bool *)cookie;
	*shouldStop = true;
}

/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *l2tpReassemblyCookie)
{
	// get a pointer to the L2TP reassembly instance and feed the packet arrived to it
	pcpp::L2TPReassembly *l2tpReassembly = (pcpp::L2TPReassembly *)l2tpReassemblyCookie;
	l2tpReassembly->reassemblePacket(packet);
}

/**
 * The method responsible for L2TP reassembly on pcap/pcapng files
 */
void doL2tpReassemblyOnPcapFile(std::string fileName, pcpp::L2TPReassembly &l2tpReassembly, std::string bpfFilter = "")
{
	// open input file (pcap or pcapng file)
	pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(fileName);

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

	// run in a loop that reads one packet from the file in each iteration and feeds it to the L2TP reassembly instance
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		l2tpReassembly.reassemblePacket(&rawPacket);
	}

	// close the reader and free its memory
	reader->close();
	delete reader;

	std::cout << "Done! " << std::endl;
	std::cout << "Totally processed " << GlobalConfig::getInstance().PacketNum << " packets handled." << std::endl;
}

/**
 * The method responsible for L2TP reassembly on live traffic
 */
void doL2tpReassemblyOnLiveTraffic(pcpp::PcapLiveDevice *dev, pcpp::L2TPReassembly &l2tpReassembly,
								  std::string bpfFilter = "")
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
	dev->startCapture(onPacketArrives, &l2tpReassembly);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user presses ctrl+c
	while (!shouldStop)
		pcpp::multiPlatformSleep(1);

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	std::cout << "Done! " << std::endl;
	std::cout << "Totally processed " << GlobalConfig::getInstance().PacketNum << " packets handled." << std::endl;
}

/**
 * main method of this utility
 */
int main(int argc, char *argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP;
	std::string inputPcapFileName;
	std::string bpfFilter;
	std::string outputDir;
	bool writeMetadata = false;
	bool writeToConsole = false;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:r:o:e:f:mcvhl", L2tpAssemblyOptions, &optionIndex)) != -1)
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
	if (inputPcapFileName.empty() && interfaceNameOrIP.empty())
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// verify output dir exists
	if (!outputDir.empty() && !pcpp::directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().writeToConsole = writeToConsole;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info on all connections
	L2tpReassemblyMgr mgr;

	//  create the L2TP reassembly instance
	pcpp::L2TPReassembly l2tpReassembly(OnL2tpMessageReadyCallback, &mgr);

	// analyze in pcap file mode
	if (!inputPcapFileName.empty())
	{
		doL2tpReassemblyOnPcapFile(inputPcapFileName, l2tpReassembly, bpfFilter);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		pcpp::PcapLiveDevice *dev =
			pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);
		if (dev == NULL)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

		// start capturing packets and do L2TP reassembly
		doL2tpReassemblyOnLiveTraffic(dev, l2tpReassembly, bpfFilter);
	}
}
