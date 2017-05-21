#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
//#include <iomanip> //TODO: remove
#include "TcpReassembly.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
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

static struct option TcpAssemblyOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'r'},
	{"output-dir", required_argument, 0, 'o'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"filter", required_argument, 0, 'e'},
	{"write-metadata", no_argument, 0, 'm'},
	{"write-to-console", no_argument, 0, 'c'},
	{"separate-sides", no_argument, 0, 's'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


class GlobalConfig
{
private:
	GlobalConfig() { writeMetadata = false; outputDir = ""; writeToConsole = false; separateSides = false; }

public:
	bool writeMetadata;
	std::string outputDir;
	bool writeToConsole;
	bool separateSides;

	std::string getFileName(ConnectionData connData, int side, bool separareSides)
	{
		std::stringstream stream;

		if (outputDir != "")
			stream << outputDir << SEPARATOR;

		if (side <= 0 || separareSides == false)
			stream << connData.srcIP.toString() << "." << connData.srcPort << "-" << connData.dstIP.toString() << "." << connData.dstPort;
		else
			stream << connData.dstIP.toString() << "." << connData.dstPort << "-" << connData.srcIP.toString() << "." << connData.srcPort;

		//TODO: remove
//		if (side <= 0 || separareSides == false)
//			stream << connData.srcIP.toString() << "." << std::setw(5) << std::setfill('0') << connData.srcPort << "-" << connData.dstIP.toString() << "." << std::setw(5) << std::setfill('0') << connData.dstPort;
//		else
//			stream << connData.dstIP.toString() << "." << std::setw(5) << std::setfill('0') << connData.dstPort << "-" << connData.srcIP.toString() << "." << std::setw(5) << std::setfill('0') << connData.srcPort;


		return stream.str();
	}

	std::ostream* openFileStream(std::string fileName)
	{
		if (writeToConsole)
			return &std::cout;

		return new std::ofstream(fileName.c_str(), std::ios_base::binary);
	}

	void closeFileSteam(std::ostream* fileStream)
	{
		if (!writeToConsole)
		{
			std::ofstream* fstream = (std::ofstream*)fileStream;
			fstream->close();
			delete fstream;
		}
	}

	static inline GlobalConfig& getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
};


struct TcpReassemblyData
{
	std::ostream* fileStreams[2];
	int curSide;
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];
	int bytesFromSide[2];
	bool connectionsStarted;
	bool connectionsEnded;
	bool connectionsEndedManually;

	TcpReassemblyData() { fileStreams[0] = NULL; fileStreams[1] = NULL; clear(); }

	~TcpReassemblyData()
	{
		if (fileStreams[0] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);

		if (fileStreams[1] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);

	}

	void clear()
	{
		if (fileStreams[0] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[0]);

		if (fileStreams[1] != NULL)
			GlobalConfig::getInstance().closeFileSteam(fileStreams[1]);

		numOfDataPackets[0] = 0;
		numOfDataPackets[1] = 0;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		bytesFromSide[0] = 0;
		bytesFromSide[1] = 0;
		curSide = -1;
		connectionsStarted = false;
		connectionsEnded = false;
		connectionsEndedManually = false;
	}
};


typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;



/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"TcpReassembly [-hlcms] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter]\n"
			"\nOptions:\n\n"
			"    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
			"    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface\n"
			"    -o outpit_dir : Specify output directory (default is '.')\n"
			"    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets\n"
			"    -c            : Write all output to console (nothing will be written to files\n"
			"    -m            : Write a metadata file for each connection\n"
			"    -s            : Write each side of each connection to a separate file (default is writing both sides of each connection to the same file)\n"
			"    -l            : Print the list of interfaces and exist\n"
			"    -h            : Display this help message and exit\n\n");
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


static void tcpReassemblyMsgReadyCallback(int sideIndex, TcpStreamData tcpData, void* userCookie)
{
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	}

	int side;
	if (GlobalConfig::getInstance().separateSides)
		side = sideIndex;
	else
		side = 0;

	if (iter->second.fileStreams[side] == NULL)
	{
		std::string fileName = GlobalConfig::getInstance().getFileName(tcpData.getConnectionData(), sideIndex, GlobalConfig::getInstance().separateSides) + ".txt";
		iter->second.fileStreams[side] = GlobalConfig::getInstance().openFileStream(fileName);
	}

	if (sideIndex != iter->second.curSide)
	{
		//TODO: think what to do here
//		if (iter->second.curSide != -1)
//			iter->second.fileStreams[side]->write("\n\n", 2);

		iter->second.numOfMessagesFromSide[sideIndex]++;
		iter->second.curSide = sideIndex;
	}

	iter->second.numOfDataPackets[sideIndex]++;
	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	iter->second.fileStreams[side]->write((char*)tcpData.getData(), tcpData.getDataLength());
}

static void tcpReassemblyConnectionStartCallback(ConnectionData connectionData, void* userCookie)
{
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
		iter = connMgr->find(connectionData.flowKey);
	}

	iter->second.connectionsStarted = true;
}

static void tcpReassemblyConnectionEndCallback(ConnectionData connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);
	if (iter == connMgr->end())
		return;

	if (GlobalConfig::getInstance().writeMetadata)
	{
		std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.txt";
		std::ofstream metadataFile(fileName.c_str());
		metadataFile << "Number of data packets in side 0:  " << iter->second.numOfDataPackets[0] << std::endl;
		metadataFile << "Number of data packets in side 1:  " << iter->second.numOfDataPackets[1] << std::endl;
		metadataFile << "Total number of data packets:      " << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
		metadataFile << std::endl;
		metadataFile << "Number of bytes in side 0:         " << iter->second.bytesFromSide[0] << std::endl;
		metadataFile << "Number of bytes in side 1:         " << iter->second.bytesFromSide[1] << std::endl;
		metadataFile << "Total number of bytes:             " << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
		metadataFile << std::endl;
		metadataFile << "Number of messages in side 0:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
		metadataFile << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[1] << std::endl;
		metadataFile.close();
	}

	connMgr->erase(iter);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
	printf("got to ctrl-c code\n");
}

/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(RawPacket* packet, PcapLiveDevice* dev, void* tcpReassemblyCookie)
{
	TcpReassembly* tcpReassembly = (TcpReassembly*)tcpReassemblyCookie;
	tcpReassembly->ReassemblePacket(packet);
}

void doTcpReassemblyOnPcapFile(std::string fileName, TcpReassembly& tcpReassembly, std::string bpfFiler = "")
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());

	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	if (bpfFiler != "")
	{
		if (!reader->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
	}

	RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		tcpReassembly.ReassemblePacket(&rawPacket);
	}

	tcpReassembly.closeAllConnections();

	reader->close();

	delete reader;
}

void doTcpReassemblyOnLiveTraffic(PcapLiveDevice* dev, TcpReassembly& tcpReassembly, std::string bpfFiler = "")
{
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open interface");

	if (bpfFiler != "")
	{
		if (!dev->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to interface");
	}

	dev->startCapture(onPacketArrives, &tcpReassembly);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
		PCAP_SLEEP(1);

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	tcpReassembly.closeAllConnections();
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	std::string interfaceNameOrIP = "";
	std::string inputPcapFileName = "";
	std::string bpfFilter = "";
	std::string outputDir = "";
	bool writeMetadata = false;
	bool writeToConsole = false;
	bool separateSides = false;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:r:o:e:mcshl", TcpAssemblyOptions, &optionIndex)) != -1)
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
			case 'h':
				printUsage();
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

	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().writeToConsole = writeToConsole;
	GlobalConfig::getInstance().separateSides = separateSides;

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	// create the TCP reassembly instance
	TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

	// analyze in pcap file mode
	if (inputPcapFileName != "")
	{
		doTcpReassemblyOnPcapFile(inputPcapFileName, tcpReassembly, bpfFilter);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		PcapLiveDevice* dev = NULL;
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}

		// start capturing packets and do TCP reassembly
		doTcpReassemblyOnLiveTraffic(dev, tcpReassembly, bpfFilter);
	}

}
