/**
 * Filter Traffic PF_RING example application
 * ==========================================
 * An application that listens to one or more PF_RING interface, captures all traffic
 * and matches packets by user-defined matching criteria. Matching criteria is given on startup and can contain one or
 * more of the following: source IP, destination IP, source TCP/UDP port, destination TCP/UDP port and TCP or UDP
 * protocol. Matching is done per flow, meaning the first packet received on a flow is matched against the matching
 * criteria and if it's matched then all packets of the same flow will be matched too. Packets that are matched can be
 * send to another PF_RING interface and/or be save to a pcap file. In addition the application collect statistics on
 * received and matched packets: number of packets per protocol, number of matched flows and number of matched packets.
 *
 * The application uses PfRingDevice's multi-threaded capturing. Number of capture threads can be set by the user (to
 * the maximum of machine's core number minus 1) or set to default (default is all machine cores minus one management
 * core the application runs on). Each core is assigned with one capture thread. PfRingDevice tries to assign one RX
 * channel for each capturing thread (to improve performance), but if NIC doesn't enough RX channels to provide one for
 * each thread, it will assign several thread with the same RX channel For example: if NIC supports 4 RX channels but
 * the user asks for 6 capturing threads than 4 cores will share 2 RX channels and the 2 remaining cores will use RX
 * channels of their own. Each capturing thread does exactly the same work: receiving packets, collecting packet
 * statistics, matching flows and sending/saving matched packets
 *
 * Another thing shown here is getting interface capabilities such as total RX channels available, MAC address, PF_RING
 * interface index, MTU, etc.
 *
 * __Important__:
 * 1. Before compiling this application make sure you set "Compile PcapPlusPlus with PF_RING" to "y" in
 * configure-linux.sh. Otherwise the application won't compile
 * 2. Before running the application make sure you load the PF_RING kernel module: sudo insmod
 * <PF_RING_LOCATION>/kernel/pf_ring.ko Otherwise the application will exit with an error log that instructs you to load
 * the kernel module
 * 3. This application (like all applications using PF_RING) should be run as 'sudo'
 */

#include "Common.h"
#include "PacketMatchingEngine.h"
#include <PcapFileDevice.h>
#include <PacketUtils.h>
#include <PcapPlusPlusVersion.h>
#include <TablePrinter.h>
#include <Logger.h>
#include <getopt.h>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <unistd.h>

// clang-format off
static struct option PfFilterTrafficOptions[] = {
	{ "interface-name",       required_argument, nullptr, 'n' },
	{ "send-matched-packets", required_argument, nullptr, 's' },
	{ "save-matched-packets", required_argument, nullptr, 'f' },
	{ "match-source-ip",      required_argument, nullptr, 'i' },
	{ "match-dest-ip",        required_argument, nullptr, 'I' },
	{ "match-source-port",    required_argument, nullptr, 'p' },
	{ "match-dest-port",      required_argument, nullptr, 'P' },
	{ "match-protocol",       required_argument, nullptr, 'r' },
	{ "num-of-threads",       required_argument, nullptr, 't' },
	{ "help",                 no_argument,       nullptr, 'h' },
	{ "version",              no_argument,       nullptr, 'v' },
	{ "list",                 no_argument,       nullptr, 'l' },
	{ nullptr,                0,                 nullptr,  0  }
};
// clang-format on

/**
 * A struct that holds all arguments passed to capture threads: packetArrived()
 */
struct CaptureThreadArgs
{
	PacketStats* packetStatArr;
	PacketMatchingEngine* matchingEngine;
	std::unordered_map<uint32_t, bool>* flowTables;
	pcpp::PfRingDevice* sendPacketsTo;
	pcpp::PcapFileWriterDevice** pcapWriters;

	CaptureThreadArgs()
	    : packetStatArr(nullptr), matchingEngine(nullptr), flowTables(nullptr), sendPacketsTo(nullptr),
	      pcapWriters(nullptr)
	{}
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
	    << pcpp::AppName::get()
	    << " [-hvl] [-s INTERFACE_NAME] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL]"
	    << std::endl
	    << "                    [-c NUM_OF_THREADS] -n INTERFACE_NAME" << std::endl
	    << std::endl
	    << "Options:" << std::endl
	    << std::endl
	    << "    -h|--help                                  : Displays this help message and exits" << std::endl
	    << "    -v|--version                               : Displays the current version and exits" << std::endl
	    << "    -l|--list                                  : Print the list of PF_RING devices and exit" << std::endl
	    << "    -n|--interface-name       INTERFACE_NAME   : A PF_RING interface name to receive packets from."
	    << std::endl
	    << "                                                 To see all available interfaces use the -l switch"
	    << std::endl
	    << "    -s|--send-matched-packets INTERFACE_NAME   : PF_RING interface name to send matched packets to"
	    << std::endl
	    << "    -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH."
	    << std::endl
	    << "                                                 Packets matched by thread X will be saved under"
	    << std::endl
	    << "                                                 'FILEPATH/ThreadX.pcap'" << std::endl
	    << "    -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address" << std::endl
	    << "    -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address" << std::endl
	    << "    -p|--match-source-port    PORT             : Match source TCP/UDP port" << std::endl
	    << "    -P|--match-dest-port      PORT             : Match destination TCP/UDP port" << std::endl
	    << "    -r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'"
	    << std::endl
	    << "    -t|--num-of-threads       NUM_OF_THREADS   : Number of capture threads to open. Should be in"
	    << std::endl
	    << "                                                 the range of 1 to NUM_OF_CORES_ON_MACHINE-1." << std::endl
	    << "                                                 Default is using all machine cores except the core"
	    << std::endl
	    << "                                                 the application is running on" << std::endl
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
 * Print to console all available PF_RING devices. Used by the -l switch
 */
void listPfRingDevices()
{
	// suppress errors as there may be devices (like lo) that their MAC address can't be read, etc.
	pcpp::Logger::getInstance().suppressLogs();

	const std::vector<pcpp::PfRingDevice*>& devList = pcpp::PfRingDeviceList::getInstance().getPfRingDevicesList();
	for (const auto& dev : devList)
	{
		std::ostringstream interfaceIndex;
		if (dev->getInterfaceIndex() <= 9999)
		{
			interfaceIndex << dev->getInterfaceIndex();
		}
		else
		{
			interfaceIndex << "N/A";
		}

		std::cout << "    -> Name: " << std::left << std::setw(8) << dev->getDeviceName() << " Index: " << std::setw(5)
		          << interfaceIndex.str() << " MAC address: " << std::setw(19)
		          << (dev->getMacAddress() == pcpp::MacAddress::Zero ? "N/A" : dev->getMacAddress().toString())
		          << " Available RX channels: " << std::setw(3) << (int)dev->getTotalNumOfRxChannels()
		          << " MTU: " << dev->getMtu() << std::endl;
	}

	// re-enable errors
	pcpp::Logger::getInstance().enableLogs();
}

/**
 * The method that is called each time a packet is received on any of the threads. It collects all relevant stats for
 * the packet and matches it with the matching engine. If packet is matched it sends it to the TX interface (if needed)
 * or writes it to the thread's pcap file (if needed)
 */
void packetArrived(pcpp::RawPacket* packets, uint32_t numOfPackets, uint8_t threadId, pcpp::PfRingDevice* device,
                   void* userCookie)
{
	CaptureThreadArgs* args = (CaptureThreadArgs*)userCookie;
	for (uint32_t i = 0; i < numOfPackets; i++)
	{
		// parse packet
		pcpp::Packet packet(&packets[i]);

		// collect stats for packet
		args->packetStatArr[threadId].collectStats(packet);

		bool packetMatched = false;

		// hash the packet by 5-tuple and look in the flow table to see whether this packet belongs to an existing or
		// new flow
		uint32_t hash = pcpp::hash5Tuple(&packet);
		std::unordered_map<uint32_t, bool>::const_iterator iter = args->flowTables[threadId].find(hash);

		// if packet belongs to an already existing flow
		if (iter != args->flowTables[threadId].end() && iter->second)
		{
			packetMatched = true;
		}
		else  // packet belongs to a new flow
		{
			packetMatched = args->matchingEngine->isMatched(packet);
			if (packetMatched)
			{
				// put new flow in flow table
				args->flowTables[threadId][hash] = true;

				// collect stats
				if (packet.isPacketOfType(pcpp::TCP))
				{
					args->packetStatArr[threadId].MatchedTcpFlows++;
				}
				else if (packet.isPacketOfType(pcpp::UDP))
				{
					args->packetStatArr[threadId].MatchedUdpFlows++;
				}
			}
		}

		if (packetMatched)
		{
			// send packet to TX port if needed
			if (args->sendPacketsTo != nullptr)
			{
				args->sendPacketsTo->sendPacket(packet);
			}

			// save packet to file if needed
			if (args->pcapWriters != nullptr)
			{
				args->pcapWriters[threadId]->writePacket(packets[i]);
			}

			args->packetStatArr[threadId].MatchedPackets++;
		}
	}
}

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;

	*shouldStop = true;
}

int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	pcpp::PfRingDevice* dev = nullptr;

	int totalNumOfCores = pcpp::getNumOfCores();
	int numOfCaptureThreads = totalNumOfCores - 1;

	pcpp::PfRingDevice* sendPacketsToIface = nullptr;

	std::string packetFilePath = "";
	bool writePacketsToDisk = true;

	pcpp::IPv4Address srcIPToMatch = pcpp::IPv4Address::Zero;
	pcpp::IPv4Address dstIPToMatch = pcpp::IPv4Address::Zero;
	uint16_t srcPortToMatch = 0;
	uint16_t dstPortToMatch = 0;
	pcpp::ProtocolType protocolToMatch = pcpp::UnknownProtocol;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "n:s:t:f:i:I:p:P:r:hvl", PfFilterTrafficOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
		{
			break;
		}
		case 'n':
		{
			std::string ifaceName = std::string(optarg);
			dev = pcpp::PfRingDeviceList::getInstance().getPfRingDeviceByName(ifaceName);
			if (dev == nullptr)
				EXIT_WITH_ERROR("Could not find PF_RING device '" << ifaceName << "'");
			break;
		}
		case 's':
		{
			std::string sendPacketsToIfaceName = std::string(optarg);
			sendPacketsToIface = pcpp::PfRingDeviceList::getInstance().getPfRingDeviceByName(sendPacketsToIfaceName);
			if (sendPacketsToIface == nullptr)
				EXIT_WITH_ERROR("Could not find PF_RING device '" << sendPacketsToIfaceName << "'");

			break;
		}
		case 't':
		{
			numOfCaptureThreads = atoi(optarg);
			if (numOfCaptureThreads < 1 || numOfCaptureThreads > totalNumOfCores - 1)
				EXIT_WITH_ERROR("Number of capture threads must be in the range of 1 to " << totalNumOfCores - 1);
			break;
		}
		case 'f':
		{
			packetFilePath = std::string(optarg);
			// make sure the path ends with '/'
			if (packetFilePath.length() > 1 && (0 != packetFilePath.compare(packetFilePath.length() - 1, 1, "/")))
				packetFilePath += "/";

			writePacketsToDisk = true;
			break;
		}
		case 'i':
		{
			try
			{
				srcIPToMatch = pcpp::IPv4Address(optarg);
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Source IP to match isn't a valid IP address");
			}
			break;
		}
		case 'I':
		{
			try
			{
				dstIPToMatch = pcpp::IPv4Address(optarg);
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination IP to match isn't a valid IP address");
			}
			break;
		}
		case 'p':
		{
			int ret = atoi(optarg);
			if (ret <= 0 || ret > 65535)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Source port to match isn't a valid TCP/UDP port");
			}
			srcPortToMatch = ret;
			break;
		}
		case 'P':
		{
			int ret = atoi(optarg);
			if (ret <= 0 || ret > 65535)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Destination port to match isn't a valid TCP/UDP port");
			}
			dstPortToMatch = ret;
			break;
		}
		case 'r':
		{
			std::string protocol = std::string(optarg);
			if (protocol == "TCP")
				protocolToMatch = pcpp::TCP;
			else if (protocol == "UDP")
				protocolToMatch = pcpp::UDP;
			else
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Protocol to match isn't TCP or UDP");
			}
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
		case 'l':
		{
			listPfRingDevices();
			exit(0);
		}
		default:
		{
			printUsage();
			exit(0);
		}
		}
	}

	if (dev == nullptr)
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Interface name was not provided");

	// open the PF_RING device in multi-thread mode. Distribution of packets between threads will be done per-flow (as
	// opposed to round-robin)
	if (!dev->openMultiRxChannels(numOfCaptureThreads, pcpp::PfRingDevice::PerFlow))
		EXIT_WITH_ERROR("Couldn't open " << numOfCaptureThreads << " RX channels on interface '" << dev->getDeviceName()
		                                 << "'");

	if (sendPacketsToIface != nullptr && !sendPacketsToIface->open())
		EXIT_WITH_ERROR("Couldn't open PF_RING device '" << sendPacketsToIface->getDeviceName()
		                                                 << "' for sending matched packets");

	pcpp::CoreMask coreMask = 0;
	int threadId = 0;
	int threadCount = 0;

	// create an array of packet stats with the size of all machine cores
	std::vector<PacketStats> packetStatsArr(totalNumOfCores);

	// init each packet stats instance with an illegal core ID
	for (int coreId = 0; coreId < totalNumOfCores; coreId++)
		packetStatsArr[coreId].ThreadId = MAX_NUM_OF_CORES + 1;

	// mark only relevant cores by adding them to core mask
	// mark only relevant packet stats instances by setting their core ID
	while (threadCount < numOfCaptureThreads)
	{
		if (pcpp::SystemCores::IdToSystemCore[threadId].Id != dev->getCurrentCoreId().Id)
		{
			coreMask |= pcpp::SystemCores::IdToSystemCore[threadId].Mask;
			packetStatsArr[threadId].ThreadId = pcpp::SystemCores::IdToSystemCore[threadId].Id;
			threadCount++;
		}

		threadId++;
	}

	// create the matching engine instance
	PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);

	// create a flow table for each core
	std::vector<std::unordered_map<uint32_t, bool>> flowTables(totalNumOfCores);

	pcpp::PcapFileWriterDevice** pcapWriters = nullptr;

	// if needed, prepare pcap writers for all capturing threads
	if (writePacketsToDisk)
	{
		pcapWriters = new pcpp::PcapFileWriterDevice*[totalNumOfCores];

		for (int coreId = 0; coreId < totalNumOfCores; coreId++)
		{
			// if core doesn't participate in capturing, skip it
			if ((coreMask & pcpp::SystemCores::IdToSystemCore[coreId].Mask) == 0)
			{
				pcapWriters[coreId] = nullptr;
				continue;
			}

			std::stringstream packetFileName;
			packetFileName << packetFilePath << "Thread" << coreId << ".pcap";
			pcapWriters[coreId] = new pcpp::PcapFileWriterDevice(packetFileName.str());
			if (!pcapWriters[coreId]->open())
			{
				EXIT_WITH_ERROR("Couldn't open pcap writer device for core " << coreId);
			}
		}
	}

	std::cout << "Start capturing on " << numOfCaptureThreads << " threads core mask = 0x" << std::hex << coreMask
	          << std::dec << std::endl;

	// prepare packet capture configuration
	CaptureThreadArgs args;
	args.packetStatArr = packetStatsArr.data();
	args.matchingEngine = &matchingEngine;
	args.flowTables = flowTables.data();
	args.sendPacketsTo = sendPacketsToIface;
	args.pcapWriters = pcapWriters;

	// start capturing packets on all threads
	if (!dev->startCaptureMultiThread(packetArrived, &args, coreMask))
	{
		EXIT_WITH_ERROR("Couldn't start capturing on core mask 0x" << std::hex << coreMask << " on interface '"
		                                                           << dev->getDeviceName() << "'");
	}

	bool shouldStop = false;

	// register the on app close event to print summary stats on app termination
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// infinite loop (until program is terminated)
	while (!shouldStop)
	{
		sleep(5);
	}

	// stop capturing packets, close the device
	dev->stopCapture();
	dev->close();

	// close and delete pcap writers
	if (writePacketsToDisk)
	{
		for (int coreId = 0; coreId < totalNumOfCores; coreId++)
		{
			if ((coreMask & pcpp::SystemCores::IdToSystemCore[coreId].Mask) == 0)
				continue;

			pcapWriters[coreId]->close();
			delete pcapWriters[coreId];
		}
	}

	std::cout << std::endl << std::endl << "Application stopped" << std::endl;

	// print final stats for every capture thread plus sum of all threads and free worker threads memory
	PacketStats aggregatedStats;

	// create table printer
	std::vector<std::string> columnNames;
	std::vector<int> columnWidths;
	PacketStats::getStatsColumns(columnNames, columnWidths);
	pcpp::TablePrinter printer(columnNames, columnWidths);

	for (int i = 0; i < totalNumOfCores; i++)
	{
		if (packetStatsArr[i].ThreadId == MAX_NUM_OF_CORES + 1)
			continue;

		aggregatedStats.collectStats(packetStatsArr[i]);
		printer.printRow(packetStatsArr[i].getStatValuesAsString("|"), '|');
	}
	printer.printRow(aggregatedStats.getStatValuesAsString("|"), '|');
}
