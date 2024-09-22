/**
 * Filter Traffic AF_XDP example application
 * =========================================
 *
 * This application demonstrates PcapPlusPlus AF_XDP APIs.
 * Please read the README.md file for more information.
 *
 * You can also run `XdpTrafficFilter -h` for modes of operation and parameters.
 */

#include "PacketMatchingEngine.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "PacketUtils.h"
#include "TablePrinter.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include <getopt.h>
#include <unordered_map>
#include <future>
#include <iostream>
#include <thread>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason)                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

/**
 * A struct to collect packet stats
 */
struct PacketStats
{
public:
	int packetCount;
	int ethCount;
	int arpCount;
	int ip4Count;
	int ip6Count;
	int tcpCount;
	int udpCount;
	int httpCount;
	int dnsCount;
	int sslCount;
	int totalTcpFlows;
	int totalUdpFlows;
	int matchedTcpFlows;
	int matchedUdpFlows;
	int matchedPacketCount;

	PacketStats()
	    : packetCount(0), ethCount(0), arpCount(0), ip4Count(0), ip6Count(0), tcpCount(0), udpCount(0), httpCount(0),
	      dnsCount(0), sslCount(0), totalTcpFlows(0), totalUdpFlows(0), matchedTcpFlows(0), matchedUdpFlows(0),
	      matchedPacketCount(0)
	{}

	/**
	 * Collect stats per packet
	 */
	void collectStats(pcpp::Packet& packet)
	{
		packetCount++;
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			arpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpCount++;
		if (packet.isPacketOfType(pcpp::DNS))
			dnsCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			sslCount++;
	}
};

/**
 * A struct that holds all arguments passed to the packet capture callback
 */
struct PacketCaptureArgs
{
	PacketStats* packetStats;
	PacketMatchingEngine* matchingEngine;
	std::unordered_map<uint32_t, bool> flowTable;
	pcpp::XdpDevice* sendPacketsTo;
	pcpp::PcapFileWriterDevice* pcapWriter;
	bool stopCapture;

	PacketCaptureArgs()
	    : packetStats(nullptr), matchingEngine(nullptr), sendPacketsTo(nullptr), pcapWriter(nullptr), stopCapture(false)
	{}
};

// clang-format off
static struct option XdpFilterTrafficOptions[] = {
	{ "interface",            required_argument, nullptr, 'n' },
	{ "send-matched-packets", required_argument, nullptr, 's' },
	{ "save-matched-packets", required_argument, nullptr, 'f' },
	{ "match-source-ip",      required_argument, nullptr, 'i' },
	{ "match-dest-ip",        required_argument, nullptr, 'I' },
	{ "match-source-port",    required_argument, nullptr, 'p' },
	{ "match-dest-port",      required_argument, nullptr, 'P' },
	{ "match-protocol",       required_argument, nullptr, 'r' },
	{ "help",                 no_argument,       nullptr, 'h' },
	{ "version",              no_argument,       nullptr, 'v' },
	{ "list-interfaces",      no_argument,       nullptr, 'l' }
};
// clang-format on

/**
 * A callback to handle packets that were received on the AF_XDP socket
 */
void onPacketsArrive(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
{
	auto args = reinterpret_cast<PacketCaptureArgs*>(userCookie);

	// if the user asked to interrupt the app, stop receiving packets
	if (args->stopCapture)
	{
		device->stopReceivePackets();
		return;
	}

	pcpp::RawPacketVector packetsToSend;

	// go over all received packets
	for (uint32_t i = 0; i < packetCount; i++)
	{
		// parse packet
		pcpp::Packet packet(&packets[i]);

		// collect stats for packet
		args->packetStats->collectStats(packet);

		// hash the packet by 5-tuple and look in the flow table to see whether this packet belongs to an existing or
		// new flow
		uint32_t hash = pcpp::hash5Tuple(&packet);
		auto iter = args->flowTable.find(hash);

		bool packetMatched;

		// if packet belongs to an already existing flow
		if (iter != args->flowTable.end())
		{
			packetMatched = true;
		}
		else  // packet belongs to a new flow
		{
			auto isTcpFlow = packet.isPacketOfType(pcpp::TCP);
			auto isUdpFlow = packet.isPacketOfType(pcpp::UDP);

			if (isTcpFlow)
			{
				args->packetStats->totalTcpFlows++;
			}
			else if (isUdpFlow)
			{
				args->packetStats->totalUdpFlows++;
			}

			packetMatched = args->matchingEngine->isMatched(packet);
			if (packetMatched)
			{
				// put new flow in flow table
				args->flowTable[hash] = true;

				// collect stats
				if (isTcpFlow)
				{
					args->packetStats->matchedTcpFlows++;
				}
				else if (isUdpFlow)
				{
					args->packetStats->matchedUdpFlows++;
				}
			}
		}

		if (packetMatched)
		{
			if (args->sendPacketsTo != nullptr)
			{
				// add packet to the vector of packets to send
				packetsToSend.pushBack(new pcpp::RawPacket(packets[i]));
			}

			// save packet to file if needed
			if (args->pcapWriter != nullptr)
			{
				args->pcapWriter->writePacket(packets[i]);
			}
			args->packetStats->matchedPacketCount++;
		}
	}

	// send packets if there are packets to send and a send device was configured
	if (args->sendPacketsTo != nullptr && packetsToSend.size() > 0)
	{
		args->sendPacketsTo->sendPackets(packetsToSend, true);
	}
}

/**
 * Print the stats in a table
 */
void printStats(PacketStats* packetStats, pcpp::XdpDevice::XdpDeviceStats* rxDeviceStats,
                pcpp::XdpDevice::XdpDeviceStats* txDeviceStats)
{
	std::vector<std::string> columnNames = { "Stat", "Count" };
	std::vector<int> columnsWidths = { 21, 10 };
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	printer.printRow("Eth count|" + std::to_string(packetStats->ethCount), '|');
	printer.printRow("ARP count|" + std::to_string(packetStats->arpCount), '|');
	printer.printRow("IPv4 count|" + std::to_string(packetStats->ip4Count), '|');
	printer.printRow("IPv6 count|" + std::to_string(packetStats->ip6Count), '|');
	printer.printRow("TCP count|" + std::to_string(packetStats->tcpCount), '|');
	printer.printRow("UDP count|" + std::to_string(packetStats->udpCount), '|');
	printer.printRow("HTTP count|" + std::to_string(packetStats->httpCount), '|');
	printer.printRow("DNS count|" + std::to_string(packetStats->dnsCount), '|');
	printer.printRow("SSL/TLS count|" + std::to_string(packetStats->sslCount), '|');
	printer.printSeparator();
	printer.printRow("Matched TCP flows|" + std::to_string(packetStats->matchedTcpFlows), '|');
	printer.printRow("Matched UDP flows|" + std::to_string(packetStats->matchedUdpFlows), '|');
	printer.printRow("Total TCP flows|" + std::to_string(packetStats->totalTcpFlows), '|');
	printer.printRow("Total UDP flows|" + std::to_string(packetStats->totalUdpFlows), '|');
	printer.printSeparator();
	printer.printRow("Matched packet count|" + std::to_string(packetStats->matchedPacketCount), '|');
	printer.printRow("Total packet count|" + std::to_string(packetStats->packetCount), '|');
	printer.printSeparator();
	printer.printRow("RX packets|" + std::to_string(rxDeviceStats->rxPackets), '|');
	printer.printRow("RX packets/sec|" + std::to_string(rxDeviceStats->rxPacketsPerSec), '|');
	printer.printRow("RX bytes|" + std::to_string(rxDeviceStats->rxBytes), '|');
	printer.printRow("RX bytes/sec|" + std::to_string(rxDeviceStats->rxBytesPerSec), '|');
	if (txDeviceStats)
	{
		printer.printRow("TX packets|" + std::to_string(txDeviceStats->txCompletedPackets), '|');
		printer.printRow("TX packets/sec|" + std::to_string(txDeviceStats->txCompletedPacketsPerSec), '|');
		printer.printRow("TX bytes|" + std::to_string(txDeviceStats->txSentBytes), '|');
		printer.printRow("TX bytes/sec|" + std::to_string(txDeviceStats->txSentBytesPerSec), '|');
	}
	printer.closeTable();
}

/**
 * Collect stats thread runner
 */
void collectStats(std::future<void> futureObj, PacketStats* packetStats, pcpp::XdpDevice* dev, pcpp::XdpDevice* sendDev)
{
	// run in an endless loop until the signal is received and print stats every 1 sec
	while (futureObj.wait_for(std::chrono::milliseconds(1000)) == std::future_status::timeout)
	{
		// collect RX stats
		auto rxStats = dev->getStatistics();

		pcpp::XdpDevice::XdpDeviceStats* txStats = nullptr;

		if (sendDev)
		{
			// if send socket is different from receive socket, collect stats from the send socket
			if (sendDev != dev)
			{
				txStats = new pcpp::XdpDevice::XdpDeviceStats(sendDev->getStatistics());
			}
			else  // send and receive sockets are the same
			{
				txStats = &rxStats;
			}
		}

		// print RX and (maybe) TX stats in a table
		printStats(packetStats, &rxStats, txStats);

		if (txStats != &rxStats)
		{
			delete txStats;
		}
	}
}

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get()
	          << " [-hvl] [-s INTERFACE_NAME] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r "
	             "PROTOCOL] -n INTERFACE_NAME"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -h|--help                                  : Displays this help message and exits" << std::endl
	          << "    -v|--version                               : Displays the current version and exits" << std::endl
	          << "    -l|--list                                  : Print the list of network interfaces and exit"
	          << std::endl
	          << "    -n|--interface-name       INTERFACE_NAME   : An interface name to open AF_XDP socket and receive "
	             "packets from."
	          << std::endl
	          << "                                                 To see all available interfaces use the -l switch"
	          << std::endl
	          << "    -s|--send-matched-packets INTERFACE_NAME   : Network interface name to send matched packets to."
	          << std::endl
	          << "                                                 The app will open another AF_XDP socket for sending "
	             "packets."
	          << std::endl
	          << "                                                 Note: this interface can be the same one used to "
	             "receive packets."
	          << std::endl
	          << "    -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH."
	          << std::endl
	          << "    -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address" << std::endl
	          << "    -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address" << std::endl
	          << "    -p|--match-source-port    PORT             : Match source TCP/UDP port" << std::endl
	          << "    -P|--match-dest-port      PORT             : Match destination TCP/UDP port" << std::endl
	          << "    -r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'"
	          << std::endl
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
	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (const auto& device : pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList())
	{
		if (device->getIPv4Address() != pcpp::IPv4Address::Zero)
		{
			std::cout << "    -> Name: '" << device->getName()
			          << "'   IP address: " << device->getIPv4Address().toString() << std::endl;
		}
	}
	exit(0);
}

int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt;

	std::string interfaceName;

	pcpp::IPv4Address srcIPToMatch = pcpp::IPv4Address::Zero;
	pcpp::IPv4Address dstIPToMatch = pcpp::IPv4Address::Zero;
	uint16_t srcPortToMatch = 0;
	uint16_t dstPortToMatch = 0;
	pcpp::ProtocolType protocolToMatch = pcpp::UnknownProtocol;

	std::string writePacketsToFileName;
	std::string sendInterfaceName;

	while ((opt = getopt_long(argc, argv, "n:f:s:i:I:p:P:r:vhl", XdpFilterTrafficOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
		{
			break;
		}
		case 'n':
		{
			interfaceName = std::string(optarg);
			break;
		}
		case 'f':
		{
			writePacketsToFileName = std::string(optarg);
			break;
		}
		case 's':
		{
			sendInterfaceName = std::string(optarg);
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
			int ret = std::stoi(optarg);
			if (ret <= 0 || ret > 65535)
			{
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Source port to match isn't a valid TCP/UDP port");
			}
			srcPortToMatch = ret;
			break;
		}
		case 'P':
		{
			int ret = std::stoi(optarg);
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
			{
				protocolToMatch = pcpp::TCP;
			}
			else if (protocol == "UDP")
			{
				protocolToMatch = pcpp::UDP;
			}
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
			listInterfaces();
			exit(0);
		}
		default:
		{
			printUsage();
			exit(0);
		}
		}
	}

	if (interfaceName.empty())
	{
		EXIT_WITH_ERROR("Interface name was not provided");
	}

	// open the pcap writer if needed
	pcpp::PcapFileWriterDevice* pcapWriter = nullptr;
	if (!writePacketsToFileName.empty())
	{
		pcapWriter = new pcpp::PcapFileWriterDevice(writePacketsToFileName);
		if (!pcapWriter->open())
		{
			delete pcapWriter;
			EXIT_WITH_ERROR("Couldn't open pcap file to write packets");
		}
	}

	// open the XDP device
	pcpp::XdpDevice dev(interfaceName);
	if (!dev.open())
	{
		EXIT_WITH_ERROR("Error opening the device");
	}

	// open the XDP device to send packets if needed
	pcpp::XdpDevice* sendDev = nullptr;
	if (!sendInterfaceName.empty())
	{
		// send and receive devices might be the same
		if (sendInterfaceName == interfaceName)
		{
			sendDev = &dev;
		}
		else
		{
			// if they are not the same, open another AF_XDP socket for the send device
			sendDev = new pcpp::XdpDevice(sendInterfaceName);
			if (!sendDev->open())
			{
				dev.close();
				delete sendDev;
				EXIT_WITH_ERROR("Error opening send device");
			}
		}
	}

	// create the matching engine instance
	PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);
	PacketStats packetStats;

	// prepare configuration
	PacketCaptureArgs args;
	args.packetStats = &packetStats;
	args.matchingEngine = &matchingEngine;
	args.sendPacketsTo = sendDev;
	args.pcapWriter = pcapWriter;

	// create future and promise instances to signal the stats collection threads when to stop
	std::promise<void> exitSignal;
	std::future<void> futureObj = exitSignal.get_future();

	// create and run a stats collection thread
	std::thread collectStatsThread(&collectStats, std::move(futureObj), &packetStats, &dev, sendDev);

	// add an handler for app interrupted signal, i.e ctrl+c
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(
	    [](void* args) { reinterpret_cast<PacketCaptureArgs*>(args)->stopCapture = true; }, &args);

	// start receiving packets on the AF_XDP socket
	auto res = dev.receivePackets(onPacketsArrive, &args, -1);

	// user clicked ctrl+c, prepare to shut the app down

	// signal the stats collection thread to stop and wait for it to stop
	exitSignal.set_value();
	collectStatsThread.join();

	// close the pcap writer if needed
	std::vector<std::string> additionalStats;
	if (pcapWriter)
	{
		pcpp::IPcapDevice::PcapStats stats;
		pcapWriter->getStatistics(stats);
		additionalStats.push_back("Wrote " + std::to_string(stats.packetsRecv) + " packets to '" +
		                          pcapWriter->getFileName() + "'");
		pcapWriter->close();
		delete pcapWriter;
	}

	pcpp::XdpDevice::XdpDeviceStats* txStats = nullptr;

	// close the send XDP device if needed
	if (sendDev != nullptr)
	{
		// collect final TX stats
		txStats = new pcpp::XdpDevice::XdpDeviceStats(sendDev->getStatistics());

		// if the send and receive devices are the same - no need to close the device again
		if (sendInterfaceName != interfaceName)
		{
			sendDev->close();
			delete sendDev;
		}
	}

	// collect final RX stats
	pcpp::XdpDevice::XdpDeviceStats rxStats = dev.getStatistics();

	// close the XDP device
	dev.close();

	// print final stats
	printStats(&packetStats, &rxStats, txStats);
	delete txStats;

	for (const auto& additionalStat : additionalStats)
	{
		std::cout << additionalStat << std::endl;
	}

	// exit with an error if there was an error receiving packets
	if (!res)
	{
		EXIT_WITH_ERROR("Something went wrong while receiving packets");
	}
}
