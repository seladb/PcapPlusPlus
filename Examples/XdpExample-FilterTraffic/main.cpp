#include "PacketMatchingEngine.h"
#include "SystemUtils.h"
#include "PacketUtils.h"
#include "TablePrinter.h"
#include "XdpDevice.h"
#include "PcapFileDevice.h"
#include <getopt.h>
#include <unordered_map>
#include <future>
#include <iostream>
#include <thread>

#define EXIT_WITH_ERROR(reason) do { \
	/*printUsage();*/ \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

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

	PacketStats() : packetCount(0), ethCount(0), arpCount(0), ip4Count(0), ip6Count(0), tcpCount(0), udpCount(0), httpCount(0), dnsCount(0), sslCount(0), totalTcpFlows(0), totalUdpFlows(0), matchedTcpFlows(0), matchedUdpFlows(0), matchedPacketCount(0) {}

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
 * A struct that holds all arguments passed to capture threads: packetArrived()
 */
struct PacketCaptureArgs
{
	PacketStats* packetStats;
	PacketMatchingEngine* matchingEngine;
	std::unordered_map<uint32_t, bool> flowTable;
	pcpp::XdpDevice* sendPacketsTo;
	pcpp::PcapFileWriterDevice* pcapWriter;

	PacketCaptureArgs() : packetStats(nullptr), matchingEngine(nullptr), sendPacketsTo(nullptr), pcapWriter(nullptr) {}
};

static struct option XdpFilterTrafficOptions[] = {
	{"interface",  required_argument, nullptr, 'i'},
	{"save-matched-packets", required_argument, nullptr, 'f'},
};

void onPacketsArrive(pcpp::RawPacket packets[], uint32_t packetCount, pcpp::XdpDevice* device, void* userCookie)
{
	auto args = reinterpret_cast<PacketCaptureArgs*>(userCookie);

	for (uint32_t i = 0; i < packetCount; i++)
	{
		// parse packet
		pcpp::Packet packet(&packets[i]);

		// collect stats for packet
		args->packetStats->collectStats(packet);

		// hash the packet by 5-tuple and look in the flow table to see whether this packet belongs to an existing or new flow
		uint32_t hash = pcpp::hash5Tuple(&packet);
		auto iter = args->flowTable.find(hash);

		bool packetMatched;

		// if packet belongs to an already existing flow
		if (iter != args->flowTable.end())
		{
			packetMatched = true;
		}
		else // packet belongs to a new flow
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

				//collect stats
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
			// send packet to TX port if needed
			// TODO
//			if (args->sendPacketsTo != nullptr)
//			{
//				args->sendPacketsTo->sendPackets(packet);
//			}

			// save packet to file if needed
			if (args->pcapWriter != nullptr)
			{
				args->pcapWriter->writePacket(packets[i]);
			}
			args->packetStats->matchedPacketCount++;
		}
	}
}

void printStats(PacketStats* packetStats)
{
	std::vector<std::string> columnNames = {"Stat", "Count"};
	std::vector<int> columnsWidths = {21, 5};
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
	printer.closeTable();
}

void collectStats(std::future<void> futureObj, PacketStats* packetStats)
{
	while (futureObj.wait_for(std::chrono::milliseconds(1000)) == std::future_status::timeout)
	{
		printStats(packetStats);
	}
}

int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted([](void*){}, nullptr);

	int optionIndex = 0;
	int opt;

	std::string interfaceName;

	pcpp::IPv4Address  srcIPToMatch = pcpp::IPv4Address::Zero;
	pcpp::IPv4Address  dstIPToMatch = pcpp::IPv4Address::Zero;
	uint16_t           srcPortToMatch = 0;
	uint16_t           dstPortToMatch = 0;
	pcpp::ProtocolType protocolToMatch = pcpp::UnknownProtocol;

	std::string writePacketsToFileName;

	while((opt = getopt_long(argc, argv, "i:f:", XdpFilterTrafficOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
			{
				break;
			}
			case 'i':
			{
				interfaceName = std::string(optarg);
				break;
			}
			case 'f':
			{
				writePacketsToFileName = std::string(optarg);
				break;
			}
			default:
			{
				//			printUsage();
				exit(0);
			}
		}
	}

	if (interfaceName.empty())
	{
		EXIT_WITH_ERROR("Interface name was not provided");
	}

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

	pcpp::XdpDevice dev(interfaceName);

	if (!dev.open())
	{
		EXIT_WITH_ERROR("Error opening the device");
	}

	// create the matching engine instance
	PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);
	PacketStats packetStats;

	// prepare packet capture configuration
	PacketCaptureArgs args;
	args.packetStats = &packetStats;
	args.matchingEngine = &matchingEngine;
	args.sendPacketsTo = nullptr; //TODO
	args.pcapWriter = pcapWriter;

	std::promise<void> exitSignal;
	std::future<void> futureObj = exitSignal.get_future();

	std::thread collectStatsThread(&collectStats, std::move(futureObj), &packetStats);

	auto res = dev.receivePackets(onPacketsArrive, &args, 0);

	exitSignal.set_value();

	collectStatsThread.join();

	dev.close();

	if (pcapWriter)
	{
		pcapWriter->close();
		delete pcapWriter;
	}

	if (!res)
	{
		EXIT_WITH_ERROR("Something went wrong while receiving packets");
	}

	printStats(&packetStats);
}