#pragma once

#include "Packet.h"
#include "DpdkDevice.h"

#include <SystemUtils.h>

#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <iostream>
#include <stdlib.h>

using namespace std;

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("Application terminated in error: " reason "\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while (0)

typedef map<pcpp::DpdkDevice*, vector<int> > InputDataConfig;


/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK ports and which RX queues to receive packet from
 * - Whether to send matched packets to TX DPDK port and/or save them to a pcap file
 */
struct AppWorkerConfig
{
	uint32_t CoreId;
	InputDataConfig InDataCfg;
	pcpp::DpdkDevice* SendPacketsTo;
	bool WriteMatchedPacketsToFile;
	string PathToWritePackets;

	AppWorkerConfig() : CoreId(MAX_NUM_OF_CORES+1), SendPacketsTo(NULL), WriteMatchedPacketsToFile(false), PathToWritePackets("")
	{
	}
};


/**
 * Collect and analyze packet and flow statistics
 */
struct PacketStats
{
private:
    static const char separator = ' ';
    static const int narrowColumnWidth  = 13;
    static const int wideColumnWidth  = 18;

    template<typename T>
    void printElement(T t, int width)
    {
        cout << left << setw(width) << setfill(separator) << t;
    }

public:
	uint8_t WorkerId;

	int PacketCount;
	int EthCount;
	int ArpCount;
	int Ip4Count;
	int Ip6Count;
	int TcpCount;
	int UdpCount;
	int HttpCount;

	int MatchedTcpFlows;
	int MatchedUdpFlows;
	int MatchedPackets;

	PacketStats() : WorkerId(MAX_NUM_OF_CORES+1), PacketCount(0), EthCount(0), ArpCount(0), Ip4Count(0), Ip6Count(0), TcpCount(0), UdpCount(0), HttpCount(0), MatchedTcpFlows(0), MatchedUdpFlows(0), MatchedPackets(0) {}

	void collectStats(pcpp::Packet& packet)
	{
		PacketCount++;
		if (packet.isPacketOfType(pcpp::Ethernet))
			EthCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			ArpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			Ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			Ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			TcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			UdpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			HttpCount++;
	}

	void collectStats(PacketStats& stats)
	{
		PacketCount += stats.PacketCount;
		EthCount += stats.EthCount;
		ArpCount += stats.ArpCount;
		Ip4Count += stats.Ip4Count;
		Ip6Count += stats.Ip6Count;
		TcpCount += stats.TcpCount;
		UdpCount += stats.UdpCount;
		HttpCount += stats.HttpCount;

		MatchedTcpFlows += stats.MatchedTcpFlows;
		MatchedUdpFlows += stats.MatchedUdpFlows;
		MatchedPackets += stats.MatchedPackets;
	}

	void clear() { WorkerId = MAX_NUM_OF_CORES+1; PacketCount = 0; EthCount = 0; ArpCount = 0; Ip4Count = 0; Ip6Count = 0; TcpCount = 0; UdpCount = 0; HttpCount = 0; MatchedTcpFlows = 0; MatchedUdpFlows = 0; MatchedPackets = 0; }

	void printStats()
	{
		if (WorkerId == MAX_NUM_OF_CORES+1)
			printElement("Total", narrowColumnWidth);
		else
			printElement((int)WorkerId, narrowColumnWidth);
		printElement(PacketCount, narrowColumnWidth);
		printElement(EthCount, narrowColumnWidth);
		printElement(ArpCount, narrowColumnWidth);
		printElement(Ip4Count, narrowColumnWidth);
		printElement(Ip6Count, narrowColumnWidth);
		printElement(TcpCount, narrowColumnWidth);
		printElement(UdpCount, narrowColumnWidth);
		printElement(HttpCount, narrowColumnWidth);
		printElement(MatchedTcpFlows, wideColumnWidth);
		printElement(MatchedUdpFlows, wideColumnWidth);
		printElement(MatchedPackets, wideColumnWidth);
	    cout << endl;
	}

	void printStatsHeadline()
	{
		printElement("Core ID", narrowColumnWidth);
		printElement("Packet Count", narrowColumnWidth);
		printElement("Eth Count", narrowColumnWidth);
		printElement("ARP Count", narrowColumnWidth);
		printElement("IPv4 Count", narrowColumnWidth);
		printElement("IPv6 Count", narrowColumnWidth);
		printElement("TCP Count", narrowColumnWidth);
		printElement("UDP Count", narrowColumnWidth);
		printElement("HTTP Count", narrowColumnWidth);
		printElement("Matched TCP Flows", wideColumnWidth);
		printElement("Matched UDP Flows", wideColumnWidth);
		printElement("Matched Packets", wideColumnWidth);
	    cout << endl;
	    cout << left << setw(narrowColumnWidth*9 + wideColumnWidth*3) << setfill('=') << "";
	    cout << endl;
	}
};
