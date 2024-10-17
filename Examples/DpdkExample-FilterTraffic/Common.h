#pragma once

#include "Packet.h"
#include "DpdkDevice.h"

#include <SystemUtils.h>

#include <string>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <iostream>
#include <sstream>

/**
 * Macros for exiting the application with error
 */

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

typedef std::unordered_map<pcpp::DpdkDevice*, std::vector<int>> InputDataConfig;

/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK ports and which RX queues to receive packet from
 * - Whether to send matched packets to TX DPDK port and/or save them to a pcap file
 */
struct AppWorkerConfig
{
	uint32_t coreId;
	InputDataConfig inDataCfg;
	pcpp::DpdkDevice* sendPacketsTo;
	bool writeMatchedPacketsToFile;
	std::string pathToWritePackets;

	AppWorkerConfig()
	    : coreId(MAX_NUM_OF_CORES + 1), sendPacketsTo(nullptr), writeMatchedPacketsToFile(false), pathToWritePackets("")
	{}
};

/**
 * Collect and analyze packet and flow statistics
 */
struct PacketStats
{
public:
	uint8_t workerId;

	int packetCount;
	int ethCount;
	int arpCount;
	int ipv4Count;
	int ipv6Count;
	int tcpCount;
	int udpCount;
	int httpCount;
	int dnsCount;
	int tlsCount;

	int matchedTcpFlows;
	int matchedUdpFlows;
	int matchedPackets;

	PacketStats()
	    : workerId(MAX_NUM_OF_CORES + 1), packetCount(0), ethCount(0), arpCount(0), ipv4Count(0), ipv6Count(0),
	      tcpCount(0), udpCount(0), httpCount(0), dnsCount(0), tlsCount(0), matchedTcpFlows(0), matchedUdpFlows(0),
	      matchedPackets(0)
	{}

	void collectStats(pcpp::Packet& packet)
	{
		packetCount++;
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			arpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipv4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipv6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpCount++;
		if (packet.isPacketOfType(pcpp::DNS))
			dnsCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			tlsCount++;
	}

	void collectStats(const PacketStats& stats)
	{
		packetCount += stats.packetCount;
		ethCount += stats.ethCount;
		arpCount += stats.arpCount;
		ipv4Count += stats.ipv4Count;
		ipv6Count += stats.ipv6Count;
		tcpCount += stats.tcpCount;
		udpCount += stats.udpCount;
		httpCount += stats.httpCount;
		dnsCount += stats.dnsCount;
		tlsCount += stats.tlsCount;

		matchedTcpFlows += stats.matchedTcpFlows;
		matchedUdpFlows += stats.matchedUdpFlows;
		matchedPackets += stats.matchedPackets;
	}

	void clear()
	{
		workerId = MAX_NUM_OF_CORES + 1;
		packetCount = 0;
		ethCount = 0;
		arpCount = 0;
		ipv4Count = 0;
		ipv6Count = 0;
		tcpCount = 0;
		udpCount = 0;
		httpCount = 0;
		dnsCount = 0;
		tlsCount = 0;

		matchedTcpFlows = 0;
		matchedUdpFlows = 0;
		matchedPackets = 0;
	}
};
