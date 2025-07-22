#pragma once

#include <Packet.h>
#include <PfRingDeviceList.h>
#include <sstream>

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		std::cout << '\n' << "ERROR: " << reason << '\n' << '\n';                                       \
		exit(1);                                                                                                       \
	} while (0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason)                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << '\n' << "ERROR: " << reason << '\n' << '\n';                                       \
		exit(1);                                                                                                       \
	} while (0)

/**
 * Collect and analyze packet and flow statistics
 */
struct PacketStats
{
public:
	uint8_t ThreadId;

	int PacketCount{ 0 };
	int EthCount{ 0 };
	int ArpCount{ 0 };
	int Ip4Count{ 0 };
	int Ip6Count{ 0 };
	int TcpCount{ 0 };
	int UdpCount{ 0 };
	int HttpCount{ 0 };

	int MatchedTcpFlows{ 0 };
	int MatchedUdpFlows{ 0 };
	int MatchedPackets{ 0 };

	PacketStats() : ThreadId(MAX_NUM_OF_CORES + 1)
	{}

	void collectStats(pcpp::Packet& packet)
	{
		PacketCount++;
		if (packet.isPacketOfType(pcpp::Ethernet))
		{
			EthCount++;
		}
		if (packet.isPacketOfType(pcpp::ARP))
		{
			ArpCount++;
		}
		if (packet.isPacketOfType(pcpp::IPv4))
		{
			Ip4Count++;
		}
		if (packet.isPacketOfType(pcpp::IPv6))
		{
			Ip6Count++;
		}
		if (packet.isPacketOfType(pcpp::TCP))
		{
			TcpCount++;
		}
		if (packet.isPacketOfType(pcpp::UDP))
		{
			UdpCount++;
		}
		if (packet.isPacketOfType(pcpp::HTTP))
		{
			HttpCount++;
		}
	}

	void collectStats(const PacketStats& stats)
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

	void clear()
	{
		ThreadId = MAX_NUM_OF_CORES + 1;
		PacketCount = 0;
		EthCount = 0;
		ArpCount = 0;
		Ip4Count = 0;
		Ip6Count = 0;
		TcpCount = 0;
		UdpCount = 0;
		HttpCount = 0;
		MatchedTcpFlows = 0;
		MatchedUdpFlows = 0;
		MatchedPackets = 0;
	}

	std::string getStatValuesAsString(const std::string& delimiter) const
	{
		std::stringstream values;
		if (ThreadId == MAX_NUM_OF_CORES + 1)
		{
			values << "Total" << delimiter;
		}
		else
		{
			values << (int)ThreadId << delimiter;
		}
		values << PacketCount << delimiter;
		values << EthCount << delimiter;
		values << ArpCount << delimiter;
		values << Ip4Count << delimiter;
		values << Ip6Count << delimiter;
		values << TcpCount << delimiter;
		values << UdpCount << delimiter;
		values << HttpCount << delimiter;
		values << MatchedTcpFlows << delimiter;
		values << MatchedUdpFlows << delimiter;
		values << MatchedPackets;

		return values.str();
	}

	static void getStatsColumns(std::vector<std::string>& columnNames, std::vector<int>& columnWidths)
	{
		columnNames.clear();
		columnWidths.clear();

		static const int narrowColumnWidth = 11;
		static const int wideColumnWidth = 18;

		columnNames.emplace_back("Core ID");
		columnNames.emplace_back("Packet Cnt");
		columnNames.emplace_back("Eth Cnt");
		columnNames.emplace_back("ARP Cnt");
		columnNames.emplace_back("IPv4 Cnt");
		columnNames.emplace_back("IPv6 Cnt");
		columnNames.emplace_back("TCP Cnt");
		columnNames.emplace_back("UDP Cnt");
		columnNames.emplace_back("HTTP Cnt");
		columnNames.emplace_back("Matched TCP Flows");
		columnNames.emplace_back("Matched UDP Flows");
		columnNames.emplace_back("Matched Packets");

		columnWidths.push_back(7);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(wideColumnWidth);
		columnWidths.push_back(wideColumnWidth);
		columnWidths.push_back(wideColumnWidth);
	}
};
