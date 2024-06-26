#pragma once

#include "Splitters.h"

/**
 * Splits a pcap file by 2-tuple (IP src and IP dst). Works for IPv4 & IPv6.
 * All packets that aren't IPv4 or IPv6 will be placed in one file.
 * If the user wants to limit the number of files, the splitter will divide the 2-tuple connections equally between the
 * files. If no limit is set then each connection will be written to a separate file
 */
class TwoTupleSplitter : public ValueBasedSplitter
{
public:
	/**
	 * A c'tor for this class that gets the maximum number of files. If this number is lower or equal to 0 it's
	 * considered not to have a file count limit
	 */
	explicit TwoTupleSplitter(int maxFiles) : ValueBasedSplitter(maxFiles)
	{}

	/**
	 * Find the 2-tuple flow for this packet and get the file number it belongs to. If flow is new, return a new file
	 * number
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		// hash the 2-tuple and look for it in the flow table
		uint32_t hash = pcpp::hash2Tuple(&packet);

		// if flow isn't found in the flow table
		if (m_FlowTable.find(hash) == m_FlowTable.end())
		{
			// create a new entry and get a new file number for it
			m_FlowTable[hash] = getNextFileNumber(filesToClose);
		}
		else  // flow is found in the 2-tuple flow table
		{
			// indicate file is being written because this file may not be in the LRU list (and hence closed),
			// so we need to put it there, open it, and maybe close another file
			writingToFile(m_FlowTable[hash], filesToClose);
		}

		return m_FlowTable[hash];
	}
};

/**
 * Splits a pcap file by connection (IP src + IP dst + port src + port dst + protocol)
 * Works for IPv4, IPv6, TCP and UDP.
 * All packets that aren't IPv4/IPv6 or TCP/UDP will be placed in one file.
 * If the user wants to limit the number of files, the splitter will divide the connections equally between the
 * files. If no limit is set then each connection will be written to a separate file
 */
class FiveTupleSplitter : public ValueBasedSplitter
{
private:
	// a flow table for saving TCP state per flow. Currently the only data that is saved is whether
	// the last packet seen on the flow was a TCP SYN packet
	std::unordered_map<uint32_t, bool> m_TcpFlowTable;

	/**
	 * A utility method that takes a packet and returns true if it's a TCP SYN packet
	 */
	bool isTcpSyn(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::TCP))
		{
			// extract the TCP layer
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();

			// extract SYN and ACK flags
			bool isSyn = (tcpLayer->getTcpHeader()->synFlag == 1);
			bool isNotAck = (tcpLayer->getTcpHeader()->ackFlag == 0);

			// return true only if it's a pure SYN packet (and not SYN/ACK)
			return (isSyn && isNotAck);
		}

		return false;
	}

public:
	/**
	 * A c'tor for this class that gets the maximum number of files. If this number is lower or equal to 0 it's
	 * considered not to have a file count limit
	 */
	explicit FiveTupleSplitter(int maxFiles) : ValueBasedSplitter(maxFiles)
	{}

	/**
	 * Find the flow for this packet and get the file number it belongs to. If flow is new, return a new file number
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		// hash the 5-tuple and look for it in the flow table
		uint32_t hash = pcpp::hash5Tuple(&packet);

		// if flow isn't found in the flow table
		if (m_FlowTable.find(hash) == m_FlowTable.end())
		{
			// create a new entry and get a new file number for it
			m_FlowTable[hash] = getNextFileNumber(filesToClose);

			// if this is s a TCP packet check whether it's a SYN packet
			// and save this data in the TCP flow table
			if (packet.isPacketOfType(pcpp::TCP))
			{
				m_TcpFlowTable[hash] = isTcpSyn(packet);
			}
		}
		else  // flow is found in the flow table
		{
			if (packet.isPacketOfType(pcpp::TCP))
			{
				// if this is a TCP flow, check if this is a SYN packet
				bool isSyn = isTcpSyn(packet);

				// if this is a SYN packet it means this is a beginning of a new flow
				//(with the same 5-tuple as the previous one), so assign a new file number to it.
				// unless the last packet was also SYN, which is an indication of SYN retransmission.
				// In this case don't assign a new file number
				if (isSyn && m_TcpFlowTable.find(hash) != m_TcpFlowTable.end() && m_TcpFlowTable[hash] == false)
				{
					m_FlowTable[hash] = getNextFileNumber(filesToClose);
				}
				else
				{
					// indicate file is being written because this file may not be in the LRU list (and hence closed),
					// so we need to put it there, open it, and maybe close another file
					writingToFile(m_FlowTable[hash], filesToClose);
				}

				// update the TCP flow table
				m_TcpFlowTable[hash] = isSyn;
			}
			else
			{
				// indicate file is being written because this file may not be in the LRU list (and hence closed),
				// so we need to put it there, open it, and maybe close another file
				writingToFile(m_FlowTable[hash], filesToClose);
			}
		}

		return m_FlowTable[hash];
	}

	void updateStringStream(std::ostringstream& sstream, const std::string& srcIp, uint16_t srcPort,
	                        const std::string& dstIp, uint16_t dstPort)
	{
		sstream << hyphenIP(srcIp) << "_" << srcPort << "-" << hyphenIP(dstIp) << "_" << dstPort;
	}

	/**
	 * Re-implement Splitter's getFileName() method, this time with the IPs/Ports/protocol value
	 */
	std::string getFileName(pcpp::Packet& packet, const std::string& outputPcapBasePath, int fileNumber)
	{
		std::ostringstream sstream;

		// if it's not a TCP or UDP packet, put it in file #0
		if (!packet.isPacketOfType(pcpp::TCP) && !packet.isPacketOfType(pcpp::UDP))
		{
			return Splitter::getFileName(packet, outputPcapBasePath, fileNumber);
		}

		sstream << "connection-";

		if (packet.isPacketOfType(pcpp::TCP))
		{
			// extract TCP layer
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			if (tcpLayer != nullptr)
			{
				uint16_t srcPort = tcpLayer->getSrcPort();
				uint16_t dstPort = tcpLayer->getDstPort();

				sstream << "tcp_";

				if ((tcpLayer->getTcpHeader()->synFlag == 1) && (tcpLayer->getTcpHeader()->ackFlag == 0))
				{
					updateStringStream(sstream, getSrcIPString(packet), srcPort, getDstIPString(packet), dstPort);
				}
				else if (((tcpLayer->getTcpHeader()->synFlag == 1) && (tcpLayer->getTcpHeader()->ackFlag == 1)) ||
				         (srcPort < dstPort))
				{
					updateStringStream(sstream, getDstIPString(packet), dstPort, getSrcIPString(packet), srcPort);
				}
				else
				{
					updateStringStream(sstream, getSrcIPString(packet), srcPort, getDstIPString(packet), dstPort);
				}
				return outputPcapBasePath + sstream.str();
			}
		}
		else if (packet.isPacketOfType(pcpp::UDP))
		{
			// for UDP packets, decide the server port by the lower port
			pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
			if (udpLayer != nullptr)
			{
				sstream << "udp_";
				updateStringStream(sstream, getSrcIPString(packet), udpLayer->getSrcPort(), getDstIPString(packet),
				                   udpLayer->getDstPort());
				return outputPcapBasePath + sstream.str();
			}
		}

		// if reached here, return 'miscellaneous'
		return outputPcapBasePath + "miscellaneous";
	}
};
