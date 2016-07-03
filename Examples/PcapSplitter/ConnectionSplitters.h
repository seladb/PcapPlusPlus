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
	TwoTupleSplitter(int maxFiles) : ValueBasedSplitter(maxFiles) {}

	/**
	 * Find the 2-tuple flow for this packet and get the file number it belongs to. If flow is new, return a new file number
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
		else // flow is found in the 2-tuple flow table
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
public:

	/**
	 * A c'tor for this class that gets the maximum number of files. If this number is lower or equal to 0 it's
	 * considered not to have a file count limit
	 */
	FiveTupleSplitter(int maxFiles) : ValueBasedSplitter(maxFiles) {}

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
		}
		else // flow is found in the flow table
		{
			// indicate file is being written because this file may not be in the LRU list (and hence closed),
			// so we need to put it there, open it, and maybe close another file
			writingToFile(m_FlowTable[hash], filesToClose);
		}

		return m_FlowTable[hash];
	}
};
