#pragma once

#include "Splitters.h"

/**
 * Splits a pcap file by number of packets
 */
class PacketCountSplitter : public Splitter
{
private:
	int m_PacketCount;
	int m_MaxPacketsPerFile;

public:

	/**
	 * A c'tor for this class which gets the packet count for each split file
	 */
	PacketCountSplitter(int maxPacketsPerFile)
	{
		m_PacketCount = 0;
		m_MaxPacketsPerFile = maxPacketsPerFile;
	}

	/**
	 * Return the current file number if its packet count didn't reach the limit, or else return the next
	 * file number and close the current file
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		// check the current file number
		int prevFile = m_PacketCount / m_MaxPacketsPerFile;
		// increment packet count
		m_PacketCount++;
		// check the new file number
		int nextFile = m_PacketCount / m_MaxPacketsPerFile;
		// if reached packet count limit, close the previous file and return the next file number
		if (prevFile != nextFile)
			filesToClose.push_back(prevFile);
		return nextFile;
	}

	/**
	 * Make sure packet count is a positive number
	 */
	bool isSplitterParamLegal(std::string& errorString)
	{
		if (m_MaxPacketsPerFile < 1)
		{
			errorString = "max packets per file must be be a positive number greater than 0";
			return false;
		}

		return true;
	}
};



/**
 * Splits a pcap file by number of byte in each file
 */
class FileSizeSplitter : public Splitter
{
private:
	int m_TotalSize;
	int m_MaxBytesPerFile;

	static const int PCAP_FILE_HEADER_SIZE = 24;   // == sizeof(pcap_file_header)
	static const int PCAP_PACKET_HEADER_SIZE = 16; // == sizeof(pcap_pkthdr)

public:

	/**
	 * A c'tor for this class which gets the file size in bytes for each split file
	 */
	FileSizeSplitter(int maxBytesPerFile)
	{
		m_TotalSize = 0;
		// each file size contains a pcap header with size of PCAP_FILE_HEADER_SIZE
		m_MaxBytesPerFile = maxBytesPerFile - PCAP_FILE_HEADER_SIZE;
	}

	/**
	 * Return the current file number if its size didn't reach the file size limit, or else return the next
	 * file number and close the current file
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		// check the current file
		int prevFile = m_TotalSize / m_MaxBytesPerFile;
		// add the current packet size and packet header
		m_TotalSize += packet.getRawPacket()->getRawDataLen() + PCAP_PACKET_HEADER_SIZE;
		// calculate the new file number
		int nextFile = m_TotalSize / m_MaxBytesPerFile;
		// if reached the maximum size per file, close the previous file
		if (prevFile != nextFile)
			filesToClose.push_back(prevFile);
		return nextFile;
	}

	/**
	 * Each file size must be at least in size of PCAP_FILE_HEADER_SIZE + PCAP_PACKET_HEADER_SIZE
	 */
	bool isSplitterParamLegal(std::string& errorString)
	{
		if (m_MaxBytesPerFile < PCAP_PACKET_HEADER_SIZE + 1)
		{
			errorString = "max bytes per file must be be a positive number greater than 48";
			return false;
		}

		return true;
	}

};
