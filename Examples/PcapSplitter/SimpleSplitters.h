#pragma once

#include "Splitters.h"
#include "PcapDevice.h"

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
		int curFile = m_PacketCount / m_MaxPacketsPerFile;
		// increment packet count
		m_PacketCount++;
		// check the new file number
		int nextFile = m_PacketCount / m_MaxPacketsPerFile;
		// if reached packet count limit, close the previous file and return the next file number
		if (curFile != nextFile)
			filesToClose.push_back(curFile);
		return curFile;
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
	uint64_t m_TotalSize;
	uint64_t m_MaxBytesPerFile;

	static const int PCAP_FILE_HEADER_SIZE = 24;   // == sizeof(pcap_file_header)
	static const int PCAP_PACKET_HEADER_SIZE = 16; // == sizeof(pcap_pkthdr)

public:

	/**
	 * A c'tor for this class which gets the file size in bytes for each split file
	 */
	FileSizeSplitter(uint64_t maxBytesPerFile)
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
		m_TotalSize += (uint64_t)packet.getRawPacket()->getRawDataLen() + PCAP_PACKET_HEADER_SIZE;
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


/**
 * Splits a pcap file into two files: one that contains all packets matching a given BPF filter and one that contains the rest
 * of the packets
 */
class BpfCriteriaSplitter : public Splitter
{
private:
	std::string m_BpfFilter;

public:
	BpfCriteriaSplitter(std::string bpfFilter)
	{
		m_BpfFilter = bpfFilter;
	}

	/**
	 * Return file #0 if packet matches the BPF filer, and file #1 if it's not
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		if (pcpp::IPcapDevice::matchPakcetWithFilter(m_BpfFilter, packet.getRawPacket()))
			return 0;
		return 1;
	}

	/**
	 * Re-implement Splitter's getFileName() method, clarifying which file was matched by the BPF
	 * filter and which didn't
	 */
	std::string getFileName(pcpp::Packet& packet, std::string outputPcapBasePath, int fileNumber)
	{
		if (fileNumber == 0)
			return outputPcapBasePath + "match-bpf";
		else
			return outputPcapBasePath + "not-match-bpf";
	}

	/**
	 * Verifies the BPF filter set in the c'tor is a valid BPF filter
	 */
	bool isSplitterParamLegal(std::string& errorString)
	{
		if (m_BpfFilter == "")
		{
			errorString = "No BPF filter was set or set an empty one";
			return false;
		}

		bool filterValid = pcpp::IPcapDevice::verifyFilter(m_BpfFilter);
		if (!filterValid)
			errorString = "BPF filter is not valid";

		return filterValid;
	}
};


/**
 * Split a pcap file to an arbitrary number of files in a round-robin manner, each read packet to the next file in line
 */
class RoundRobinSplitter : public SplitterWithMaxFiles
{
public:
	RoundRobinSplitter(int numOfFiles) : SplitterWithMaxFiles(numOfFiles) { }

	/**
	 * Get the next file number, SplitterWithMaxFiles#getNextFileNumber() takes care of the round-robin method
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		return getNextFileNumber(filesToClose);
	}

	/**
	 * Number of files must be a positive integer
	 */
	bool isSplitterParamLegal(std::string& errorString)
	{
		if (m_MaxFiles < 1)
		{
			errorString = "number of files must be a positive integer";
			return false;
		}

		return true;
	}
};
