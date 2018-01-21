#pragma once

#include <LRUList.h>
#include <IpUtils.h>
#include <RawPacket.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <PacketUtils.h>
#include <map>
#include <algorithm>
#include <iomanip>
#include <sstream>

/**
 * The base splitter class. All type of splitters inherit from it. It's a virtual abstract class that doesn't
 * implement any logic
 */
class Splitter
{
public:

	/**
	 * A method that gets a packet and returns:
	 * - The file number to write the packet to
	 * - A vector of file numbers to close (may be empty)
	 */
	virtual int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose) = 0;

	/**
	 * Most splitters have a parameter (for example: packet count for each file or max file size, etc.).
	 * This method should return true if the parameter value is legal or false otherwise. If parameter value is
	 * illegal it should return a proper error string that will be displayed for the user
	 */
	virtual bool isSplitterParamLegal(std::string& errorString) = 0;

	/**
	 * A method that enables the splitter to decide what will be the output file names based on the file number
	 * (determined also by the splitter), the output path and input file name (determined by the user) and the
	 * first packet that will be written to this file. The default implementation is the following:
	 * ' /requested-path/original-file-name-[4-digit-number-starting-at-0000].pcap'
	 */
	virtual std::string getFileName(pcpp::Packet& packet, std::string outputPcapBasePath, int fileNumber)
	{
	    std::ostringstream sstream;
	    sstream << std::setw(4) << std::setfill( '0' ) << fileNumber;
		return outputPcapBasePath.c_str() + sstream.str();
	}

	/**
	 * A virtual d'tor
	 */
	virtual ~Splitter() {}
};


/**
 * A virtual abstract splitter which represent splitters that may or may not have a limit on the number of
 * output files after the split
 * Since any OS has a limit on concurrently open files, this class implements a mechanism that makes sure no more than a
 * certain number of files are opened concurrently without limiting the number of output files desired by the user.
 * The idea is to use a LRU list that holds the number of currently open files. Each time a packet is written to a
 * certain file, the file number is advance to the head of the LRU list (or added if it's not there),
 * and if the list is full then the least recently used file is leaving it and gets closed. The next time a packet will
 * be written to a file that left the LRU list, this file will be put back in the LRU list, re-opened and packet will
 * be appended to that file
 */
class SplitterWithMaxFiles : public Splitter
{
	// in order to support all OS's, the maximum number of concurrent open file is set to 500
	static const int MAX_NUMBER_OF_CONCURRENT_OPEN_FILES = 500;

protected:
	int m_MaxFiles;
	int m_NextFile;
	pcpp::LRUList<int> m_LRUFileList;

	/**
	 * A helper method that needs to be called by child classes each time a packet is written to a certain file.
	 * This method puts the file in the LRU list, and if the list is full it pulls out the least recently used file
	 * and returns it in filesToClose vector. The application will take care of closing that file
	 */
	inline void writingToFile(int fileNum, std::vector<int>& filesToClose)
	{
		int* fileToClose = m_LRUFileList.put(fileNum);
		if (fileToClose != NULL)
		{
			filesToClose.push_back(*fileToClose);
			delete fileToClose;
		}
	}

	/**
	 * A helper method that is called by child classes and returns the next file number. If there's no output file limit
	 * it just return prev_file_number+1. But if there is a file limit it return file number in cyclic manner, meaning if
	 * reached the max file number, the next file number will be 0.
	 * In addition the method puts the next file in the LRU list and if the list is full it pulls out the least recently
	 * used file and returns it in filesToClose vector. The application will take care of closing that file
	 */
	inline int getNextFileNumber(std::vector<int>& filesToClose)
	{
		int nextFile = 0;

		// zero or negative m_MaxFiles means no limit
		if (m_MaxFiles <= 0)
			nextFile = m_NextFile++;
		else // m_MaxFiles is positive, meaning there is a output file limit
		{
			nextFile = (m_NextFile) % m_MaxFiles;
			m_NextFile++;
		}


		// put the next file in the LRU list
		int* fileToClose = m_LRUFileList.put(nextFile);
		if (fileToClose != NULL)
		{
			// if a file is pulled out of the LRU list - return it
			filesToClose.push_back(*fileToClose);
			delete fileToClose;
		}
		return nextFile;
	}

	/**
	 * A protected c'tor for this class which gets the output file limit size. If maxFile is UNLIMITED_FILES_MAGIC_NUMBER,
	 * it's considered there's no output files limit
	 */
	SplitterWithMaxFiles(int maxFiles, int firstFileNumber = 0) : m_LRUFileList(MAX_NUMBER_OF_CONCURRENT_OPEN_FILES)
	{
		m_MaxFiles = maxFiles;
		m_NextFile = firstFileNumber;
	}

public:

	static const int UNLIMITED_FILES_MAGIC_NUMBER = -12345;

	/**
	 * This method checks the maximum number of file parameter. If it equals UNLIMITED_FILES_MAGIC_NUMBER it means there
	 * is no limit. Else it verifies the limit is a positive number
	 */
	bool isSplitterParamLegal(std::string& errorString)
	{
		// unlimited number of output files
		if (m_MaxFiles == UNLIMITED_FILES_MAGIC_NUMBER)
			return true;

		if (m_MaxFiles <= 0)
		{
			errorString = "max number of file must be a positive number";
			return false;
		}

		return true;
	}
};


/**
 * An abstract virtual splitter which represent splitters that needs to keep a mapping between a certain packet value to
 * a certain file number the packet needs to be written to. For example: in client-ip splitter all flows with a
 * certain client-ip should be written to the same file. So this class will enable it to keep a mapping between client-ips
 * and file numbers. This class inherits SplitterWithMaxFiles so it supports having or not having a limit on the number
 * of output files
 */
class ValueBasedSplitter : public SplitterWithMaxFiles
{
protected:
	// A flow table that keeps track of all flows (a flow is usually identified by 5-tuple)
	std::map<uint32_t, int> m_FlowTable;
	// a map between the relevant packet value (e.g client-ip) and the file to write the packet to
	std::map<uint32_t, int> m_ValueToFileTable;

	/**
	 * A protected c'tor for this class that only propagate the maxFiles to its ancestor
	 */
	ValueBasedSplitter(int maxFiles) : SplitterWithMaxFiles(maxFiles, 1) {}

	/**
	 * A helper method that gets the packet value and returns the file to write it to, and also a file to close if the
	 * LRU list is full
	 */
	int getFileNumberForValue(uint32_t value, std::vector<int>& filesToClose)
	{
		// search the value in the value-to-file map. If it's there, return the file number
		if (m_ValueToFileTable.find(value) != m_ValueToFileTable.end())
		{
			// if value was already seen, follow the same file number
			return m_ValueToFileTable[value];
		}

		// if it's not there, use SplitterWithMaxFiles's helper method to get a new file number, put it in the map
		// and return this file number
		m_ValueToFileTable[value] = getNextFileNumber(filesToClose);
		return m_ValueToFileTable[value];
	}
};

