#pragma once

#include <string>
#include <vector>
#include <map>
#include "RawPacket.h"
#include "Device.h"

class DeviceTeardown
{
private:

	pcpp::IDevice* m_Device;

public:

	DeviceTeardown(pcpp::IDevice* device) : m_Device(device) {}

	~DeviceTeardown() 
	{ 
		if (m_Device != NULL && m_Device->isOpened())
		{
			m_Device->close();
		}
	}
};

bool sendURLRequest(std::string url);

bool readPcapIntoPacketVec(std::string pcapFileName, std::vector<pcpp::RawPacket>& packetStream, std::string& errMsg);

int getFileLength(std::string filename);

uint8_t* readFileIntoBuffer(std::string filename, int& bufferLength);

template<typename KeyType, typename LeftValue, typename RightValue>
void intersectMaps(
	const std::map<KeyType, LeftValue> & left, 
	const std::map<KeyType, RightValue> & right, 
	std::map<KeyType, std::pair<LeftValue, RightValue> >& result)
{
	typename std::map<KeyType, LeftValue>::const_iterator il = left.begin();
	typename std::map<KeyType, RightValue>::const_iterator ir = right.begin();
	while (il != left.end() && ir != right.end())
	{
			if (il->first < ir->first)
					++il;
			else if (ir->first < il->first)
					++ir;
			else
			{
					result.insert(std::make_pair(il->first, std::make_pair(il->second, ir->second)));
					++il;
					++ir;
			}
	}
}

void testSetUp();