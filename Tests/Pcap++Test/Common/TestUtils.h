#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "RawPacket.h"
#include "Device.h"

class DeviceTeardown
{
private:
	pcpp::IDevice* m_Device;
	bool m_CancelTeardown;
	bool m_DeleteDevice;

public:
	explicit DeviceTeardown(pcpp::IDevice* device, bool deleteDevice = false)
	    : m_Device(device), m_CancelTeardown(false), m_DeleteDevice(deleteDevice)
	{}

	~DeviceTeardown()
	{
		if (!m_CancelTeardown && m_Device != NULL && m_Device->isOpened())
		{
			m_Device->close();
		}
		if (m_DeleteDevice)
		{
			delete m_Device;
		}
	}

	void cancelTeardown()
	{
		m_CancelTeardown = true;
	}
};

bool sendURLRequest(const std::string& url);

bool readPcapIntoPacketVec(const std::string& pcapFileName, std::vector<pcpp::RawPacket>& packetStream,
                           std::string& errMsg);

int getFileLength(const std::string& filename);

uint8_t* readFileIntoBuffer(const std::string& filename, int& bufferLength);

template <typename KeyType, typename LeftValue, typename RightValue>
void intersectMaps(const std::unordered_map<KeyType, LeftValue>& left,
                   const std::unordered_map<KeyType, RightValue>& right,
                   std::unordered_map<KeyType, std::pair<LeftValue, RightValue>>& result)
{
	typename std::unordered_map<KeyType, LeftValue>::const_iterator il = left.begin();
	typename std::unordered_map<KeyType, RightValue>::const_iterator ir = right.begin();
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
