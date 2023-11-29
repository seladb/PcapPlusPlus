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
	bool m_CancelTeardown;
	bool m_DeleteDevice;

public:

	explicit DeviceTeardown(pcpp::IDevice* device, bool deleteDevice = false) : m_Device(device), m_CancelTeardown(false), m_DeleteDevice(deleteDevice) {}

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

class SystemCommandTeardown
{
private:
	std::string m_command;
	bool m_CancelTeardown;

public:

	explicit SystemCommandTeardown(const std::string& command) : m_command(command) , m_CancelTeardown(false) {}

	~SystemCommandTeardown()
	{
		if (!m_CancelTeardown)
		{
			std::system(m_command.c_str());
		}
	}

	void cancelTeardown()
	{
		m_CancelTeardown = true;
	}
};

bool sendURLRequest(const std::string &url);

bool readPcapIntoPacketVec(const std::string& pcapFileName, std::vector<pcpp::RawPacket>& packetStream, std::string& errMsg);

int getFileLength(const std::string &filename);

uint8_t* readFileIntoBuffer(const std::string &filename, int& bufferLength);

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

#if !defined(_WIN32)
/// Find the interface name from the IP address
/// @param[in] ipAddress the given IP address
/// @param[out] errorMessage the error message
/// @return non-empty string represented the interface name of the given IP address; otherwise the empty string
std::string findInterfaceNameByIpAddress(const std::string& ipAddress, std::string& errorMessage);
#endif
