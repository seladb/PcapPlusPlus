#pragma once

#include <string>
#include <vector>
#include "RawPacket.h"
#include "Device.h"

bool sendURLRequest(std::string url);

bool readPcapIntoPacketVec(std::string pcapFileName, std::vector<pcpp::RawPacket>& packetStream, std::string& errMsg);

int getFileLength(std::string filename);

uint8_t* readFileIntoBuffer(std::string filename, int& bufferLength);

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