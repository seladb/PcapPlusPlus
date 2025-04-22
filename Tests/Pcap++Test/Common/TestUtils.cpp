#include "TestUtils.h"
#include <fstream>
#include "GlobalTestArgs.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
// clang-format off
#ifdef USE_PF_RING
#include "PfRingDeviceList.h"
#endif
#ifdef USE_DPDK
#include "DpdkDeviceList.h"
#endif
// clang-format on

extern PcapTestArgs PcapTestGlobalArgs;

bool sendURLRequest(const std::string& url)
{
#if defined(_WIN32)
	std::string cmd = "curl.exe -s -o NUL";
#else
	std::string cmd = "curl -s -o /dev/null";
#endif

	cmd += " " + url;
	return system(cmd.c_str()) != -1;
}

bool readPcapIntoPacketVec(const std::string& pcapFileName, std::vector<pcpp::RawPacket>& packetStream,
                           std::string& errMsg)
{
	errMsg = "";
	packetStream.clear();

	pcpp::PcapFileReaderDevice reader(pcapFileName);
	if (!reader.open())
	{
		errMsg = "Cannot open pcap file";
		return false;
	}

	pcpp::RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket))
	{
		packetStream.push_back(rawPacket);
	}

	return true;
}

int getFileLength(const std::string& filename)
{
	std::ifstream infile(filename.c_str(), std::ifstream::binary);
	if (!infile)
		return -1;
	infile.seekg(0, infile.end);
	int length = infile.tellg();
	infile.close();
	return length;
}

uint8_t* readFileIntoBuffer(const std::string& filename, int& bufferLength)
{
	int fileLength = getFileLength(filename);
	if (fileLength == -1)
		return nullptr;

	std::ifstream infile(filename.c_str());
	if (!infile)
		return nullptr;

	bufferLength = fileLength / 2 + 2;
	uint8_t* result = new uint8_t[bufferLength];
	int i = 0;
	while (!infile.eof())
	{
		char byte[3];
		memset(byte, 0, 3);
		infile.read(byte, 2);
		result[i] = (uint8_t)strtol(byte, nullptr, 16);
		i++;
	}
	infile.close();
	bufferLength -= 2;
	return result;
}

void testSetUp()
{
	pcpp::PcapLiveDeviceList::getInstance();

#ifdef USE_PF_RING
	pcpp::PfRingDeviceList::getInstance();
#endif

#ifdef USE_DPDK
	if (PcapTestGlobalArgs.dpdkPort > -1)
	{
		pcpp::CoreMask coreMask = 0;
		for (int i = 0; i < pcpp::getNumOfCores(); i++)
		{
			coreMask |= pcpp::SystemCores::IdToSystemCore[i].Mask;
		}
		pcpp::DpdkDeviceList::initDpdk(coreMask, 16383);
	}
#endif
}
