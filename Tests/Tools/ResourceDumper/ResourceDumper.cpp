#include <iostream>

#include "PcapFileDevice.h"
#include "Resources.h"

int main(int argc, char* argv[])
{
	if (argc != 5)
	{
		std::cerr << "Usage: " << argv[0] << " <pcap file> <packet num> <resource type [hex]> <output file>"
		          << std::endl;
		return 1;
	}

	std::string pcapFile = argv[1];
	int packetNum = std::stoi(argv[2]);
	std::string resourceType = argv[3];
	std::string outputFile = argv[4];

	if (resourceType != "hex")
	{
		std::cerr << "Unsupported resource type: " << resourceType << std::endl;
		return 1;
	}

	auto dev = pcpp::IFileReaderDevice::getReader(pcapFile);
	if (!dev->open())
	{
		std::cerr << "Error opening the pcap file" << std::endl;
		return 1;
	}

	pcpp_tests::utils::ResourceProvider resourceProvider(".", false /* unfreeze the provider */);

	// Skip packets until we reach the packet we want to dump.
	pcpp::RawPacket rawPacket;
	for (int i = 0; i < packetNum; i++)
	{
		if (!dev->getNextPacket(rawPacket))
		{
			std::cerr << "Error reading packet number " << i << std::endl;
			return 1;
		}
	}

	// Read the actual packet we want to dump
	if (!dev->getNextPacket(rawPacket))
	{
		std::cerr << "Error reading packet number " << packetNum << std::endl;
		return 1;
	}

	using pcpp_tests::utils::ResourceType;
	resourceProvider.saveResource(ResourceType::HexData, outputFile.c_str(), rawPacket.getRawData(),
	                              rawPacket.getRawDataLen());

	// Test loading the resource back to ensure it was saved correctly
	auto res = resourceProvider.loadResourceToVector(outputFile.c_str(), ResourceType::HexData);
	for (size_t i = 0; i < res.size(); ++i)
	{
		if (res[i] != rawPacket.getRawData()[i])
		{
			std::cerr << "Error: loaded resource does not match original packet data at byte " << i << std::endl;
			return 1;
		}
	}

	dev->close();
	return 0;
}
