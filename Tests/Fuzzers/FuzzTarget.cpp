#include <PcapFileDevice.h>
#include <Packet.h>
#include <Logger.h>
#include "DumpToFile.h"
#include "ReadParsedPacket.h"

static std::string tmpName;
static std::string tmpFile;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (tmpName.empty())
		tmpName = tmpnam(nullptr);

	if (tmpFile.empty())
		tmpFile = tmpName + FILE_EXT;

	if (dumpDataToPcapFile(data, size, tmpFile.c_str()) != 0)
	{
		std::cerr << "Can't Dump buffer to the '" << tmpFile << "' file!!!!\n";
		return -1;
	}

	pcpp::Logger::getInstance().suppressLogs();

	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(tmpFile));
	if (!reader->open())
	{
		std::cerr << "Error opening the '" << tmpFile << "' file\n";
		return -1;
	}

	pcpp::IPcapDevice::PcapStats stats;
	reader->getStatistics(stats);
	std::cout << "Read " << stats.packetsRecv << " packets successfully and " << stats.packetsDrop
	          << " packets could not be read" << std::endl;

	if (auto ngReader = dynamic_cast<pcpp::PcapNgFileReaderDevice*>(reader.get()))
	{
		std::cout << "OS is '" << ngReader->getOS() << "'; Hardware is '" << ngReader->getHardware() << "'"
		          << "'; CaptureApplication is '" << ngReader->getCaptureApplication() << "'; CaptureFileComment is '"
		          << ngReader->getCaptureFileComment() << "'" << std::endl;
	}

	pcpp::RawPacketVector packets;
	if (reader->getNextPackets(packets, 1) != 1)
	{
		std::cerr << "Couldn't read the first packet in the file\n";
		return 0;
	}

	pcpp::RawPacket& rawPacket = *packets.front();
	do
	{
		// go deeper only for .pcap and .pcapng format
		// for .snoop we are only fuzzing the reader
		if (0 == strcmp(FILE_EXT, ".pcap") || 0 == strcmp(FILE_EXT, ".pcapng"))
		{
			pcpp::Packet parsedPacket(&rawPacket);
			parsedPacket.toString();
			auto layer = parsedPacket.getFirstLayer();
			while (layer != nullptr)
			{
				std::cout << layer->toString() << std::endl;
				layer->getHeaderLen();
				readParsedPacket(parsedPacket, layer);
				layer = layer->getNextLayer();
			}
			parsedPacket.computeCalculateFields();
		}
	} while (reader->getNextPacket(rawPacket));

	reader->close();
	return 0;
}
