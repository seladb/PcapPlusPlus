#include <functional>
#include <Packet.h>
#include <PcapFileDevice.h>

#include "Logger.h"
#include "DumpToFile.h"

static std::string tmpName;
static std::string tmpFile;
static std::string outPcapFile;
static int writes = 0;

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

	if (outPcapFile.empty())
#ifdef NG_WRITER
		outPcapFile = tmpName + ".pcapng";
#else
		outPcapFile = tmpName + ".pcap";
#endif

#ifdef NG_WRITER
	pcpp::PcapNgFileWriterDevice pcapWriter(outPcapFile);
#else
	pcpp::PcapFileWriterDevice pcapWriter(outPcapFile, pcpp::LINKTYPE_ETHERNET);
#endif
	if (writes++ == 10)
	{
		writes = 1;
		remove(outPcapFile.c_str());
	}
	if (!pcapWriter.open(writes != 1))
	{
		std::cerr << "Cannot open '" << outPcapFile << "' for writing" << std::endl;
		return -1;
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
		pcapWriter.writePacket(rawPacket);
	} while (reader->getNextPacket(rawPacket));

	pcpp::IPcapDevice::PcapStats stats;
	pcapWriter.getStatistics(stats);
	std::cout << "Written " << stats.packetsRecv << " packets successfully to pcap writer and " << stats.packetsDrop
	          << " packets could not be written" << std::endl;

	pcapWriter.close();
	return 0;
}
