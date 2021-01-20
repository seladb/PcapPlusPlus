#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

// This function is created as PcapPlusPlus doesn't seem to offer a way of
// parsing Pcap files directly from memory
int dumpDataToPcapFile(const uint8_t *data, size_t size) {
	FILE *fd;
	int written = 0;

	fd = fopen("/tmp/fuzz_sample.pcap", "wb");
	if (fd == NULL) {
		printf("Error opening pcap file for writing\n");
		return -1;
	}

	written = fwrite(data, 1, size, fd);
	if (written != size) {
		printf("Error writing pcap file\n");
		fclose(fd);
		return -1;
	}

	fclose(fd);

	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

	if (dumpDataToPcapFile(Data, Size) < 0) {
		return 1;
	}

	// open a pcap file for reading
	pcpp::PcapFileReaderDevice reader("/tmp/fuzz_sample.pcap");
	if (!reader.open())
	{
		printf("Error opening the pcap file\n");
		return 1;
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader.getNextPacket(rawPacket))
	{
		printf("Couldn't read the first packet in the file\n");
		return 1;
	}

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// verify the packet is IPv4
	if (parsedPacket.isPacketOfType(pcpp::IPv4))
	{
		// extract source and dest IPs
		pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
		pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

		// print source and dest IPs
		printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(), destIP.toString().c_str());
	}

	// close the file
	reader.close();

	return 0;
}
