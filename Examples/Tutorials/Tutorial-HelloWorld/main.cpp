#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

int main(int argc, char* argv[])
{
	// open a pcap file for reading
	pcpp::PcapFileReaderDevice reader("1_packet.pcap");
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
		pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
		pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();

		// print source and dest IPs
		printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(), destIP.toString().c_str());
	}

	// close the file
	reader.close();

	return 0;
}
