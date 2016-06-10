/**
 * Pcap++ example: break a pcap file into streams
 * ==============================================
 * This is a simple example that demonstrates some of PcapPlusPlus APIs and use.
 * This application takes a pcap file, goes over all its packets and classifies each TCP or UDP packet to the
 * stream (== flow/connection) it belongs to. All non-TCP/UDP packets are ignored.
 * For doing that it contains a simple flow table which is a map of flow-keys (a 2-byte hash key calculated from the
 * flow's 5-tuple) and a vector of all packets matching that flow.
 * After going over all packets and classifying them into flows the application runs over the flow table and saves each
 * flow containing at 10 packets to a separate pcap file named "Output/Stream#X.pcap" (X is a stream counter)
 */

#include <stdio.h>
#include <math.h>
#include <map>
#include <Logger.h>
#include <Packet.h>
#include <PacketUtils.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <PcapFileDevice.h>
#include <PlatformSpecificUtils.h>

using namespace pcpp;

/**
 * An auxiliary method that gets a vector of packets and a pcap filename and writes the packets to the file
 */
void printPacketsToFile(char* fileName, std::vector<Packet*>& packets, char* errString)
{
	// create a pcap writer and open it
	PcapFileWriterDevice writerDevice(fileName);
	if (!writerDevice.open())
	{
		printf("Error opening writer device for %s: %s", fileName, errString);
		return;
	}

	// iterate all packets in the vector and write them to the pcap file
	for (std::vector<Packet*>::iterator packetIter = packets.begin(); packetIter != packets.end(); packetIter++)
	{
		writerDevice.writePacket(*(*packetIter)->getRawPacket());
	}

	// don't forget to close the pcap writer
	writerDevice.close();
}


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// redirecting all errors to a string variable (the default is stderr)
	char errorString[1000];
	LoggerPP::getInstance().setErrorString(errorString, 1000);

	// creating the flow table which is a map between a 2-byte hash key and the vector of packets belong to it
	std::map<uint32_t,std::vector<Packet*> > flowTable;

	// open the pcap file for reading
	PcapFileReaderDevice readerDevice("example.pcap");
	if (!readerDevice.open())
	{
		printf("Error opening the device: %s", errorString);
		return 1;
	}

	// create and array of raw and parsed packets as these packets later go into the flow table
	RawPacket* rawPackets = new RawPacket[100000];
	Packet** tcpOrUdpPackets = new Packet*[100000];
	int i = 0;

	// go over all packets in the input pcap file
	while (readerDevice.getNextPacket(rawPackets[i]))
	{
		// parse the packet
		tcpOrUdpPackets[i] = new Packet(&rawPackets[i]);

		// ignore packets that are not a TCP or UDP or are IPv6
		if ((!tcpOrUdpPackets[i]->isPacketOfType(UDP) && !tcpOrUdpPackets[i]->isPacketOfType(TCP)) || !tcpOrUdpPackets[i]->isPacketOfType(IPv4))
			continue;

		// use a method in PcapPlusPlus for calculating a 2-byte hash value out of a packet 5-tuple
		uint32_t hash = hash5Tuple(tcpOrUdpPackets[i]);

		// insert the packet to the relevant flow in the flow table
		flowTable[hash].push_back(tcpOrUdpPackets[i]);

		i++;
	}


	// close the pcap reader
	readerDevice.close();

	// create a directory where all output pcap files will be written into
	CREATE_DIRECTORY("Output");

	printf("Number of streams found: %d\n", flowTable.size());
	i = 0;

	// go over the flow table and save each flow with 10 packets or more to a pcap file
	for(std::map<uint32_t, std::vector<Packet*> >::iterator iter = flowTable.begin(); iter != flowTable.end(); iter++)
	{
		// print stream size
		printf("Stream #%03d: %3d packets\n", ++i, iter->second.size());

		// save to file only streams with more than 9 packets
		if (iter->second.size() > 9)
		{
			char streamName[100];
			sprintf(streamName, "Output/Stream#%d.pcap", i);
			printPacketsToFile(streamName, iter->second, errorString);
		}
	}

	delete rawPackets;
	delete tcpOrUdpPackets;

	return 0;
}
