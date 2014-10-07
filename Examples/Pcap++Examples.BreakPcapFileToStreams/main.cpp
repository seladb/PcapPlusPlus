#include <stdio.h>
#include <unordered_map>
#include <math.h>
#include <Logger.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <PcapFileDevice.h>

using namespace std;

size_t hash5Tuple(Packet* packet)
{
	IPv4Layer* ipv4Layer = (IPv4Layer*)packet->getLayerOfType(IPv4);
	TcpLayer* tcpLayer = (TcpLayer*)packet->getLayerOfType(TCP);
	if (ipv4Layer->getIPv4Header()->ipSrc < ipv4Layer->getIPv4Header()->ipDst)
	{
		return 	((size_t)(ipv4Layer->getIPv4Header()->ipSrc) * 59) ^
				((size_t)(ipv4Layer->getIPv4Header()->ipDst)) ^
				((size_t)(tcpLayer->getTcpHeader()->portSrc) << 16) ^
				((size_t)(tcpLayer->getTcpHeader()->portDst)) ^
				((size_t)(ipv4Layer->getIPv4Header()->protocol));
	}
	else
	{
		return 	((size_t)(ipv4Layer->getIPv4Header()->ipDst) * 59) ^
				((size_t)(ipv4Layer->getIPv4Header()->ipSrc)) ^
				((size_t)(tcpLayer->getTcpHeader()->portDst) << 16) ^
				((size_t)(tcpLayer->getTcpHeader()->portSrc)) ^
				((size_t)(ipv4Layer->getIPv4Header()->protocol));

	}
}

void printPacketsToFile(char* fileName, vector<Packet*>& packets, char* errString)
{
	PcapFileWriterDevice writerDevice(fileName);
	if (!writerDevice.open())
	{
		printf("Error opening writer device for %s: %s", fileName, errString);
		return;
	}

	for (auto packetIter = packets.begin(); packetIter != packets.end(); packetIter++)
	{
		writerDevice.writePacket(*(*packetIter)->getRawPacket());
	}

	writerDevice.close();
}

int main(int argc, char* argv[])
{
	char errorString[1000];
	LoggerPP::getInstance().setErrorString(errorString, 1000);
	unordered_map<size_t,vector<Packet*>> tcpStreamsMap;
	PcapFileReaderDevice readerDevice("example.pcap");
	if (!readerDevice.open())
	{
		printf("Error opening the device: %s", errorString);
		return 1;
	}

	RawPacket rawPackets[10000];
	Packet* tcpPackets[10000];
	int i = 0;
	while (readerDevice.getNextPacket(rawPackets[i]))
	{
		tcpPackets[i] = new Packet(&rawPackets[i]);
		if (!tcpPackets[i]->isPacketOfType(TCP) || !tcpPackets[i]->isPacketOfType(IPv4))
			continue;

		size_t hash = hash5Tuple(tcpPackets[i]);
		tcpStreamsMap[hash].push_back(tcpPackets[i]);
		i++;
	}

	readerDevice.close();

	printf("Number of streams found: %d\n", tcpStreamsMap.size());
	i = 0;
	for(auto iter = tcpStreamsMap.begin(); iter != tcpStreamsMap.end(); iter++)
	{
		// Print stream size
		printf("Stream #%d: %d packets\n", ++i, iter->second.size());

		// Save to file only streams with more than 9 packets
		if (iter->second.size() > 9)
		{
			char streamName[100];
			sprintf(streamName, "Output/Stream#%d.pcap", i);
			printPacketsToFile(streamName, iter->second, errorString);
		}
	}

	return 0;
}
