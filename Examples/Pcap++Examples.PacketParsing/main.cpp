/**
 * Pcap++ example: packet parsing
 * ==============================
 * This is a simple example that demonstrates some of PcapPlusPlus APIs and use.
 * This application reads a file containing raw packet data in hex format, converts it into RawPacket object,
 * parses it into a Packet object and then queries the packet for all sorts of data (protocols, IPs, etc.)
 */


#include <stdlib.h>
#include <fstream>
#include <string.h>
#include <RawPacket.h>
#include <Packet.h>
#include <IpAddress.h>
#include <EthLayer.h>
#include <IPv6Layer.h>
#include <UdpLayer.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <in.h>
#endif
#include <SystemUtils.h>

using namespace std;
using namespace pcpp;

int getFileLength(const char* filename)
{
	ifstream infile(filename, ifstream::binary);
	if (!infile)
		return -1;
	infile.seekg(0, infile.end);
    int length = infile.tellg();
    infile.close();
    return length;
}

/**
 * A method for reading a file in hex string format and converting it to byte array
 */
uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength)
{
	int fileLength = getFileLength(filename);
	if (fileLength == -1)
		return NULL;

	ifstream infile(filename);
	if (!infile)
		return NULL;

	bufferLength = fileLength/2 + 2;
	uint8_t* result = new uint8_t[bufferLength];
	int i = 0;
	while (!infile.eof())
	{
		char byte[3];
		memset(byte, 0, 3);
		infile.read(byte, 2);
		result[i] = (uint8_t)strtol(byte, NULL, 16);
		i++;
	}
	infile.close();
	bufferLength -= 2;
	return result;
}


int main(int argc, char* argv[])
{
	// Read file into buffer (byte array)
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("UdpPacket.dat", bufferLength);
	if (buffer == NULL)
	{
		printf("Cannot read file!\n");
		return 1;
	}

	// Convert the byte array into RawPacket
	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet packet(&rawPacket);

	// Print packet types
	printf("Packet is of type: ");
	if (packet.isPacketOfType(Ethernet))
		printf("Ethernet ");
	if (packet.isPacketOfType(IP))
		printf("IP ");
	if (packet.isPacketOfType(IPv4))
		printf("IPv4 ");
	if (packet.isPacketOfType(IPv6))
		printf("IPv6 ");
	if (packet.isPacketOfType(TCP))
		printf("TCP ");
	if (packet.isPacketOfType(UDP))
		printf("UDP ");
	printf("\n");

	// Access L2 fields
	printf("Src MAC: %s\n", ((EthLayer*)packet.getFirstLayer())->getSourceMac().toString().c_str());

	// Access L3 fields
	IPv6Layer* ipv6Layer = packet.getLayerOfType<IPv6Layer>();
	if (ipv6Layer != NULL)
		printf("Dst IP: %s\n", packet.getLayerOfType<IPv6Layer>()->getDstIpAddress().toString().c_str());

	// Access L4 fields
	UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
	if (udpLayer != NULL)
		printf("Port Dst: %d\n", ntohs(udpLayer->getUdpHeader()->portDst));

	// Access packet properties
	printf("Packet length: %d\n", packet.getRawPacket()->getRawDataLen());
	if (udpLayer != NULL)
		printf("Packet payload offset: %d\n", udpLayer->getNextLayer()->getDataLen());
}
