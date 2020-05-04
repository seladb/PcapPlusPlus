#include "TestUtils.h"
#include <string.h>
#include <fstream>

namespace pcpp_tests
{

int getFileLength(const char* filename)
{
	std::ifstream infile(filename, std::ifstream::binary);
	if (!infile)
		return -1;
	infile.seekg(0, infile.end);
	int length = infile.tellg();
	infile.close();
	return length;
}

uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength)
{
	int fileLength = getFileLength(filename);
	if (fileLength == -1)
		return NULL;

	std::ifstream infile(filename);
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

void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len)
{
	printf("\n\n\n");
	for(int i = 0; i<(int)buffer1Len; i++)
		printf(" 0x%2X  ", buffer1[i]);
	printf("\n\n\n");
	for(int i = 0; i<(int)buffer2Len; i++)
	{
		if (buffer2[i] != buffer1[i])
			printf("*0x%2X* ", buffer2[i]);
		else
			printf(" 0x%2X  ", buffer2[i]);
	}
	printf("\n\n\n");
}

#ifdef PCPP_TESTS_DEBUG
#include <pcap.h>

void savePacketToPcap(Packet& packet, std::string fileName)
{
   pcap_t* pcap;
   pcap = pcap_open_dead(1, 65565);

   pcap_dumper_t* d;
   /* open output file */
   d = pcap_dump_open(pcap, fileName.c_str());
   if (d == NULL)
   {
       pcap_perror(pcap, "pcap_dump_fopen");
       return;
   }

   /* prepare for writing */
   struct pcap_pkthdr hdr;
   hdr.ts.tv_sec = 0;  /* sec */
   hdr.ts.tv_usec = 0; /* ms */
   hdr.caplen = hdr.len = packet.getRawPacket()->getRawDataLen();
   /* write single IP packet */
   pcap_dump((u_char*)d, &hdr, packet.getRawPacketReadOnly()->getRawData());

   /* finish up */
   pcap_dump_close(d);
   return;
}
#endif

}