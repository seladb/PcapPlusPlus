#include "TestUtils.h"
#include "SomeIpLayer.h"
#include <iostream>
#include <iomanip>
#include <string.h>
#include <string>
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

	namespace
	{
		std::uint8_t hexCharToDigit(char c)
		{
			if (c >= '0' && c <= '9')
				return c - '0';
			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;
			if (c >= 'A' && c <= 'F')
				return c - 'A' + 10;
			throw std::invalid_argument("Invalid hex character");
		}

		std::uint8_t hexPairToByte(const char* pair)
		{
			return (hexCharToDigit(pair[0]) << 4) | hexCharToDigit(pair[1]);
		}
	}  // namespace

	std::vector<std::uint8_t> readFileIntoBuffer(const char* filename)
	{
		int fileLength = getFileLength(filename);
		if (fileLength == -1)
			throw std::runtime_error(std::string("Failed to open file: ") + filename);

		std::ifstream infile(filename);
		if (!infile)
			throw std::runtime_error(std::string("Failed to open file: ") + filename);

		std::vector<std::uint8_t> buffer;
		char hexPair[2];  // 0 - high, 1 - low
		while (infile.read(hexPair, 2))
		{
			buffer.push_back(hexPairToByte(hexPair));
		}
		return buffer;
	}

	uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength)
	{
		int fileLength = getFileLength(filename);
		if (fileLength == -1)
			return nullptr;

		std::ifstream infile(filename);
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

	void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len)
	{
		std::cout << "First buffer (" << std::dec << buffer1Len << " bytes):\n\n";
		for (int i = 0; i < (int)buffer1Len; i++)
		{
			std::cout << " 0x" << std::setfill('0') << std::setw(2) << std::hex << (int)buffer1[i] << " ";
			if ((i + 1) % 16 == 0)
			{
				std::cout << std::endl;
			}
		}
		std::cout << "\n\n"
		          << "Second buffer (" << std::dec << buffer2Len << " bytes):\n\n";

		int differenceCount = 0;
		for (int i = 0; i < (int)buffer2Len; i++)
		{
			std::string starOrSpace = (buffer2[i] != buffer1[i] ? "*" : " ");
			differenceCount += (buffer2[i] != buffer1[i] ? 1 : 0);
			std::cout << starOrSpace << "0x" << std::setfill('0') << std::setw(2) << std::hex << (int)buffer2[i] << " ";
			if ((i + 1) % 16 == 0)
			{
				std::cout << std::endl;
			}
		}
		std::cout << "\n\n" << std::dec << differenceCount << " bytes differ\n\n";
	}

	void testSetUp()
	{
		pcpp::SomeIpLayer::addSomeIpPort(1);
		pcpp::SomeIpLayer::removeSomeIpPort(1);
	}

#ifdef PCPP_TESTS_DEBUG
#	include "pcap.h"

	void savePacketToPcap(pcpp::Packet& packet, const std::string& fileName)
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
		pcap_dump(static_cast<u_char*>(d), &hdr, packet.getRawPacketReadOnly()->getRawData());

		/* finish up */
		pcap_dump_close(d);
		return;
	}
#endif

}  // namespace pcpp_tests
