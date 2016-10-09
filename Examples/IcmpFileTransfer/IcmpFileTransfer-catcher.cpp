#include <stdlib.h>
#include <iostream>
#include <fstream>
#ifndef WIN32
#include <in.h>
#endif
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "Common.h"

using namespace pcpp;

struct IcmpFileTransferStart
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	std::string fileName;
	uint16_t icmpId;
};

struct IcmpFileContentDataRecv
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	std::ofstream* file;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
};

struct IcmpFileContentDataSend
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	std::ifstream* file;
	bool readingFromFile;
	size_t blockSize;
	char* memblock;
};

bool waitForFileTransferStart(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileTransferStart* icmpFTStart = (IcmpFileTransferStart*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == NULL)
		return false;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFTStart->pitcherIPAddr || ip4Layer->getDstIpAddress() != icmpFTStart->catcherIPAddr)
		return false;

	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;
	if (resMsg != ICMP_FT_START)
		return false;

	if (icmpLayer->getEchoRequestData()->data == NULL)
		return false;

	icmpFTStart->fileName = std::string((char*)icmpLayer->getEchoRequestData()->data);

	EthLayer* ethLayer = parsedPacket.getLayerOfType<EthLayer>();
	uint16_t icmpId = ntohs(icmpLayer->getEchoRequestData()->header->id);

	if (!sendIcmpResponse(dev,
			dev->getMacAddress(), ethLayer->getSourceMac(),
			icmpFTStart->catcherIPAddr, icmpFTStart->pitcherIPAddr,
			icmpId, ICMP_FT_ACK,
			NULL, 0))
		EXIT_WITH_ERROR("Cannot send ACK message to pitcher");

	icmpFTStart->icmpId = icmpId;
	return true;
}

bool getFileContent(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileContentDataRecv* icmpData = (IcmpFileContentDataRecv*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == NULL)
		return false;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpData->pitcherIPAddr || ip4Layer->getDstIpAddress() != icmpData->catcherIPAddr)
		return false;

	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;

	if (resMsg == ICMP_FT_END)
	{
		icmpData->file->close();
		return true;
	}
	else if (resMsg != ICMP_FT_DATA)
		return false;

	if (icmpLayer->getEchoRequestData()->data == NULL)
		return false;

	if (ntohs(icmpLayer->getEchoRequestData()->header->id) < icmpData->expectedIcmpId)
		return false;

	if (ntohs(icmpLayer->getEchoRequestData()->header->id) > icmpData->expectedIcmpId)
		EXIT_WITH_ERROR("Didn't get expected ICMP message #%d, got #%d", icmpData->expectedIcmpId, ntohs(icmpLayer->getEchoRequestData()->header->id));

	icmpData->expectedIcmpId++;
	icmpData->file->write((char*)icmpLayer->getEchoRequestData()->data, icmpLayer->getEchoRequestData()->dataLength);
	icmpData->fileSize += icmpLayer->getEchoRequestData()->dataLength;

//	EthLayer* ethLayer = parsedPacket.getLayerOfType<EthLayer>();

//	static int blabla = 0;
//	blabla++;
//	printf("%d packets aaaarrived\n", blabla);
//	return false;


//	if (!sendIcmpResponse(dev,
//			dev->getMacAddress(), ethLayer->getSourceMac(),
//			icmpData->catcherIPAddr, icmpData->pitcherIPAddr,
//			icmpLayer->getEchoRequestData()->header->id, ICMP_FT_ACK,
//			NULL, 0))
//		EXIT_WITH_ERROR("Cannot send ACK message to pitcher");

	return false;
}

void receiveFile(IPv4Address pitcherIP, IPv4Address catcherIP)
{
	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&catcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find device for IP '%s'", catcherIP.toString().c_str());

	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open device");

	ProtoFilter protocolFilter(ICMP);
	if (!dev->setFilter(protocolFilter))
		EXIT_WITH_ERROR("Can't set ICMP filter on device");

	IcmpFileTransferStart icmpFTStart = {
			pitcherIP,
			catcherIP,
			"",
			0
	};

	printf("Waiting for pitcher to send a file...\n");

	int res = dev->startCaptureBlockingMode(waitForFileTransferStart, &icmpFTStart, -1);
	if (!res)
		EXIT_WITH_ERROR("Couldn't start capturing packets");

	std::ofstream file(icmpFTStart.fileName.c_str(), std::ios::out|std::ios::binary);

	if (file.is_open())
	{
		printf("Getting file from pitcher: '%s'\n", icmpFTStart.fileName.c_str());

		IcmpFileContentDataRecv icmpFileContentData = {
				pitcherIP,
				catcherIP,
				&file,
				icmpFTStart.icmpId+1,
				0
		};

		res = dev->startCaptureBlockingMode(getFileContent, &icmpFileContentData, -1);
		if (!res)
			EXIT_WITH_ERROR("Couldn't start capturing packets");

		file.close();

		printf("Finished getting file '%s' [received %d bytes]\n", icmpFTStart.fileName.c_str(), icmpFileContentData.fileSize);
	}
	else
		EXIT_WITH_ERROR("Couldn't create file");

	dev->close();
}


bool startFileTransfer(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileTransferStart* icmpFTStart = (IcmpFileTransferStart*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == NULL)
		return false;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFTStart->pitcherIPAddr || ip4Layer->getDstIpAddress() != icmpFTStart->catcherIPAddr)
		return false;

	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;
	if (resMsg != ICMP_FT_WAITING_FT_START)
		return false;

	EthLayer* ethLayer = parsedPacket.getLayerOfType<EthLayer>();
	uint16_t icmpId = ntohs(icmpLayer->getEchoRequestData()->header->id);

	if (!sendIcmpResponse(dev,
			dev->getMacAddress(), ethLayer->getSourceMac(),
			icmpFTStart->catcherIPAddr, icmpFTStart->pitcherIPAddr,
			icmpId, ICMP_FT_START,
			(uint8_t*)icmpFTStart->fileName.c_str(), icmpFTStart->fileName.length()+1))
		EXIT_WITH_ERROR("Cannot send file transfer start message to pitcher");

	icmpFTStart->icmpId = icmpId;
	return true;
}


bool sendContent(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileContentDataSend* icmpFileContentData = (IcmpFileContentDataSend*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == NULL)
		return false;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFileContentData->pitcherIPAddr || ip4Layer->getDstIpAddress() != icmpFileContentData->catcherIPAddr)
		return false;

	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;
	if (resMsg != ICMP_FT_WAITING_DATA)
		return false;

	EthLayer* ethLayer = parsedPacket.getLayerOfType<EthLayer>();
	uint16_t icmpId = ntohs(icmpLayer->getEchoRequestData()->header->id);

	if (!icmpFileContentData->readingFromFile)
	{
		if (!sendIcmpResponse(dev,
				dev->getMacAddress(), ethLayer->getSourceMac(),
				icmpFileContentData->catcherIPAddr, icmpFileContentData->pitcherIPAddr,
				icmpId, ICMP_FT_END,
				NULL, 0))
			EXIT_WITH_ERROR("Cannot send file transfer end message to pitcher");

		return true;
	}

	if (icmpFileContentData->file->read(icmpFileContentData->memblock, icmpFileContentData->blockSize))
	{
		if (!sendIcmpResponse(dev,
				dev->getMacAddress(), ethLayer->getSourceMac(),
				icmpFileContentData->catcherIPAddr, icmpFileContentData->pitcherIPAddr,
				icmpId, ICMP_FT_DATA,
				(uint8_t*)icmpFileContentData->memblock, icmpFileContentData->blockSize))
			EXIT_WITH_ERROR("Cannot send file transfer data message to pitcher");
	}
	else if (icmpFileContentData->file->gcount() > 0)
	{
		if (!sendIcmpResponse(dev,
				dev->getMacAddress(), ethLayer->getSourceMac(),
				icmpFileContentData->catcherIPAddr, icmpFileContentData->pitcherIPAddr,
				icmpId, ICMP_FT_DATA,
				(uint8_t*)icmpFileContentData->memblock, icmpFileContentData->file->gcount()))
			EXIT_WITH_ERROR("Cannot send file transfer last data message to pitcher");

		icmpFileContentData->readingFromFile = false;
	}
	else
	{
		icmpFileContentData->readingFromFile = false;
	}

	return false;
}

void sendFile(std::string filePath, IPv4Address pitcherIP, IPv4Address catcherIP, size_t blockSize)
{
	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&catcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find device for IP '%s'", catcherIP.toString().c_str());

	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open device");

	std::ifstream file(filePath.c_str(), std::ios::in|std::ios::binary);

	if (file.is_open())
	{
		file.seekg(0, std::ios_base::end);
	    uint32_t fileSize = file.tellg();

		file.seekg(0, std::ios::beg);

		std::string fileName = getFileNameFromPath(filePath);

		IcmpFileTransferStart icmpFTStart = {
				pitcherIP,
				catcherIP,
				fileName,
				0
		};

		printf("Waiting for pitcher to send a keep-alive signal...\n");

		int res  = dev->startCaptureBlockingMode(startFileTransfer, &icmpFTStart, -1);
		if (!res)
			EXIT_WITH_ERROR("Couldn't start capturing packets");

		printf("Sending file '%s'\n", fileName.c_str());


		IcmpFileContentDataSend icmpFileContentData = {
				pitcherIP,
				catcherIP,
				&file,
				true,
				blockSize,
				NULL
		};

		icmpFileContentData.memblock = new char[blockSize];

		res = dev->startCaptureBlockingMode(sendContent, &icmpFileContentData, -1);

		delete [] icmpFileContentData.memblock;
		file.close();

		if (!res)
			EXIT_WITH_ERROR("Couldn't start capturing packets");

		printf("Finished sending '%s' [sent %d bytes]\n", fileName.c_str(), fileSize);
	}
	else
		EXIT_WITH_ERROR("Couldn't open file '%s'", filePath.c_str());

	dev->close();
}

/**
 * main method of this ICMP catcher
 */
int main(int argc, char* argv[])
{
	bool sender, receiver;
	IPv4Address pitcherIP = IPv4Address::Zero;
	IPv4Address catcherIP = IPv4Address::Zero;
	std::string fileNameToSend = "";
	int packetsPerSec = 0;
	size_t blockSize = 0;

	readCommandLineArguments(argc, argv, "catcher", "pitcher", sender, receiver, catcherIP, pitcherIP, fileNameToSend, packetsPerSec, blockSize);

	if (sender)
		sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize);

	if (receiver)
		receiveFile(pitcherIP, catcherIP);
}
