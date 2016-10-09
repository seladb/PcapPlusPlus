#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "unistd.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "Common.h"
#include "PlatformSpecificUtils.h"


using namespace pcpp;

#define SEND_TIMEOUT_BEFORE_FT_START 3

struct IcmpFileTransferStartSend
{
	uint16_t icmpMsgId;
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
};

struct IcmpFileTransferStartRecv
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	bool gotFileTransferStartMsg;
	std::string fileName;
};

struct IcmpFileContentData
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	std::ofstream* file;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
	bool fileTransferCompleted;
};

void waitForFileTransferStart(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return;

	if (icmpVoidData == NULL)
		return;

	IcmpFileTransferStartRecv* icmpFTStart = (IcmpFileTransferStartRecv*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFTStart->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpFTStart->pitcherIPAddr)
		return;

	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg != ICMP_FT_START)
		return;

	if (icmpLayer->getEchoReplyData()->data == NULL)
		return;

	icmpFTStart->fileName = std::string((char*)icmpLayer->getEchoReplyData()->data);

	icmpFTStart->gotFileTransferStartMsg = true;
}


void getFileContent(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return;

	if (icmpVoidData == NULL)
		return;

	IcmpFileContentData* icmpFileContentData = (IcmpFileContentData*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFileContentData->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpFileContentData->pitcherIPAddr)
		return;

	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg == ICMP_FT_END)
	{
		icmpFileContentData->fileTransferCompleted = true;
		return;
	}

	if (resMsg != ICMP_FT_DATA)
		return;

	if (ntohs(icmpLayer->getEchoReplyData()->header->id) != icmpFileContentData->expectedIcmpId)
		EXIT_WITH_ERROR("Didn't get expected ICMP message #%d, got #%d", icmpFileContentData->expectedIcmpId, ntohs(icmpLayer->getEchoReplyData()->header->id));

	if (icmpLayer->getEchoReplyData()->data == NULL)
		return;

	icmpFileContentData->expectedIcmpId++;
	icmpFileContentData->file->write((char*)icmpLayer->getEchoReplyData()->data, icmpLayer->getEchoReplyData()->dataLength);
	icmpFileContentData->fileSize += icmpLayer->getEchoReplyData()->dataLength;
}


void receiveFile(IPv4Address pitcherIP, IPv4Address catcherIP, int packetPerSec)
{
	double arpResTO = 0;

	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&pitcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find device for IP '%s'", pitcherIP.toString().c_str());

	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open device");

	MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	MacAddress catcherMacAddr = NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, pitcherMacAddr, pitcherIP, 10);
	if (catcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

	uint16_t icmpId = 1;

	IcmpFileTransferStartRecv icmpFTStart = {
			pitcherIP,
			catcherIP,
			false,
			""
	};

	printf("Waiting for catcher to start sending a file...\n");

	if (!dev->startCapture(waitForFileTransferStart, &icmpFTStart))
		EXIT_WITH_ERROR("Couldn't start capturing packets");

	while (!icmpFTStart.gotFileTransferStartMsg)
	{
		sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_FT_START, NULL, 0);
		icmpId++;
		PCAP_SLEEP(SEND_TIMEOUT_BEFORE_FT_START);
	}

	dev->stopCapture();


	std::ofstream file(icmpFTStart.fileName, std::ios::out|std::ios::binary);

	if (file.is_open())
	{
		printf("Getting file from catcher: '%s'\n", icmpFTStart.fileName.c_str());

		IcmpFileContentData icmpFileContentData = {
				pitcherIP,
				catcherIP,
				&file,
				icmpId,
				0,
				false
		};

		uint32_t sleepBetweenPackets = 0;
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		if (!dev->startCapture(getFileContent, &icmpFileContentData))
			EXIT_WITH_ERROR("Couldn't start capturing packets");

		while (!icmpFileContentData.fileTransferCompleted)
		{
			sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_DATA, NULL, 0);

			if (packetPerSec > 1)
				usleep(sleepBetweenPackets);
			else if (packetPerSec == 1)
				PCAP_SLEEP(1);

			icmpId++;
		}

		dev->stopCapture();

		printf("Finished getting file '%s' [received %d bytes]\n", icmpFTStart.fileName.c_str(), icmpFileContentData.fileSize);
	}
	else
		EXIT_WITH_ERROR("Couldn't create file");


	dev->close();
}


bool waitForFileTransferStartAck(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	Packet parsedPacket(rawPacket);

	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileTransferStartSend* icmpData = (IcmpFileTransferStartSend*)icmpVoidData;

	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return false;

	if (icmpLayer->getEchoReplyData()->header->id != htons(icmpData->icmpMsgId))
		return false;

	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpData->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpData->pitcherIPAddr)
		return false;

	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg != ICMP_FT_ACK)
		return false;

	return true;
}


void sendFile(std::string filePath, IPv4Address pitcherIP, IPv4Address catcherIP, size_t blockSize, int packetPerSec)
{
	double arpResTO = 0;

	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&pitcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find device for IP '%s'", pitcherIP.toString().c_str());

	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open device");

	MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	MacAddress catcherMacAddr = NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, pitcherMacAddr, pitcherIP, 10);
	if (catcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

	uint8_t* memblock = new uint8_t[blockSize];
	memset(memblock, 0, blockSize);

	std::ifstream file(filePath, std::ios::in|std::ios::binary);

	if (file.is_open())
	{
		std::string fileName = getFileNameFromPath(filePath);

		file.seekg(0, std::ios::beg);
		uint16_t icmpId = 1;

		strcpy((char*)memblock, fileName.c_str());

		IcmpFileTransferStartSend ftStartData = {
				icmpId,
				pitcherIP,
				catcherIP
		};

		printf("Waiting for catcher...\n");

		while (1)
		{
			if (!sendIcmpRequest(dev,
					pitcherMacAddr, catcherMacAddr,
					pitcherIP, catcherIP,
					icmpId, ICMP_FT_START,
					memblock, fileName.length() + 1))
				EXIT_WITH_ERROR("Couldn't send file transfer start message");

			int res = dev->startCaptureBlockingMode(waitForFileTransferStartAck, &ftStartData, SEND_TIMEOUT_BEFORE_FT_START);
			if (!res)
				EXIT_WITH_ERROR("Couldn't start capturing packets");

			if (res == 1)
				break;
		}

		printf("Sending file '%s'\n", fileName.c_str());

		icmpId++;
		uint32_t bytesSentSoFar = 0;

		uint32_t sleepBetweenPackets = 0;
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		while (file.read((char*)memblock, blockSize))
		{
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA, memblock, blockSize))
				EXIT_WITH_ERROR("Couldn't send file data message");

			printf("sent #%d\n", icmpId);
			if (packetPerSec > 1)
				usleep(sleepBetweenPackets);
			else if (packetPerSec == 1)
				PCAP_SLEEP(1);

			bytesSentSoFar += blockSize;
			icmpId++;
		}

		if (file.gcount() > 0)
		{
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA, memblock, file.gcount()))
				EXIT_WITH_ERROR("Couldn't send file data message");

			bytesSentSoFar += file.gcount();
		}

		if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_END, NULL, 0))
			EXIT_WITH_ERROR("Couldn't send file transfer end message");

		printf("Finished sending '%s' [sent %d bytes]\n", fileName.c_str(), bytesSentSoFar);
	}
	else
		EXIT_WITH_ERROR("Couldn't open file '%s'", filePath.c_str());

	file.close();
	dev->close();
	delete [] memblock;
}

/**
 * main method of this ICMP pitcher
 */
int main(int argc, char* argv[])
{
	bool sender, receiver;
	IPv4Address pitcherIP = IPv4Address::Zero;
	IPv4Address catcherIP = IPv4Address::Zero;
	std::string fileNameToSend = "";
	int packetsPerSec = 0;
	size_t blockSize = 0;

	readCommandLineArguments(argc, argv, "pitcher", "catcher", sender, receiver, pitcherIP, catcherIP, fileNameToSend, packetsPerSec, blockSize);

	if (sender)
		sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize, packetsPerSec);

	if (receiver)
		receiveFile(pitcherIP, catcherIP, packetsPerSec);
}
