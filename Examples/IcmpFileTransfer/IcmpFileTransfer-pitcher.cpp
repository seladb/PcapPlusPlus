/**
 * ICMP file transfer utility - pitcher
 * ========================================
 * This utility demonstrates how to transfer files between 2 machines using only ICMP messages.
 * This is the pitcher part of the utility
 * For more information please refer to README.md
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#ifndef _MSC_VER
#include "unistd.h"
#endif
#if !defined(WIN32) && !defined(WINx64)
#include <in.h>
#endif
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "Common.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"


using namespace pcpp;

#define SEND_TIMEOUT_BEFORE_FT_START 3

#define SLEEP_BETWEEN_ABORT_MESSAGES  100000 // 100 msec
#define NUM_OF_ABORT_MESSAGES_TO_SEND 5

#ifdef _MSC_VER
#include <windows.h>

void usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * usec); // Convert to 100 nanosecond interval, negative value indicates relative time

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
}
#endif

/**
 * A struct used for start sending a file to the catcher
 */
struct IcmpFileTransferStartSend
{
	uint16_t icmpMsgId;
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
};

/**
 * A struct used for start receiving a file from the catcher
 */
struct IcmpFileTransferStartRecv
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	bool gotFileTransferStartMsg;
	std::string fileName;
};

/**
 * A struct used for receiving file content from the catcher
 */
struct IcmpFileContentData
{
	IPv4Address pitcherIPAddr;
	IPv4Address catcherIPAddr;
	std::ofstream* file;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
	uint32_t MBReceived;
	bool fileTransferCompleted;
	bool fileTransferError;
};


/**
 * A callback used in the receiveFile() method and responsible to wait for the catcher to send an ICMP response containing the file name
 * to be received
 */
static void waitForFileTransferStart(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return;

	if (icmpVoidData == NULL)
		return;

	IcmpFileTransferStartRecv* icmpFTStart = (IcmpFileTransferStartRecv*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFTStart->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpFTStart->pitcherIPAddr)
		return;

	// extract the message type in the ICMP reply timestamp field and check if it's  ICMP_FT_START
	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg != ICMP_FT_START)
		return;

	// verify there is data in the ICMP reply
	if (icmpLayer->getEchoReplyData()->data == NULL)
		return;

	// extract the file name from the ICMP reply data
	icmpFTStart->fileName = std::string((char*)icmpLayer->getEchoReplyData()->data);

	// signal the receiveFile() file name was extracted and it can stop capturing packets
	icmpFTStart->gotFileTransferStartMsg = true;
}


/**
 * A callback used in the receiveFile() method and responsible to receive file data chunks arriving from the catcher and write them to the
 * local file
 */
static void getFileContent(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return;

	if (icmpVoidData == NULL)
		return;

	IcmpFileContentData* icmpFileContentData = (IcmpFileContentData*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpFileContentData->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpFileContentData->pitcherIPAddr)
		return;

	// extract the message type from the ICMP reply timestamp field
	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;

	// if message type is ICMP_FT_END it means all file was sent by the catcher. In that case set the icmpFileContentData->fileTransferCompleted to true
	// the receiveFile() method checks that flag periodically and will stop capture packets
	if (resMsg == ICMP_FT_END)
	{
		icmpFileContentData->fileTransferCompleted = true;
		printf(".");
		return;
	}

	// if message type isn't ICMP_FT_END and ICMP_FT_DATA, ignore it
	if (resMsg != ICMP_FT_DATA)
		return;

	// if got to here it means it's an ICMP_FT_DATA message

	// verify we're not missing any message by checking the ICMP ID of the reply and compare it to the expected ICMP ID. If one or more
	// message were missed, set fileTransferError flag so the main thread could abort the catcher and exit the program
	if (ntohs(icmpLayer->getEchoReplyData()->header->id) != icmpFileContentData->expectedIcmpId)
	{
		icmpFileContentData->fileTransferError = true;
		printf("\n\nDidn't get expected ICMP message #%d, got #%d\n", icmpFileContentData->expectedIcmpId, ntohs(icmpLayer->getEchoReplyData()->header->id));
		return;
	}

	// verify the ICMP reply has data
	if (icmpLayer->getEchoReplyData()->data == NULL)
		return;

	// increment the expected ICMP ID
	icmpFileContentData->expectedIcmpId++;

	// write the file data chunk in the ICMP reply data to the output file
	icmpFileContentData->file->write((char*)icmpLayer->getEchoReplyData()->data, icmpLayer->getEchoReplyData()->dataLength);

	// count the bytes received
	icmpFileContentData->fileSize += icmpLayer->getEchoReplyData()->dataLength;

	// print a dot (".") for every 1MB received
	icmpFileContentData->MBReceived += icmpLayer->getEchoReplyData()->dataLength;
	if (icmpFileContentData->MBReceived > ONE_MBYTE)
	{
		icmpFileContentData->MBReceived -= ONE_MBYTE;
		printf(".");
	}
}


/**
 * Receive a file from the catcher
 */
void receiveFile(IPv4Address pitcherIP, IPv4Address catcherIP, int packetPerSec)
{
	// identify the interface to listen and send packets to
	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&pitcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find network interface with IP '%s'", pitcherIP.toString().c_str());

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface ");

	// get the MAC address of the interface
	MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	// discover the MAC address of the catcher by sending an ARP ping to it
	double arpResTO = 0;
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

	// set an ICMP protocol filter so it'll capture only ICMP packets
	ProtoFilter protocolFilter(ICMP);
	if (!dev->setFilter(protocolFilter))
		EXIT_WITH_ERROR("Can't set ICMP filter on device");

	// since it's the pitcher's job to send ICMP requests and the catcher's job to get them and send ICMP replies,
	// sending a file from the catcher to the pitcher is a bit more complicated
	// so for start the pitcher needs the file name. It sends an ICMP request with ICMP_FT_WAITING_FT_START message in the timestamp field
	// and awaits for catcher response that should include the file name

	// start capturing ICMP packets. The waitForFileTransferStart callback should look for the catcher reply and set icmpFTStart.gotFileTransferStartMsg
	// to true
	if (!dev->startCapture(waitForFileTransferStart, &icmpFTStart))
		EXIT_WITH_ERROR("Cannot start capturing packets");

	// while didn't receive response from the catcher, keep sending the ICMP_FT_WAITING_FT_START message
	while (!icmpFTStart.gotFileTransferStartMsg)
	{
		sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_FT_START, NULL, 0);
		icmpId++;
		// sleep for a few seconds between sending the message
		PCAP_SLEEP(SEND_TIMEOUT_BEFORE_FT_START);
	}

	// stop capturing packets
	dev->stopCapture();


	// create a new file with the name provided by the catcher
	std::ofstream file(icmpFTStart.fileName.c_str(), std::ios::out|std::ios::binary);

	if (file.is_open())
	{
		printf("Getting file from catcher: '%s' ", icmpFTStart.fileName.c_str());

		IcmpFileContentData icmpFileContentData = {
				pitcherIP,
				catcherIP,
				&file,
				icmpId,
				0,
				0,
				false,
				false
		};

		// the next thing to do is start getting the file data. For doing that the pitcher sends the catcher ICMP requests with message type
		// ICMP_FT_WAITING_DATA in the timestamp field. The catcher should send an ICMP response for each such request with data chunk of the
		// file

		// calculate how many microseconds (usec) the pitcher needs to sleep between sending the ICMP_FT_WAITING_DATA message
		// (calculated from user defined packetPerSec parameter).
		// The calculation is done in usec as in most cases the pitcher needs to sleep less than 1 second between chunks. However if packetPerSec
		// equals to 1 it means sleeping for 1 second and in this case we can't use usleep (as it's not working for 1 sec or more) and we use
		// sleep instead
		uint32_t sleepBetweenPackets = 0;
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		// start capturing ICMP packets. The getFileContent callback should look for the catcher replies containing data chunks of the file
		// and write them to the opened file. When catcher signals the end of the file transfer, the callback will set the
		// icmpFileContentData.fileTransferCompleted flag to true
		if (!dev->startCapture(getFileContent, &icmpFileContentData))
		{
			file.close();
			EXIT_WITH_ERROR_AND_RUN_COMMAND("Cannot start capturing packets", std::remove(icmpFTStart.fileName.c_str()));
		}

		// keep sending ICMP requests with ICMP_FT_WAITING_DATA message in the timestamp field until all file was received or until an error occured
		while (!icmpFileContentData.fileTransferCompleted && !icmpFileContentData.fileTransferError)
		{
			sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_DATA, NULL, 0);

			// if rate limit was set by the user, sleep between sending packets
			if (packetPerSec > 1)
				usleep(sleepBetweenPackets);
			else if (packetPerSec == 1)
				PCAP_SLEEP(1);

			icmpId++;
		}

		// stop capturing packets
		dev->stopCapture();

		// if an error occurred (for example: pitcher missed some of the file content packets), send several abort message to the catcher
		// so it'll stop waiting for packets, and exit the program
		if (icmpFileContentData.fileTransferError)
		{
			for (int i = 0; i < NUM_OF_ABORT_MESSAGES_TO_SEND; i++)
			{
				sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_ABORT, NULL, 0);
				usleep(SLEEP_BETWEEN_ABORT_MESSAGES);
			}

			file.close();
			EXIT_WITH_ERROR_AND_RUN_COMMAND("Sent abort message to catcher. Exiting...", std::remove(icmpFTStart.fileName.c_str()));
		}

		// file transfer was completed successfully
		printf("\n\nFinished getting file '%s' [received %d bytes]\n", icmpFTStart.fileName.c_str(), icmpFileContentData.fileSize);
	}
	else
		EXIT_WITH_ERROR("Cannot create file");

	// close the device
	dev->close();
}


/**
 * A callback used in the sendFile() method and responsible to wait for ICMP responses coming from the catcher indicating it's alive
 * and ready for file transfer to start
 */
static bool waitForFileTransferStartAck(RawPacket* rawPacket, PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(ICMP) || !parsedPacket.isPacketOfType(IPv4))
		return false;

	if (icmpVoidData == NULL)
		return false;

	IcmpFileTransferStartSend* icmpData = (IcmpFileTransferStartSend*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == NULL)
		return false;

	// verify the ICMP ID of the reply matched the ICMP ID the pitcher sent in the request
	if (icmpLayer->getEchoReplyData()->header->id != htons(icmpData->icmpMsgId))
		return false;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
	if (ip4Layer->getSrcIpAddress() != icmpData->catcherIPAddr || ip4Layer->getDstIpAddress() != icmpData->pitcherIPAddr)
		return false;

	// verify the message type is ICMP_FT_ACK
	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg != ICMP_FT_ACK)
		return false;

	// if arrived to here it means we got a response from the catcher and it's ready for file transfer to start
	return true;
}


/**
 * Send a file to the catcher
 */
void sendFile(std::string filePath, IPv4Address pitcherIP, IPv4Address catcherIP, size_t blockSize, int packetPerSec)
{
	// identify the interface to listen and send packets to
	PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(&pitcherIP);
	if (dev == NULL)
		EXIT_WITH_ERROR("Cannot find network interface with IP '%s'", pitcherIP.toString().c_str());

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface ");

	// get the MAC address of the interface
	MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	// discover the MAC address of the catcher by sending an ARP ping to it
	double arpResTO = 0;
	MacAddress catcherMacAddr = NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, pitcherMacAddr, pitcherIP, 10);
	if (catcherMacAddr == MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

	// create a buffer that will be used to send data chunks of the file
	uint8_t* memblock = new uint8_t[blockSize];
	memset(memblock, 0, blockSize);

	// try the open the file for reading
	std::ifstream file(filePath.c_str(), std::ios::in|std::ios::binary);

	if (file.is_open())
	{
		// remove the path and keep just the file name. This is the name that will be delivered to the catcher
		std::string fileName = getFileNameFromPath(filePath);

		// go back to the beginning of the file
		file.seekg(0, std::ios::beg);

		uint16_t icmpId = 1;

		// copy the file name to the buffer
		strcpy((char*)memblock, fileName.c_str());

		IcmpFileTransferStartSend ftStartData = {
				icmpId,
				pitcherIP,
				catcherIP
		};

		printf("Waiting for catcher...\n");

		// establish connection with the catcher by sending it ICMP requests that contains the file name and wait for a response
		// keep sending these requests until the catcher answers or until the program is stopped
		while (1)
		{
			// send the catcher an ICMP request that includes an special ICMP_FT_START message in the timestamp field and the filename
			// in the request data. The catcher should intercept this message and send an ICMP response with an ICMP_FT_ACK message in
			// the timestamp field
			if (!sendIcmpRequest(dev,
					pitcherMacAddr, catcherMacAddr,
					pitcherIP, catcherIP,
					icmpId, ICMP_FT_START,
					memblock, fileName.length() + 1))
				EXIT_WITH_ERROR("Cannot send file transfer start message");

			// now wait for the catcher to answer. The timeout is SEND_TIMEOUT_BEFORE_FT_START. After that another ICMP request will be sent
			int res = dev->startCaptureBlockingMode(waitForFileTransferStartAck, &ftStartData, SEND_TIMEOUT_BEFORE_FT_START);
			if (!res)
				EXIT_WITH_ERROR("Cannot start capturing packets");

			// res == 1 means we got the catcher response so we can break the endless loop
			if (res == 1)
				break;

			// increase ICMP ID so we won't send the same ICMP ID again
			icmpId++;
			ftStartData.icmpMsgId++;
		}

		printf("Sending file '%s' ", fileName.c_str());

		icmpId++;
		uint32_t bytesSentSoFar = 0;
		uint32_t MBSent = 0;

		uint32_t sleepBetweenPackets = 0;
		// calculate how many microseconds (usec) the pitcher needs to sleep between sending each file data chunk (calculated from user defined
		// packetPerSec parameter).
		// The calculation is done in usec as in most cases the pitcher needs to sleep less than 1 second between chunks. However if packetPerSec
		// equals to 1 it means sleeping for 1 second and in this case we can't use usleep (as it's not working for 1 sec or more) and we use
		// sleep instead
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		// read one chunk of the file and send it to catcher. This loop breaks when it is reaching the end of the file and can't read a block
		// of size blockSize from the file
		while (file.read((char*)memblock, blockSize))
		{
			// send an ICMP request to the catcher containing the data chunk.The message type (set in the timestamp field) is ICMP_FT_DATA
			// so the catcher knows it's a data chunk
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA, memblock, blockSize))
				EXIT_WITH_ERROR("Cannot send file data message");

			// use usleep or sleep (see comment a few lines below)
			//printf("sent #%d\n", icmpId);
			if (packetPerSec > 1)
				usleep(sleepBetweenPackets);
			else if (packetPerSec == 1)
				PCAP_SLEEP(1);

			bytesSentSoFar += blockSize;

			// print a dot ('.') on every 1MB sent
			MBSent += blockSize;
			if (MBSent > ONE_MBYTE)
			{
				MBSent -= ONE_MBYTE;
				printf(".");
			}

			icmpId++;
		}

		// after the loop above breaks there may be one more block to read (of size less than blockSize). Read it and send it to the catcher
		if (file.gcount() > 0)
		{
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA, memblock, file.gcount()))
				EXIT_WITH_ERROR("Cannot send file data message");

			bytesSentSoFar += file.gcount();
			printf(".");
		}

		// done sending the file to the catcher, send an ICMP request with message type ICMP_FT_END (in the timestamp field) to the catcher
		// to indicate all file was sent
		if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_END, NULL, 0))
			EXIT_WITH_ERROR("Cannot send file transfer end message");

		printf("\n\nFinished sending '%s' [sent %d bytes]\n", fileName.c_str(), bytesSentSoFar);
	}
	else
		EXIT_WITH_ERROR("Cannot open file '%s'", filePath.c_str());

	// close the file and the device. Free the memory for memblock
	file.close();
	dev->close();
	delete [] memblock;
}

/**
 * main method of this ICMP pitcher
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	bool sender, receiver;
	IPv4Address pitcherIP = IPv4Address::Zero;
	IPv4Address catcherIP = IPv4Address::Zero;
	std::string fileNameToSend = "";
	int packetsPerSec = 0;
	size_t blockSize = 0;

	// disable stdout buffering so all printf command will be printed immediately
	setbuf(stdout, NULL);

	// read and parse command line arguments. This method also takes care of arguments correctness. If they're not correct, it'll exit the program
	readCommandLineArguments(argc, argv, "pitcher", "catcher", sender, receiver, pitcherIP, catcherIP, fileNameToSend, packetsPerSec, blockSize);

	// send a file to the catcher
	if (sender)
		sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize, packetsPerSec);
	// receive a file from the catcher
	else if (receiver)
		receiveFile(pitcherIP, catcherIP, packetsPerSec);
}
