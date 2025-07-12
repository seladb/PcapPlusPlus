/**
 * ICMP file transfer utility - pitcher
 * ========================================
 * This utility demonstrates how to transfer files between 2 machines using only ICMP messages.
 * This is the pitcher part of the utility
 * For more information please refer to README.md
 */

#include <stdexcept>
#include <iostream>
#include <fstream>
#ifndef _MSC_VER
#	include "unistd.h"
#endif
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "Common.h"
#include "SystemUtils.h"

#define SEND_TIMEOUT_BEFORE_FT_START 3

#define SLEEP_BETWEEN_ABORT_MESSAGES 100000  // 100 msec
#define NUM_OF_ABORT_MESSAGES_TO_SEND 5

#ifdef _MSC_VER
#	include <windows.h>

void usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * usec);  // Convert to 100 nanosecond interval, negative value indicates relative time
	// NULL is used instead of nullptr for Windows APIs. Check
	// https://devblogs.microsoft.com/oldnewthing/20180307-00/?p=98175
	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (timer == nullptr)
	{
		throw std::runtime_error("Could not create waitable timer with error: " + std::to_string(GetLastError()));
	}
	// NULL is used instead of nullptr for Windows APIs. Check
	// https://devblogs.microsoft.com/oldnewthing/20180307-00/?p=98175
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
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
};

/**
 * A struct used for start receiving a file from the catcher
 */
struct IcmpFileTransferStartRecv
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	bool gotFileTransferStartMsg;
	std::string fileName;
};

/**
 * A struct used for receiving file content from the catcher
 */
struct IcmpFileContentData
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	std::ofstream* file;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
	uint32_t MBReceived;
	bool fileTransferCompleted;
	bool fileTransferError;
};

/**
 * A callback used in the receiveFile() method and responsible to wait for the catcher to send an ICMP response
 * containing the file name to be received
 */
static void waitForFileTransferStart(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return;

	if (icmpVoidData == nullptr)
		return;

	IcmpFileTransferStartRecv* icmpFTStart = (IcmpFileTransferStartRecv*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == nullptr)
		return;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpFTStart->catcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpFTStart->pitcherIPAddr)
		return;

	// extract the message type in the ICMP reply timestamp field and check if it's  ICMP_FT_START
	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;
	if (resMsg != ICMP_FT_START)
		return;

	// verify there is data in the ICMP reply
	if (icmpLayer->getEchoReplyData()->data == nullptr)
		return;

	// extract the file name from the ICMP reply data
	icmpFTStart->fileName = std::string((char*)icmpLayer->getEchoReplyData()->data);

	// signal the receiveFile() file name was extracted and it can stop capturing packets
	icmpFTStart->gotFileTransferStartMsg = true;
}

/**
 * A callback used in the receiveFile() method and responsible to receive file data chunks arriving from the catcher and
 * write them to the local file
 */
static void getFileContent(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return;

	if (icmpVoidData == nullptr)
		return;

	IcmpFileContentData* icmpFileContentData = (IcmpFileContentData*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == nullptr)
		return;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpFileContentData->catcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpFileContentData->pitcherIPAddr)
		return;

	// extract the message type from the ICMP reply timestamp field
	uint64_t resMsg = icmpLayer->getEchoReplyData()->header->timestamp;

	// if message type is ICMP_FT_END it means all file was sent by the catcher. In that case set the
	// icmpFileContentData->fileTransferCompleted to true the receiveFile() method checks that flag periodically and
	// will stop capture packets
	if (resMsg == ICMP_FT_END)
	{
		icmpFileContentData->fileTransferCompleted = true;
		std::cout << ".";
		return;
	}

	// if message type isn't ICMP_FT_END and ICMP_FT_DATA, ignore it
	if (resMsg != ICMP_FT_DATA)
		return;

	// if got to here it means it's an ICMP_FT_DATA message

	// verify we're not missing any message by checking the ICMP ID of the reply and compare it to the expected ICMP ID.
	// If one or more message were missed, set fileTransferError flag so the main thread could abort the catcher and
	// exit the program
	if (pcpp::netToHost16(icmpLayer->getEchoReplyData()->header->id) != icmpFileContentData->expectedIcmpId)
	{
		icmpFileContentData->fileTransferError = true;
		std::cout << std::endl
		          << std::endl
		          << "Didn't get expected ICMP message #" << icmpFileContentData->expectedIcmpId << ", got #"
		          << pcpp::netToHost16(icmpLayer->getEchoReplyData()->header->id) << std::endl;
		return;
	}

	// verify the ICMP reply has data
	if (icmpLayer->getEchoReplyData()->data == nullptr)
		return;

	// increment the expected ICMP ID
	icmpFileContentData->expectedIcmpId++;

	// write the file data chunk in the ICMP reply data to the output file
	icmpFileContentData->file->write((char*)icmpLayer->getEchoReplyData()->data,
	                                 icmpLayer->getEchoReplyData()->dataLength);

	// count the bytes received
	icmpFileContentData->fileSize += icmpLayer->getEchoReplyData()->dataLength;

	// print a dot (".") for every 1MB received
	icmpFileContentData->MBReceived += icmpLayer->getEchoReplyData()->dataLength;
	if (icmpFileContentData->MBReceived > ONE_MBYTE)
	{
		icmpFileContentData->MBReceived -= ONE_MBYTE;
		std::cout << ".";
	}
}

/**
 * Receive a file from the catcher
 */
void receiveFile(pcpp::IPv4Address pitcherIP, pcpp::IPv4Address catcherIP, int packetPerSec)
{
	// identify the interface to listen and send packets to
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(pitcherIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Cannot find network interface with IP '" << pitcherIP << "'");

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface ");

	// get the MAC address of the interface
	pcpp::MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	// discover the MAC address of the catcher by sending an ARP ping to it
	double arpResTO = 0;
	pcpp::MacAddress catcherMacAddr =
	    pcpp::NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, pitcherMacAddr, pitcherIP, 10);
	if (catcherMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

	uint16_t icmpId = 1;

	IcmpFileTransferStartRecv icmpFTStart = { pitcherIP, catcherIP, false, "" };

	std::cout << "Waiting for catcher to start sending a file..." << std::endl;

	// set an ICMP protocol filter so it'll capture only ICMP packets
	pcpp::ProtoFilter protocolFilter(pcpp::ICMP);
	if (!dev->setFilter(protocolFilter))
		EXIT_WITH_ERROR("Can't set ICMP filter on device");

	// since it's the pitcher's job to send ICMP requests and the catcher's job to get them and send ICMP replies,
	// sending a file from the catcher to the pitcher is a bit more complicated
	// so for start the pitcher needs the file name. It sends an ICMP request with ICMP_FT_WAITING_FT_START message in
	// the timestamp field and awaits for catcher response that should include the file name

	// start capturing ICMP packets. The waitForFileTransferStart callback should look for the catcher reply and set
	// icmpFTStart.gotFileTransferStartMsg to true
	if (!dev->startCapture(waitForFileTransferStart, &icmpFTStart))
		EXIT_WITH_ERROR("Cannot start capturing packets");

	// while didn't receive response from the catcher, keep sending the ICMP_FT_WAITING_FT_START message
	while (!icmpFTStart.gotFileTransferStartMsg)
	{
		sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_FT_START,
		                nullptr, 0);
		icmpId++;
		// sleep for a few seconds between sending the message
		std::this_thread::sleep_for(std::chrono::seconds(SEND_TIMEOUT_BEFORE_FT_START));
	}

	// stop capturing packets
	dev->stopCapture();

	// create a new file with the name provided by the catcher
	std::ofstream file(icmpFTStart.fileName.c_str(), std::ios::out | std::ios::binary);

	if (file.is_open())
	{
		std::cout << "Getting file from catcher: '" << icmpFTStart.fileName << "' ";

		IcmpFileContentData icmpFileContentData = { pitcherIP, catcherIP, &file, icmpId, 0, 0, false, false };

		// the next thing to do is start getting the file data. For doing that the pitcher sends the catcher ICMP
		// requests with message type ICMP_FT_WAITING_DATA in the timestamp field. The catcher should send an ICMP
		// response for each such request with data chunk of the file

		// calculate how many microseconds (usec) the pitcher needs to sleep between sending the ICMP_FT_WAITING_DATA
		// message (calculated from user defined packetPerSec parameter). The calculation is done in usec as in most
		// cases the pitcher needs to sleep less than 1 second between chunks. However if packetPerSec equals to 1 it
		// means sleeping for 1 second and in this case we can't use usleep (as it's not working for 1 sec or more) and
		// we use sleep instead
		uint32_t sleepBetweenPackets = 0;
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		// start capturing ICMP packets. The getFileContent callback should look for the catcher replies containing data
		// chunks of the file and write them to the opened file. When catcher signals the end of the file transfer, the
		// callback will set the icmpFileContentData.fileTransferCompleted flag to true
		if (!dev->startCapture(getFileContent, &icmpFileContentData))
		{
			file.close();
			EXIT_WITH_ERROR_AND_RUN_COMMAND("Cannot start capturing packets",
			                                std::remove(icmpFTStart.fileName.c_str()));
		}

		// keep sending ICMP requests with ICMP_FT_WAITING_DATA message in the timestamp field until all file was
		// received or until an error occurred
		while (!icmpFileContentData.fileTransferCompleted && !icmpFileContentData.fileTransferError)
		{
			sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_WAITING_DATA,
			                nullptr, 0);

			// if rate limit was set by the user, sleep between sending packets
			if (packetPerSec > 1)
				std::this_thread::sleep_for(std::chrono::microseconds(sleepBetweenPackets));
			else if (packetPerSec == 1)
				std::this_thread::sleep_for(std::chrono::seconds(1));

			icmpId++;
		}

		// stop capturing packets
		dev->stopCapture();

		// if an error occurred (for example: pitcher missed some of the file content packets), send several abort
		// message to the catcher so it'll stop waiting for packets, and exit the program
		if (icmpFileContentData.fileTransferError)
		{
			for (int i = 0; i < NUM_OF_ABORT_MESSAGES_TO_SEND; i++)
			{
				sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_ABORT,
				                nullptr, 0);
				std::this_thread::sleep_for(std::chrono::microseconds(SLEEP_BETWEEN_ABORT_MESSAGES));
			}

			file.close();
			EXIT_WITH_ERROR_AND_RUN_COMMAND("Sent abort message to catcher. Exiting...",
			                                std::remove(icmpFTStart.fileName.c_str()));
		}

		// file transfer was completed successfully
		std::cout << std::endl
		          << std::endl
		          << "Finished getting file '" << icmpFTStart.fileName << "' "
		          << "[received " << icmpFileContentData.fileSize << " bytes]" << std::endl;
	}
	else
		EXIT_WITH_ERROR("Cannot create file");

	// close the device
	dev->close();
}

/**
 * A callback used in the sendFile() method and responsible to wait for ICMP responses coming from the catcher
 * indicating it's alive and ready for file transfer to start
 */
static bool waitForFileTransferStartAck(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return false;

	if (icmpVoidData == nullptr)
		return false;

	IcmpFileTransferStartSend* icmpData = (IcmpFileTransferStartSend*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP reply
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoReplyData() == nullptr)
		return false;

	// verify the ICMP ID of the reply matched the ICMP ID the pitcher sent in the request
	if (icmpLayer->getEchoReplyData()->header->id != pcpp::hostToNet16(icmpData->icmpMsgId))
		return false;

	// verify the source IP is the catcher's IP and the dest IP is the pitcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpData->catcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpData->pitcherIPAddr)
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
void sendFile(const std::string& filePath, pcpp::IPv4Address pitcherIP, pcpp::IPv4Address catcherIP, size_t blockSize,
              int packetPerSec)
{
	// identify the interface to listen and send packets to
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(pitcherIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Cannot find network interface with IP '" << pitcherIP << "'");

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface ");

	// get the MAC address of the interface
	pcpp::MacAddress pitcherMacAddr = dev->getMacAddress();
	if (pitcherMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find pitcher MAC address");

	// discover the MAC address of the catcher by sending an ARP ping to it
	double arpResTO = 0;
	pcpp::MacAddress catcherMacAddr =
	    pcpp::NetworkUtils::getInstance().getMacAddress(catcherIP, dev, arpResTO, pitcherMacAddr, pitcherIP, 10);
	if (catcherMacAddr == pcpp::MacAddress::Zero)
		EXIT_WITH_ERROR("Cannot find catcher MAC address");

	// create a buffer that will be used to send data chunks of the file
	uint8_t* memblock = new uint8_t[blockSize];
	memset(memblock, 0, blockSize);

	// try the open the file for reading
	std::ifstream file(filePath.c_str(), std::ios::in | std::ios::binary);

	if (file.is_open())
	{
		// remove the path and keep just the file name. This is the name that will be delivered to the catcher
		std::string fileName = getFileNameFromPath(filePath);

		// go back to the beginning of the file
		file.seekg(0, std::ios::beg);

		uint16_t icmpId = 1;

		// copy the file name to the buffer
		strcpy((char*)memblock, fileName.c_str());

		IcmpFileTransferStartSend ftStartData = { icmpId, pitcherIP, catcherIP };

		std::cout << "Waiting for catcher..." << std::endl;

		// establish connection with the catcher by sending it ICMP requests that contains the file name and wait for a
		// response keep sending these requests until the catcher answers or until the program is stopped
		while (1)
		{
			// send the catcher an ICMP request that includes an special ICMP_FT_START message in the timestamp field
			// and the filename in the request data. The catcher should intercept this message and send an ICMP response
			// with an ICMP_FT_ACK message in the timestamp field
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_START,
			                     memblock, fileName.length() + 1))
				EXIT_WITH_ERROR("Cannot send file transfer start message");

			// now wait for the catcher to answer. The timeout is SEND_TIMEOUT_BEFORE_FT_START. After that another ICMP
			// request will be sent
			int res =
			    dev->startCaptureBlockingMode(waitForFileTransferStartAck, &ftStartData, SEND_TIMEOUT_BEFORE_FT_START);
			if (!res)
				EXIT_WITH_ERROR("Cannot start capturing packets");

			// res == 1 means we got the catcher response so we can break the endless loop
			if (res == 1)
				break;

			// increase ICMP ID so we won't send the same ICMP ID again
			icmpId++;
			ftStartData.icmpMsgId++;
		}

		std::cout << "Sending file '" << fileName << "' ";

		icmpId++;
		uint32_t bytesSentSoFar = 0;
		uint32_t MBSent = 0;

		uint32_t sleepBetweenPackets = 0;
		// calculate how many microseconds (usec) the pitcher needs to sleep between sending each file data chunk
		// (calculated from user defined packetPerSec parameter). The calculation is done in usec as in most cases the
		// pitcher needs to sleep less than 1 second between chunks. However if packetPerSec equals to 1 it means
		// sleeping for 1 second and in this case we can't use usleep (as it's not working for 1 sec or more) and we use
		// sleep instead
		if (packetPerSec > 1)
			sleepBetweenPackets = (uint32_t)(1000000UL / packetPerSec);

		// read one chunk of the file and send it to catcher. This loop breaks when it is reaching the end of the file
		// and can't read a block of size blockSize from the file
		while (file.read((char*)memblock, blockSize))
		{
			// send an ICMP request to the catcher containing the data chunk.The message type (set in the timestamp
			// field) is ICMP_FT_DATA so the catcher knows it's a data chunk
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA,
			                     memblock, blockSize))
				EXIT_WITH_ERROR("Cannot send file data message");

			// use usleep or sleep (see comment a few lines below)
			if (packetPerSec > 1)
				std::this_thread::sleep_for(std::chrono::microseconds(sleepBetweenPackets));
			else if (packetPerSec == 1)
				std::this_thread::sleep_for(std::chrono::seconds(1));

			bytesSentSoFar += blockSize;

			// print a dot ('.') on every 1MB sent
			MBSent += blockSize;
			if (MBSent > ONE_MBYTE)
			{
				MBSent -= ONE_MBYTE;
				std::cout << ".";
			}

			icmpId++;
		}

		// after the loop above breaks there may be one more block to read (of size less than blockSize). Read it and
		// send it to the catcher
		if (file.gcount() > 0)
		{
			if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_DATA,
			                     memblock, file.gcount()))
				EXIT_WITH_ERROR("Cannot send file data message");

			bytesSentSoFar += file.gcount();
			std::cout << ".";
		}

		// done sending the file to the catcher, send an ICMP request with message type ICMP_FT_END (in the timestamp
		// field) to the catcher to indicate all file was sent
		if (!sendIcmpRequest(dev, pitcherMacAddr, catcherMacAddr, pitcherIP, catcherIP, icmpId, ICMP_FT_END, nullptr,
		                     0))
			EXIT_WITH_ERROR("Cannot send file transfer end message");

		std::cout << std::endl
		          << std::endl
		          << "Finished sending '" << fileName << "' "
		          << "[sent " << bytesSentSoFar << " bytes]" << std::endl;
	}
	else
		EXIT_WITH_ERROR("Cannot open file '" << filePath << "'");

	// close the file and the device. Free the memory for memblock
	file.close();
	dev->close();
	delete[] memblock;
}

/**
 * main method of this ICMP pitcher
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	bool sender, receiver;
	pcpp::IPv4Address pitcherIP;
	pcpp::IPv4Address catcherIP;
	std::string fileNameToSend;
	int packetsPerSec = 0;
	size_t blockSize = 0;

	// disable stdout buffering so all std::cout command will be printed immediately
	setbuf(stdout, nullptr);

	// read and parse command line arguments. This method also takes care of arguments correctness. If they're not
	// correct, it'll exit the program
	readCommandLineArguments(argc, argv, "pitcher", "catcher", sender, receiver, pitcherIP, catcherIP, fileNameToSend,
	                         packetsPerSec, blockSize);

	// send a file to the catcher
	if (sender)
		sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize, packetsPerSec);
	// receive a file from the catcher
	else if (receiver)
		receiveFile(pitcherIP, catcherIP, packetsPerSec);
}
