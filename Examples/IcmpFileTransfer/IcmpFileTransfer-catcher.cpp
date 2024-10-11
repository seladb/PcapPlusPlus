/**
 * ICMP file transfer utility - catcher
 * ========================================
 * This utility demonstrates how to transfer files between 2 machines using only ICMP messages.
 * This is the catcher part of the utility
 * For more information please refer to README.md
 */

#include <iostream>
#include <fstream>
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "Common.h"
#include "SystemUtils.h"

/**
 * A struct used for starting a file transfer, mainly sending or getting the file name
 */
struct IcmpFileTransferStart
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	std::string fileName;
	uint16_t icmpId;
};

/**
 * A strcut used for receiving file data from the pitcher
 */
struct IcmpFileContentDataRecv
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	std::ofstream* file;
	std::string fileName;
	uint16_t expectedIcmpId;
	uint32_t fileSize;
	uint32_t MBReceived;
};

/**
 * A strcut used for sending file data to the pitcher
 */
struct IcmpFileContentDataSend
{
	pcpp::IPv4Address pitcherIPAddr;
	pcpp::IPv4Address catcherIPAddr;
	std::ifstream* file;
	bool readingFromFile;
	uint32_t MBSent;
	size_t blockSize;
	char* memblock;
};

/**
 * A callback used in the receiveFile() method and responsible to wait for the pitcher to send an ICMP request
 * containing the file name to be received
 */
static bool waitForFileTransferStart(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return false;

	if (icmpVoidData == nullptr)
		return false;

	IcmpFileTransferStart* icmpFTStart = (IcmpFileTransferStart*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP request
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == nullptr)
		return false;

	// verify the source IP is the pitcher's IP and the dest IP is the catcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpFTStart->pitcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpFTStart->catcherIPAddr)
		return false;

	// check the ICMP timestamp field which contains the type of message delivered between pitcher and catcher
	// in this case the catcher is waiting for a file-transfer start message from the pitcher containing the file name
	// which is of type ICMP_FT_START
	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;
	if (resMsg != ICMP_FT_START)
		return false;

	// extract the file name from the ICMP request data
	icmpFTStart->fileName = std::string((char*)icmpLayer->getEchoRequestData()->data);

	// extract ethernet layer and ICMP ID to be able to respond to the pitcher
	pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	uint16_t icmpId = pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id);

	// send the pitcher an ICMP response containing an ack message (of type ICMP_FT_ACK) so it knows the catcher has
	// received the file name and it's ready to start getting the file data
	if (!sendIcmpResponse(dev, dev->getMacAddress(), ethLayer->getSourceMac(), icmpFTStart->catcherIPAddr,
	                      icmpFTStart->pitcherIPAddr, icmpId, ICMP_FT_ACK, nullptr, 0))
		EXIT_WITH_ERROR("Cannot send ACK message to pitcher");

	// set the current ICMP ID. It's important for the catcher to keep track of the ICMP ID to make sure it doesn't miss
	// any message
	icmpFTStart->icmpId = icmpId;

	// file name has arrived, stop receiveFile() from blocking
	return true;
}

/**
 * A callback used in the receiveFile() method and responsible to receive file data chunks arriving from the pitcher and
 * write them to the local file
 */
static bool getFileContent(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return false;

	if (icmpVoidData == nullptr)
		return false;

	IcmpFileContentDataRecv* icmpData = (IcmpFileContentDataRecv*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP request
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == nullptr)
		return false;

	// verify the source IP is the pitcher's IP and the dest IP is the catcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpData->pitcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpData->catcherIPAddr)
		return false;

	// extract message type from the ICMP request. Message type is written in ICMP request timestamp field
	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;

	// if message type is ICMP_FT_END it means pitcher finished sending all file chunks
	if (resMsg == ICMP_FT_END)
	{
		// close the file and stop receiveFile() from blocking
		icmpData->file->close();
		std::cout << ".";
		return true;
	}
	// if message type is not ICMP_FT_END not ICMP_FT_DATA - do nothing, it's probably an ICMP request not relevant for
	// this file transfer
	else if (resMsg != ICMP_FT_DATA)
		return false;

	// compare the ICMP ID of the request to the ICMP ID we expect to see. If it's smaller than expected it means
	// catcher already saw this message so it can be ignored
	if (pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id) < icmpData->expectedIcmpId)
		return false;

	// if ICMP ID is bigger than expected it probably means catcher missed one or more packets. Since a reliability
	// mechanism isn't currently implemented in this program, the only thing left to do is to exit the program with an
	// error
	if (pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id) > icmpData->expectedIcmpId)
	{
		// close the file, remove it and exit the program with error
		icmpData->file->close();
		EXIT_WITH_ERROR_AND_RUN_COMMAND("Didn't get expected ICMP message #"
		                                    << icmpData->expectedIcmpId << ", got #"
		                                    << pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id),
		                                std::remove(icmpData->fileName.c_str()));
	}

	// increment expected ICMP ID
	icmpData->expectedIcmpId++;

	// write the data received from the pitcher to the local file
	icmpData->file->write((char*)icmpLayer->getEchoRequestData()->data, icmpLayer->getEchoRequestData()->dataLength);

	// add chunk size to the aggregated file size
	icmpData->fileSize += icmpLayer->getEchoRequestData()->dataLength;

	// print a dot (".") for every 1MB received
	icmpData->MBReceived += icmpLayer->getEchoRequestData()->dataLength;
	if (icmpData->MBReceived > ONE_MBYTE)
	{
		icmpData->MBReceived -= ONE_MBYTE;
		std::cout << ".";
	}

	// return and wait for the next data packet
	return false;
}

/**
 * Receive a file from the pitcher
 */
void receiveFile(pcpp::IPv4Address pitcherIP, pcpp::IPv4Address catcherIP)
{
	// identify the interface to listen and send packets to
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(catcherIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Cannot find network interface with IP '" << catcherIP << "'");

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface");

	// set an ICMP protocol filter so it'll capture only ICMP packets
	pcpp::ProtoFilter protocolFilter(pcpp::ICMP);
	if (!dev->setFilter(protocolFilter))
		EXIT_WITH_ERROR("Can't set ICMP filter on device");

	std::cout << "Waiting for pitcher to send a file..." << std::endl;

	IcmpFileTransferStart icmpFTStart = { pitcherIP, catcherIP, "", 0 };

	// wait until the pitcher sends an ICMP request with the file name in its data
	int res = dev->startCaptureBlockingMode(waitForFileTransferStart, &icmpFTStart, -1);
	if (!res)
		EXIT_WITH_ERROR("Cannot start capturing packets");

	// create a new file with the name provided by the pitcher
	std::ofstream file(icmpFTStart.fileName.c_str(), std::ios::out | std::ios::binary);

	if (file.is_open())
	{
		std::cout << "Getting file from pitcher: '" << icmpFTStart.fileName << "' ";

		IcmpFileContentDataRecv icmpFileContentData = {
			pitcherIP, catcherIP, &file, icmpFTStart.fileName, (uint16_t)(icmpFTStart.icmpId + 1), 0, 0
		};

		// get all file data from the pitcher. This method blocks until all file is received
		res = dev->startCaptureBlockingMode(getFileContent, &icmpFileContentData, -1);
		if (!res)
		{
			file.close();
			EXIT_WITH_ERROR_AND_RUN_COMMAND("Cannot start capturing packets",
			                                std::remove(icmpFTStart.fileName.c_str()));
		}

		std::cout << std::endl
		          << std::endl
		          << "Finished getting file '" << icmpFTStart.fileName << "' "
		          << "[received " << icmpFileContentData.fileSize << " bytes]" << std::endl;
	}
	else
		EXIT_WITH_ERROR("Cannot create file");

	// remove the filter and close the device (interface)
	dev->clearFilter();
	dev->close();
}

/**
 * A callback used in the sendFile() method and responsible to wait for the pitcher to send a keep-alive ICMP request.
 * When such message arrives this callback takes care of sending an ICMP response to the pitcher which is data contains
 * the file name to send
 */
static bool startFileTransfer(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return false;

	if (icmpVoidData == nullptr)
		return false;

	IcmpFileTransferStart* icmpFTStart = (IcmpFileTransferStart*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP request
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == nullptr)
		return false;

	// verify the source IP is the pitcher's IP and the dest IP is the catcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpFTStart->pitcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpFTStart->catcherIPAddr)
		return false;

	// check the ICMP timestamp field which contains the type of message delivered between pitcher and catcher
	// in this case the catcher is waiting for a keep-alive message from the pitcher which is of type
	// ICMP_FT_WAITING_FT_START
	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;
	if (resMsg != ICMP_FT_WAITING_FT_START)
		return false;

	// extract ethernet layer and ICMP ID to be able to respond to the pitcher
	pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	uint16_t icmpId = pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id);

	// send the ICMP response containing the file name back to the pitcher
	if (!sendIcmpResponse(dev, dev->getMacAddress(), ethLayer->getSourceMac(), icmpFTStart->catcherIPAddr,
	                      icmpFTStart->pitcherIPAddr, icmpId, ICMP_FT_START, (uint8_t*)icmpFTStart->fileName.c_str(),
	                      icmpFTStart->fileName.length() + 1))
		EXIT_WITH_ERROR("Cannot send file transfer start message to pitcher");

	return true;
}

/**
 * A callback used in the sendFile() method and responsible to wait for ICMP requests coming from the pitcher and send
 * file data chunks as a reply in the ICMP response data
 */
static bool sendContent(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* icmpVoidData)
{
	// first, parse the packet
	pcpp::Packet parsedPacket(rawPacket);

	// verify it's ICMP and IPv4 (IPv6 and ICMPv6 are not supported)
	if (!parsedPacket.isPacketOfType(pcpp::ICMP) || !parsedPacket.isPacketOfType(pcpp::IPv4))
		return false;

	if (icmpVoidData == nullptr)
		return false;

	IcmpFileContentDataSend* icmpFileContentData = (IcmpFileContentDataSend*)icmpVoidData;

	// extract the ICMP layer, verify it's an ICMP request
	pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer->getEchoRequestData() == nullptr)
		return false;

	// verify the source IP is the pitcher's IP and the dest IP is the catcher's IP
	pcpp::IPv4Layer* ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ip4Layer->getSrcIPv4Address() != icmpFileContentData->pitcherIPAddr ||
	    ip4Layer->getDstIPv4Address() != icmpFileContentData->catcherIPAddr)
		return false;

	// check the ICMP timestamp field which contains the type of message delivered between pitcher and catcher
	uint64_t resMsg = icmpLayer->getEchoRequestData()->header->timestamp;

	// if the pitcher sent an abort message, exit the program
	if (resMsg == ICMP_FT_ABORT)
		EXIT_WITH_ERROR("Got an abort message from pitcher. Exiting...");

	// if it's not an abort message, catcher is only waiting for data messages which are of type ICMP_FT_WAITING_DATA
	if (resMsg != ICMP_FT_WAITING_DATA)
		return false;

	// extract ethernet layer and ICMP ID to be able to respond to the pitcher
	pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	uint16_t icmpId = pcpp::netToHost16(icmpLayer->getEchoRequestData()->header->id);

	// if all file was already sent to the pitcher
	if (!icmpFileContentData->readingFromFile)
	{
		// send an ICMP response with ICMP_FT_END value in the timestamp field, indicating the pitcher all file was sent
		// to it
		if (!sendIcmpResponse(dev, dev->getMacAddress(), ethLayer->getSourceMac(), icmpFileContentData->catcherIPAddr,
		                      icmpFileContentData->pitcherIPAddr, icmpId, ICMP_FT_END, nullptr, 0))
			EXIT_WITH_ERROR("Cannot send file transfer end message to pitcher");

		// then return true so the sendFile() will stop blocking
		return true;
	}

	// try to read another block of data from the file
	if (icmpFileContentData->file->read(icmpFileContentData->memblock, icmpFileContentData->blockSize))
	{
		// if managed to read a full block, send it via the ICMP response to the pitcher. The data chunk will be sent in
		// the response data
		if (!sendIcmpResponse(dev, dev->getMacAddress(), ethLayer->getSourceMac(), icmpFileContentData->catcherIPAddr,
		                      icmpFileContentData->pitcherIPAddr, icmpId, ICMP_FT_DATA,
		                      (uint8_t*)icmpFileContentData->memblock, icmpFileContentData->blockSize))
			EXIT_WITH_ERROR("Cannot send file transfer data message to pitcher");

		// print a dot ('.') on every 1MB sent
		icmpFileContentData->MBSent += icmpFileContentData->blockSize;
		if (icmpFileContentData->MBSent > ONE_MBYTE)
		{
			icmpFileContentData->MBSent -= ONE_MBYTE;
			std::cout << ".";
		}
	}
	// if read only partial block, it means it's the last block
	else if (icmpFileContentData->file->gcount() > 0)
	{
		// send the remaining bytes of data to the pitcher via the ICMP response. The data chunk will be sent in the
		// response data
		if (!sendIcmpResponse(dev, dev->getMacAddress(), ethLayer->getSourceMac(), icmpFileContentData->catcherIPAddr,
		                      icmpFileContentData->pitcherIPAddr, icmpId, ICMP_FT_DATA,
		                      (uint8_t*)icmpFileContentData->memblock, icmpFileContentData->file->gcount()))
			EXIT_WITH_ERROR("Cannot send file transfer last data message to pitcher");

		// set an indication that all file was delivered to the pitcher
		icmpFileContentData->readingFromFile = false;

		std::cout << ".";
	}
	// if couldn't read anything, it means the previous block was the last block of the file
	else
	{
		// nothing to send to the pitcher

		// set an indication that all file was delivered to the pitcher
		icmpFileContentData->readingFromFile = false;
	}

	return false;
}

/**
 * Send a file to the pitcher
 */
void sendFile(const std::string& filePath, pcpp::IPv4Address pitcherIP, pcpp::IPv4Address catcherIP, size_t blockSize)
{
	// identify the interface to listen and send packets to
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(catcherIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Cannot find network interface with IP '" << catcherIP << "'");

	// try to open the interface (device)
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open network interface");

	// set an ICMP protocol filter so it'll capture only ICMP packets
	pcpp::ProtoFilter protocolFilter(pcpp::ICMP);
	if (!dev->setFilter(protocolFilter))
		EXIT_WITH_ERROR("Can't set ICMP filter on device");

	// try the open the file for reading
	std::ifstream file(filePath.c_str(), std::ios::in | std::ios::binary);

	if (file.is_open())
	{
		// extract file size
		file.seekg(0, std::ios_base::end);
		uint32_t fileSize = file.tellg();

		// go back to the beginning of the file
		file.seekg(0, std::ios::beg);

		// remove the path and keep just the file name. This is the name that will be delivered to the pitcher
		std::string fileName = getFileNameFromPath(filePath);

		std::cout << "Waiting for pitcher to send a keep-alive signal..." << std::endl;

		IcmpFileTransferStart icmpFTStart = { pitcherIP, catcherIP, fileName, 0 };

		// first, establish a connection with the pitcher and send it the file name. This method waits for the pitcher
		// to send an ICMP request which indicates it's alive. The response to the request will contain the file name in
		// the ICMP response data
		int res = dev->startCaptureBlockingMode(startFileTransfer, &icmpFTStart, -1);
		// if an error occurred
		if (!res)
			EXIT_WITH_ERROR("Cannot start capturing packets");

		std::cout << "Sending file '" << fileName << "' ";

		IcmpFileContentDataSend icmpFileContentData = { pitcherIP, catcherIP, &file, true, 0, blockSize, nullptr };

		// create the memory block that will contain the file data chunks that will be transferred to the pitcher
		icmpFileContentData.memblock = new char[blockSize];

		// wait for ICMP requests coming from the pitcher and send file data chunks as a reply in the ICMP response data
		// this method returns when all file was transferred to the pitcher
		res = dev->startCaptureBlockingMode(sendContent, &icmpFileContentData, -1);

		// free the memory block data and close the file
		delete[] icmpFileContentData.memblock;
		file.close();

		// if capture failed, exit the program
		if (!res)
			EXIT_WITH_ERROR("Cannot start capturing packets");

		std::cout << std::endl
		          << std::endl
		          << "Finished sending '" << fileName << "' "
		          << "[sent " << fileSize << " bytes]" << std::endl;
	}
	else  // if file couldn't be opened
		EXIT_WITH_ERROR("Cannot open file '" << filePath << "'");

	// close the device
	dev->close();
}

/**
 * main method of this ICMP catcher
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
	readCommandLineArguments(argc, argv, "catcher", "pitcher", sender, receiver, catcherIP, pitcherIP, fileNameToSend,
	                         packetsPerSec, blockSize);

	// send a file to the pitcher
	if (sender)
		sendFile(fileNameToSend, pitcherIP, catcherIP, blockSize);
	// receive a file from the pitcher
	else if (receiver)
		receiveFile(pitcherIP, catcherIP);
}
