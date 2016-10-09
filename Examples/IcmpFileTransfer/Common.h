#ifndef COMMON_H_
#define COMMON_H_

#include "MacAddress.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"


#define ICMP_FT_WAITING_FT_START 0x345a56c8e7f3cd67
#define ICMP_FT_START 0xd45ae6c2e7a3cd67
#define ICMP_FT_WAITING_DATA 0x6d5f86c817fb5d7e
#define ICMP_FT_DATA 0x3d5a76c827f35d77
#define ICMP_FT_ACK 0x395156c857fbcc6a
#define ICMP_FT_END 0x144156cbeffa2687

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)



/**
 * Go over all interfaces and output their names
 */
void listInterfaces();

void readCommandLineArguments(int argc, char* argv[],
		std::string thisSide, std::string otherSide,
		bool& sender,  bool& receiver,
		pcpp::IPv4Address& myIP, pcpp::IPv4Address& otherSideIP,
		std::string& fileNameToSend,
		int& packetPerSec, size_t& blockSize);

bool sendIcmpRequest(pcpp::PcapLiveDevice* dev,
		pcpp::MacAddress srcMacAddr, pcpp::MacAddress dstMacAddr,
		pcpp::IPv4Address srcIPAddr, pcpp::IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen);

bool sendIcmpResponse(pcpp::PcapLiveDevice* dev,
		pcpp::MacAddress srcMacAddr, pcpp::MacAddress dstMacAddr,
		pcpp::IPv4Address srcIPAddr, pcpp::IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen);

/**
 * An auxiliary method for extracting the file name from file path,
 * for example: for the input '/home/myuser/mypcap.pcap' -> return value will be 'mypcap.pcap'
 */
std::string getFileNameFromPath(const std::string& filePath);

#endif /* COMMON_H_ */
