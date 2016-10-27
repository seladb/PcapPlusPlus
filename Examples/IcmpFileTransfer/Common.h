#ifndef COMMON_H_
#define COMMON_H_

#include "MacAddress.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"


#define ICMP_FT_WAITING_FT_START 0x345a56c8e7f3cd67ULL
#define ICMP_FT_START 0xd45ae6c2e7a3cd67ULL
#define ICMP_FT_WAITING_DATA 0x6d5f86c817fb5d7eULL
#define ICMP_FT_DATA 0x3d5a76c827f35d77ULL
#define ICMP_FT_ACK 0x395156c857fbcc6aULL
#define ICMP_FT_END 0x144156cbeffa2687ULL
#define ICMP_FT_ABORT 0x146158cbafff2b8aULL

#define ONE_MBYTE 1048576

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)

#define EXIT_WITH_ERROR_AND_RUN_COMMAND(reason, command, ...) do { \
	command; \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)


/**
 * Go over all interfaces and output their names
 */
void listInterfaces();

/**
 * Read and parse the command line arguments from the user. If arguments are wrong or parsing fails the method causes the program to exit
 */
void readCommandLineArguments(int argc, char* argv[],
		std::string thisSide, std::string otherSide,
		bool& sender,  bool& receiver,
		pcpp::IPv4Address& myIP, pcpp::IPv4Address& otherSideIP,
		std::string& fileNameToSend,
		int& packetPerSec, size_t& blockSize);

/**
 * Send an ICMP request from source to dest with certain ICMP ID, msgType will be written in the timestamp field of the request, and data
 * will be written in the data section of the request
 */
bool sendIcmpRequest(pcpp::PcapLiveDevice* dev,
		pcpp::MacAddress srcMacAddr, pcpp::MacAddress dstMacAddr,
		pcpp::IPv4Address srcIPAddr, pcpp::IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen);

/**
 * Send an ICMP reply from source to dest with certain ICMP ID, msgType will be written in the timestamp field of the request, and data
 * will be written in the data section of the request
 */
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
