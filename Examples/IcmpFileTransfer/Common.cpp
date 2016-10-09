#include "Common.h"
#include <stdlib.h>
#include <vector>
#include <getopt.h>
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "PcapLiveDeviceList.h"

using namespace pcpp;


#ifdef WIN32
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif

#define DEFAULT_BLOCK_SIZE 1400

static struct option IcmpFTOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"dest-ip",  required_argument, 0, 'd'},
	{"send-file",  required_argument, 0, 's'},
	{"receive-file", no_argument, 0, 'r'},
	{"speed", required_argument, 0, 'p'},
	{"block-size", required_argument, 0, 'b'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};


#define EXIT_WITH_ERROR_PRINT_USAGE(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(thisSide, otherSide); \
	exit(1); \
	} while(0)


void printUsage(std::string thisSide, std::string otherSide)
{
	std::string messagesPerSecShort = (thisSide == "pitcher") ? "[-p messages_per_sec] " : "";
	std::string messagesPerSecLong = (thisSide == "pitcher") ? "    -p messages_per_sec  : Set number of messages to be sent per seconds. Default is max possible speed\n" : "";

	printf("\nUsage:\n"
			"-------\n"
			"IcmpFileTransfer-%s [-h] [-l] -i %s_interface -d %s_ip -s file_path -r %s[-b block_size]\n"
			"\nOptions:\n\n"
			"    -i %s_interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
			"    -d %s_ip        : %s IPv4 address\n"
			"    -s file_path         : Send file mode: send file_path to %s\n"
			"    -r                   : Receive file mode: receive file from %s\n"
			"%s"
			"    -b block_size        : Set the size of data chunk sent in each ICMP message (in bytes). Default is %d bytes. Relevant only\n"
			"                           in send file mode (when -s is set)\n"
			"    -l                   : Print the list of interfaces and exit\n"
			"    -h                   : Display this help message and exit\n",
			thisSide.c_str(), thisSide.c_str(), otherSide.c_str(), messagesPerSecShort.c_str(), thisSide.c_str(), otherSide.c_str(), otherSide.c_str(), otherSide.c_str(), otherSide.c_str(),
			messagesPerSecLong.c_str(), DEFAULT_BLOCK_SIZE);
	exit(0);
}

void listInterfaces()
{
	const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}

void readCommandLineArguments(int argc, char* argv[],
		std::string thisSide, std::string otherSide,
		bool& sender, bool& receiver,
		pcpp::IPv4Address& myIP, pcpp::IPv4Address& otherSideIP,
		std::string& fileNameToSend,
		int& packetsPerSec, size_t& blockSize)
{
	std::string interfaceNameOrIP = "";
	std::string otherSideIPAsString = "";
	fileNameToSend = "";
	packetsPerSec = -1;
	receiver = false;
	sender = false;
	blockSize = DEFAULT_BLOCK_SIZE;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long(argc, argv, "i:d:s:rp:b:hl", IcmpFTOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'd':
				otherSideIPAsString = optarg;
				break;
			case 's':
				fileNameToSend = optarg;
				sender = true;
				receiver = false;
				break;
			case 'r':
				sender = false;
				receiver = true;
				break;
			case 'p':
				if (thisSide == "catcher")
					EXIT_WITH_ERROR_PRINT_USAGE("Unknown option -p");
				packetsPerSec = atoi(optarg);
				break;
			case 'b':
				blockSize = atoi(optarg);
				break;
			case 'h':
				printUsage(thisSide, otherSide);
				break;
			case 'l':
				listInterfaces();
				break;
			default:
				printUsage(thisSide, otherSide);
				exit(-1);
		}
	}

	// extract my IP address by interface name or IP address string
	if (interfaceNameOrIP == "")
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide %s interface name or IP", thisSide.c_str());

	IPv4Address interfaceIP(interfaceNameOrIP);
	if (!interfaceIP.isValid())
	{
		PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
		if (dev == NULL)
			EXIT_WITH_ERROR_PRINT_USAGE("Couldn't find interface by provided name");

		myIP = dev->getIPv4Address();
	}
	else
		myIP = interfaceIP;

	// validate pitcher/catcher IP address
	if (otherSideIPAsString == "")
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide %s IP address", otherSide.c_str());

	IPv4Address tempIP = IPv4Address(otherSideIPAsString);
	if (!tempIP.isValid())
		EXIT_WITH_ERROR_PRINT_USAGE("Invalid %s IP address", otherSide.c_str());
	otherSideIP = tempIP;

	// verify only one of sender and receiver switches are set
	if (sender && receiver)
		EXIT_WITH_ERROR_PRINT_USAGE("Cannot set both send file mode (-s) and receive file mode (-r) switches");

	if (!sender && !receiver)
		EXIT_WITH_ERROR_PRINT_USAGE("Must set either send file mode (-s) or receive file mode (-r) switches");

	// validate block size
	if (blockSize < 1 || blockSize > 1464)
		EXIT_WITH_ERROR_PRINT_USAGE("Block size must be a positive integer lower or equal to 1464 bytes (which is the maximum size for a standard packet)");
}

bool sendIcmpMessage(PcapLiveDevice* dev,
		MacAddress srcMacAddr, MacAddress dstMacAddr,
		IPv4Address srcIPAddr, IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen,
		bool sendRequest)
{
	EthLayer ethLayer(srcMacAddr, dstMacAddr, PCPP_ETHERTYPE_IP);
	IPv4Layer ipLayer(srcIPAddr, dstIPAddr);
	ipLayer.getIPv4Header()->timeToLive = 128;
	IcmpLayer icmpLayer;
	if (sendRequest && icmpLayer.setEchoRequestData(icmpMsgId, 0, msgType, data, dataLen) == NULL)
		EXIT_WITH_ERROR("Cannot set ICMP echo request data");
	else if (!sendRequest && icmpLayer.setEchoReplyData(icmpMsgId, 0, msgType, data, dataLen) == NULL)
		EXIT_WITH_ERROR("Cannot set ICMP echo response data");
	Packet packet;
	packet.addLayer(&ethLayer);
	packet.addLayer(&ipLayer);
	packet.addLayer(&icmpLayer);
	packet.computeCalculateFields();
	return dev->sendPacket(&packet);
}

bool sendIcmpRequest(PcapLiveDevice* dev,
		MacAddress srcMacAddr, const MacAddress dstMacAddr,
		IPv4Address srcIPAddr, const IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen)
{
	return sendIcmpMessage(dev, srcMacAddr, dstMacAddr, srcIPAddr, dstIPAddr, icmpMsgId, msgType, data, dataLen, true);
}

bool sendIcmpResponse(PcapLiveDevice* dev,
		MacAddress srcMacAddr, MacAddress dstMacAddr,
		IPv4Address srcIPAddr, IPv4Address dstIPAddr,
		size_t icmpMsgId,
		uint64_t msgType,
		uint8_t* data, size_t dataLen)
{
	return sendIcmpMessage(dev, srcMacAddr, dstMacAddr, srcIPAddr, dstIPAddr, icmpMsgId, msgType, data, dataLen, false);
}

std::string getFileNameFromPath(const std::string& filePath)
{
	// find the last "\\" or "/" (depends on the os) - where path ends and filename starts
	size_t i = filePath.rfind(SEPARATOR, filePath.length());
	if (i != std::string::npos)
	{
		// extract filename from path
		return filePath.substr(i+1, filePath.length() - i);
	}

	return filePath;
}
