#include "Common.h"
#include <iostream>
#include <vector>
#include <getopt.h>
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"

#if defined(_WIN32)
#	define SEPARATOR '\\'
#else
#	define SEPARATOR '/'
#endif

#define DEFAULT_BLOCK_SIZE 1400

static struct option IcmpFTOptions[] = {
	{ "interface",       required_argument, nullptr, 'i'         },
	{ "dest-ip",         required_argument, nullptr, 'd'         },
	{ "send-file",       required_argument, nullptr, 's'         },
	{ "receive-file",    no_argument,       nullptr, 'r'         },
	{ "speed",           required_argument, nullptr, 'p'         },
	{ "block-size",      required_argument, nullptr, 'b'         },
	{ "list-interfaces", no_argument,       nullptr, 'l'         },
	{ "version",         no_argument,       nullptr, 'v'         },
	{ "help",            no_argument,       nullptr, 'h'         },
	{ nullptr,           no_argument,       nullptr, no_argument }
};

#define EXIT_WITH_ERROR_PRINT_USAGE(reason)                                                                            \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage(thisSide, otherSide);                                                                               \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

void printUsage(const std::string& thisSide, const std::string& otherSide)
{
	std::string messagesPerSecShort = (thisSide == "pitcher") ? "[-p messages_per_sec] " : "";
	std::string messagesPerSecLong = (thisSide == "pitcher") ? "    -p messages_per_sec  : Set number of messages to "
	                                                           "be sent per seconds. Default is max possible speed\n"
	                                                         : "";

	std::string thisSideInterface = thisSide + "_interface";
	std::string otherSideIP = otherSide + "_ip";

	std::cout
	    << std::endl
	    << "Usage:" << std::endl
	    << "------" << std::endl
	    << pcpp::AppName::get() << " [-h] [-v] [-l] -i " << thisSideInterface << " -d " << otherSideIP
	    << " -s file_path -r " << messagesPerSecShort << "[-b block_size]" << std::endl
	    << std::endl
	    << "Options:" << std::endl
	    << std::endl
	    << "    -i " << thisSideInterface
	    << " : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address" << std::endl
	    << "    -d " << otherSideIP << "        : " << otherSide << " IPv4 address" << std::endl
	    << "    -s file_path         : Send file mode: send file_path to " << otherSide << std::endl
	    << "    -r                   : Receive file mode: receive file from " << otherSide << std::endl
	    << messagesPerSecLong
	    << "    -b block_size        : Set the size of data chunk sent in each ICMP message (in bytes). Default is "
	    << DEFAULT_BLOCK_SIZE << " bytes. Relevant only" << std::endl
	    << "                           in send file mode (when -s is set)" << std::endl
	    << "    -l                   : Print the list of interfaces and exit" << std::endl
	    << "    -v                   : Displays the current version and exists" << std::endl
	    << "    -h                   : Display this help message and exit" << std::endl
	    << std::endl;
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<pcpp::PcapLiveDevice*>& devList =
	    pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (const auto& dev : devList)
	{
		std::cout << "    -> Name: '" << dev->getName() << "'   IP address: " << dev->getIPv4Address().toString()
		          << std::endl;
	}
	exit(0);
}

void readCommandLineArguments(int argc, char* argv[], const std::string& thisSide, const std::string& otherSide,
                              bool& sender, bool& receiver, pcpp::IPv4Address& myIP, pcpp::IPv4Address& otherSideIP,
                              std::string& fileNameToSend, int& packetsPerSec, size_t& blockSize)
{
	std::string interfaceNameOrIP;
	std::string otherSideIPAsString;
	fileNameToSend.clear();
	packetsPerSec = -1;
	bool packetsPerSecSet = false;
	receiver = false;
	sender = false;
	blockSize = DEFAULT_BLOCK_SIZE;
	bool blockSizeSet = false;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:d:s:rp:b:hvl", IcmpFTOptions, &optionIndex)) != -1)
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
			break;
		case 'r':
			receiver = true;
			break;
		case 'p':
			if (thisSide == "catcher")
				EXIT_WITH_ERROR_PRINT_USAGE("Unknown option -p");
			packetsPerSec = atoi(optarg);
			packetsPerSecSet = true;
			break;
		case 'b':
			blockSize = atoi(optarg);
			blockSizeSet = true;
			break;
		case 'h':
			printUsage(thisSide, otherSide);
			exit(0);
			break;
		case 'v':
			printAppVersion();
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
	if (interfaceNameOrIP.empty())
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide " << thisSide << " interface name or IP");

	pcpp::IPv4Address interfaceIP;
	try
	{
		interfaceIP = pcpp::IPv4Address(interfaceNameOrIP);
		myIP = interfaceIP;
	}
	catch (const std::exception&)
	{
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR_PRINT_USAGE("Cannot find interface by provided name");

		myIP = dev->getIPv4Address();
	}

	// validate pitcher/catcher IP address
	if (otherSideIPAsString.empty())
		EXIT_WITH_ERROR_PRINT_USAGE("Please provide " << otherSide << " IP address");

	pcpp::IPv4Address tempIP;
	try
	{
		tempIP = pcpp::IPv4Address(otherSideIPAsString);
	}
	catch (const std::exception&)
	{
		EXIT_WITH_ERROR_PRINT_USAGE("Invalid " << otherSide << " IP address");
	}
	otherSideIP = tempIP;

	// verify only one of sender and receiver switches are set
	if (sender && receiver)
		EXIT_WITH_ERROR_PRINT_USAGE("Cannot set both send file mode (-s) and receive file mode (-r) switches");

	if (!sender && !receiver)
		EXIT_WITH_ERROR_PRINT_USAGE("Must set either send file mode (-s) or receive file mode (-r) switches");

	// cannot set block size if in receiving file mode
	if (!sender && blockSizeSet)
		EXIT_WITH_ERROR_PRINT_USAGE("Setting block size (-b switch) is relevant for sending files only");

	// validate block size
	if (blockSize < 1 || blockSize > 1464)
		EXIT_WITH_ERROR_PRINT_USAGE("Block size must be a positive integer lower or equal to 1464 bytes (which is the "
		                            "maximum size for a standard packet)");

	// validate packets per sec
	if (packetsPerSecSet && packetsPerSec < 1)
		EXIT_WITH_ERROR_PRINT_USAGE("message_per_sec must be a positive value greater or equal to 1");
}

bool sendIcmpMessage(pcpp::PcapLiveDevice* dev, pcpp::MacAddress srcMacAddr, pcpp::MacAddress dstMacAddr,
                     pcpp::IPv4Address srcIPAddr, pcpp::IPv4Address dstIPAddr, size_t icmpMsgId, uint64_t msgType,
                     uint8_t* data, size_t dataLen, bool sendRequest)
{
	// a static variable that holds an incrementing IP ID
	static uint16_t ipID = 0x1234;

	// keep IP ID in the range of 0x1234-0xfff0
	if (ipID == 0xfff0)
		ipID = 0x1234;

	// create the different layers

	// Eth first
	pcpp::EthLayer ethLayer(srcMacAddr, dstMacAddr, PCPP_ETHERTYPE_IP);

	// then IPv4 (IPv6 is not supported)
	pcpp::IPv4Layer ipLayer(srcIPAddr, dstIPAddr);
	ipLayer.getIPv4Header()->timeToLive = 128;
	// set and increment the IP ID
	ipLayer.getIPv4Header()->ipId = pcpp::hostToNet16(ipID++);

	// then ICMP
	pcpp::IcmpLayer icmpLayer;
	if (sendRequest && icmpLayer.setEchoRequestData(icmpMsgId, 0, msgType, data, dataLen) == nullptr)
		EXIT_WITH_ERROR("Cannot set ICMP echo request data");
	else if (!sendRequest && icmpLayer.setEchoReplyData(icmpMsgId, 0, msgType, data, dataLen) == nullptr)
		EXIT_WITH_ERROR("Cannot set ICMP echo response data");

	// create an new packet and add all layers to it
	pcpp::Packet packet;
	packet.addLayer(&ethLayer);
	packet.addLayer(&ipLayer);
	packet.addLayer(&icmpLayer);
	packet.computeCalculateFields();

	// send the packet through the device
	return dev->sendPacket(&packet);
}

bool sendIcmpRequest(pcpp::PcapLiveDevice* dev, pcpp::MacAddress srcMacAddr, const pcpp::MacAddress dstMacAddr,
                     pcpp::IPv4Address srcIPAddr, const pcpp::IPv4Address dstIPAddr, size_t icmpMsgId, uint64_t msgType,
                     uint8_t* data, size_t dataLen)
{
	return sendIcmpMessage(dev, srcMacAddr, dstMacAddr, srcIPAddr, dstIPAddr, icmpMsgId, msgType, data, dataLen, true);
}

bool sendIcmpResponse(pcpp::PcapLiveDevice* dev, pcpp::MacAddress srcMacAddr, pcpp::MacAddress dstMacAddr,
                      pcpp::IPv4Address srcIPAddr, pcpp::IPv4Address dstIPAddr, size_t icmpMsgId, uint64_t msgType,
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
		return filePath.substr(i + 1, filePath.length() - i);
	}

	return filePath;
}
