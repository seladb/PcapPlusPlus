/**
 * Arping example application
 * ================================
 * This application resolves a target MAC address by its IPv4 address by sending an ARP request and translating the ARP response.
 * Its basic input is the target IP address and the interface name/IP to send the ARP request from
 */

#include <stdlib.h>
#include <MacAddress.h>
#include <IpAddress.h>
#include <Logger.h>
#include <PcapPlusPlusVersion.h>
#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <NetworkUtils.h>
#include <getopt.h>
#include <SystemUtils.h>


#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while (0)

#define DEFAULT_MAX_TRIES	1000000

using namespace pcpp;

static struct option ArpingOptions[] =
{
	{"interface",  optional_argument, 0, 'i'},
	{"source-mac",  optional_argument, 0, 's'},
	{"source-ip", optional_argument, 0, 'S'},
	{"target-ip", required_argument, 0, 'T'},
	{"count", optional_argument, 0, 'c'},
	{"help", optional_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{"list", optional_argument, 0, 'l'},
	{"timeout", optional_argument, 0, 'w'},
    {0, 0, 0, 0}
};


/**
 * Print application usage
 */
void printUsage() {
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvl] [-c count] [-w timeout] [-i interface] [-s mac_sddr] [-S ip_addr] -T ip_addr\n"
			"\nOptions:\n\n"
			"    -h           : Displays this help message and exits\n"
			"    -v           : Displays the current version and exists\n"
			"    -l           : Print the list of interfaces and exists\n"
			"    -c count     : Send 'count' requests\n"
			"    -i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
			"    -s mac_addr  : Set source MAC address\n"
			"    -S ip_addr   : Set source IP address\n"
			"    -T ip_addr   : Set target IP address\n"
			"    -w timeout   : How long to wait for a reply (in seconds)\n", AppName::get().c_str());

	exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}


/**
 * Go over all interfaces and output their names
 */
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


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	int maxTries = DEFAULT_MAX_TRIES;
	MacAddress sourceMac = MacAddress::Zero;
	IPv4Address sourceIP = IPv4Address::Zero;
	IPv4Address targetIP = IPv4Address::Zero;
	bool targetIpProvided = false;
	std::string ifaceNameOrIP = "";
	bool ifaceNameOrIpProvided = false;
	int timeoutSec = NetworkUtils::DefaultTimeout;
	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:s:S:T:c:hvlw:", ArpingOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				ifaceNameOrIP = optarg;
				ifaceNameOrIpProvided = true;
				break;
			case 's':
				sourceMac = MacAddress(optarg);
				break;
			case 'S':
				sourceIP = IPv4Address(optarg);
				break;
			case 'T':
				targetIP = IPv4Address(optarg);
				targetIpProvided = true;
				break;
			case 'c':
				maxTries = atoi(optarg);;
				break;
			case 'h':
				printUsage();
				break;
			case 'v':
				printAppVersion();
				break;
			case 'l':
				listInterfaces();
				break;
			case 'w':
				timeoutSec = atoi(optarg);
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	// verify that interface name or IP were provided
	if (!ifaceNameOrIpProvided)
		EXIT_WITH_ERROR_AND_PRINT_USAGE("You must provide at least interface name or interface IP (-i switch)");

	// verify target IP was provided
	if (!targetIpProvided)
		EXIT_WITH_ERROR_AND_PRINT_USAGE("You must provide target IP (-T switch)");

	// verify target IP is value
	if (!targetIP.isValid())
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Target IP is not valid");


	PcapLiveDevice* dev = NULL;

	// Search interface by name or IP
	if (ifaceNameOrIP != "")
	{
		IPv4Address interfaceIP(ifaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ifaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR_AND_PRINT_USAGE("Couldn't find interface by provided name");
		}
	}
	else
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Interface name or IP empty");

	// open device in promiscuous mode
	if (!dev->open())
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Couldn't open interface device '%s'", dev->getName());

	// verify source MAC is valud
	if (!sourceMac.isValid())
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Source MAC address is invalid");

	// if source MAC not provided - use the interface MAC address
	if (sourceMac == MacAddress::Zero)
		sourceMac = dev->getMacAddress();

	// if source MAC is still invalid, it means it couldn't be extracted from interface
	if (!sourceMac.isValid() || sourceMac == MacAddress::Zero)
		EXIT_WITH_ERROR_AND_PRINT_USAGE("MAC address couldn't be extracted from interface");

	if (!sourceIP.isValid() || sourceIP == IPv4Address::Zero)
		sourceIP = dev->getIPv4Address();

	if (!sourceIP.isValid() || sourceIP == IPv4Address::Zero)
		EXIT_WITH_ERROR_AND_PRINT_USAGE("Source IPv4 address wasn't supplied and couldn't be retrieved from interface");

	// let's go
	double arpResonseTimeMS = 0;
	int i = 1;
	char errString[1000];
	LoggerPP::getInstance().setErrorString(errString, 1000);
	while (i <= maxTries)
	{
		// use the getMacAddress utility to send an ARP request and resolve the MAC address
		MacAddress result = NetworkUtils::getInstance().getMacAddress(targetIP, dev, arpResonseTimeMS, sourceMac, sourceIP, timeoutSec);

		// failed fetching MAC address
		if (result == MacAddress::Zero)
		{
			printf("Arping  index=%d : %s", i, errString);
		}
		else // Succeeded fetching MAC address
		{
			// output ARP ping data
			printf("Reply from %s [%s]  %.3fms  index=%d\n",
					targetIP.toString().c_str(),
					result.toString().c_str(),
					arpResonseTimeMS,
					i);
		}

		i++;
	}

	dev->close();
}
