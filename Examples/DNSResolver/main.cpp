#include <stdlib.h>
#include "PcapPlusPlusVersion.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include <getopt.h>
#include "SystemUtils.h"

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)

using namespace pcpp;

static struct option DNSResolverOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"hostname", required_argument, 0, 's'},
	{"dns-server", required_argument, 0, 'd'},
	{"gateway", required_argument, 0, 'g'},
	{"timeout", optional_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{"list", no_argument, 0, 'l'},
    {0, 0, 0, 0}
};


/**
 * Print application usage
 */
void printUsage() {
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvl] [-t timeout] [-d dns_server] [-g gateway] [-i interface] -s hostname\n"
			"\nOptions:\n\n"
			"    -h           : Displays this help message and exits\n"
			"    -v           : Displays the current version and exists\n"
			"    -l           : Print the list of interfaces and exists\n"
			"    -s hostname  : Hostname to resolve\n"
			"    -i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. If not set\n"
			"                   one of the interfaces that has a default gateway will be used\n"
			"    -d dns_server: IPv4 address of DNS server to send the DNS request to. If not set the DNS request will be sent to the gateway\n"
			"    -g gateway   : IPv4 address of the gateway to send the DNS request to. If not set the default gateway will be chosen\n"
			"    -t timeout   : How long to wait for a reply (in seconds). Default timeout is 5 seconds\n", AppName::get().c_str());

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
		std::string defaultGateway = ((*iter)->getDefaultGateway() != IPv4Address::Zero ? (*iter)->getDefaultGateway().toString() : "None");

		printf("    -> Name: '%s'   IP address: %s   Default gateway: %s\n",
				(*iter)->getName(),
				(*iter)->getIPv4Address().toString().c_str(),
				defaultGateway.c_str());
	}
	exit(0);
}


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string hostname;
	bool hostnameProvided = false;
	std::string interfaceNameOrIP;
	bool interfaceNameOrIPProvided = false;
	IPv4Address dnsServerIP = IPv4Address::Zero;
	IPv4Address gatewayIP = IPv4Address::Zero;
	int timeoutSec = -1;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:d:g:s:t:hvl", DNSResolverOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
			{
				break;
			}
			case 'h':
			{
				printUsage();
				exit(0);
			}
			case 'v':
			{
				printAppVersion();
				break;
			}
			case 'l':
			{
				listInterfaces();
				exit(0);
			}
			case 'i':
			{
				interfaceNameOrIP = optarg;
				interfaceNameOrIPProvided = true;
				break;
			}
			case 'd':
			{
				dnsServerIP = IPv4Address(optarg);
				break;
			}
			case 'g':
			{
				gatewayIP = IPv4Address(optarg);
				break;
			}
			case 's':
			{
				hostname = optarg;
				hostnameProvided = true;
				break;
			}
			case 't':
			{
				timeoutSec = atoi(optarg);
				break;
			}
			default:
			{
				printUsage();
				exit(1);
			}
		}
	}

	// make sure that hostname is provided
	if (!hostnameProvided)
		EXIT_WITH_ERROR("Hostname not provided");

	// find the interface to send the DNS request from
	PcapLiveDevice* dev = NULL;

	// if interface name or IP was provided - find the device accordingly
	if (interfaceNameOrIPProvided)
	{
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}
	}
	// if interface name or IP was not provided - find a device that has a default gateway
	else
	{
		const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

		for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
		{
			if ((*iter)->getDefaultGateway() != IPv4Address::Zero)
			{
				dev = *iter;
				break;
			}
		}

		if (dev == NULL)
			EXIT_WITH_ERROR("Couldn't find an interface with a default gateway");
	}

	printf("Using interface '%s'\n", dev->getIPv4Address().toString().c_str());

	// find the IPv4 address for provided hostname
	double responseTime = 0;
	uint32_t dnsTTL = 0;
	IPv4Address resultIP = NetworkUtils::getInstance().getIPv4Address(hostname, dev, responseTime, dnsTTL, timeoutSec, dnsServerIP, gatewayIP);

	// print resolved IPv4 address if found
	if (resultIP == IPv4Address::Zero)
		printf("\nCould not resolve hostname [%s]\n", hostname.c_str());
	else
		printf("\nIP address of [%s] is: %s  DNS-TTL=%d  time=%dms\n", hostname.c_str(), resultIP.toString().c_str(), dnsTTL, (int)responseTime);

}
