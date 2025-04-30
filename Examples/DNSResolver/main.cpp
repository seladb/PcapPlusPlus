#include <iostream>
#include "PcapPlusPlusVersion.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "NetworkUtils.h"
#include "SystemUtils.h"
#include "Logger.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

static struct option DNSResolverOptions[] = {
	{ "interface",  required_argument, nullptr, 'i' },
	{ "hostname",   required_argument, nullptr, 's' },
	{ "dns-server", required_argument, nullptr, 'd' },
	{ "gateway",    required_argument, nullptr, 'g' },
	{ "timeout",    optional_argument, nullptr, 't' },
	{ "help",       no_argument,       nullptr, 'h' },
	{ "version",    no_argument,       nullptr, 'v' },
	{ "list",       no_argument,       nullptr, 'l' },
	{ nullptr,      0,                 nullptr, 0   }
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get() << " [-hvl] [-t timeout] [-d dns_server] [-g gateway] [-i interface] -s hostname"
	          << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -h           : Displays this help message and exits" << std::endl
	          << "    -v           : Displays the current version and exists" << std::endl
	          << "    -l           : Print the list of interfaces and exists" << std::endl
	          << "    -s hostname  : Hostname to resolve" << std::endl
	          << "    -i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 "
	             "address. If not set"
	          << std::endl
	          << "                   one of the interfaces that has a default gateway will be used" << std::endl
	          << "    -d dns_server: IPv4 address of DNS server to send the DNS request to. If not set the DNS request "
	             "will be sent to the gateway"
	          << std::endl
	          << "    -g gateway   : IPv4 address of the gateway to send the DNS request to. If not set the default "
	             "gateway will be chosen"
	          << std::endl
	          << "    -t timeout   : How long to wait for a reply (in seconds). Default timeout is 5 seconds"
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
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	auto device = (pcpp::PcapLiveDevice*)cookie;
	device->close();
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string hostname;
	bool hostnameProvided = false;
	std::string interfaceNameOrIP;
	bool interfaceNameOrIPProvided = false;
	pcpp::IPv4Address dnsServerIP;
	pcpp::IPv4Address gatewayIP;
	int timeoutSec = -1;

	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:d:g:s:t:hvl", DNSResolverOptions, &optionIndex)) != -1)
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
			dnsServerIP = pcpp::IPv4Address(static_cast<char const*>(optarg));
			break;
		}
		case 'g':
		{
			gatewayIP = pcpp::IPv4Address(static_cast<char const*>(optarg));
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
	pcpp::PcapLiveDevice* dev = nullptr;

	// if interface name or IP was provided - find the device accordingly
	if (interfaceNameOrIPProvided)
	{
		dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");
	}
	// if interface name or IP was not provided - find a device that has a default gateway
	else
	{
		const std::vector<pcpp::PcapLiveDevice*>& devList =
		    pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

		auto iter = std::find_if(devList.begin(), devList.end(), [](pcpp::PcapLiveDevice* dev) {
			return dev->getDefaultGateway() != pcpp::IPv4Address::Zero;
		});
		if (iter != devList.end())
		{
			dev = *iter;
		}

		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find an interface with a default gateway");
	}

	std::cout << "Using interface '" << dev->getIPv4Address() << "'" << std::endl;

	// suppressing errors to avoid cluttering stdout
	pcpp::Logger::getInstance().suppressLogs();

	// make sure the app closes the device upon termination
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, dev);

	try
	{
		// find the IPv4 address for provided hostname
		double responseTime = 0;
		uint32_t dnsTTL = 0;
		pcpp::IPv4Address resultIP = pcpp::NetworkUtils::getInstance().getIPv4Address(
		    hostname, dev, responseTime, dnsTTL, timeoutSec, dnsServerIP, gatewayIP);
		if (resultIP == pcpp::IPv4Address::Zero)
		{
			std::cout << std::endl << "Could not resolve hostname [" << hostname << "]" << std::endl;
		}
		else
		{
			std::cout << std::endl
			          << "IP address of [" << hostname << "] is: " << resultIP << "  DNS-TTL=" << dnsTTL
			          << "  time=" << (int)responseTime << "ms" << std::endl;
		}
	}
	catch (const std::exception&)
	{
		std::cout << std::endl << "Could not resolve hostname [" << hostname << "]" << std::endl;
	}
}
