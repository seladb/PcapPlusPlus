/**
 * Arping example application
 * ================================
 * This application resolves a target MAC address by its IPv4 address by sending an ARP request and translating the ARP
 * response. Its basic input is the target IP address and the interface name/IP to send the ARP request from
 */

#include <iostream>
#include <MacAddress.h>
#include <IpAddress.h>
#include <Logger.h>
#include <PcapPlusPlusVersion.h>
#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <NetworkUtils.h>
#include <getopt.h>
#include <SystemUtils.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << '\n' << "ERROR: " << reason << '\n' << '\n';                                                      \
		exit(1);                                                                                                       \
	} while (0)

enum
{
	DEFAULT_MAX_TRIES = 1000000
};

// clang-format off
static struct option ArpingOptions[] = {
	{ "interface",  optional_argument, nullptr, 'i' },
	{ "source-mac", optional_argument, nullptr, 's' },
	{ "source-ip",  optional_argument, nullptr, 'S' },
	{ "target-ip",  required_argument, nullptr, 'T' },
	{ "count",      optional_argument, nullptr, 'c' },
	{ "version",    no_argument,       nullptr, 'v' },
	{ "list",       optional_argument, nullptr, 'l' },
	{ "timeout",    optional_argument, nullptr, 'w' },
	{ "help",       optional_argument, nullptr, 'h' },
	{ nullptr,      0,                 nullptr, 0   }
};
// clang-format on

/**
 * Print application usage
 */
void printUsage()
{
	std::cout
	    << '\n'
	    << "Usage:" << '\n'
	    << "------" << '\n'
	    << pcpp::AppName::get() << " [-hvl] [-c count] [-w timeout] [-s mac_addr] [-S ip_addr] -i interface -T ip_addr"
	    << '\n'
	    << '\n'
	    << "Options:" << '\n'
	    << '\n'
	    << "    -h           : Displays this help message and exits" << '\n'
	    << "    -v           : Displays the current version and exists" << '\n'
	    << "    -l           : Print the list of interfaces and exists" << '\n'
	    << "    -c count     : Send 'count' requests" << '\n'
	    << "    -i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address"
	    << '\n'
	    << "    -s mac_addr  : Set source MAC address" << '\n'
	    << "    -S ip_addr   : Set source IP address" << '\n'
	    << "    -T ip_addr   : Set target IP address" << '\n'
	    << "    -w timeout   : How long to wait for a reply (in seconds)" << '\n'
	    << '\n';
}

/**
 * Print application version
 */
void printAppVersion()
{
	std::cout << pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << '\n'
	          << "Built: " << pcpp::getBuildDateTime() << '\n'
	          << "Built from: " << pcpp::getGitInfo() << '\n';
	exit(0);
}

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<pcpp::PcapLiveDevice*>& devList =
	    pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << '\n' << "Network interfaces:" << '\n';
	for (const auto& dev : devList)
	{
		std::cout << "    -> Name: '" << dev->getName() << "'   IP address: " << dev->getIPv4Address().toString()
		          << '\n';
	}
	exit(0);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	auto* shouldStop = static_cast<bool*>(cookie);
	*shouldStop = true;
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	int maxTries = DEFAULT_MAX_TRIES;
	pcpp::MacAddress sourceMac;
	pcpp::IPv4Address sourceIP;
	pcpp::IPv4Address targetIP;
	bool targetIpProvided = false;
	std::string ifaceNameOrIP;
	bool ifaceNameOrIpProvided = false;
	int timeoutSec = pcpp::NetworkUtils::DefaultTimeout;
	int optionIndex = 0;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, "i:s:S:T:c:hvlw:", ArpingOptions, &optionIndex)) != -1)
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
			try
			{
				sourceMac = pcpp::MacAddress(optarg);
			}
			catch (std::exception&)
			{
				EXIT_WITH_ERROR("Source MAC address is not valid");
			}
			break;
		case 'S':
			try
			{
				sourceIP = pcpp::IPv4Address(static_cast<char const*>(optarg));
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR("Source IP address is not valid");
			}
			break;
		case 'T':
			try
			{
				targetIP = pcpp::IPv4Address(static_cast<char const*>(optarg));
			}
			catch (const std::exception&)
			{
				EXIT_WITH_ERROR("Target IP is not valid");
			}
			targetIpProvided = true;
			break;
		case 'c':
			maxTries = atoi(optarg);
			break;
		case 'h':
			printUsage();
			exit(0);
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
	{
		EXIT_WITH_ERROR("You must provide at least interface name or interface IP (-i switch)");
	}

	// verify target IP was provided
	if (!targetIpProvided)
	{
		EXIT_WITH_ERROR("You must provide target IP (-T switch)");
	}

	pcpp::PcapLiveDevice* dev = nullptr;

	// Search interface by name or IP
	if (!ifaceNameOrIP.empty())
	{
		dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIpOrName(ifaceNameOrIP);
		if (dev == nullptr)
		{
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");
		}
	}
	else
	{
		EXIT_WITH_ERROR("Interface name or IP empty");
	}

	// open device in promiscuous mode
	if (!dev->open())
	{
		EXIT_WITH_ERROR("Couldn't open interface device '" << dev->getName() << "'");
	}

	// if source MAC not provided - use the interface MAC address
	if (sourceMac == pcpp::MacAddress::Zero)
	{
		sourceMac = dev->getMacAddress();
	}

	// if source MAC is still invalid, it means it couldn't be extracted from interface
	if (sourceMac == pcpp::MacAddress::Zero)
	{
		EXIT_WITH_ERROR("MAC address couldn't be extracted from interface");
	}

	if (sourceIP == pcpp::IPv4Address::Zero)
	{
		sourceIP = dev->getIPv4Address();
	}

	if (sourceIP == pcpp::IPv4Address::Zero)
	{
		EXIT_WITH_ERROR("Source IPv4 address wasn't supplied and couldn't be retrieved from interface");
	}

	// let's go
	double arpResponseTimeMS = 0;
	int i = 1;

	// suppressing errors to avoid cluttering stdout
	pcpp::Logger::getInstance().suppressLogs();

	// make sure the app closes the device upon termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while (i <= maxTries && !shouldStop)
	{
		// use the getMacAddress utility to send an ARP request and resolve the MAC address
		const pcpp::MacAddress result = pcpp::NetworkUtils::getInstance().getMacAddress(
		    targetIP, dev, arpResponseTimeMS, sourceMac, sourceIP, timeoutSec);

		// failed fetching MAC address
		if (result == pcpp::MacAddress::Zero)
		{
			// PcapPlusPlus logger saves the last internal error message
			std::cout << "Arping  index=" << i << " : " << pcpp::Logger::getInstance().getLastError() << '\n';
		}
		else  // Succeeded fetching MAC address
		{
			// output ARP ping data
			std::cout.precision(3);
			std::cout << "Reply from " << targetIP << " "
			          << "[" << result << "]  " << std::fixed << arpResponseTimeMS << "ms  "
			          << "index=" << i << '\n';
		}

		i++;
	}

	dev->close();
}
