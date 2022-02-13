/**
 * Simple SOME/IP messages trace application
 * ================================
 * This application implements simple tracing of the SOME/IP messages on the network
 */

#include <vector>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <utility>
#include <map>
#if !defined(_WIN32)
#include <errno.h>
#endif
#include "IpAddress.h"
#include "RawPacket.h"
#include "ProtocolType.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "SomeIpLayer.h"
#include "SomeIpSdLayer.h"
#include "PcapFilter.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>


#define EXIT_WITH_ERROR(reason) do { \
	printUsage(); \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)


static struct option DnsSpoofingOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{0, 0, 0, 0}
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
		<< "Usage:" << std::endl
		<< "------" << std::endl
		<< pcpp::AppName::get() << " [-hvl] [-o host1,host2,...,host_n] [-c ip_address] -i interface -d ip_address" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -h                          : Displays this help message and exits" << std::endl
		<< "    -v                          : Displays the current version and exists" << std::endl
		<< "    -l                          : Print the list of available interfaces" << std::endl
		<< "    -i interface                : The interface name or interface IP address to use." << std::endl
		<< "                                  Use the -l switch to see all interfaces" << std::endl
		<< std::endl;
}


/**
 * Print application version
 */
void printAppVersion()
{
	std::cout
		<< pcpp::AppName::get() << " " << pcpp::getPcapPlusPlusVersionFull() << std::endl
		<< "Built: " << pcpp::getBuildDateTime() << std::endl
		<< "Built from: " << pcpp::getGitInfo() << std::endl;
	exit(0);
}


/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	std::cout << std::endl << "Network interfaces:" << std::endl;
	for (std::vector<pcpp::PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		std::cout << "    -> Name: '" << (*iter)->getName() << "'   IP address: " << (*iter)->getIPv4Address().toString() << std::endl;
	}
	exit(0);
}

struct SomeIpStats {

	bool shouldStop;
	long processedMessages;

	SomeIpStats() : shouldStop(false), processedMessages(0) {}

};


/**
 * The method that is called each time a SOME/IP message is received and prints it's contents to stdout.
 */
void handleSomeIpMessage(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie)
{
	SomeIpStats* someIpStats = (SomeIpStats*)cookie;

	// create a parsed packet from the raw packet
	pcpp::Packet packet(rawPacket);

	if(!packet.isPacketOfType(pcpp::SomeIp)) {
		return;
	}

	someIpStats->processedMessages++;

	// extract all packet layers
	pcpp::IPLayer* ipLayer = packet.getLayerOfType<pcpp::IPLayer>();
	pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
	pcpp::SomeIpLayer* someIpLayer = packet.getLayerOfType<pcpp::SomeIpLayer>();

	// get ip's of sender and receiver
	pcpp::IPAddress srcIp = ipLayer->getSrcIPAddress();
	pcpp::IPAddress dstIp = ipLayer->getDstIPAddress();

	// get ports of sender and receiver
	uint16_t srcPort = udpLayer->getSrcPort();
	uint16_t dstPort = udpLayer->getDstPort();

	// process plain SOME/IP message (request / notification)
	std::cout   << "SOME/IP Message " 
			    << srcIp.toString() << ":" << srcPort << " -> " 
				<< dstIp.toString() << ":" << dstPort << std::endl
				<< someIpLayer->toString()
				<< std::endl;

	// check if it's service discovery message
	if(packet.isPacketOfType(pcpp::SomeIpSd)) 
	{
		pcpp::SomeIpSdLayer* someIpSdLayer = packet.getLayerOfType<pcpp::SomeIpSdLayer>();

		std::cout   << "SOME/IP SD" << std::endl
				    << someIpSdLayer->toString()
					<< std::endl;

		return;
	} 
}


/**
 * A callback for application interrupted event (ctrl+c): print SOME/IP stats summary
 */
void onApplicationInterrupted(void* cookie)
{
	SomeIpStats* someIpStats = (SomeIpStats*)cookie;

	std::cout << std::endl << "Application closing. Messages processed " << someIpStats->processedMessages << std::endl;
	
	someIpStats->shouldStop = true;
}

/**
 * Activate SOME/IP messages tracing
 */
void traceSomeIpMessages(pcpp::PcapLiveDevice* dev)
{
	// open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open capture device");


	// make args for callback
	SomeIpStats someIpStats;

	// start capturing SOME/IP messages
	if (!dev->startCapture(handleSomeIpMessage, &someIpStats))
		EXIT_WITH_ERROR("Cannot start packet capture");


	// register the on app close event to print summary stats on app termination
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &someIpStats);

	// run an endless loop until ctrl+c is pressed
	while (!someIpStats.shouldStop)
	{
		pcpp::multiPlatformSleep(1);
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

	while((opt = getopt_long(argc, argv, "i:d:c:o:hvl", DnsSpoofingOptions, &optionIndex)) != -1)
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
			default:
			{
				printUsage();
				exit(1);
			}
		}
	}

	pcpp::PcapLiveDevice* dev = NULL;

	// check if interface argument is IP or name and extract the device
	if (interfaceNameOrIP.empty())
	{
		EXIT_WITH_ERROR("Interface name or IP weren't provided. Please use the -i switch or -h for help");
	}

	dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);

	if (dev == NULL) 
	{
		EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");
	}

	traceSomeIpMessages(dev);
}
