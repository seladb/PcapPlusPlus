#include <iostream>
#include <algorithm>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
/**
 * A struct for collecting packet statistics
 */
struct PacketStats
{
	int ethPacketCount = 0;
    int ipv4PacketCount = 0;
    int ipv6PacketCount = 0;
    int tcpPacketCount = 0;
    int udpPacketCount = 0;
    int dnsPacketCount = 0;
    int httpPacketCount = 0;
    int sslPacketCount = 0;


	/**
	 * Clear all stats
	 */
	void clear() { ethPacketCount = ipv4PacketCount = ipv6PacketCount = tcpPacketCount = udpPacketCount = dnsPacketCount = httpPacketCount = sslPacketCount = 0; }

	// Constructor is optional here since the members are already initialized
	PacketStats() = default;

	/**
	 * Collect stats from a packet
	 */
	void consumePacket(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS))
			dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			sslPacketCount++;
	}

	/**
	 * Print stats to console
	 */
	void printToConsole()
	{
		std::cout << "Ethernet packet count: " << ethPacketCount << "\n"
                  << "IPv4 packet count:     " << ipv4PacketCount << "\n"
                  << "IPv6 packet count:     " << ipv6PacketCount << "\n"
                  << "TCP packet count:      " << tcpPacketCount << "\n"
                  << "UDP packet count:      " << udpPacketCount << "\n"
                  << "DNS packet count:      " << dnsPacketCount << "\n"
                  << "HTTP packet count:     " << httpPacketCount << "\n"
                  << "SSL packet count:      " << sslPacketCount << "\n";
	}
};


/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// extract the stats object form the cookie
	auto* stats = static_cast<PacketStats*>(cookie);

	// parsed the raw packet
	pcpp::Packet parsedPacket(packet);

	// collect stats from packet
	stats->consumePacket(parsedPacket);
}


/**
 * a callback function for the blocking mode capture which is called each time a packet is captured
 */
static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// extract the stats object form the cookie
	auto* stats = static_cast<PacketStats*>(cookie);

	// parsed the raw packet
	pcpp::Packet parsedPacket(packet);

	// collect stats from packet
	stats->consumePacket(parsedPacket);

	// return false means we don't want to stop capturing after this callback
	return false;
}


/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	// IPv4 address of the interface we want to sniff
	std::string interfaceIPAddr = "10.0.0.1";

	// find the interface by IP address
	auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
	if (dev == nullptr)
	{
		std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'\n";
		return 1;
	}

	// Get device info
	// ~~~~~~~~~~~~~~~

	// before capturing packets let's print some info about this interface
	std::cout
		<< "Interface info:\n"
		<< "   Interface name:        " << dev->getName() << "\n" // get interface name
		<< "   Interface description: " << dev->getDesc() << "\n" // get interface description
		<< "   MAC address:           " << dev->getMacAddress() << "\n" // get interface MAC address
		<< "   Default gateway:       " << dev->getDefaultGateway() << "\n" // get default gateway
		<< "   Interface MTU:         " << dev->getMtu() << "\n"; // get interface MTU

	if (!dev->getDnsServers().empty())
        std::cout << "   DNS server:            " << dev->getDnsServers().front() << "\n";

	// open the device before start capturing/sending packets
	if (!dev->open())
	{
		std::cerr << "Cannot open device\n";
		return 1;
	}

	// create the stats object
	PacketStats stats;


	// Async packet capture with a callback function
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	std::cout << "\nStarting async capture...\n";

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	pcpp::multiPlatformSleep(10);

	// stop capturing packets
	dev->stopCapture();

	// print results
	std::cout << "Results:\n";
	stats.printToConsole();

	// clear stats
	stats.clear();


	// Capturing packets in a packet vector
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	std::cout << "\nStarting capture with packet vector...\n";

	// create an empty packet vector object
	pcpp::RawPacketVector packetVec;

	// start capturing packets. All packets will be added to the packet vector
	dev->startCapture(packetVec);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	pcpp::multiPlatformSleep(10);

	// stop capturing packets
	dev->stopCapture();

	// go over the packet vector and feed all packets to the stats object
	for (const auto& packet : packetVec) {
        pcpp::Packet parsedPacket(packet);
        stats.consumePacket(parsedPacket);
    }

	// print results
	std::cout << "Results:\n";
	stats.printToConsole();

	// clear stats
	stats.clear();


	// Capturing packets in blocking mode
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	std::cout << "\nStarting capture in blocking mode...\n";

	// start capturing in blocking mode. Give a callback function to call to whenever a packet is captured, the stats object as the cookie and a 10 seconds timeout
	dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

	// thread is blocked until capture is finished

	// capture is finished, print results
	std::cout << "Results:\n";
	stats.printToConsole();

	stats.clear();


	// Sending single packets
	// ~~~~~~~~~~~~~~~~~~~~~~

	std::cout << "\nSending " << packetVec.size() << " packets one by one...\n";

	// go over the vector of packets and send them one by one
	bool allSent = std::all_of(packetVec.begin(), packetVec.end(), [dev](const auto& packet) {
		return dev->sendPacket(*packet);
	});

	if (!allSent) {
		std::cerr << "Couldn't send packet\n";
		return 1;
	}

	std::cout << packetVec.size() << " packets sent\n";


	// Sending batch of packets
	// ~~~~~~~~~~~~~~~~~~~~~~~~

	std::cout << "\nSending " << packetVec.size() << " packets...\n";

	// send all packets in the vector. The returned number shows how many packets were actually sent (expected to be equal to vector size)
	int packetsSent = dev->sendPackets(packetVec);

	std::cout << packetsSent << " packets sent\n";


	// Using filters
	// ~~~~~~~~~~~~~

	// create a filter instance to capture only traffic on port 80
	pcpp::PortFilter portFilter(80, pcpp::SRC_OR_DST);

	// create a filter instance to capture only TCP traffic
	pcpp::ProtoFilter protocolFilter(pcpp::TCP);

	// create an AND filter to combine both filters - capture only TCP traffic on port 80
	pcpp::AndFilter andFilter;
	andFilter.addFilter(&portFilter);
	andFilter.addFilter(&protocolFilter);

	// set the filter on the device
	dev->setFilter(andFilter);

	std::cout << "\nStarting packet capture with a filter in place...\n";

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	pcpp::multiPlatformSleep(10);

	// stop capturing packets
	dev->stopCapture();

	// print results - should capture only packets which match the filter (which is TCP port 80)
	std::cout << "Results:\n";
	stats.printToConsole();


	// close the device before application ends
	dev->close();
}
