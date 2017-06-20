#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"

/**
 * A struct for collecting packet statistics
 */
struct PacketStats
{
	int ethPacketCount;
	int ipv4PacketCount;
	int ipv6PacketCount;
	int tcpPacketCount;
	int udpPacketCount;
	int dnsPacketCount;
	int httpPacketCount;
	int sslPacketCount;


	/**
	 * Clear all stats
	 */
	void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

	/**
	 * C'tor
	 */
	PacketStats() { clear(); }

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
		printf("Ethernet packet count: %d\n", ethPacketCount);
		printf("IPv4 packet count:     %d\n", ipv4PacketCount);
		printf("IPv6 packet count:     %d\n", ipv6PacketCount);
		printf("TCP packet count:      %d\n", tcpPacketCount);
		printf("UDP packet count:      %d\n", udpPacketCount);
		printf("DNS packet count:      %d\n", dnsPacketCount);
		printf("HTTP packet count:     %d\n", httpPacketCount);
		printf("SSL packet count:      %d\n", sslPacketCount);
	}
};


/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// extract the stats object form the cookie
	PacketStats* stats = (PacketStats*)cookie;

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
	PacketStats* stats = (PacketStats*)cookie;

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
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());
	if (dev == NULL)
	{
		printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
		exit(1);
	}

	// Get device info
	// ~~~~~~~~~~~~~~~

	// before capturing packets let's print some info about this interface
	printf("Interface info:\n");
	// get interface name
	printf("   Interface name:        %s\n", dev->getName());
	// get interface description
	printf("   Interface description: %s\n", dev->getDesc());
	// get interface MAC address
	printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
	// get default gateway for interface
	printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
	// get interface MTU
	printf("   Interface MTU:         %d\n", dev->getMtu());
	// get DNS server if defined for this interface
	if (dev->getDnsServers().size() > 0)
		printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());

	// open the device before start capturing/sending packets
	if (!dev->open())
	{
		printf("Cannot open device\n");
		exit(1);
	}

	// create the stats object
	PacketStats stats;


	// Async packet capture with a callback function
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	printf("\nStarting async capture...\n");

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	PCAP_SLEEP(10);

	// stop capturing packets
	dev->stopCapture();

	// print results
	printf("Results:\n");
	stats.printToConsole();

	// clear stats
	stats.clear();


	// Capturing packets in a packet vector
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	printf("\nStarting capture with packet vector...\n");

	// create an empty packet vector object
	pcpp::RawPacketVector packetVec;

	// start capturing packets. All packets will be added to the packet vector
	dev->startCapture(packetVec);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	PCAP_SLEEP(10);

	// stop capturing packets
	dev->stopCapture();

	// go over the packet vector and feed all packets to the stats object
	for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		// parse raw packet
		pcpp::Packet parsedPacket(*iter);

		// feed packet to the stats object
		stats.consumePacket(parsedPacket);
	}

	// print results
	printf("Results:\n");
	stats.printToConsole();

	// clear stats
	stats.clear();


	// Capturing packets in blocking mode
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	printf("\nStarting capture in blocking mode...\n");

	// start capturing in blocking mode. Give a callback function to call to whenever a packet is captured, the stats object as the cookie and a 10 seconds timeout
	dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

	// thread is blocked until capture is finished

	// capture is finished, print results
	printf("Results:\n");
	stats.printToConsole();

	stats.clear();


	// Sending single packets
	// ~~~~~~~~~~~~~~~~~~~~~~

	printf("\nSending %d packets one by one...\n", packetVec.size());

	// go over the vector of packets and send them one by one
	for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		// send the packet. If fails exit the application
		if (!dev->sendPacket(**iter))
		{
			printf("Couldn't send packet\n");
			exit(1);
		}
	}
	printf("%d packets sent\n", packetVec.size());


	// Sending batch of packets
	// ~~~~~~~~~~~~~~~~~~~~~~~~

	printf("\nSending %d packets...\n", packetVec.size());

	// send all packets in the vector. The returned number shows how many packets were actually sent (expected to be equal to vector size)
	int packetsSent = dev->sendPackets(packetVec);

	printf("%d packets sent\n", packetsSent);


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

	printf("\nStarting packet capture with a filter in place...\n");

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
	PCAP_SLEEP(10);

	// stop capturing packets
	dev->stopCapture();

	// print results - should capture only packets which match the filter (which is TCP port 80)
	printf("Results:\n");
	stats.printToConsole();


	// close the device before application ends
	dev->close();
}
