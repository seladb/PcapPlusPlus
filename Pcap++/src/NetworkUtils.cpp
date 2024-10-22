#define LOG_MODULE NetworkUtils

#include <condition_variable>
#include <errno.h>
#include <mutex>
#include <stdlib.h>
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFilter.h"
#include "NetworkUtils.h"
#include "EndianPortable.h"
#ifdef _MSC_VER
#include "SystemUtils.h"
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT  10060
#endif

#define DNS_PORT   53


namespace pcpp
{

const int NetworkUtils::DefaultTimeout = 5;


struct ArpingReceivedData
{
	std::mutex &mutex;
	std::condition_variable &cond;
	IPv4Address ipAddr;
	clock_t start;
	MacAddress result;
	double arpResponseTime;
};


static void arpPacketReceived(RawPacket* rawPacket, PcapLiveDevice*, void* userCookie)
{
	// extract timestamp of packet
	clock_t receiveTime = clock();

	// get the data from the main thread
	ArpingReceivedData* data = (ArpingReceivedData*)userCookie;

	// parse the response packet
	Packet packet(rawPacket);

	// verify that it's an ARP packet (although it must be because I set an ARP reply filter on the interface)
	if (!packet.isPacketOfType(ARP))
		return;

	// extract the ARP layer from the packet
	ArpLayer* arpReplyLayer = packet.getLayerOfType<ArpLayer>(true); // lookup in reverse order
	if (arpReplyLayer == nullptr)
		return;

	// verify it's the right ARP response
	if (arpReplyLayer->getArpHeader()->hardwareType != htobe16(1) /* Ethernet */
			|| arpReplyLayer->getArpHeader()->protocolType != htobe16(PCPP_ETHERTYPE_IP))
		return;

	// verify the ARP response is the response for out request (and not some arbitrary ARP response)
	if (arpReplyLayer->getSenderIpAddr() != data->ipAddr)
		return;

	// measure response time
	double diffticks = receiveTime-data->start;
	double diffms = (diffticks*1000)/CLOCKS_PER_SEC;

	data->arpResponseTime = diffms;
	data->result = arpReplyLayer->getSenderMacAddress();

	// signal the main thread the ARP reply was received
	data->cond.notify_one();
}


MacAddress NetworkUtils::getMacAddress(IPv4Address ipAddr, PcapLiveDevice* device, double& arpResponseTimeMS,
		MacAddress sourceMac, IPv4Address sourceIP, int arpTimeout) const
{
	MacAddress result = MacAddress::Zero;

	// open the device if not already opened
	bool closeDeviceAtTheEnd = false;
	if (!device->isOpened())
	{
		closeDeviceAtTheEnd = true;
		if (!device->open())
		{
			PCPP_LOG_ERROR("Cannot open device");
			return result;
		}
	}

	if (sourceMac == MacAddress::Zero)
		sourceMac = device->getMacAddress();

	if (sourceIP == IPv4Address::Zero)
		sourceIP = device->getIPv4Address();

	if (arpTimeout <= 0)
		arpTimeout = NetworkUtils::DefaultTimeout;

	// create an ARP request from sourceMac and sourceIP and ask for target IP

	Packet arpRequest(100);

	MacAddress destMac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	EthLayer ethLayer(sourceMac, destMac);

	ArpLayer arpLayer(ARP_REQUEST, sourceMac, destMac, sourceIP, ipAddr);

	if (!arpRequest.addLayer(&ethLayer))
	{
		PCPP_LOG_ERROR("Couldn't build Eth layer for ARP request");
		return result;
	}

	if (!arpRequest.addLayer(&arpLayer))
	{
		PCPP_LOG_ERROR("Couldn't build ARP layer for ARP request");
		return result;
	}

	arpRequest.computeCalculateFields();

	// set a filter for the interface to intercept only ARP response packets
	ArpFilter arpFilter(ARP_REPLY);
	if (!device->setFilter(arpFilter))
	{
		PCPP_LOG_ERROR("Couldn't set ARP filter for device");
		return result;
	}

	// since packet capture is done on another thread, I use a conditional mutex with timeout to synchronize between the capture
	// thread and the main thread. When the capture thread starts running the main thread is blocking on the conditional mutex.
	// When the ARP response is captured the capture thread signals the main thread and the main thread stops capturing and continues
	// to the next iteration. If a timeout passes and no ARP response is captured, the main thread stops capturing

	std::mutex mutex;
	std::condition_variable cond;

	// this is the token that passes between the 2 threads. It contains pointers to the conditional mutex, the target IP for identifying
	// the ARP response, the iteration index and a timestamp to calculate the response time
	ArpingReceivedData data = {
			mutex,
			cond,
			ipAddr,
			clock(),
			MacAddress::Zero,
			0
	};

	struct timeval now;
	gettimeofday(&now,nullptr);

	// start capturing. The capture is done on another thread, hence "arpPacketReceived" is running on that thread
	device->startCapture(arpPacketReceived, &data);

	// send the ARP request
	device->sendPacket(&arpRequest);

	// block on the conditional mutex until capture thread signals or until timeout expires
	// cppcheck-suppress localMutex
	std::unique_lock<std::mutex> lock(mutex);
	std::cv_status res = cond.wait_for(lock, std::chrono::seconds(arpTimeout));

	// stop the capturing thread
	device->stopCapture();

	// check if timeout expired
	if (res == std::cv_status::timeout)
	{
		PCPP_LOG_ERROR("ARP request time out");
		return result;
	}

	if (closeDeviceAtTheEnd)
		device->close();
	else
		device->clearFilter();

	result = data.result;
	arpResponseTimeMS = data.arpResponseTime;

	return result;
}



struct DNSReceivedData
{
	std::mutex &mutex;
	std::condition_variable &cond;
	std::string hostname;
	uint16_t transactionID;
	clock_t start;
	IPv4Address result;
	uint32_t ttl;
	double dnsResponseTime;
};

static void dnsResponseReceived(RawPacket* rawPacket, PcapLiveDevice*, void* userCookie)
{
	// extract timestamp of packet
	clock_t receiveTime = clock();

	// get data from the main thread
	DNSReceivedData* data = (DNSReceivedData*)userCookie;

	// parse the response packet
	Packet packet(rawPacket);

	// verify that it's an DNS packet (although it must be because DNS port filter was set on the interface)
	if (!packet.isPacketOfType(DNS))
		return;

	// extract the DNS layer from the packet
	DnsLayer* dnsResponseLayer = packet.getLayerOfType<DnsLayer>(true); // lookup in reverse order
	if (dnsResponseLayer == nullptr)
		return;

	// verify it's the right DNS response
	if (dnsResponseLayer->getDnsHeader()->queryOrResponse != 1 /* DNS response */
			|| dnsResponseLayer->getDnsHeader()->numberOfAnswers < htobe16(1)
			|| dnsResponseLayer->getDnsHeader()->transactionID != htobe16(data->transactionID))
	{
		return;
	}

	// DNS resolving can be recursive as many DNS responses contain multiple answers with recursive canonical names (CNAME) for
	// the hostname. For example: a DNS response for www.a.com can have multiple answers:
	//- First with CNAME: www.a.com -> www.b.com
	//- Second with CNAME: www.b.com -> www.c.com
	//- Third with resolving: www.c.com -> 1.1.1.1
	// So the search must be recursive until an IPv4 resolving is found or until no hostname or canonical name are found (and then return)

	std::string hostToFind = data->hostname;

	DnsResource* dnsAnswer = nullptr;

	while (true)
	{
		dnsAnswer = dnsResponseLayer->getAnswer(hostToFind, true);

		// if response doesn't contain hostname or cname - return
		if (dnsAnswer == nullptr)
		{
			PCPP_LOG_DEBUG("DNS answer doesn't contain hostname '" << hostToFind << "'");
			return;
		}

		DnsType dnsType = dnsAnswer->getDnsType();
		// if answer contains IPv4 resolving - break the loop and return the IP address
		if (dnsType == DNS_TYPE_A)
		{
			PCPP_LOG_DEBUG("Found IPv4 resolving for hostname '" << hostToFind << "'");
			break;
		}
		// if answer contains a cname - continue to search this cname in the packet - hopefully find the IP resolving
		else if (dnsType == DNS_TYPE_CNAME)
		{
			PCPP_LOG_DEBUG("Got a DNS response for hostname '" << hostToFind << "' with CNAME '" << dnsAnswer->getData()->toString() << "'");
			hostToFind = dnsAnswer->getData()->toString();
		}
		// if answer is of type other than A or CNAME (for example AAAA - IPv6) - type is not supported - return
		else
		{
			PCPP_LOG_DEBUG("Got a DNS response with type which is not A or CNAME");
			return;
		}
	}
	// if we got here it means an IPv4 resolving was found

	// measure response time
	clock_t diffticks = receiveTime-data->start;
	double diffms = (diffticks*1000.0)/CLOCKS_PER_SEC;

	data->dnsResponseTime = diffms;
	data->result = dnsAnswer->getData()->castAs<IPv4DnsResourceData>()->getIpAddress();
	data->ttl = dnsAnswer->getTTL();

	// signal the main thread the ARP reply was received
	data->cond.notify_one();
}


IPv4Address NetworkUtils::getIPv4Address(const std::string& hostname, PcapLiveDevice* device, double& dnsResponseTimeMS, uint32_t& dnsTTL,
		int dnsTimeout, IPv4Address dnsServerIP, IPv4Address gatewayIP) const
{
	IPv4Address result = IPv4Address::Zero;

	// open the device if not already opened
	bool closeDeviceAtTheEnd = false;
	if (!device->isOpened())
	{
		closeDeviceAtTheEnd = true;
		if (!device->open())
		{
			PCPP_LOG_ERROR("Cannot open device");
			return result;
		}
	}

	// first - resolve gateway MAC address

	// if gateway IP wasn't provided - try to find the default gateway
	if (gatewayIP == IPv4Address::Zero)
	{
		gatewayIP = device->getDefaultGateway();
	}

	if (!gatewayIP.isValid() || gatewayIP == IPv4Address::Zero)
	{
		PCPP_LOG_ERROR("Gateway address isn't valid or couldn't find default gateway");
		return result;
	}

	// send the ARP request to find gateway MAC address
	double arpResTime;
	MacAddress gatewayMacAddress = getMacAddress(gatewayIP, device, arpResTime);

	if (gatewayMacAddress == MacAddress::Zero)
	{
		PCPP_LOG_ERROR("Couldn't resolve gateway MAC address");
		return result;
	}

	if (dnsTimeout <= 0)
		dnsTimeout = NetworkUtils::DefaultTimeout;

	// validate DNS server IP. If it wasn't provided - set the system-configured DNS server
	if (dnsServerIP == IPv4Address::Zero && device->getDnsServers().size() > 0)
	{
		dnsServerIP = device->getDnsServers().at(0);
	}

	if (!dnsServerIP.isValid())
	{
		PCPP_LOG_ERROR("DNS server IP isn't valid");
		return result;
	}

	// create DNS request

	Packet dnsRequest(100);
	MacAddress sourceMac = device->getMacAddress();
	EthLayer ethLayer(sourceMac, gatewayMacAddress, PCPP_ETHERTYPE_IP);
	IPv4Layer ipLayer(device->getIPv4Address(), dnsServerIP);
	ipLayer.getIPv4Header()->timeToLive = 128;

	// randomize source port to a number >= 10000
	int srcPortLowest = 10000;
	int srcPortRange = 65535 - srcPortLowest;
	uint16_t srcPort = (rand() % srcPortRange) + srcPortLowest;
	UdpLayer udpLayer(srcPort, DNS_PORT);

	// create the DNS request for the hostname
	DnsLayer dnsLayer;

	// randomize transaction ID
	uint16_t transactionID = rand() % 65535;
	dnsLayer.getDnsHeader()->transactionID = htobe16(transactionID);
	dnsLayer.addQuery(hostname, DNS_TYPE_A, DNS_CLASS_IN);

	// add all layers to packet
	if (!dnsRequest.addLayer(&ethLayer) || !dnsRequest.addLayer(&ipLayer) || !dnsRequest.addLayer(&udpLayer) || !dnsRequest.addLayer(&dnsLayer))
	{
		PCPP_LOG_ERROR("Couldn't construct DNS query");
		return result;
	}

	dnsRequest.computeCalculateFields();

	// set a DNS response filter on the device
	PortFilter dnsResponseFilter(53, SRC);
	if (!device->setFilter(dnsResponseFilter))
	{
		PCPP_LOG_ERROR("Couldn't set DNS response filter");
		return result;
	}

	// since packet capture is done on another thread, I use a conditional mutex with timeout to synchronize between the capture
	// thread and the main thread. When the capture thread starts running the main thread is blocking on the conditional mutex.
	// When the DNS response are captured the capture thread signals the main thread and the main thread stops capturing and continues
	// to the next iteration. if a timeout passes and no DNS response is captured, the main thread stops capturing

	std::mutex mutex;
	std::condition_variable cond;

	// this is the token that passes between the 2 threads
	DNSReceivedData data = {
			mutex,
			cond,
			hostname,
			transactionID,
			clock(),
			IPv4Address::Zero,
			0,
			0
	};


	struct timeval now;
	gettimeofday(&now,nullptr);

	// start capturing. The capture is done on another thread, hence "dnsResponseReceived" is running on that thread
	device->startCapture(dnsResponseReceived, &data);

	// send the DNS request
	device->sendPacket(&dnsRequest);

	// block on the conditional mutex until capture thread signals or until timeout expires
	// cppcheck-suppress localMutex
	std::unique_lock<std::mutex> lock(mutex);
	std::cv_status res = cond.wait_for(lock, std::chrono::seconds(dnsTimeout));

	// stop the capturing thread
	device->stopCapture();

	// check if timeout expired
	if (res == std::cv_status::timeout)
	{
		PCPP_LOG_ERROR("DNS request time out");
		return result;
	}

	if (closeDeviceAtTheEnd)
		device->close();
	else
		device->clearFilter();

	result = data.result;
	dnsResponseTimeMS = data.dnsResponseTime;
	dnsTTL = data.ttl;

	return result;
}

} // namespace pcpp
