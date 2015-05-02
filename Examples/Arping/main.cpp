#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <fstream>
#include <memory>
#include <pthread.h>
#ifdef WIN32
#include <winsock2.h>
#endif
#include <MacAddress.h>
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <EthLayer.h>
#include <ArpLayer.h>
#include <Logger.h>
#ifndef WIN32 //for using ntohl, ntohs, etc.
#include <in.h>
#include <errno.h>
#endif

using namespace std;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("Arping terminated in error: " reason "\n", ## __VA_ARGS__); \
	exit(0); \
	} while(0)

#define DEFAULT_MAX_TRIES	1000000
#define DEFAULT_TIMEOUT		5

static struct option ArpingOptions[] =
{
	{"interface",  optional_argument, 0, 'i'},
	{"source-mac",  optional_argument, 0, 's'},
	{"source-ip", optional_argument, 0, 'S'},
	{"target-ip", required_argument, 0, 'T'},
	{"count", optional_argument, 0, 'c'},
	{"help", optional_argument, 0, 'h'},
	{"list", optional_argument, 0, 'l'},
	{"timeout", optional_argument, 0, 'w'},
    {0, 0, 0, 0}
};


struct PacketRecievedData
{
	pthread_mutex_t* mutex;
	pthread_cond_t* cond;
	IPv4Address ipAddr;
	int index;
	clock_t start;
};

void printUsage() {
	printf("\nUsage: Arping [-hl] [-c count] [-w timeout] [-i interface] [-s mac_sddr] [-S ip_addr] -T ip_addr\n"
			"\nOptions:\n\n"
			"    -h           : Displays this help message and exits\n"
			"    -l           : Print the list of interfaces and exists\n"
			"    -c count     : Send 'count' requests\n"
			"    -i interface : Use the specified interface\n"
			"    -s mac_addr  : Set source MAC address\n"
			"    -S ip_addr   : Set source IP address\n"
			"    -T ip_addr   : Set target IP address\n"
			"    -w timeout   : How long to wait for a reply (in seconds)\n");

	exit(0);
}


// This method is running in the capturing thread (not on the main thread)
void packetRecieved(RawPacket* rawPacket, PcapLiveDevice* pDevice, void* userCookie)
{
	// extract timestamp of packet
	clock_t recieveTime = clock();

	// get the data from the main thread
	PacketRecievedData* data = (PacketRecievedData*)userCookie;

	// parse the response packet
	Packet packet(rawPacket);

	// verify that it's an ARP packet (although it must be because I set an ARP reply filter on the interface)
	if (!packet.isPacketOfType(ARP))
		return;

	// extract the ARP layer from the packet
	ArpLayer* arpReplyLayer = packet.getLayerOfType<ArpLayer>();
	if (arpReplyLayer == NULL)
		return;

	// verify it's the right ARP response
	if (arpReplyLayer->getArpHeader()->hardwareType != htons(1) /* Ethernet */
			|| arpReplyLayer->getArpHeader()->protocolType != htons(ETHERTYPE_IP))
		return;

	// verify the ARP response is the response for out request (and not some arbitrary ARP response)
	if (arpReplyLayer->getSenderIpAddr() != data->ipAddr)
		return;

	// measure response time
	double diffticks = recieveTime-data->start;
	double diffms = (diffticks*1000)/CLOCKS_PER_SEC;

	// output ARP ping data
	printf("Reply from %s [%s]  %.3fms  index=%d\n",
			arpReplyLayer->getSenderIpAddr().toString().c_str(),
			arpReplyLayer->getSenderMacAddress().toString().c_str(),
			diffms,
			data->index);

	// signal the main thread the ARP reply was received
	pthread_mutex_lock(data->mutex);
	pthread_cond_signal(data->cond);
    pthread_mutex_unlock(data->mutex);
}


void doArpPing(PcapLiveDevice* dev, MacAddress sourceMac, IPv4Address sourceIP, IPv4Address targetIP, int maxTries, int timeoutSec)
{
	// create an ARP request from sourceMac and sourceIP and ask for target IP

	Packet arpRequest(100);

	MacAddress destMac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	EthLayer ethLayer(sourceMac, destMac, (uint16_t)ETHERTYPE_ARP);

	ArpLayer arpLayer(ARP_REQUEST, sourceMac, destMac, sourceIP, targetIP);

	if (!arpRequest.addLayer(&ethLayer))
		EXIT_WITH_ERROR("Couldn't build Eth layer for ARP request");

	if (!arpRequest.addLayer(&arpLayer))
		EXIT_WITH_ERROR("Couldn't build ARP layer for ARP request");

	arpRequest.computeCalculateFields();

	// set a filter for the interface to intercept only ARP response packets
	ArpFilter arpFilter(ARP_REPLY);
	if (!dev->setFilter(arpFilter))
		EXIT_WITH_ERROR("Couldn't set ARP filter for device");

	// now send maxTries ARP requests
	for (int i = 0; i < maxTries; i++)
	{
		// since packet capture is done on another thread, I use a conditional mutex with timeout to synchronize between the capture
		// thread and the main thread. When the capture thread starts running the main thread is blocking on the conditional mutex.
		// When the ARP response is captured the capture thread signals the main thread and the main thread stops capturing and continues
		// to the next iteration. if a timeout passes and no ARP response is captured, the main thread stop the capture and
		// outputs "Request time out"

		pthread_mutex_t mutex;
		pthread_cond_t cond;

		// init the conditonal mutex
	    pthread_mutex_init(&mutex, 0);
	    pthread_cond_init(&cond, 0);

	    // this is the token that passes between the 2 threads. I contains pointers to the conditional mutex, the target IP for identifying
	    // the ARP response, the iteration index and a timestamp to calculate the response time
		PacketRecievedData data = {
				&mutex,
				&cond,
				targetIP,
				i+1,
				clock()
		};

	    struct timeval now;
	    gettimeofday(&now,NULL);

	    // create the timeout
		timespec timeout = {
				now.tv_sec + timeoutSec,
				now.tv_usec
		};

		// start capturing. The capture is done on another thread, hence "packetRecieved" is running on that thread
		dev->startCapture(packetRecieved, &data);

		// send the ARP request
		dev->sendPacket(&arpRequest);

		pthread_mutex_lock(&mutex);

		// block on the conditional mutex until capture thread signals or until timeout expires
		int res = pthread_cond_timedwait(&cond, &mutex, &timeout);

		// stop the capturing thread
		dev->stopCapture();

		pthread_mutex_unlock(&mutex);

		// check if timeout expired
		if (res == ETIMEDOUT)
			printf("Request time out\n");

	    pthread_mutex_destroy(&mutex);
	    pthread_cond_destroy(&cond);
	}
}

// go over all interfaces and output their names
void listInterfaces()
{
	const vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}

int main(int argc, char* argv[])
{
	int maxTries = DEFAULT_MAX_TRIES;
	MacAddress sourceMac = MacAddress::Zero;
	IPv4Address sourceIP = IPv4Address::Zero;
	IPv4Address targetIP = IPv4Address::Zero;
	bool targetIpProvided = false;
	string iface = "";
	bool ifaceOrSourceIpProvided = false;
	int timeoutSec = DEFAULT_TIMEOUT;
	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:s:S:T:c:hlw:", ArpingOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				iface = optarg;
				ifaceOrSourceIpProvided = true;
				break;
			case 's':
				sourceMac = MacAddress(optarg);
				break;
			case 'S':
				sourceIP = IPv4Address(optarg);
				ifaceOrSourceIpProvided = true;
				break;
			case 'T':
				targetIP = IPv4Address(optarg);
				targetIpProvided = true;
				break;
			case 'c':
				maxTries = atoi(optarg);;
				break;
			case 'h':
				printUsage();
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

	// verify that either interface name or source IP were provided
	if (!ifaceOrSourceIpProvided)
		EXIT_WITH_ERROR("You must provide at least interface name (-i switch) or source IP (-S switch)");

	// verify target IP was provided
	if (!targetIpProvided)
		EXIT_WITH_ERROR("You must provide target IP (-T switch)");

	// verify target IP is value
	if (!targetIP.isValid())
		EXIT_WITH_ERROR("Target IP is not valid");


	PcapLiveDevice* dev = NULL;

	// if -i switch exists, search interface by name
	if (iface != "")
	{
		dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface);
		// if couldn't find the interface by name exit
		if (dev == NULL)
		{
			EXIT_WITH_ERROR("Couldn't find interface '%s'", iface.c_str());
		}
	}
	// if -i switch doesn't exist but -S switch exists, try to search the interface by the source IP
	else if (sourceIP.isValid())
	{
		dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(sourceIP);
	}

	// couldn't find interface either by name or by source IP, exit with error
	if (dev == NULL)
	{
		EXIT_WITH_ERROR("Couldn't find interface by name or by source IP");
	}

	// open device in promiscuous mode
	if (!dev->open())
		EXIT_WITH_ERROR("Couldn't open interface device '%s'", dev->getName());

	// verify source MAC is valud
	if (!sourceMac.isValid())
		EXIT_WITH_ERROR("Source MAC address is invalid");

	// if source MAC not provided - use the interface MAC address
	if (sourceMac == MacAddress::Zero)
		sourceMac = dev->getMacAddress();

	// if source MAC is still invalid, it means it couldn't be extracted from interface
	if (!sourceMac.isValid() || sourceMac == MacAddress::Zero)
		EXIT_WITH_ERROR("MAC address couldn't be extracted from interface");

	if (!sourceIP.isValid() || sourceIP == IPv4Address::Zero)
		sourceIP = dev->getIPv4Address();

	if (!sourceIP.isValid() || sourceIP == IPv4Address::Zero)
		EXIT_WITH_ERROR("Source IPv4 address wasn't supplied and couldn't be retrieved from interface");

	// let's go
	doArpPing(dev, sourceMac, sourceIP, targetIP, maxTries, timeoutSec);
}
