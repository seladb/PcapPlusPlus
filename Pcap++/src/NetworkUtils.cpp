#include <pthread.h>
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "PcapFilter.h"
#include "NetworkUtils.h"

#define DEFAULT_ARPING_TIMEOUT		5

struct ArpingRecievedData
{
	pthread_mutex_t* mutex;
	pthread_cond_t* cond;
	IPv4Address ipAddr;
	clock_t start;
	MacAddress result;
	double arpResponseTime;
};


void arpPacketRecieved(RawPacket* rawPacket, PcapLiveDevice* pDevice, void* userCookie)
{
	// extract timestamp of packet
	clock_t recieveTime = clock();

	// get the data from the main thread
	ArpingRecievedData* data = (ArpingRecievedData*)userCookie;

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

	data->arpResponseTime = diffms;
	data->result = arpReplyLayer->getSenderMacAddress();

	// signal the main thread the ARP reply was received
	pthread_mutex_lock(data->mutex);
	pthread_cond_signal(data->cond);
    pthread_mutex_unlock(data->mutex);
}

MacAddress NetworkUtils::getMacAddress(IPv4Address ipAddr, PcapLiveDevice* device, double& arpResponseTimeMS,
		MacAddress sourceMac, IPv4Address sourceIP, int arpTimeout)
{
	MacAddress result = MacAddress::Zero;

	bool closeDeviceAtTheEnd = false;
	if (!device->isOpened())
	{
		closeDeviceAtTheEnd = true;
		if (!device->open())
		{
			LOG_ERROR("Cannot open device");
			return result;
		}
	}

	if (sourceMac == MacAddress::Zero)
		sourceMac = device->getMacAddress();

	if (sourceIP == IPv4Address::Zero)
		sourceIP = device->getIPv4Address();

	if (arpTimeout <= 0)
		arpTimeout = DEFAULT_ARPING_TIMEOUT;

	// create an ARP request from sourceMac and sourceIP and ask for target IP

	Packet arpRequest(100);

	MacAddress destMac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	EthLayer ethLayer(sourceMac, destMac, (uint16_t)ETHERTYPE_ARP);

	ArpLayer arpLayer(ARP_REQUEST, sourceMac, destMac, sourceIP, ipAddr);

	if (!arpRequest.addLayer(&ethLayer))
	{
		LOG_ERROR("Couldn't build Eth layer for ARP request");
		return result;
	}

	if (!arpRequest.addLayer(&arpLayer))
	{
		LOG_ERROR("Couldn't build ARP layer for ARP request");
		return result;
	}

	arpRequest.computeCalculateFields();

	// set a filter for the interface to intercept only ARP response packets
	ArpFilter arpFilter(ARP_REPLY);
	if (!device->setFilter(arpFilter))
	{
		LOG_ERROR("Couldn't set ARP filter for device");
		return result;
	}

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
	ArpingRecievedData data = {
			&mutex,
			&cond,
			ipAddr,
			clock(),
			MacAddress::Zero,
			0
	};

	struct timeval now;
	gettimeofday(&now,NULL);

	// create the timeout
	timespec timeout = {
			now.tv_sec + arpTimeout,
			now.tv_usec
	};

	// start capturing. The capture is done on another thread, hence "packetRecieved" is running on that thread
	device->startCapture(arpPacketRecieved, &data);

	// send the ARP request
	device->sendPacket(&arpRequest);

	pthread_mutex_lock(&mutex);

	// block on the conditional mutex until capture thread signals or until timeout expires
	int res = pthread_cond_timedwait(&cond, &mutex, &timeout);

	// stop the capturing thread
	device->stopCapture();

	pthread_mutex_unlock(&mutex);

	// check if timeout expired
	if (res == ETIMEDOUT)
	{
		LOG_ERROR("Request time out");
		return result;
	}

	pthread_mutex_destroy(&mutex);
	pthread_cond_destroy(&cond);

	if (closeDeviceAtTheEnd)
		device->close();

	result = data.result;
	arpResponseTimeMS = data.arpResponseTime;

	return result;
}
