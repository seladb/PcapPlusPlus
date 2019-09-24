#include <memory>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <map>
#include <Logger.h>
#include <IpAddress.h>
#include <MacAddress.h>
#include <Packet.h>
#include <PacketUtils.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <VlanLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <PayloadLayer.h>
#include <TcpReassembly.h>
#include <IPReassembly.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <WinPcapLiveDevice.h>
#include <PcapLiveDevice.h>
#include <PcapRemoteDevice.h>
#include <PcapRemoteDeviceList.h>
#include <PfRingDevice.h>
#include <PfRingDeviceList.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <PcapFilter.h>
#include <PlatformSpecificUtils.h>
#include <PcapPlusPlusVersion.h>
#include <getopt.h>
#include <stdlib.h>
#include <SystemUtils.h>
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include <KniDevice.h>
#include <KniDeviceList.h>
#include <NetworkUtils.h>
#include <RawSocketDevice.h>
#include "PcppTestFramework.h"
#if !defined(WIN32) && !defined(WINx64) && !defined(PCAPPP_MINGW_ENV)  //for using ntohl, ntohs, etc.
#include <in.h>
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)	//Disable this warning - deprecated warning - for this file
#endif

using namespace std;
using namespace pcpp;

#define EXAMPLE_PCAP_WRITE_PATH "PcapExamples/example_copy.pcap"
#define EXAMPLE_PCAP_PATH "PcapExamples/example.pcap"
#define EXAMPLE2_PCAP_PATH "PcapExamples/example2.pcap"
#define EXAMPLE_PCAP_HTTP_REQUEST "PcapExamples/4KHttpRequests.pcap"
#define EXAMPLE_PCAP_HTTP_RESPONSE "PcapExamples/650HttpResponses.pcap"
#define EXAMPLE_PCAP_VLAN "PcapExamples/VlanPackets.pcap"
#define EXAMPLE_PCAP_DNS "PcapExamples/DnsPackets.pcap"
#define DPDK_PCAP_WRITE_PATH "PcapExamples/DpdkPackets.pcap"
#define SLL_PCAP_WRITE_PATH "PcapExamples/sll_copy.pcap"
#define SLL_PCAP_PATH "PcapExamples/sll.pcap"
#define RAW_IP_PCAP_WRITE_PATH "PcapExamples/raw_ip_copy.pcap"
#define RAW_IP_PCAP_PATH "PcapExamples/raw_ip.pcap"
#define RAW_IP_PCAPNG_PATH "PcapExamples/raw_ip.pcapng"
#define EXAMPLE_PCAPNG_PATH "PcapExamples/many_interfaces-1.pcapng"
#define EXAMPLE2_PCAPNG_PATH "PcapExamples/pcapng-example.pcapng"
#define EXAMPLE_PCAPNG_WRITE_PATH "PcapExamples/many_interfaces_copy.pcapng"
#define EXAMPLE2_PCAPNG_WRITE_PATH "PcapExamples/pcapng-example-write.pcapng"
#define EXAMPLE_PCAP_GRE "PcapExamples/GrePackets.cap"
#define EXAMPLE_PCAP_IGMP "PcapExamples/IgmpPackets.pcap"

#define KNI_TEST_NAME "tkni%d"

struct PcapTestArgs
{
	string ipToSendReceivePackets;
	bool debugMode;
	string remoteIp;
	uint16_t remotePort;
	int dpdkPort;
	string kniIp;
	char* errString;
};

static PcapTestArgs PcapGlobalArgs;

void packetArrives(RawPacket* pRawPacket, PcapLiveDevice* pDevice, void* userCookie)
{
	(*(int*)userCookie)++;
}

#ifdef USE_PF_RING
struct PfRingPacketData
{
	uint8_t ThreadId;
	int PacketCount;
	int EthCount;
	int IpCount;
	int TcpCount;
	int UdpCount;
	map<uint32_t, RawPacketVector> FlowKeys;

	PfRingPacketData() : ThreadId(-1), PacketCount(0), EthCount(0), IpCount(0), TcpCount(0), UdpCount(0) {}
	void clear() { ThreadId = -1; PacketCount = 0; EthCount = 0; IpCount = 0; TcpCount = 0; UdpCount = 0; FlowKeys.clear(); }
};

void pfRingPacketsArrive(RawPacket* packets, uint32_t numOfPackets, uint8_t threadId, PfRingDevice* device, void* userCookie)
{
	PfRingPacketData* data = (PfRingPacketData*)userCookie;

	data->ThreadId = threadId;
	data->PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		Packet packet(&packets[i]);
		if (packet.isPacketOfType(Ethernet))
			data->EthCount++;
		if (packet.isPacketOfType(IPv4))
			data->IpCount++;
		if (packet.isPacketOfType(TCP))
			data->TcpCount++;
		if (packet.isPacketOfType(UDP))
			data->UdpCount++;
	}
}

void pfRingPacketsArriveMultiThread(RawPacket* packets, uint32_t numOfPackets, uint8_t threadId, PfRingDevice* device, void* userCookie)
{
	PfRingPacketData* data = (PfRingPacketData*)userCookie;

	data[threadId].ThreadId = threadId;
	data[threadId].PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		Packet packet(&packets[i]);
		if (packet.isPacketOfType(Ethernet))
			data[threadId].EthCount++;
		if (packet.isPacketOfType(IPv4))
			data[threadId].IpCount++;
		if (packet.isPacketOfType(TCP))
		{
			data[threadId].TcpCount++;
			if (packet.isPacketOfType(IPv4))
			{
				RawPacket* newRawPacket = new RawPacket(packets[i]);
				data[threadId].FlowKeys[hash5Tuple(&packet)].pushBack(newRawPacket);
			}
		}
		if (packet.isPacketOfType(UDP))
			data[threadId].UdpCount++;

	}
}

struct SetFilterInstruction
{
	int Instruction;
	string Data;
};

void pfRingPacketsArriveSetFilter(RawPacket* packets, uint32_t numOfPackets, uint8_t threadId, PfRingDevice* device, void* userCookie)
{
	SetFilterInstruction* instruction = (SetFilterInstruction*)userCookie;
	switch(instruction->Instruction)
	{
	case 1: //verify TCP packet
		for (uint32_t i = 0; i < numOfPackets; i++)
		{
			Packet packet(&packets[i]);
			if (!packet.isPacketOfType(TCP))
			{
				instruction->Instruction = 0;
			}
		}
		break;

	case 2: //verify IP filter
		IPv4Address addr(instruction->Data);
		for (uint32_t i = 0; i < numOfPackets; i++)
		{
			Packet packet(&packets[i]);
			if (!packet.isPacketOfType(IPv4))
			{
				instruction->Instruction = 0;
			}
			IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
			if (!(ipv4Layer->getSrcIpAddress() == addr))
			{
				instruction->Instruction = 0;
			}
		}
		break;
	}
}

#endif

#ifdef USE_DPDK
struct DpdkPacketData
{
	uint8_t ThreadId;
	int PacketCount;
	int EthCount;
	int ArpCount;
	int Ip4Count;
	int Ip6Count;
	int TcpCount;
	int UdpCount;
	int HttpCount;

	map<uint32_t, RawPacketVector> FlowKeys;

	DpdkPacketData() : ThreadId(-1), PacketCount(0), EthCount(0), ArpCount(0), Ip4Count(0), Ip6Count(0), TcpCount(0), UdpCount(0), HttpCount(0) {}
	void clear() { ThreadId = -1; PacketCount = 0; EthCount = 0; ArpCount = 0; Ip4Count = 0; Ip6Count = 0; TcpCount = 0; UdpCount = 0; HttpCount = 0; FlowKeys.clear(); }
};

void dpdkPacketsArrive(MBufRawPacket* packets, uint32_t numOfPackets, uint8_t threadId, DpdkDevice* device, void* userCookie)
{
	DpdkPacketData* data = (DpdkPacketData*)userCookie;

	data->ThreadId = threadId;
	data->PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		Packet packet(&packets[i]);
		if (packet.isPacketOfType(Ethernet))
			data->EthCount++;
		if (packet.isPacketOfType(ARP))
			data->ArpCount++;
		if (packet.isPacketOfType(IPv4))
			data->Ip4Count++;
		if (packet.isPacketOfType(IPv6))
			data->Ip6Count++;
		if (packet.isPacketOfType(TCP))
			data->TcpCount++;
		if (packet.isPacketOfType(UDP))
			data->UdpCount++;
		if (packet.isPacketOfType(HTTP))
			data->HttpCount++;

	}
}

void dpdkPacketsArriveMultiThread(MBufRawPacket* packets, uint32_t numOfPackets, uint8_t threadId, DpdkDevice* device, void* userCookie)
{
	DpdkPacketData* data = (DpdkPacketData*)userCookie;

	data[threadId].ThreadId = threadId;
	data[threadId].PacketCount += numOfPackets;

	for (int i = 0; i < (int)numOfPackets; i++)
	{
		Packet packet(&packets[i]);
		if (packet.isPacketOfType(Ethernet))
			data[threadId].EthCount++;
		if (packet.isPacketOfType(ARP))
			data[threadId].ArpCount++;
		if (packet.isPacketOfType(IPv4))
			data[threadId].Ip4Count++;
		if (packet.isPacketOfType(IPv6))
			data[threadId].Ip6Count++;
		if (packet.isPacketOfType(TCP))
		{
			data[threadId].TcpCount++;
			if (packet.isPacketOfType(IPv4))
			{
				RawPacket* newRawPacket = new RawPacket(packets[i]);
				data[threadId].FlowKeys[hash5Tuple(&packet)].pushBack(newRawPacket);
			}
		}
		if (packet.isPacketOfType(UDP))
		{
			data[threadId].UdpCount++;
			if (packet.isPacketOfType(IPv4))
			{
				RawPacket* newRawPacket = new RawPacket(packets[i]);
				data[threadId].FlowKeys[hash5Tuple(&packet)].pushBack(newRawPacket);
			}
		}
		if (packet.isPacketOfType(HTTP))
			data[threadId].HttpCount++;


	}
}

class DpdkTestWorkerThread : public DpdkWorkerThread
{
private:
	uint32_t m_CoreId;
	DpdkDevice* m_DpdkDevice;
	bool m_Stop;
	pthread_mutex_t* m_QueueLock;
	uint16_t m_QueueId;
	int m_PacketCount;
	bool m_Initialized;
	bool m_RanAndStopped;
public:
	DpdkTestWorkerThread()
	{
		m_DpdkDevice = NULL;
		m_QueueId = -1;
		m_QueueLock = NULL;
		m_CoreId = -1;
		m_Stop = false;
		m_PacketCount = 0;
		m_Initialized = false;
		m_RanAndStopped = false;
	}

	void init(DpdkDevice* dpdkDevice, uint16_t queueId, pthread_mutex_t* queueLock)
	{
		m_DpdkDevice = dpdkDevice;
		m_QueueId = queueId;
		m_QueueLock = queueLock;
		m_Initialized = true;
	}

	bool run(uint32_t coreId)
	{
		if (!m_Initialized)
		{
			printf("Error: Thread %d was not initialized\n", coreId);
			return false;
		}

		m_CoreId = coreId;

		if (m_DpdkDevice == NULL)
		{
			printf("Error: DpdkDevice is NULL");
			return false;
		}

		PTF_PRINT_VERBOSE("Worker thread on core %d is starting", m_CoreId);

		m_PacketCount = 0;
		MBufRawPacket* mBufArr[32] = {};

		while (!m_Stop)
		{
			pthread_mutex_lock(m_QueueLock);
			uint16_t packetReceived = m_DpdkDevice->receivePackets(mBufArr, 32, m_QueueId);
			pthread_mutex_unlock(m_QueueLock);
			m_PacketCount += packetReceived;
			pthread_mutex_lock(m_QueueLock);
			uint16_t packetsSent = m_DpdkDevice->sendPackets(mBufArr, packetReceived, m_QueueId);
			if (packetsSent != packetReceived)
			{
				printf("Error: Couldn't send all received packets on thread %d", m_CoreId);
				pthread_mutex_unlock(m_QueueLock);
				return false;
			}
			pthread_mutex_unlock(m_QueueLock);
		}

		for (int i = 0; i < 32; i++)
		{
			if (mBufArr[i] != NULL)
				delete mBufArr[i];
		}

		PTF_PRINT_VERBOSE("Worker thread on %d stopped", m_CoreId);

		m_RanAndStopped = true;
		return true;
	}

	void stop() { m_Stop = true; }

	uint32_t getCoreId() { return m_CoreId; }

	int getPacketCount() { return m_PacketCount; }

	bool threadRanAndStopped() { return m_RanAndStopped; }
};

#ifdef LINUX
struct KniRequestsCallbacksMock
{
	static int change_mtu_new(uint16_t, unsigned int) { return 0; }
	static int change_mtu_old(uint8_t, unsigned int) { return 0; }
	static int config_network_if_new(uint16_t, uint8_t) { return 0; }
	static int config_network_if_old(uint8_t, uint8_t) { return 0; }
	static int config_mac_address(uint16_t, uint8_t[]) { return 0; }
	static int config_promiscusity(uint16_t, uint8_t) { return 0; }

	static bool onPacketsCallbackSingleBurst(MBufRawPacket*, uint32_t numOfPackets, KniDevice*, void* userCookie)
	{
		unsigned int* counter = (unsigned int*)userCookie;
		*counter = numOfPackets;
		// Break after first burst
		return false;
	}
	static bool onPacketsMock(MBufRawPacket*, uint32_t, KniDevice*, void*)
	{
		return true;
	}
	static bool onPacketsCallback(MBufRawPacket*, uint32_t numOfPackets, KniDevice*, void* userCookie)
	{
		unsigned int* counter = (unsigned int*)userCookie;
		*counter = *counter + numOfPackets;
		return true;
	}

	static KniDevice::KniIoctlCallbacks cb_new;
	static KniDevice::KniOldIoctlCallbacks cb_old;
	static void setCallbacks()
	{
		cb_new.change_mtu = change_mtu_new;
		cb_new.config_network_if = config_network_if_new;
		cb_new.config_mac_address = config_mac_address;
		cb_new.config_promiscusity = config_promiscusity;
		cb_old.change_mtu = change_mtu_old;
		cb_old.config_network_if = config_network_if_old;
	}
};
KniDevice::KniIoctlCallbacks KniRequestsCallbacksMock::cb_new;
KniDevice::KniOldIoctlCallbacks KniRequestsCallbacksMock::cb_old;

namespace KNI {
enum
{
	TEST_PORT_ID0 = 42,
	TEST_PORT_ID1 = 43,
	DEVICE0 = 0,
	DEVICE1 = 1,
	TEST_MEMPOOL_CAPACITY = 512
};

inline bool setKniDeviceIp(const pcpp::IPAddress& ip, int kniDeviceId)
{
	char buff[256];
	snprintf(buff, sizeof(buff), "ip a add %s/30 dev " KNI_TEST_NAME, ip.toString().c_str(), kniDeviceId);
	(void)executeShellCommand(buff);
	snprintf(buff, sizeof(buff), "ip a | grep %s", ip.toString().c_str());
	std::string result = executeShellCommand(buff);
	return result != "" && result != "ERROR";
}
} // namespace KNI
#endif /* LINUX */
#endif /* USE_DPDK */

template<typename KeyType, typename LeftValue, typename RightValue>
void intersectMaps(const map<KeyType, LeftValue> & left, const map<KeyType, RightValue> & right, map<KeyType, pair<LeftValue, RightValue> >& result)
{
    typename map<KeyType, LeftValue>::const_iterator il = left.begin();
    typename map<KeyType, RightValue>::const_iterator ir = right.begin();
    while (il != left.end() && ir != right.end())
    {
        if (il->first < ir->first)
            ++il;
        else if (ir->first < il->first)
            ++ir;
        else
        {
            result.insert(make_pair(il->first, make_pair(il->second, ir->second)));
            ++il;
            ++ir;
        }
    }
}

void statsUpdate(pcap_stat& stats, void* userCookie)
{
	(*(int*)userCookie)++;
}

int getFileLength(const char* filename)
{
	ifstream infile(filename, ifstream::binary);
	if (!infile)
		return -1;
	infile.seekg(0, infile.end);
    int length = infile.tellg();
    infile.close();
    return length;
}

uint8_t* readFileIntoBuffer(const char* filename, int& bufferLength)
{
	int fileLength = getFileLength(filename);
	if (fileLength == -1)
		return NULL;

	ifstream infile(filename);
	if (!infile)
		return NULL;

	bufferLength = fileLength/2 + 2;
	uint8_t* result = new uint8_t[bufferLength];
	int i = 0;
	while (!infile.eof())
	{
		char byte[3];
		memset(byte, 0, 3);
		infile.read(byte, 2);
		result[i] = (uint8_t)strtol(byte, NULL, 16);
		i++;
	}
	infile.close();
	bufferLength -= 2;
	return result;
}

void printBufferDifferences(const uint8_t* buffer1, size_t buffer1Len, const uint8_t* buffer2, size_t buffer2Len)
{
	printf("\n\n\n");
	for(int i = 0; i<(int)buffer1Len; i++)
		printf(" 0x%2X  ", buffer1[i]);
	printf("\n\n\n");
	for(int i = 0; i<(int)buffer2Len; i++)
	{
		if (buffer2[i] != buffer1[i])
			printf("*0x%2X* ", buffer2[i]);
		else
			printf(" 0x%2X  ", buffer2[i]);
	}
	printf("\n\n\n");
}

bool sendURLRequest(string url)
{
	//TODO: what about windows 64?
#ifdef WIN32
	string cmd = "cUrl\\curl_win32.exe -s -o cUrl\\curl_output.txt";
#elif LINUX
	string cmd = "cUrl/curl.linux32 -s -o cUrl/curl_output.txt";
#elif MAC_OS_X
	string cmd = "curl -s -o cUrl/curl_output.txt";
#endif

	cmd += " " + url;
	if (system(cmd.c_str()) == -1)
		return false;
	return true;
}

#ifdef WIN32
HANDLE activateRpcapdServer(string ip, uint16_t port)
{
	char portAsString[10];
	sprintf(portAsString, "%d", port);
	string cmd = "rpcapd\\rpcapd.exe";
	string args = "rpcapd\\rpcapd.exe -b " + ip + " -p " + string(portAsString) + " -n";

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );
	if (!CreateProcess
			(
			TEXT(cmd.c_str()),
			(char*)TEXT(args.c_str()),
			NULL,NULL,FALSE,
			CREATE_NEW_CONSOLE,
			NULL,NULL,
			&si,
			&pi
			)
			)
		{
			return NULL;
		}

	return pi.hProcess;
}

void terminateRpcapdServer(HANDLE processHandle)
{
	if (processHandle != NULL)
		TerminateProcess(processHandle, 0);
}

#endif

bool packetArrivesBlockingModeTimeout(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	return false;
}

bool packetArrivesBlockingModeNoTimeout(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}

bool packetArrivesBlockingModeNoTimeoutPacketCount(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	int* packetCount = (int*)userCookie;
	(*packetCount)++;
	return false;
}


bool packetArrivesBlockingModeStartCapture(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	LoggerPP::getInstance().supressErrors();
	if (dev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5) != 0)
		return false;

	int temp = 0;
	if (dev->startCapture(packetArrives, &temp) != 0)
		return false;

	LoggerPP::getInstance().enableErrors();

	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}


bool packetArrivesBlockingModeStopCapture(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	// shouldn't do anything
	dev->stopCapture();

	int* packetCount = (int*)userCookie;
	if ((*packetCount) == 5)
		return true;

	(*packetCount)++;
	return false;
}



PTF_TEST_CASE(TestIPAddress)
{
	IPAddress::Ptr_t ip4Addr = IPAddress::fromString((char*)"10.0.0.4");
	PTF_ASSERT(ip4Addr.get() != NULL, "IPv4 address is NULL");
	PTF_ASSERT(ip4Addr->getType() == IPAddress::IPv4AddressType, "IPv4 address is not of type IPv4Address");
	PTF_ASSERT(strcmp(ip4Addr->toString().c_str(), "10.0.0.4") == 0, "IPv4 toString doesn't return the correct string");
	IPv4Address* ip4AddrAfterCast = static_cast<IPv4Address*>(ip4Addr.get());
	PTF_ASSERT(ntohl(ip4AddrAfterCast->toInt()) == 0x0A000004, "toInt() gave wrong result: %X", ip4AddrAfterCast->toInt());
	IPv4Address secondIPv4Address(string("1.1.1.1"));
	secondIPv4Address = *ip4AddrAfterCast;
	PTF_ASSERT(secondIPv4Address.isValid() == true, "Valid address identified as non-valid");
	PTF_ASSERT((*ip4AddrAfterCast) == secondIPv4Address, "IPv4Address assignment operator didn't work");

	IPv4Address ipv4Addr("10.0.0.4"), subnet1("10.0.0.0"), subnet2("10.10.0.0"), mask("255.255.255.0");
	PTF_ASSERT(ipv4Addr.isValid() == true, "Valid ipv4Addr identified as non-valid");
	PTF_ASSERT(subnet1.isValid() == true, "Valid subnet1 identified as non-valid");
	PTF_ASSERT(subnet2.isValid() == true, "Valid subnet2 identified as non-valid");
	PTF_ASSERT(mask.isValid() == true, "Valid mask identified as non-valid");
	PTF_ASSERT(ipv4Addr.matchSubnet(subnet1, mask) == true, "Incorrect result: ipv4Addr address does not belong to subnet1");
	PTF_ASSERT(ipv4Addr.matchSubnet(subnet2, mask) == false, "Incorrect result: ipv4Addr address belongs to subnet2");

	IPv4Address badAddress(std::string("sdgdfgd"));
	PTF_ASSERT(badAddress.isValid() == false, "Non-valid address identified as valid");
	IPv4Address anotherBadAddress = IPv4Address(std::string("321.123.1000.1"));
	PTF_ASSERT(anotherBadAddress.isValid() == false, "Non-valid address copied by copy c'tor identified as valid");

	string ip6AddrString("2607:f0d0:1002:51::4");
	IPAddress::Ptr_t ip6Addr = IPAddress::fromString(ip6AddrString);
	PTF_ASSERT(ip6Addr.get() != NULL, "IPv6 address is NULL");
	PTF_ASSERT(ip6Addr->getType() == IPAddress::IPv6AddressType, "IPv6 address is not of type IPv6Address");
	PTF_ASSERT(strcmp(ip6Addr->toString().c_str(), "2607:f0d0:1002:51::4") == 0, "IPv6 toString doesn't return the correct string");
	IPv6Address* ip6AddrAfterCast = static_cast<IPv6Address*>(ip6Addr.get());
	size_t length = 0;
	uint8_t* addrAsByteArray;
	ip6AddrAfterCast->copyTo(&addrAsByteArray, length);
	PTF_ASSERT(length == 16, "IPv6 packet length is wrong. Expected 16, got %d", (int)length);
	uint8_t expectedByteArray[16] = { 0x26, 0x07, 0xF0, 0xD0, 0x10, 0x02, 0x00, 0x51, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
	for (int i = 0; i < 16; i++)
		PTF_ASSERT_AND_RUN_COMMAND(addrAsByteArray[i] == expectedByteArray[i], delete [] addrAsByteArray, "Failed to convert IPv6 address to byte array; byte #%d: expected 0x%X got 0x%X", i, expectedByteArray[i], addrAsByteArray[i]);

	delete [] addrAsByteArray;
	ip6Addr = IPAddress::fromString(string("2607:f0d0:1002:0051:0000:0000:0000:0004"));
	PTF_ASSERT(ip6Addr.get() != NULL, "IPv6 address is NULL");
	PTF_ASSERT(ip6Addr->getType() == IPAddress::IPv6AddressType, "IPv6 address is not of type IPv6Address");
	PTF_ASSERT(strcmp(ip6Addr->toString().c_str(), "2607:f0d0:1002:0051:0000:0000:0000:0004") == 0, "IPv6 toString doesn't return the correct string");
	IPv6Address secondIPv6Address(string("2607:f0d0:1002:52::5"));
	ip6AddrAfterCast = static_cast<IPv6Address*>(ip6Addr.get());
	secondIPv6Address = *ip6AddrAfterCast;
	PTF_ASSERT(ip6Addr->isValid() == true, "Valid IPv6 address identified as non-valid");
	PTF_ASSERT((*ip6AddrAfterCast) == secondIPv6Address, "IPv6Address assignment operator didn't work");

	char badIp6AddressStr[] = "lasdfklsdkfdls";
	IPv6Address badIp6Address(badIp6AddressStr);
	PTF_ASSERT(badIp6Address.isValid() == false, "Non-valid IPv6 address identified as valid");
	IPv6Address anotherBadIp6Address = badIp6Address;
	PTF_ASSERT(anotherBadIp6Address.isValid() == false, "Non-valid IPv6 address copied by copy c'tor identified as valid");
}

PTF_TEST_CASE(TestMacAddress)
{
	MacAddress macAddr1(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT(macAddr1.isValid(), "macAddr1 is not valid");
	MacAddress macAddr2(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT(macAddr2.isValid(), "macAddr2 is not valid");
	PTF_ASSERT(macAddr1 == macAddr2, "Equal operator failed");

	MacAddress macAddr3(string("11:02:33:04:55:06"));
	PTF_ASSERT(macAddr3.isValid(), "macAddr3 is not valid");
	PTF_ASSERT(macAddr1 == macAddr3, "Different c'tors with same MAC address (string and by octets) give different addresses");

	uint8_t addrAsArr[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	MacAddress macAddr4(addrAsArr);
	PTF_ASSERT(macAddr4.isValid(), "macAddr4 is not valid");
	PTF_ASSERT(macAddr1 == macAddr4, "Different c'tors with same MAC address (from arr and by octets) give different addresses");

	string macAsStr = macAddr1.toString();
	PTF_ASSERT(macAsStr == string("11:02:33:04:55:06"), "String representation failure: expected '%s', got '%s'", "11:02:33:04:55:06", macAddr1.toString().c_str());

	uint8_t* arrToCopyTo = NULL;
	macAddr3.copyTo(&arrToCopyTo);
	PTF_ASSERT(arrToCopyTo[0] == 0x11 && arrToCopyTo[1] == 0x02 && arrToCopyTo[2] == 0x33 && arrToCopyTo[3] == 0x04 && arrToCopyTo[4] == 0x55 && arrToCopyTo[5] == 0x06, "Copy MacAddress to array failed");
	delete [] arrToCopyTo;

	uint8_t macBytes[6];
	macAddr3.copyTo(macBytes);
	PTF_ASSERT(memcmp(macBytes, addrAsArr, sizeof addrAsArr) == 0, "Incorrect result of calling copyTo(uint8_t* ptr)");

	#if __cplusplus > 199711L || _MSC_VER >= 1800
	MacAddress macCpp11Valid { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
	MacAddress macCpp11Wrong { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
	PTF_ASSERT(macCpp11Valid.isValid(), "macCpp11Valid is not valid");
	PTF_ASSERT(!macCpp11Wrong.isValid(), "macCpp11Wrong is valid");
	#endif

	MacAddress mac6(macAddr1);
	PTF_ASSERT(mac6.isValid(), "Incorrect copy constructing: mac6 is not valid");
	PTF_ASSERT(mac6 == macAddr1, "Incorrect copy constructing: mac6 is not equal to macAddr1");
	mac6 = macAddr2;
	PTF_ASSERT(mac6.isValid(), "Incorrect copy assignment: mac6 is not valid");
	PTF_ASSERT(mac6 == macAddr2, "Incorrect copy assignment: mac6 is not equal to macAddr2");

	MacAddress macWithZero("aa:aa:00:aa:00:aa");
	MacAddress macWrong1("aa:aa:aa:aa:aa:aa:bb:bb:bb:bb");
	MacAddress macWrong2("aa:aa:aa");
	MacAddress macWrong3("aa:aa:aa:ZZ:aa:aa");
	PTF_ASSERT(macWithZero.isValid(), "macWithZero is not valid");
	PTF_ASSERT(!macWrong1.isValid(), "macWrong1 is valid");
	PTF_ASSERT(!macWrong2.isValid(), "macWrong2 is valid");
	PTF_ASSERT(!macWrong3.isValid(), "macWrong3 is valid");
}

static void openAndValidateFileDevice(int& ptfResult, IFileDevice* fileDevice)
{
	PTF_ASSERT(fileDevice->open(), "cannot open file device");
	PTF_ASSERT(fileDevice->isOpened(), "File device should be opened");
}

static void closeAndValidateFileDevice(int& ptfResult, IFileDevice* fileDevice)
{
	fileDevice->close();
	PTF_ASSERT(!fileDevice->isOpened(), "File device should be closed");
}

PTF_TEST_CASE(TestPcapFileReadWrite)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
    PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
    openAndValidateFileDevice(ptfResult, &readerDev);
    openAndValidateFileDevice(ptfResult, &writerDev);
    PTF_ASSERT(readerDev.getFileName() == EXAMPLE_PCAP_PATH, "Reader file name different than expected");
    PTF_ASSERT(writerDev.getFileName() == EXAMPLE_PCAP_WRITE_PATH, "Writer file name different than expected");
    PTF_ASSERT(readerDev.getFileSize() == 3812643, "Reader file size different than expected. Expected: %d, got: %d", 3812643, (int)readerDev.getFileSize());
    RawPacket rawPacket;
    int packetCount = 0;
    int ethCount = 0;
    int sllCount = 0;
    int ipCount = 0;
    int tcpCount = 0;
    int udpCount = 0;
    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(SLL))
			sllCount++;
		if (packet.isPacketOfType(IPv4))
			ipCount++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;

		writerDev.writePacket(rawPacket);
    }


    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PTF_ASSERT(readerStatistics.ps_recv == 4631, "Incorrect number of packets read from file. Expected: 4631; read: %d", readerStatistics.ps_recv);
    PTF_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PTF_ASSERT(writerStatistics.ps_recv == 4631, "Incorrect number of packets written to file. Expected: 4631; read: %d", writerStatistics.ps_recv);
    PTF_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PTF_ASSERT(ethCount == 4631, "Incorrect number of Ethernet packets read. Expected: 4631; read: %d", ethCount);
    PTF_ASSERT(sllCount == 0, "Incorrect number of SLL packets read. Expected: 0; read: %d", sllCount);
    PTF_ASSERT(ipCount == 4631, "Incorrect number of IPv4 packets read. Expected: 4631; read: %d", ipCount);
    PTF_ASSERT(tcpCount == 4492, "Incorrect number of IPv4 packets read. Expected: 4492; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 139, "Incorrect number of IPv4 packets read. Expected: 139; read: %d", udpCount);

    closeAndValidateFileDevice(ptfResult, &readerDev);
    closeAndValidateFileDevice(ptfResult, &writerDev);

    // read all packets in a bulk
    PcapFileReaderDevice readerDev2(EXAMPLE_PCAP_PATH);
    openAndValidateFileDevice(ptfResult, &readerDev2);

    RawPacketVector packetVec;
    int numOfPacketsRead = readerDev2.getNextPackets(packetVec);
    PTF_ASSERT(numOfPacketsRead == 4631, "Bulk read: num of packets read isn't 4631");
    PTF_ASSERT(packetVec.size() == 4631, "Bulk read: num of packets in vec isn't 4631");

    closeAndValidateFileDevice(ptfResult, &readerDev2);
}

PTF_TEST_CASE(TestPcapSllFileReadWrite)
{
    PcapFileReaderDevice readerDev(SLL_PCAP_PATH);
    PcapFileWriterDevice writerDev(SLL_PCAP_WRITE_PATH, LINKTYPE_LINUX_SLL);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");
    PTF_ASSERT(writerDev.open(), "cannot open writer device");
    RawPacket rawPacket;
    int packetCount = 0;
    int sllCount = 0;
    int ethCount = 0;
    int ipCount = 0;
    int tcpCount = 0;
    int udpCount = 0;
    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(SLL))
			sllCount++;
		if (packet.isPacketOfType(IPv4))
			ipCount++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;

		writerDev.writePacket(rawPacket);
    }

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PTF_ASSERT(readerStatistics.ps_recv == 518, "Incorrect number of packets read from file. Expected: 518; read: %d", readerStatistics.ps_recv);
    PTF_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PTF_ASSERT(writerStatistics.ps_recv == 518, "Incorrect number of packets written to file. Expected: 518; written: %d", writerStatistics.ps_recv);
    PTF_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PTF_ASSERT(ethCount == 0, "Incorrect number of Ethernet packets read. Expected: 0; read: %d", ethCount);
    PTF_ASSERT(sllCount == 518, "Incorrect number of SLL packets read. Expected: 518; read: %d", sllCount);
    PTF_ASSERT(ipCount == 510, "Incorrect number of IPv4 packets read. Expected: 510; read: %d", ipCount);
    PTF_ASSERT(tcpCount == 483, "Incorrect number of TCP packets read. Expected: 483; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 28, "Incorrect number of UDP packets read. Expected: 28; read: %d", udpCount);

    readerDev.close();
    writerDev.close();
}

PTF_TEST_CASE(TestPcapRawIPFileReadWrite)
{
	LoggerPP::getInstance().supressErrors();
	PcapFileWriterDevice tempWriter(RAW_IP_PCAP_WRITE_PATH, LINKTYPE_RAW);
	PTF_ASSERT(tempWriter.open() == false, "managed to open pcap writer device with link type LINKTYPE_RAW");
	LoggerPP::getInstance().enableErrors();

    PcapFileReaderDevice readerDev(RAW_IP_PCAP_PATH);
    PcapFileWriterDevice writerDev(RAW_IP_PCAP_WRITE_PATH, LINKTYPE_DLT_RAW1);
    PcapNgFileWriterDevice writerNgDev(RAW_IP_PCAPNG_PATH);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");
    PTF_ASSERT(writerDev.open(), "cannot open writer device");
    PTF_ASSERT(writerNgDev.open(), "cannot open writer-ng device");
    RawPacket rawPacket;
    int packetCount = 0;
    int ethCount = 0;
    int ipv4Count = 0;
    int ipv6Count = 0;
    int tcpCount = 0;
    int udpCount = 0;
    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(IPv4))
			ipv4Count++;
		if (packet.isPacketOfType(IPv6))
			ipv6Count++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;

		writerDev.writePacket(rawPacket);
		writerNgDev.writePacket(rawPacket);
    }

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;
    pcap_stat writerNgStatistics;

    readerDev.getStatistics(readerStatistics);
    PTF_ASSERT(readerStatistics.ps_recv == 100, "Incorrect number of packets read from file. Expected: 100; read: %d", readerStatistics.ps_recv);
    PTF_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PTF_ASSERT(writerStatistics.ps_recv == 100, "Incorrect number of packets written to file. Expected: 100; written: %d", writerStatistics.ps_recv);
    PTF_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    writerNgDev.getStatistics(writerNgStatistics);
    PTF_ASSERT(writerNgStatistics.ps_recv == 100, "Incorrect number of packets written to pcap-ng file. Expected: 100; written: %d", writerNgStatistics.ps_recv);
    PTF_ASSERT(writerNgStatistics.ps_drop == 0, "Packets were not written properly to pcap-ng file. Number of packets dropped: %d", writerNgStatistics.ps_drop);

    PTF_ASSERT(ethCount == 0, "Incorrect number of Ethernet packets read. Expected: 0; read: %d", ethCount);
    PTF_ASSERT(ipv4Count == 50, "Incorrect number of IPv4 packets read. Expected: 50; read: %d", ipv4Count);
    PTF_ASSERT(ipv6Count == 50, "Incorrect number of IPv6 packets read. Expected: 50; read: %d", ipv6Count);
    PTF_ASSERT(tcpCount == 92, "Incorrect number of TCP packets read. Expected: 92; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 8, "Incorrect number of UDP packets read. Expected: 8; read: %d", udpCount);

    readerDev.close();
    writerDev.close();
    writerNgDev.close();
}

PTF_TEST_CASE(TestPcapFileAppend)
{
	// opening the file for the first time just to delete all packets in it
	PcapFileWriterDevice wd(EXAMPLE_PCAP_WRITE_PATH);
	PTF_ASSERT(wd.open() == true, "Cannot open writer dev");
	wd.close();

	for (int i = 0; i < 5; i++)
	{
		PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
		PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
		PTF_ASSERT(writerDev.open(true) == true, "Cannot open the pcap file in append mode, iteration #%d", i);
		PTF_ASSERT(readerDev.open(), "cannot open reader device, iteration #%d", i);

		RawPacket rawPacket;
	    while (readerDev.getNextPacket(rawPacket))
	    {
	    	writerDev.writePacket(rawPacket);
	    }

	    writerDev.close();
	    readerDev.close();
	}

	PcapFileReaderDevice readerDev(EXAMPLE_PCAP_WRITE_PATH);
	PTF_ASSERT(readerDev.open(), "cannot open reader device to read result file");
	int counter = 0;
	RawPacket rawPacket;
    while (readerDev.getNextPacket(rawPacket))
    	counter++;

    PTF_ASSERT(counter == (4631*5), "Number of read packets different than expected. Read: %d, expected: %d", counter, 4631*6);

    LoggerPP::getInstance().supressErrors();
    PcapFileWriterDevice writerDev2(EXAMPLE_PCAP_WRITE_PATH, LINKTYPE_LINUX_SLL);
    PTF_ASSERT(writerDev2.open(true) == false, "Managed to open file in append mode even though link layer types are different");
    LoggerPP::getInstance().enableErrors();

}

PTF_TEST_CASE(TestPcapNgFileReadWrite)
{
    PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_PATH);
    PcapNgFileWriterDevice writerDev(EXAMPLE_PCAPNG_WRITE_PATH);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");
    PTF_ASSERT(writerDev.open(), "cannot open writer device");
    PTF_ASSERT(readerDev.getFileName() == EXAMPLE_PCAPNG_PATH, "Reader file name different than expected");
    PTF_ASSERT(writerDev.getFileName() == EXAMPLE_PCAPNG_WRITE_PATH, "Writer file name different than expected");
    PTF_ASSERT(readerDev.getFileSize() == 20704, "Reader file size different than expected. Expected: %d, got: %d", 20704, (int)readerDev.getFileSize());
    PTF_ASSERT(readerDev.getOS() == "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)", "OS read incorrectly");
    PTF_ASSERT(readerDev.getCaptureApplication() == "Dumpcap 1.12.6 (v1.12.6-0-gee1fce6 from master-1.12)", "User app read incorrectly");
    PTF_ASSERT(readerDev.getCaptureFileComment() == "", "File comment isn't empty");
    PTF_ASSERT(readerDev.getHardware() == "", "Hardware string isn't empty");
    RawPacket rawPacket;
    int packetCount = 0;
    int ethLinkLayerCount = 0;
    int nullLinkLayerCount = 0;
    int otherLinkLayerCount = 0;
    int ethCount = 0;
    int nullLoopbackCount = 0;
    int ipCount = 0;
    int tcpCount = 0;
    int udpCount = 0;
    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;

    	LinkLayerType linkType = rawPacket.getLinkLayerType();
    	if (linkType == LINKTYPE_ETHERNET)
    		ethLinkLayerCount++;
    	else if (linkType == LINKTYPE_NULL)
    		nullLinkLayerCount++;
    	else
    		otherLinkLayerCount++;

    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(NULL_LOOPBACK))
			nullLoopbackCount++;
		if (packet.isPacketOfType(IPv4))
			ipCount++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;

		PTF_ASSERT(writerDev.writePacket(rawPacket) == true, "Couldn't write packet #%d", packetCount);
    }

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PTF_ASSERT(readerStatistics.ps_recv == 64, "Incorrect number of packets read from file. Expected: 64; read: %d", readerStatistics.ps_recv);
    PTF_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PTF_ASSERT(writerStatistics.ps_recv == 64, "Incorrect number of packets written to file. Expected: 64; written: %d", writerStatistics.ps_recv);
    PTF_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PTF_ASSERT(ethLinkLayerCount == 62, "Incorrect number of Ethernet link-type packets read. Expected: 62; read: %d", ethLinkLayerCount);
    PTF_ASSERT(nullLinkLayerCount == 2, "Incorrect number of Null link-type packets read. Expected: 2; read: %d", nullLinkLayerCount);
    PTF_ASSERT(otherLinkLayerCount == 0, "Incorrect number of other link-type packets read. Expected: 0; read: %d", otherLinkLayerCount);
    PTF_ASSERT(ethCount == 62, "Incorrect number of Ethernet packets read. Expected: 62; read: %d", ethCount);
    PTF_ASSERT(nullLoopbackCount == 2, "Incorrect number of Null/Loopback packets read. Expected: 2; read: %d", nullLoopbackCount);
    PTF_ASSERT(ipCount == 64, "Incorrect number of IPv4 packets read. Expected: 64; read: %d", ipCount);
    PTF_ASSERT(tcpCount == 32, "Incorrect number of TCP packets read. Expected: 32; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 32, "Incorrect number of UDP packets read. Expected: 32; read: %d", udpCount);

    readerDev.close();
    writerDev.close();

}

PTF_TEST_CASE(TestPcapNgFileReadWriteAdv)
{
	PcapNgFileReaderDevice readerDev(EXAMPLE2_PCAPNG_PATH);

	// negative tests
	readerDev.close();
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(readerDev.getOS() == "", "Managed to read OS before device is opened");
	LoggerPP::getInstance().enableErrors();
	// --------------

	PTF_ASSERT(readerDev.open(), "cannot open reader device");
    PTF_ASSERT(readerDev.getOS() == "Linux 3.18.1-1-ARCH", "OS read incorrectly");
    PTF_ASSERT(readerDev.getCaptureApplication() == "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", "User app read incorrectly");
    PTF_ASSERT(readerDev.getCaptureFileComment() == "CLIENT_RANDOM E39B5BF4903C68684E8512FB2F60213E9EE843A0810B4982B607914D8092D482 95A5D39B02693BC1FB39254B179E9293007F6D37C66172B1EE4EF0D5E25CE1DABE878B6143DC3B266883E51A75E99DF9                                                   ", "File comment read incorrectly");
    PTF_ASSERT(readerDev.getHardware() == "", "Hardware string isn't empty");

    PcapNgFileWriterDevice writerDev(EXAMPLE2_PCAPNG_WRITE_PATH);

	// negative tests
    writerDev.close();
    // --------------

    PTF_ASSERT(writerDev.open(readerDev.getOS().c_str(), "My Hardware", readerDev.getCaptureApplication().c_str(), "This is a comment in a pcap-ng file") == true, "Couldn't open writer file");

    RawPacket rawPacket;
    int packetCount = 0;
    int capLenNotMatchOrigLen = 0;
    int ethCount = 0;
    int sllCount = 0;
    int ip4Count = 0;
    int ip6Count = 0;
    int tcpCount = 0;
    int udpCount = 0;
    int httpCount = 0;
    int commentCount = 0;
    std::string pktComment;

    while (readerDev.getNextPacket(rawPacket, pktComment))
    {
    	packetCount++;

    	if (rawPacket.getRawDataLen() != rawPacket.getFrameLength())
    		capLenNotMatchOrigLen++;

    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(SLL))
			sllCount++;
		if (packet.isPacketOfType(IPv4))
			ip4Count++;
		if (packet.isPacketOfType(IPv6))
			ip6Count++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;
		if (packet.isPacketOfType(HTTP))
			httpCount++;

		if (pktComment != "")
		{
			PTF_ASSERT(pktComment.compare(0, 8, "Packet #") == 0, "Packet comment is '%s' and is not the expected one", pktComment.c_str());
			commentCount++;
		}

		PTF_ASSERT(writerDev.writePacket(rawPacket, pktComment.c_str()) == true, "Couldn't write packet #%d", packetCount);
    }

    PTF_ASSERT(packetCount == 159, "Incorrect number of packets read. Expected: 159; read: %d", packetCount);
    PTF_ASSERT(capLenNotMatchOrigLen == 39, "Incorrect number of packets where captured length doesn't match original length. Expected: 39; read: %d", capLenNotMatchOrigLen);
    PTF_ASSERT(ethCount == 59, "Incorrect number of Ethernet packets read. Expected: 59; read: %d", ethCount);
    PTF_ASSERT(sllCount == 100, "Incorrect number of SLL packets read. Expected: 100; read: %d", sllCount);
    PTF_ASSERT(ip4Count == 155, "Incorrect number of IPv4 packets read. Expected: 155; read: %d", ip4Count);
    PTF_ASSERT(ip6Count == 4, "Incorrect number of IPv6 packets read. Expected: 4; read: %d", ip6Count);
    PTF_ASSERT(tcpCount == 159, "Incorrect number of TCP packets read. Expected: 159; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 0, "Incorrect number of UDP packets read. Expected: 0; read: %d", udpCount);
    PTF_ASSERT(httpCount == 1, "Incorrect number of HTTP packets read. Expected: 1; read: %d", httpCount);
    PTF_ASSERT(commentCount == 100, "Incorrect number of packets with comment read. Expected: 100; read: %d", commentCount);

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PTF_ASSERT(readerStatistics.ps_recv == 159, "Incorrect number of packets read from file. Expected: 159; read: %d", readerStatistics.ps_recv);
    PTF_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PTF_ASSERT(writerStatistics.ps_recv == 159, "Incorrect number of packets written to file. Expected: 159; written: %d", writerStatistics.ps_recv);
    PTF_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    readerDev.close();
    writerDev.close();

    // -------

    PcapNgFileReaderDevice readerDev2(EXAMPLE2_PCAPNG_WRITE_PATH);
    PcapNgFileReaderDevice readerDev3(EXAMPLE2_PCAPNG_PATH);

    PTF_ASSERT(readerDev2.open(), "cannot open reader device 2");
    PTF_ASSERT(readerDev3.open(), "cannot open reader device 3");

    PTF_ASSERT(readerDev2.getOS() == "Linux 3.18.1-1-ARCH\0", "OS read incorrectly");
    PTF_ASSERT(readerDev2.getCaptureApplication() == "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", "User app read incorrectly");
    PTF_ASSERT(readerDev2.getCaptureFileComment() == "This is a comment in a pcap-ng file", "File comment read incorrectly");
    PTF_ASSERT(readerDev2.getHardware() == "My Hardware", "Hardware read incorrectly");

    packetCount = 0;
    ethCount = 0;
    sllCount = 0;
    ip4Count = 0;
    ip6Count = 0;
    tcpCount = 0;
    udpCount = 0;
    httpCount = 0;
    commentCount = 0;


    RawPacket rawPacket2;

    while (readerDev2.getNextPacket(rawPacket, pktComment))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(Ethernet))
			ethCount++;
		if (packet.isPacketOfType(SLL))
			sllCount++;
		if (packet.isPacketOfType(IPv4))
			ip4Count++;
		if (packet.isPacketOfType(IPv6))
			ip6Count++;
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;
		if (packet.isPacketOfType(HTTP))
			httpCount++;

		if (pktComment != "")
		{
			PTF_ASSERT(pktComment.compare(0, 8, "Packet #") == 0, "Packet comment is '%s' and is not the expected one", pktComment.c_str());
			commentCount++;
		}

		readerDev3.getNextPacket(rawPacket2);

		if (rawPacket.getPacketTimeStamp().tv_sec < rawPacket2.getPacketTimeStamp().tv_sec)
		{
			PTF_ASSERT((rawPacket2.getPacketTimeStamp().tv_sec - rawPacket.getPacketTimeStamp().tv_sec) < 2, "Timestamps are differ in more than 2 secs");
		}
		else
		{
			PTF_ASSERT((rawPacket.getPacketTimeStamp().tv_sec - rawPacket2.getPacketTimeStamp().tv_sec) < 2, "Timestamps are differ in more than 2 secs");
		}

		if (rawPacket.getPacketTimeStamp().tv_usec < rawPacket2.getPacketTimeStamp().tv_usec)
		{
			PTF_ASSERT((rawPacket2.getPacketTimeStamp().tv_usec - rawPacket.getPacketTimeStamp().tv_usec) < 100, "Timestamps are differ in more than 100 usecs");
		}
		else
		{
			PTF_ASSERT((rawPacket.getPacketTimeStamp().tv_usec - rawPacket2.getPacketTimeStamp().tv_usec) < 100, "Timestamps are differ in more than 100 usecs");
		}

    }

    PTF_ASSERT(packetCount == 159, "Read cycle 2: Incorrect number of packets read. Expected: 159; read: %d", packetCount);
    PTF_ASSERT(ethCount == 59, "Read cycle 2: Incorrect number of Ethernet packets read. Expected: 59; read: %d", ethCount);
    PTF_ASSERT(sllCount == 100, "Read cycle 2: Incorrect number of SLL packets read. Expected: 100; read: %d", sllCount);
    PTF_ASSERT(ip4Count == 155, "Read cycle 2: Incorrect number of IPv4 packets read. Expected: 155; read: %d", ip4Count);
    PTF_ASSERT(ip6Count == 4, "Read cycle 2: Incorrect number of IPv6 packets read. Expected: 4; read: %d", ip6Count);
    PTF_ASSERT(tcpCount == 159, "Read cycle 2: Incorrect number of TCP packets read. Expected: 159; read: %d", tcpCount);
    PTF_ASSERT(udpCount == 0, "Read cycle 2: Incorrect number of UDP packets read. Expected: 0; read: %d", udpCount);
    PTF_ASSERT(httpCount == 1, "Read cycle 2: Incorrect number of HTTP packets read. Expected: 1; read: %d", httpCount);
    PTF_ASSERT(commentCount == 100, "Read cycle 2: Incorrect number of packets with comment read. Expected: 100; read: %d", commentCount);

    readerDev2.close();
    readerDev3.close();

    PcapNgFileWriterDevice appendDev(EXAMPLE2_PCAPNG_WRITE_PATH);
    PTF_ASSERT(appendDev.open(true) == true, "Couldn't open file in append mode");

    PTF_ASSERT(appendDev.writePacket(rawPacket2, "Additional packet #1") == true, "Couldn't append packet #1");
    PTF_ASSERT(appendDev.writePacket(rawPacket2, "Additional packet #2") == true, "Couldn't append packet #2");

    appendDev.close();


    PcapNgFileReaderDevice readerDev4(EXAMPLE2_PCAPNG_WRITE_PATH);
    PTF_ASSERT(readerDev4.open(), "cannot open reader device 4");

    packetCount = 0;

    while (readerDev4.getNextPacket(rawPacket, pktComment))
    {
    	packetCount++;
    }

    PTF_ASSERT(packetCount == 161, "Number of packets after append != 161, it's %d", packetCount);

    // -------

    IFileReaderDevice* genericReader = IFileReaderDevice::getReader(EXAMPLE2_PCAP_PATH);
    PTF_ASSERT_AND_RUN_COMMAND(dynamic_cast<PcapFileReaderDevice*>(genericReader) != NULL, delete genericReader, "Reader isn't of type PcapFileReaderDevice");
    PTF_ASSERT_AND_RUN_COMMAND(dynamic_cast<PcapNgFileReaderDevice*>(genericReader) == NULL, delete genericReader, "Reader is wrongly of type PcapNgFileReaderDevice");
    delete genericReader;

    genericReader = IFileReaderDevice::getReader(EXAMPLE2_PCAPNG_PATH);
    PTF_ASSERT_AND_RUN_COMMAND(dynamic_cast<PcapNgFileReaderDevice*>(genericReader) != NULL, delete genericReader, "Reader isn't of type PcapNgFileReaderDevice");
    delete genericReader;

    // -------

    PcapNgFileReaderDevice readerDev5(EXAMPLE2_PCAPNG_PATH);
	PTF_ASSERT(readerDev5.open(), "cannot open reader device 5");
    PTF_ASSERT(readerDev5.setFilter("bla bla bla") == false, "Managed to set illegal filter to reader device");
    PTF_ASSERT(readerDev5.setFilter("src net 130.217.250.129") == true, "Couldn't set filter to reader device");

	PcapNgFileWriterDevice writerDev2(EXAMPLE2_PCAPNG_WRITE_PATH);
    PTF_ASSERT(writerDev2.open(true) == true, "Couldn't writer dev 2 in append mode");
    PTF_ASSERT(writerDev2.setFilter("bla bla bla") == false, "Managed to set illegal filter to writer device");
    PTF_ASSERT(writerDev2.setFilter("dst port 35938") == true, "Couldn't set filter to writer device");

    int filteredReadPacketCount = 0;
    int filteredWritePacketCount = 0;

    while (readerDev5.getNextPacket(rawPacket, pktComment))
    {
        filteredReadPacketCount++;
    	if(writerDev2.writePacket(rawPacket))
			filteredWritePacketCount++;
    }

    PTF_ASSERT(filteredReadPacketCount == 14, "Number of packets matched to reader filter != 14, it's %d", filteredReadPacketCount);
    PTF_ASSERT(filteredWritePacketCount == 3, "Number of packets matched to writer filter != 3, it's %d", filteredWritePacketCount);

	readerDev5.close();
	writerDev2.close();
}

PTF_TEST_CASE(TestPcapLiveDeviceList)
{
    vector<PcapLiveDevice*> devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    PTF_ASSERT(!devList.empty(), "Device list is empty");

    IPv4Address defaultGateway = IPv4Address::Zero;
    for(vector<PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
    	PTF_ASSERT(!((*iter)->getName() == NULL), "Device name is NULL");
    	if (defaultGateway == IPv4Address::Zero)
    		defaultGateway = (*iter)->getDefaultGateway();

    }

    PTF_ASSERT(defaultGateway != IPv4Address::Zero, "Couldn't find default gateway for any of the interfaces");

    std::vector<IPv4Address> dnsServers = PcapLiveDeviceList::getInstance().getDnsServers();
	size_t dnsServerCount = dnsServers.size();
    //PTF_ASSERT(dnsServers.size() > 0, "DNS server list is empty");

	// reset the device list and make sure devices are back and there is no memory leak
	PcapLiveDeviceList::getInstance().reset();

	devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	PTF_ASSERT(!devList.empty(), "Device list is empty after reset");

    for(vector<PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
    	PTF_ASSERT(!((*iter)->getName() == NULL), "Device name is NULL after reset");
	}

	PTF_ASSERT(PcapLiveDeviceList::getInstance().getDnsServers().size() == dnsServerCount, "DNS server list before and after reset are not equal");
}

PTF_TEST_CASE(TestPcapLiveDeviceListSearch)
{
	PcapLiveDevice* liveDev = NULL;
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());

    string devName(liveDev->getName());
    PcapLiveDevice* liveDev2 = NULL;
    liveDev2 = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(devName);
    PTF_ASSERT(liveDev2 != NULL, "Couldn't find device by name (search returned null)");
    PTF_ASSERT(strcmp(liveDev->getName(), liveDev2->getName()) == 0, "Search by device name didn't bring the right result");

    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("255.255.255.250");
    PTF_ASSERT(liveDev == NULL, "Illegal device found with IP=255.255.255.250");
}

PTF_TEST_CASE(TestPcapLiveDevice)
{
	PcapLiveDevice* liveDev = NULL;
    IPv4Address ipToSearch(PcapGlobalArgs.ipToSendReceivePackets.c_str());
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
    PTF_ASSERT(liveDev->getMtu() > 0, "Could not get live device MTU");
    PTF_ASSERT(liveDev->open(), "Cannot open live device");
    int packetCount = 0;
    int numOfTimeStatsWereInvoked = 0;
    PTF_ASSERT(liveDev->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
    PCAP_SLEEP(20);
    liveDev->stopCapture();
    PTF_ASSERT(packetCount > 0, "No packets were captured");
    PTF_ASSERT(numOfTimeStatsWereInvoked > 18, "Stat callback was called less than expected: %d", numOfTimeStatsWereInvoked);
    pcap_stat statistics;
    liveDev->getStatistics(statistics);
    //Bad test - on high traffic libpcap/winpcap sometimes drop packets
    //PTF_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    liveDev->close();
}

PTF_TEST_CASE(TestPcapLiveDeviceByInvalidIp)
{
	PcapLiveDevice* liveDev = NULL;
	LoggerPP::getInstance().supressErrors();
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("eth0");
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT(liveDev == NULL, "Cannot get live device by invalid Ip");

}

PTF_TEST_CASE(TestPcapLiveDeviceNoNetworking)
{
	PTF_ASSERT(IPcapDevice::getPcapLibVersionInfo() != "", "Cannot get pcap lib version info");

	PcapLiveDevice* liveDev = NULL;

    vector<PcapLiveDevice*> devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    PTF_ASSERT(!devList.empty(), "Device list is empty");

    for(vector<PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
    	if (!(*iter)->getLoopback() && (*iter)->getIPv4Address() != IPv4Address::Zero)
    	{
    		liveDev = *iter;
    		break;
    	}
    }

    PTF_ASSERT(liveDev != NULL, "Cannot find a non-loopback device with IPv4 address");
    PTF_ASSERT(liveDev->getName() != NULL, "Device has no name");
    PTF_ASSERT(liveDev->getMtu() > 0, "Cannot get MTU for device '%s'", liveDev->getName());
    PTF_ASSERT(liveDev->getMacAddress() != MacAddress::Zero, "Cannot find MAC address for device '%s'", liveDev->getName());
}

PTF_TEST_CASE(TestPcapLiveDeviceStatsMode)
{
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev->open(), "Cannot open live device");
	int numOfTimeStatsWereInvoked = 0;
	PTF_ASSERT(liveDev->startCapture(1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
	sendURLRequest("www.ebay.com");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PTF_ASSERT(numOfTimeStatsWereInvoked >= 4, "Stat callback was called less than expected: %d", numOfTimeStatsWereInvoked);
    pcap_stat statistics;
    liveDev->getStatistics(statistics);
    PTF_ASSERT(statistics.ps_recv > 2, "No packets were captured");
    //Bad test - on high traffic libpcap/winpcap sometimes drop packets
    //PTF_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    liveDev->close();
}

PTF_TEST_CASE(TestPcapLiveDeviceBlockingMode)
{
	// open device
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev != NULL, "Step 0: Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev->open(), "Step 0: Cannot open live device");

	// sanity - test blocking mode returns with timeout
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5) == -1, "Step 1: Capture blocking mode with timeout 5 sec didn't return on timeout");

	// sanity - test blocking mode returns before timeout
	int packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 2: Capture blocking mode didn't return on callback");
	PTF_ASSERT(packetCount == 5, "Step 2: Capture blocking mode didn't return packet count 5");

	// verify stop capture doesn't do any effect on blocking mode
	liveDev->stopCapture();
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1) == -1, "Step 3: Capture blocking mode with timeout 1 sec after stop capture didn't return on timeout");
	packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 3: Testing capture blocking mode after stop capture didn't return on callback");
	PTF_ASSERT(packetCount == 5, "Step 3: Capture blocking mode after stop capture didn't return packet count 5");

	// verify it's possible to capture non-blocking mode after blocking mode
	packetCount = 0;
	PTF_ASSERT(liveDev->startCapture(packetArrives, &packetCount) == true, "Step 4: Couldn't start non-blocking capture");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PTF_ASSERT(packetCount > 0, "Step 4: Couldn't capture any packet on non-blocking capture");

	// verify it's possible to capture blocking mode after non-blocking mode
	packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 5: Capture blocking mode after non-blocking mode didn't return on callback");
	PTF_ASSERT(packetCount == 5, "Step 5: Capture blocking mode after non-blocking mode didn't return packet count 5, it returned %d", packetCount);

	// try to start capture from within the callback, verify no error
	packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStartCapture, &packetCount, 30) == 1, "Step 6: Capture blocking mode when trying start capture from callback didn't return on callback");
	PTF_ASSERT(packetCount == 5, "Step 6: Capture blocking mode when callback calls start capture didn't return packet count 5");

	// try to stop capture from within the callback, verify no impact on capturing
	packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStopCapture, &packetCount, 10) == 1, "Step 7: Capture blocking mode when trying to stop capture from callback didn't return on callback");
	PTF_ASSERT(packetCount == 5, "Step 7: Capture blocking mode when callback calls stop capture didn't return packet count 5");

	// verify it's possible to capture non-blocking after the mess done in previous lines
	packetCount = 0;
	PTF_ASSERT(liveDev->startCapture(packetArrives, &packetCount) == true, "Step 8: Couldn't start non-blocking capture after blocking mode with stop capture in callback");

	// verify an error returns if trying capture blocking while non-blocking is running
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1) == 0, "Step 9: Capture blocking mode while non-blocking is running didn't return an error");
	LoggerPP::getInstance().enableErrors();
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PTF_ASSERT(packetCount > 0, "Step 9: Couldn't capture any packet on non-blocking capture 2");

}

PTF_TEST_CASE(TestPcapLiveDeviceSpecialCfg)
{
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev != NULL, "Step 0: Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());

	// open device in default mode
	PTF_ASSERT(liveDev->open(), "Step 0: Cannot open live device");

	// sanity test - make sure packets are captured in default mode
	int packetCount = 0;
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7) == -1, "Step 2: Capture blocking mode didn't return on callback");

	liveDev->close();

	PTF_ASSERT(packetCount > 0, "No packets are captured in default configuration mode");

	packetCount = 0;

	// create a non-default configuration with timeout of 10ms and open the device again
	PcapLiveDevice::DeviceConfiguration devConfig(PcapLiveDevice::Promiscuous, 10, 2000000);
	liveDev->open(devConfig);

	// start capturing in non-default configuration
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7) == -1, "Step 2: Capture blocking mode didn't return on callback");

	liveDev->close();

	PTF_ASSERT(packetCount > 0, "No packets are captured in non-default configuration mode");

#ifdef HAS_SET_DIRECTION_ENABLED
	// create a non-default configuration with only cpturing incoming packets and open the device again
	PcapLiveDevice::DeviceConfiguration devConfgWithDirection(PcapLiveDevice::Promiscuous, 10, 2000000, PcapLiveDevice::PCPP_IN);
    	
	liveDev->open(devConfgWithDirection);
		
	packetCount = 0;

	// start capturing in non-default configuration witch only captures incoming traffics
	PTF_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeoutPacketCount, &packetCount, 7) == -1, "Step 2: Capture blocking mode didn't return on callback");

	PTF_ASSERT(packetCount > 0, "No packets are captured in non-default configuration mode");
	liveDev->close();
#endif 

}


PTF_TEST_CASE(TestWinPcapLiveDevice)
{
#ifdef WIN32
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev->getDeviceType() == PcapLiveDevice::WinPcapDevice, "Live device is not of type LibPcapDevice");

	WinPcapLiveDevice* pWinPcapLiveDevice = static_cast<WinPcapLiveDevice*>(liveDev);
	int defaultDataToCopy = pWinPcapLiveDevice->getMinAmountOfDataToCopyFromKernelToApplication();
	PTF_ASSERT(defaultDataToCopy == 16000, "Data to copy isn't at its default size (16000)");
	PTF_ASSERT(pWinPcapLiveDevice->open(), "Cannot open live device");
	PTF_ASSERT(pWinPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(100000), "Set data to copy to 100000 failed. Error string: %s", PcapGlobalArgs.errString);
    int packetCount = 0;
    int numOfTimeStatsWereInvoked = 0;
    PTF_ASSERT(pWinPcapLiveDevice->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
	for (int i = 0; i < 5; i++)
		sendURLRequest("www.ebay.com");
	pcap_stat statistics;
	pWinPcapLiveDevice->getStatistics(statistics);
    PTF_ASSERT(statistics.ps_recv > 20, "No packets were captured");
    PTF_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    pWinPcapLiveDevice->stopCapture();
	PTF_ASSERT(pWinPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(defaultDataToCopy), "Could not set data to copy back to default value. Error string: %s", PcapGlobalArgs.errString);
	pWinPcapLiveDevice->close();
#else
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(liveDev->getDeviceType() == PcapLiveDevice::LibPcapDevice, "Live device is not of type LibPcapDevice");
#endif


}

PTF_TEST_CASE(TestPcapFiltersLive)
{
	PcapLiveDevice* liveDev = NULL;
    IPv4Address ipToSearch(PcapGlobalArgs.ipToSendReceivePackets.c_str());
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());

    string filterAsString;
    PTF_ASSERT(liveDev->open(), "Cannot open live device");
    RawPacketVector capturedPackets;

    //-----------
    //IP filter
    //-----------
    string filterAddrAsString(PcapGlobalArgs.ipToSendReceivePackets);
    IPFilter ipFilter(filterAddrAsString, DST);
    ipFilter.parseToString(filterAsString);
    PTF_ASSERT(liveDev->setFilter(ipFilter), "Could not set filter: %s", filterAsString.c_str());
    PTF_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(sendURLRequest("www.google.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PTF_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");


	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IPv4), "Filter '%s', Packet captured isn't of type IP", filterAsString.c_str());
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ipv4Layer->getIPv4Header()->ipDst == ipToSearch.toInt(), "'IP Filter' failed. Packet IP dst is %X, expected %X", ipv4Layer->getIPv4Header()->ipDst, ipToSearch.toInt());
	}


    //------------
    //Port filter
    //------------
    uint16_t filterPort = 80;
    PortFilter portFilter(filterPort, SRC);
    portFilter.parseToString(filterAsString);
    PTF_ASSERT(liveDev->setFilter(portFilter), "Could not set filter: %s", filterAsString.c_str());
    PTF_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(sendURLRequest("www.yahoo.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PTF_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "Filter '%s', Packet captured isn't of type TCP", filterAsString.c_str());
		TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
		PTF_ASSERT(ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80, "'Port Filter' failed. Packet port src is %d, expected 80", pTcpLayer->getTcpHeader()->portSrc);
	}
	capturedPackets.clear();


    //----------------
    //IP & Port filter
    //----------------
    std::vector<GeneralFilter*> andFilterFilters;
    andFilterFilters.push_back(&ipFilter);
    andFilterFilters.push_back(&portFilter);
    AndFilter andFilter(andFilterFilters);
    andFilter.parseToString(filterAsString);
    PTF_ASSERT(liveDev->setFilter(andFilter), "Could not set filter: %s", filterAsString.c_str());
    PTF_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(sendURLRequest("www.walla.co.il"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PTF_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "Filter '%s', Packet captured isn't of type TCP", filterAsString.c_str());
		TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
		IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80, "'And Filter' failed. Packet port src is %d, expected 80", pTcpLayer->getTcpHeader()->portSrc);
		PTF_ASSERT(pIPv4Layer->getIPv4Header()->ipDst == ipToSearch.toInt(), "Filter failed. Packet IP dst is %X, expected %X", pIPv4Layer->getIPv4Header()->ipDst, ipToSearch.toInt());
	}
	capturedPackets.clear();


    //-----------------
    //IP || Port filter
    //-----------------
    std::vector<GeneralFilter*> orFilterFilters;
    ipFilter.setDirection(SRC);
    orFilterFilters.push_back(&ipFilter);
    orFilterFilters.push_back(&portFilter);
    OrFilter orFilter(orFilterFilters);
    orFilter.parseToString(filterAsString);
    PTF_ASSERT(liveDev->setFilter(orFilter), "Could not set filter: %s", filterAsString.c_str());
    PTF_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(sendURLRequest("www.youtube.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PTF_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		if (packet.isPacketOfType(TCP))
		{
			TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
			bool srcPortMatch = ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80;
			bool srcIpMatch = false;
			IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
			uint32_t ipSrcAddrAsInt = 0;
			if (pIPv4Layer != NULL)
			{
				srcIpMatch = pIPv4Layer->getIPv4Header()->ipSrc == ipToSearch.toInt();
				ipSrcAddrAsInt = pIPv4Layer->getIPv4Header()->ipSrc;
			}
			PTF_ASSERT(srcIpMatch || srcPortMatch, "'Or Filter' failed. Src port is: %d; Src IP is: %X, Expected: port 80 or IP %s", ntohs(pTcpLayer->getTcpHeader()->portSrc), ipSrcAddrAsInt, PcapGlobalArgs.ipToSendReceivePackets.c_str());
		} else
		if (packet.isPacketOfType(IP))
		{
			IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
			PTF_ASSERT(pIPv4Layer->getIPv4Header()->ipSrc == ipToSearch.toInt(), "Filter failed. Packet IP src is %X, expected %X", pIPv4Layer->getIPv4Header()->ipSrc, ipToSearch.toInt());
		}
		else
			PTF_ASSERT(true, "Filter '%s', Packet isn't of type IP or TCP", filterAddrAsString.c_str());
	}
	capturedPackets.clear();

    //----------
    //Not filter
    //----------
    NotFilter notFilter(&ipFilter);
    notFilter.parseToString(filterAsString);
    PTF_ASSERT(liveDev->setFilter(notFilter), "Could not set filter: %s", filterAsString.c_str());
    PTF_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(sendURLRequest("www.ebay.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PTF_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		if (packet.isPacketOfType(IPv4))
		{
			IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
			PTF_ASSERT(ipv4Layer->getIPv4Header()->ipSrc != ipToSearch.toInt(), "'Not Filter' failed. Packet IP src is %X, the same as %X", ipv4Layer->getIPv4Header()->ipSrc, ipToSearch.toInt());
		}
	}
	capturedPackets.clear();


    liveDev->close();

}

PTF_TEST_CASE(TestPcapFilters_General_BPFStr)
{
	RawPacketVector rawPacketVec;
	string filterAsString;

	PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);

	//------------------
	//Test GeneralFilter bpf_program + BPFStringFilter
	//------------------

	//Try to make an invalid filter
	BPFStringFilter badFilter("This is not a valid filter");
	PTF_ASSERT(!badFilter.verifyFilter() || !IPcapDevice::verifyFilter("This is not a valid filter"), "Invalid BPFStringFilter was not caught!");

	//Test stolen from MacAddress test below
	MacAddress macAddr("00:13:c3:df:ae:18");
	BPFStringFilter bpfStringFilter("ether dst " + macAddr.toString());
	PTF_ASSERT(bpfStringFilter.verifyFilter(), "Cannot verify BPFStringFilter");
	bpfStringFilter.parseToString(filterAsString);

	PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	int validCounter = 0;

	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		//Check if match using static local variable is leaking?
		//if (bpfStringFilter.matchPacketWithFilter(*iter) && IPcapDevice::matchPacketWithFilter(bpfStringFilter, *iter) && IPcapDevice::matchPacketWithFilter(filterAsString, *iter))
		if (bpfStringFilter.matchPacketWithFilter(*iter) && IPcapDevice::matchPacketWithFilter(bpfStringFilter, *iter))
		{
			++validCounter;
			Packet packet(*iter);
			EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
			PTF_ASSERT(ethLayer->getDestMac() == macAddr, "BPFStringFilter test: dest MAC different than expected, it's: '%s'", ethLayer->getDestMac().toString().c_str());
		}
	}

	PTF_ASSERT(validCounter == 5, "BPFStringFilter test: Captured: %d packets. Expected: %d packets", validCounter, 5);

	rawPacketVec.clear();
}

PTF_TEST_CASE(TestPcapFiltersOffline)
{
	RawPacketVector rawPacketVec;
	string filterAsString;

	PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);
	PcapFileReaderDevice fileReaderDev2(EXAMPLE_PCAP_PATH);
	PcapFileReaderDevice fileReaderDev3(EXAMPLE_PCAP_GRE);
	PcapFileReaderDevice fileReaderDev4(EXAMPLE_PCAP_IGMP);

	 //-----------------
    //VLAN filter
    //-----------------

	VlanFilter vlanFilter(118);
	vlanFilter.parseToString(filterAsString);

	PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev.setFilter(vlanFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev.getNextPackets(rawPacketVec);
    fileReaderDev.close();

    PTF_ASSERT(rawPacketVec.size() == 12, "VLAN filter test: Captured: %d packets. Expected: > %d packets", (int)rawPacketVec.size(), 12);
    for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
    {
    	Packet packet(*iter);
    	PTF_ASSERT(packet.isPacketOfType(VLAN), "VLAN filter test: one of the captured packets isn't of type VLAN");
    	VlanLayer* vlanLayer = packet.getLayerOfType<VlanLayer>();
    	PTF_ASSERT(vlanLayer->getVlanID() == 118, "VLAN filter test: VLAN ID != 118, it's: %d", vlanLayer->getVlanID());
    }

    rawPacketVec.clear();


    //--------------------
    //MacAddress filter
    //--------------------
    MacAddress macAddrToFilter("00:13:c3:df:ae:18");
    MacAddressFilter macAddrFilter(macAddrToFilter, DST);
    macAddrFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev.setFilter(macAddrFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev.getNextPackets(rawPacketVec);
    fileReaderDev.close();

    PTF_ASSERT(rawPacketVec.size() == 5, "MacAddress test: Captured: %d packets. Expected: %d packets", (int)rawPacketVec.size(), 5);
    for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
    {
    	Packet packet(*iter);
    	EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
    	PTF_ASSERT(ethLayer->getDestMac() == macAddrToFilter, "MacAddress test: dest MAC different than expected, it's: '%s'", ethLayer->getDestMac().toString().c_str());
    }

    rawPacketVec.clear();


	//--------------------
	//EtherType filter
	//--------------------
	EtherTypeFilter ethTypeFiler(PCPP_ETHERTYPE_VLAN);
	ethTypeFiler.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev.setFilter(ethTypeFiler), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev.getNextPackets(rawPacketVec);
    fileReaderDev.close();

	PTF_ASSERT(rawPacketVec.size() == 24, "EthTypeFilter test: Captured less than %d packets", 24);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(VLAN), "EthTypeFilter test: one of the captured packets isn't of type VLAN");
	}

	rawPacketVec.clear();


	//--------------------
	//IPv4 ID filter
	//--------------------
	uint16_t ipID(0x9900);
	IPv4IDFilter ipIDFiler(ipID, GREATER_THAN);
	ipIDFiler.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(ipIDFiler), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 1423, "IPv4IDFilter test: Captured less than %d packets", 1423);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IPv4), "IPv4IDFilter test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ntohs(ipv4Layer->getIPv4Header()->ipId) > ipID, "IPv4IDFilter test: IP ID less than %d, it's %d", ipID, ntohs(ipv4Layer->getIPv4Header()->ipId));
	}

	rawPacketVec.clear();


	//-------------------------
	//IPv4 Total Length filter
	//-------------------------
	uint16_t totalLength(576);
	IPv4TotalLengthFilter ipTotalLengthFiler(totalLength, LESS_OR_EQUAL);
	ipTotalLengthFiler.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(ipTotalLengthFiler), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 2066, "IPv4TotalLengthFilter test: Captured less than %d packets", 2066);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IPv4), "IPv4TotalLengthFilter test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ntohs(ipv4Layer->getIPv4Header()->totalLength) <= totalLength, "IPv4TotalLengthFilter test: IP total length more than %d, it's %d", totalLength, ntohs(ipv4Layer->getIPv4Header()->totalLength));
	}

	rawPacketVec.clear();


	//-------------------------
	//TCP window size filter
	//-------------------------
	uint16_t windowSize(8312);
	TcpWindowSizeFilter tcpWindowSizeFilter(windowSize, NOT_EQUALS);
	tcpWindowSizeFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(tcpWindowSizeFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 4249, "TcpWindowSizeFilter test: Captured less than %d packets", 4249);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "TcpWindowSizeFilter test: one of the captured packets isn't of type TCP");
		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
		PTF_ASSERT(ntohs(tcpLayer->getTcpHeader()->windowSize) != windowSize, "TcpWindowSizeFilter test: TCP window size equals %d", windowSize);
	}

	rawPacketVec.clear();


	//-------------------------
	//UDP length filter
	//-------------------------
	uint16_t udpLength(46);
	UdpLengthFilter udpLengthFilter(udpLength, EQUALS);
	udpLengthFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(udpLengthFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 4, "UdpLengthFilter test: Captured less than %d packets", 4);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(UDP), "UdpLengthFilter test: one of the captured packets isn't of type UDP");
		UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
		PTF_ASSERT(ntohs(udpLayer->getUdpHeader()->length) == udpLength, "UdpLengthFilter test: UDP length != %d, it's %d", udpLength, ntohs(udpLayer->getUdpHeader()->length));
	}

	rawPacketVec.clear();


	//-------------------------
	//IP filter with mask
	//-------------------------
	IPFilter ipFilterWithMask("212.199.202.9", SRC, "255.255.255.0");
	ipFilterWithMask.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(ipFilterWithMask), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 2536, "IPFilter with mask test: Captured less than %d packets", 2536);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IPv4), "IPFilter with mask test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ipLayer->getSrcIpAddress().matchSubnet(IPv4Address(string("212.199.202.9")), string("255.255.255.0")), "IPFilter with mask test: packet doesn't match subnet mask. IP src: '%s'", ipLayer->getSrcIpAddress().toString().c_str());
	}

	rawPacketVec.clear();


	ipFilterWithMask.setLen(24);
	ipFilterWithMask.setAddr("212.199.202.9");
	ipFilterWithMask.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(ipFilterWithMask), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 2536, "IPFilter with mask test #2: Captured less than %d packets", 2536);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IPv4), "IPFilter with mask test #2: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ipLayer->getSrcIpAddress().matchSubnet(IPv4Address(string("212.199.202.9")), string("255.255.255.0")), "IPFilter with mask test: packet doesn't match subnet mask. IP src: '%s'", ipLayer->getSrcIpAddress().toString().c_str());
	}
	rawPacketVec.clear();


	//-------------
	//Port range
	//-------------
	PortRangeFilter portRangeFilter(40000, 50000, SRC);
	portRangeFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(portRangeFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 1464, "PortRangeFilter: Captured less than %d packets", 1464);

	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP) || packet.isPacketOfType(UDP), "PortRangeFilter: one of the captured packets isn't of type TCP or UDP");
		if (packet.isPacketOfType(TCP))
		{
			TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
			uint16_t portSrc = ntohs(tcpLayer->getTcpHeader()->portSrc);
			PTF_ASSERT(portSrc >= 40000 && portSrc <=50000, "PortRangeFilter: TCP packet source port is out of range (40000-50000). Src port: %d", portSrc);
		}
		else if (packet.isPacketOfType(UDP))
		{
			UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
			uint16_t portSrc = ntohs(udpLayer->getUdpHeader()->portSrc);
			PTF_ASSERT(portSrc >= 40000 && portSrc <=50000, "PortRangeFilter: UDP packet source port is out of range (40000-50000). Src port: %d", portSrc);
		}
	}
	rawPacketVec.clear();


	//-------------------------
	//TCP flags filter
	//-------------------------
	uint8_t tcpFlagsBitMask(TcpFlagsFilter::tcpSyn|TcpFlagsFilter::tcpAck);
	TcpFlagsFilter tcpFlagsFilter(tcpFlagsBitMask, TcpFlagsFilter::MatchAll);
	tcpFlagsFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(tcpFlagsFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 65, "TcpFlagsFilter test #1: Captured less than 65 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "TcpFlagsFilter test #1: one of the captured packets isn't of type TCP");
		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
		PTF_ASSERT(tcpLayer->getTcpHeader()->synFlag == 1 && tcpLayer->getTcpHeader()->ackFlag == 1, "TcpFlagsFilter test #1: TCP packet isn't a SYN/ACK packet");
	}
	rawPacketVec.clear();

	tcpFlagsFilter.setTcpFlagsBitMask(tcpFlagsBitMask, TcpFlagsFilter::MatchOneAtLeast);
	tcpFlagsFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(tcpFlagsFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

    PTF_ASSERT(rawPacketVec.size() == 4489, "TcpFlagsFilter test #2: Captured less than 4489 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "TcpFlagsFilter test #2: one of the captured packets isn't of type TCP");
		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
		PTF_ASSERT(tcpLayer->getTcpHeader()->synFlag == 1 || tcpLayer->getTcpHeader()->ackFlag == 1, "TcpFlagsFilter test #2: TCP packet isn't a SYN or ACK packet");
	}

	rawPacketVec.clear();


	//------------
	//Proto filter
	//------------

	// ARP proto
	ProtoFilter protoFilter(ARP);
	protoFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev3.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev3.setFilter(protoFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev3.getNextPackets(rawPacketVec);
    fileReaderDev3.close();

	PTF_ASSERT(rawPacketVec.size() == 2, "ProtoFilter test #1: Captured less or more than 2 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(ARP), "ProtoFilter test #1: one of the captured packets isn't of type ARP");
	}
	rawPacketVec.clear();

	// TCP proto
	protoFilter.setProto(TCP);
	protoFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev3.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev3.setFilter(protoFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev3.getNextPackets(rawPacketVec);
    fileReaderDev3.close();

	PTF_ASSERT(rawPacketVec.size() == 9, "ProtoFilter test #2: Captured less or more than 9 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(TCP), "ProtoFilter test #2: one of the captured packets isn't of type TCP");
	}
	rawPacketVec.clear();

	// GRE proto
	protoFilter.setProto(GRE);
	protoFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev3.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev3.setFilter(protoFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev3.getNextPackets(rawPacketVec);
    fileReaderDev3.close();

	PTF_ASSERT(rawPacketVec.size() == 17, "ProtoFilter test #3: Captured less or more than 17 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(GRE), "ProtoFilter test #3: one of the captured packets isn't of type GRE");
	}
	rawPacketVec.clear();

	// UDP proto
	protoFilter.setProto(UDP);
	protoFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev4.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev4.setFilter(protoFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev4.getNextPackets(rawPacketVec);
    fileReaderDev4.close();

	PTF_ASSERT(rawPacketVec.size() == 38, "ProtoFilter test #4: Captured less or more than 38 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(UDP), "ProtoFilter test #4: one of the captured packets isn't of type UDP");
	}
	rawPacketVec.clear();

	// IGMP proto
	protoFilter.setProto(IGMP);
	protoFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev4.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev4.setFilter(protoFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev4.getNextPackets(rawPacketVec);
    fileReaderDev4.close();

	PTF_ASSERT(rawPacketVec.size() == 6, "ProtoFilter test #5: Captured less or more than 6 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(IGMP), "ProtoFilter test #5: one of the captured packets isn't of type IGMP");
	}
	rawPacketVec.clear();


	//-----------------------
	//And filter - Proto + IP
	//-----------------------

	IPFilter ipFilter("10.0.0.6", SRC);
	protoFilter.setProto(UDP);
    std::vector<GeneralFilter*> filterVec;
    filterVec.push_back(&ipFilter);
    filterVec.push_back(&protoFilter);
    AndFilter andFilter(filterVec);
    andFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev2.setFilter(andFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev2.getNextPackets(rawPacketVec);
    fileReaderDev2.close();

	PTF_ASSERT(rawPacketVec.size() == 69, "IP + Proto test: Captured less than %d packets", 69);
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		PTF_ASSERT(packet.isPacketOfType(UDP), "IP + Proto test: one of the captured packets isn't of type UDP");
		PTF_ASSERT(packet.isPacketOfType(IPv4), "IP + Proto test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PTF_ASSERT(ipv4Layer->getSrcIpAddress() == IPv4Address(std::string("10.0.0.6")), "IP + Proto test: srcIP is not 10.0.0.6");
	}

	rawPacketVec.clear();


	//------------------------------------------
	//Complex filter - (Proto1 and IP) || Proto2
	//------------------------------------------

	protoFilter.setProto(GRE);
	ipFilter.setAddr("20.0.0.1");
	ipFilter.setDirection(SRC_OR_DST);

	filterVec.clear();
	filterVec.push_back(&protoFilter);
	filterVec.push_back(&ipFilter);
	andFilter.setFilters(filterVec);

	filterVec.clear();
	ProtoFilter protoFilter2(ARP);
	filterVec.push_back(&protoFilter2);
	filterVec.push_back(&andFilter);
	OrFilter orFilter(filterVec);

	orFilter.parseToString(filterAsString);

    PTF_ASSERT(fileReaderDev3.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    PTF_ASSERT(fileReaderDev3.setFilter(orFilter), "Could not set filter: %s", filterAsString.c_str());
    fileReaderDev3.getNextPackets(rawPacketVec);
    fileReaderDev3.close();

	PTF_ASSERT(rawPacketVec.size() == 19, "Complex filter test: Captured less or more than 19 packets");
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		if (packet.isPacketOfType(ARP))
		{
			continue;
		}
		else
		{
			PTF_ASSERT(packet.isPacketOfType(GRE), "Complex filter test: one of the captured packets isn't of type ARP or GRE");
			PTF_ASSERT(packet.isPacketOfType(IPv4), "Complex filter test: one of the captured packets isn't of type IPv4");
			IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
			PTF_ASSERT(ipv4Layer->getSrcIpAddress() == IPv4Address(std::string("20.0.0.1"))
					|| ipv4Layer->getDstIpAddress() == IPv4Address(std::string("20.0.0.1")),
					"complex filter test: srcIP or dstIP is not 20.0.0.1");
		}

	}
	rawPacketVec.clear();
}

PTF_TEST_CASE(TestSendPacket)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
    PTF_ASSERT(liveDev->open(), "Cannot open live device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    PTF_ASSERT(liveDev->getMtu() > 0, "Could not get live device MTU");
    uint16_t mtu = liveDev->getMtu();
    int buffLen = mtu+1;
    uint8_t* buff = new uint8_t[buffLen];
    memset(buff, 0, buffLen);
    PTF_ASSERT(!liveDev->sendPacket(buff, buffLen), "Defected packet was sent successfully");

    RawPacket rawPacket;
    int packetsSent = 0;
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacket))
    {
    	packetsRead++;

    	//send packet as RawPacket
    	PTF_ASSERT(liveDev->sendPacket(rawPacket), "Could not send raw packet");

    	//send packet as raw data
    	PTF_ASSERT(liveDev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()), "Could not send raw data");

    	//send packet as parsed EthPacekt
    	Packet packet(&rawPacket);
    	PTF_ASSERT(liveDev->sendPacket(&packet), "Could not send parsed packet");

   		packetsSent++;
    }

    PTF_ASSERT(packetsRead == packetsSent, "Unexpected number of packets sent. Expected (read from file): %d; Sent: %d", packetsRead, packetsSent);

    liveDev->close();
    fileReaderDev.close();

	delete[] buff;
}

PTF_TEST_CASE(TestSendPackets)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
    PTF_ASSERT(liveDev->open(), "Cannot open live device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    RawPacket rawPacketArr[10000];
    PointerVector<Packet> packetVec;
    Packet* packetArr[10000];
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
    {
    	packetVec.pushBack(new Packet(&rawPacketArr[packetsRead]));
    	packetsRead++;
    }

    //send packets as RawPacket array
    int packetsSentAsRaw = liveDev->sendPackets(rawPacketArr, packetsRead);

    //send packets as parsed EthPacekt array
    std::copy(packetVec.begin(), packetVec.end(), packetArr);
    int packetsSentAsParsed = liveDev->sendPackets(packetArr, packetsRead);

    PTF_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRaw);
    PTF_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);

    liveDev->close();
    fileReaderDev.close();
}

PTF_TEST_CASE(TestRemoteCapture)
{
#ifdef WIN32
	bool useRemoteDevicesFromArgs = (PcapGlobalArgs.remoteIp != "") && (PcapGlobalArgs.remotePort > 0);
	string remoteDeviceIP = (useRemoteDevicesFromArgs ? PcapGlobalArgs.remoteIp : PcapGlobalArgs.ipToSendReceivePackets);
	uint16_t remoteDevicePort = (useRemoteDevicesFromArgs ? PcapGlobalArgs.remotePort : 12321);

	HANDLE rpcapdHandle = NULL;
	if (!useRemoteDevicesFromArgs)
	{
		rpcapdHandle = activateRpcapdServer(remoteDeviceIP, remoteDevicePort);
		PTF_ASSERT(rpcapdHandle != NULL, "Could not create rpcapd process. Error was: %lu", GetLastError());

	}

	IPv4Address remoteDeviceIPAddr(remoteDeviceIP);
	PcapRemoteDeviceList* remoteDevices = PcapRemoteDeviceList::getRemoteDeviceList(&remoteDeviceIPAddr, remoteDevicePort);
	PTF_ASSERT_AND_RUN_COMMAND(remoteDevices != NULL, terminateRpcapdServer(rpcapdHandle), "Error on retrieving remote devices on IP: %s port: %d. Error string was: %s", remoteDeviceIP.c_str(), remoteDevicePort, PcapGlobalArgs.errString);
	for (PcapRemoteDeviceList::RemoteDeviceListIterator remoteDevIter = remoteDevices->begin(); remoteDevIter != remoteDevices->end(); remoteDevIter++)
	{
		PTF_ASSERT_AND_RUN_COMMAND((*remoteDevIter)->getName() != NULL, terminateRpcapdServer(rpcapdHandle), "One of the remote devices has no name");
	}
	PTF_ASSERT_AND_RUN_COMMAND(remoteDevices->getRemoteMachineIpAddress()->toString() == remoteDeviceIP, terminateRpcapdServer(rpcapdHandle), "Remote machine IP got from device list doesn't match provided IP");
	PTF_ASSERT_AND_RUN_COMMAND(remoteDevices->getRemoteMachinePort() == remoteDevicePort, terminateRpcapdServer(rpcapdHandle), "Remote machine port got from device list doesn't match provided port");

	PcapRemoteDevice* pRemoteDevice = remoteDevices->getRemoteDeviceByIP(&remoteDeviceIPAddr);
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getDeviceType() == PcapLiveDevice::RemoteDevice, terminateRpcapdServer(rpcapdHandle), "Remote device type isn't 'RemoteDevice'");
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getMtu() == 0, terminateRpcapdServer(rpcapdHandle), "MTU of remote device isn't 0");
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getMacAddress() == MacAddress::Zero, terminateRpcapdServer(rpcapdHandle), "MAC address of remote device isn't zero");
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getRemoteMachineIpAddress()->toString() == remoteDeviceIP, terminateRpcapdServer(rpcapdHandle), "Remote machine IP got from device doesn't match provided IP");
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getRemoteMachinePort() == remoteDevicePort, terminateRpcapdServer(rpcapdHandle), "Remote machine port got from device doesn't match provided port");
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->open(), terminateRpcapdServer(rpcapdHandle), "Could not open the remote device. Error was: %s", PcapGlobalArgs.errString);
	RawPacketVector capturedPackets;
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->startCapture(capturedPackets), terminateRpcapdServer(rpcapdHandle), "Couldn't start capturing on remote device '%s'. Error was: %s", pRemoteDevice->getName(), PcapGlobalArgs.errString);

	if (!useRemoteDevicesFromArgs)
		PTF_ASSERT_AND_RUN_COMMAND(sendURLRequest("www.yahoo.com"), terminateRpcapdServer(rpcapdHandle), "Couldn't send URL");

	PCAP_SLEEP(20);
	pRemoteDevice->stopCapture();

	//send single packet
	PTF_ASSERT_AND_RUN_COMMAND(pRemoteDevice->sendPacket(*capturedPackets.front()), terminateRpcapdServer(rpcapdHandle), "Couldn't send a packet. Error was: %s", PcapGlobalArgs.errString);

	//send multiple packets
	RawPacketVector packetsToSend;
	vector<RawPacket*>::iterator iter = capturedPackets.begin();

	size_t capturedPacketsSize = capturedPackets.size();
	while (iter != capturedPackets.end())
	{
		if ((*iter)->getRawDataLen() <= pRemoteDevice->getMtu())
		{
			packetsToSend.pushBack(capturedPackets.getAndRemoveFromVector(iter));
		}
		else
			++iter;
	}
	int packetsSent = pRemoteDevice->sendPackets(packetsToSend);
	PTF_ASSERT_AND_RUN_COMMAND(packetsSent == (int)packetsToSend.size(), terminateRpcapdServer(rpcapdHandle), "%d packets sent out of %d. Error was: %s", packetsSent, packetsToSend.size(), PcapGlobalArgs.errString);

	//check statistics
	pcap_stat stats;
	pRemoteDevice->getStatistics(stats);
	PTF_ASSERT_AND_RUN_COMMAND(stats.ps_recv == capturedPacketsSize, terminateRpcapdServer(rpcapdHandle),
			"Statistics returned from rpcapd doesn't equal the captured packets vector size. Stats: %d; Vector size: %d",
			stats.ps_recv, capturedPacketsSize);

	pRemoteDevice->close();

	terminateRpcapdServer(rpcapdHandle);

	delete remoteDevices;
#endif


}

PTF_TEST_CASE(TestHttpRequestParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_REQUEST);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");

    RawPacket rawPacket;
    int packetCount = 0;

    int httpPackets = 0;
    int getReqs = 0;
    int postReqs = 0;
    int headReqs = 0;
    int optionsReqs = 0;
    int otherMethodReqs = 0;

    int swfReqs = 0;
    int homeReqs = 0;

    int winwinReqs = 0;
    int yad2Reqs = 0;
    int googleReqs = 0;

    int ieReqs = 0;
    int ffReqs = 0;
    int chromeReqs = 0;

    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(HTTPRequest))
			httpPackets++;
		else
			continue;

		HttpRequestLayer* httpReqLayer = packet.getLayerOfType<HttpRequestLayer>();
		PTF_ASSERT(httpReqLayer->getFirstLine() != NULL, "HTTP first line is null in packet #%d, HTTP request #%d", packetCount, httpPackets);
		switch (httpReqLayer->getFirstLine()->getMethod())
		{
		case HttpRequestLayer::HttpGET:
			getReqs++;
			break;
		case HttpRequestLayer::HttpPOST:
			postReqs++;
			break;
		case HttpRequestLayer::HttpOPTIONS:
			optionsReqs++;
			break;
		case HttpRequestLayer::HttpHEAD:
			headReqs++;
			break;
		default:
			otherMethodReqs++;
		}


		if (httpReqLayer->getFirstLine()->isComplete())
		{
			PTF_ASSERT(httpReqLayer->getFirstLine()->getVersion() == OneDotOne, "HTTP version is different than 1.1 in packet #%d, HTTP request #%d", packetCount, httpPackets);
		}

		if (httpReqLayer->getFirstLine()->getUri().find(".swf") != std::string::npos)
			swfReqs++;
		else if (httpReqLayer->getFirstLine()->getUri().find("home") != std::string::npos)
			homeReqs++;

		HeaderField* hostField = httpReqLayer->getFieldByName("Host");
		if (hostField != NULL)
		{
			std::string host = hostField->getFieldValue();
			if (host == "www.winwin.co.il")
				winwinReqs++;
			else if (host == "www.yad2.co.il")
				yad2Reqs++;
			else if (host == "www.google.com")
				googleReqs++;
		}

		HeaderField* userAgentField = httpReqLayer->getFieldByName("User-Agent");
		if (userAgentField == NULL)
			continue;

		std::string userAgent = userAgentField->getFieldValue();
		if (userAgent.find("Trident/7.0") != std::string::npos)
			ieReqs++;
		else if (userAgent.find("Firefox/33.0") != std::string::npos)
			ffReqs++;
		else if (userAgent.find("Chrome/38.0") != std::string::npos)
			chromeReqs++;
    }

    readerDev.close();

    PTF_ASSERT(packetCount == 385, "Packet count is wrong. Actual: %d; Expected: %d", packetCount, 385);

    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ")
    PTF_ASSERT(httpPackets == 385, "HTTP packet count is wrong. Actual: %d; Expected: %d", httpPackets, 385);


    PTF_ASSERT(otherMethodReqs == 0, "Parsed %d HTTP requests with unexpected method", otherMethodReqs);

    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET ")
    PTF_ASSERT(getReqs == 217, "Number of GET requests different than expected. Actual: %d; Expected: %d", getReqs, 217);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "POST ")
    PTF_ASSERT(postReqs == 156, "Number of POST requests different than expected. Actual: %d; Expected: %d", postReqs, 156);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "OPTIONS ")
    PTF_ASSERT(optionsReqs == 7, "Number of OPTIONS requests different than expected. Actual: %d; Expected: %d", optionsReqs, 7);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "HEAD ")
    PTF_ASSERT(headReqs == 5, "Number of HEAD requests different than expected. Actual: %d; Expected: %d", headReqs, 5);


    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST ") && (tcp matches "home.*HTTP/1.1")
    PTF_ASSERT(homeReqs == 13, "Number of requests with URI contains 'home' is different than expected. Actual: %d; Expected: %d", homeReqs, 13);
    // Wireshark filter: http.request.full_uri contains .swf
    PTF_ASSERT(swfReqs == 4, "Number of requests with URI contains '.swf' is different than expected. Actual: %d; Expected: %d", swfReqs, 4);

    // Wireshark filter: tcp contains "Host: www.google.com"
    PTF_ASSERT(googleReqs == 12, "Number of requests from www.google.com is different than expected. Actual: %d; Expected: %d", googleReqs, 12);
    // Wireshark filter: tcp contains "Host: www.yad2.co.il"
    PTF_ASSERT(yad2Reqs == 15, "Number of requests from www.yad2.co.il is different than expected. Actual: %d; Expected: %d", yad2Reqs, 15);
    // Wireshark filter: tcp contains "Host: www.winwin.co.il"
    PTF_ASSERT(winwinReqs == 20, "Number of requests from www.winwin.co.il is different than expected. Actual: %d; Expected: %d", winwinReqs, 20);


    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Firefox/33.0")
    PTF_ASSERT(ffReqs == 233, "Number of Firefox requests is different than expected. Actual: %d; Expected: %d", ffReqs, 233);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Chrome/38.0")
    PTF_ASSERT(chromeReqs == 82, "Number of Chrome requests is different than expected. Actual: %d; Expected: %d", chromeReqs, 82);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Trident/7.0")
    PTF_ASSERT(ieReqs == 55, "Number of IE requests is different than expected. Actual: %d; Expected: %d", ieReqs, 55);


}

PTF_TEST_CASE(TestHttpResponseParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_RESPONSE);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");

    RawPacket rawPacket;
    int packetCount = 0;
    int httpResponsePackets = 0;

	int statusCodes[80];

	int textHtmlCount = 0;
	int imageCount = 0;
	int gzipCount = 0;
	int chunkedCount = 0;

	int bigResponses = 0;

	memset(statusCodes, 0, 80*sizeof(int));

    while (readerDev.getNextPacket(rawPacket))
    {
    	packetCount++;
    	Packet packet(&rawPacket);
		if (packet.isPacketOfType(HTTPResponse))
			httpResponsePackets++;
		else
			continue;

		HttpResponseLayer* httpResLayer = packet.getLayerOfType<HttpResponseLayer>();
		PTF_ASSERT(httpResLayer->getFirstLine() != NULL, "HTTP first line is null in packet #%d, HTTP request #%d", packetCount, httpResponsePackets);
		statusCodes[httpResLayer->getFirstLine()->getStatusCode()]++;

		HeaderField* contentTypeField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		if (contentTypeField != NULL)
		{
			std::string contentType = contentTypeField->getFieldValue();
			if (contentType.find("image/") != std::string::npos)
				imageCount++;
			else if (contentType == "text/html")
				textHtmlCount++;
		}

		HeaderField* contentEncodingField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_ENCODING_FIELD);
		if (contentEncodingField != NULL && contentEncodingField->getFieldValue() == "gzip")
			gzipCount++;

		HeaderField* transferEncodingField = httpResLayer->getFieldByName(PCPP_HTTP_TRANSFER_ENCODING_FIELD);
		if (transferEncodingField != NULL && transferEncodingField->getFieldValue() == "chunked")
			chunkedCount++;

		HeaderField* contentLengthField = httpResLayer->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
		if (contentLengthField != NULL)
		{
			std::string lengthAsString = contentLengthField->getFieldValue();
			int length = atoi(lengthAsString.c_str());
			if (length > 100000)
				bigResponses++;
		}


    }

    PTF_ASSERT(packetCount == 682, "Packet count is different than expected. Found: %d; Expected: 682", packetCount);

    // *** wireshark has a bug there and displays 1 less packet as http response. Missing packet IP ID is 10419 ***
    // ************************************************************************************************************

    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080)
    PTF_ASSERT(httpResponsePackets == 682, "HTTP response count is different than expected. Found: %d; Expected: 682", httpResponsePackets);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 200
    PTF_ASSERT(statusCodes[HttpResponseLayer::Http200OK] == 592, "HTTP response with 200 OK count is different than expected. Found: %d; Expected: 592", statusCodes[HttpResponseLayer::Http200OK]);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 302
    PTF_ASSERT(statusCodes[HttpResponseLayer::Http302] == 15, "HTTP response with 302 count is different than expected. Found: %d; Expected: 15", statusCodes[HttpResponseLayer::Http302]);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 304
    PTF_ASSERT(statusCodes[HttpResponseLayer::Http304NotModified] == 26, "HTTP response with 304 count is different than expected. Found: %d; Expected: 26", statusCodes[HttpResponseLayer::Http304NotModified]);

    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type == "text/html"
    PTF_ASSERT(textHtmlCount == 38, "HTTP responses with content-type=='text/html' is different than expected. Expected: %d; Actual: %d", 38, textHtmlCount);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type contains "image/"
    PTF_ASSERT(imageCount == 369, "HTTP responses with content-type=='image/*' is different than expected. Expected: %d; Actual: %d", 369, imageCount);

    // wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && (tcp contains "Transfer-Encoding:  chunked" || tcp contains "Transfer-Encoding: chunked" || tcp contains "transfer-encoding: chunked")
    PTF_ASSERT(chunkedCount == 45, "HTTP responses with transfer-encoding=='chunked' is different than expected. Expected: %d; Actual: %d", 45, chunkedCount);
    // wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && tcp contains "Content-Encoding: gzip"
    PTF_ASSERT(gzipCount == 148, "HTTP responses with content-encoding=='gzip' is different than expected. Expected: %d; Actual: %d", 148, gzipCount);

    // wireshark filter: http.content_length > 100000
    PTF_ASSERT(bigResponses == 14, "HTTP responses with content-length > 100K is different than expected. Expected: %d; Actual: %d", 14, bigResponses);

//    printf("Total HTTP response packets: %d\n", httpResponsePackets);
//    printf("200 OK packets: %d\n", statusCodes[HttpResponseLayer::Http200OK]);
//    printf("302 packets: %d\n", statusCodes[HttpResponseLayer::Http302]);
//    printf("304 Not Modified packets: %d\n", statusCodes[HttpResponseLayer::Http304NotModified]);
//    printf("text/html responses: %d\n", textHtmlCount);
//    printf("image responses: %d\n", imageCount);
//    printf("gzip responses: %d\n", gzipCount);
//    printf("chunked responses: %d\n", chunkedCount);
//    printf("big responses: %d\n", bigResponses);


}

PTF_TEST_CASE(TestPrintPacketAndLayers)
{
	PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PTF_ASSERT(reader.open(), "Cannot open reader device for '%s'", EXAMPLE2_PCAP_PATH);
	RawPacket rawPacket;
	ostringstream outputStream;
	while (reader.getNextPacket(rawPacket))
	{
		Packet packet(&rawPacket);
		outputStream << packet.toString(false) << "\n\n";
	}

//	ofstream outputFile("output.txt");
//	outputFile << outputStream.str();
//	outputFile.close();

	ifstream referenceFile("PcapExamples/example2_summary.txt");
	stringstream referenceBuffer;
	referenceBuffer << referenceFile.rdbuf();
	referenceFile.close();

	// example2_summary.txt was written with Windows so every '\n' is translated to '\r\n'
	// in Linux '\n' stays '\n' in writing to files. So these lines of code are meant to remove the '\r' so
	// files can be later compared
	std::string referenceBufferAsString = referenceBuffer.str();
	size_t index = 0;
	while (true) {
	     index = referenceBufferAsString.find("\r\n", index);
	     if (index == string::npos) break;
	     referenceBufferAsString.replace(index, 2, "\n");
	     index += 1;
	}

	PTF_ASSERT(referenceBufferAsString == outputStream.str(), "Output is different than reference file");


}

PTF_TEST_CASE(TestPfRingDevice)
{
#ifdef USE_PF_RING

	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PTF_ASSERT(devList.getPfRingDevicesList().size() > 0, "PF_RING device list contains 0 devices");
	PTF_ASSERT(devList.getPfRingVersion() != "", "Couldn't retrieve PF_RING version");
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PTF_ASSERT(dev != NULL, "Couldn't find PF_RING device with name '%s'", pcapLiveDev->getName());
	PTF_ASSERT(dev->getMacAddress().isValid() == true, "Dev MAC addr isn't valid");
	PTF_ASSERT(dev->getMacAddress() != MacAddress::Zero, "Dev MAC addr is zero");
	PTF_ASSERT(dev->getInterfaceIndex() > 0, "Dev interface index is zero");
	PTF_ASSERT(dev->getTotalNumOfRxChannels() > 0, "Number of RX channels is zero");
	PTF_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "Number of open RX channels isn't zero");
	PTF_ASSERT(dev->open() == true, "Cannot open PF_RING device");
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->open() == false, "Managed to open the device twice");
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT(dev->getNumOfOpenedRxChannels() == 1, "After device is open number of open RX channels != 1, it's %d", dev->getNumOfOpenedRxChannels());

	PfRingPacketData packetData;
	PTF_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData), "Couldn't start capturing");
	PCAP_SLEEP(5); //TODO: put this on 10-20 sec
	dev->stopCapture();
	PTF_ASSERT(packetData.PacketCount > 0, "No packets were captured");
	PTF_ASSERT(packetData.ThreadId != -1, "Couldn't retrieve thread ID");

	PfRingDevice::PfRingStats stats;
	stats.recv = 0;
	stats.drop = 0;
	dev->getStatistics(stats);
	PTF_ASSERT(stats.recv == (uint32_t)packetData.PacketCount, "Stats received packet count is different than calculated packet count");
	dev->close();

	PTF_PRINT_VERBOSE("Thread ID: %d", packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: %d", packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: %d", packetData.EthCount);
	PTF_PRINT_VERBOSE("IP packets: %d", packetData.IpCount);
	PTF_PRINT_VERBOSE("TCP packets: %d", packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: %d", packetData.UdpCount);
	PTF_PRINT_VERBOSE("Device statistics:");
	PTF_PRINT_VERBOSE("Packets captured: %d", (int)stats.recv);
	PTF_PRINT_VERBOSE("Packets dropped: %d", (int)stats.drop);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestPfRingDeviceSingleChannel)
{
#ifdef USE_PF_RING

	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PfRingPacketData packetData;
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels()+1) == false, "Wrongly succeeded opening the device on a RX channel [%d] that doesn't exist open device on RX channel", dev->getTotalNumOfRxChannels()+1);
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels()-1) == true, "Couldn't open device on RX channel %d", dev->getTotalNumOfRxChannels());
	PTF_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData), "Couldn't start capturing");
	PCAP_SLEEP(5); //TODO: put this on 10-20 sec
	dev->stopCapture();
	PTF_ASSERT(packetData.PacketCount > 0, "No packets were captured");
	PTF_ASSERT(packetData.ThreadId != -1, "Couldn't retrieve thread ID");
	PfRingDevice::PfRingStats stats;
	dev->getStatistics(stats);
	PTF_ASSERT(stats.recv == (uint32_t)packetData.PacketCount, "Stats received packet count is different than calculated packet count");
	PTF_PRINT_VERBOSE("Thread ID: %d", packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: %d", packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: %d", packetData.EthCount);
	PTF_PRINT_VERBOSE("IP packets: %d", packetData.IpCount);
	PTF_PRINT_VERBOSE("TCP packets: %d", packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: %d", packetData.UdpCount);
	PTF_PRINT_VERBOSE("Packets captured: %d", (int)stats.recv);
	PTF_PRINT_VERBOSE("Packets dropped: %d", (int)stats.drop);

	dev->close();
	PTF_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "There are still open RX channels after device close");


#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}


void TestPfRingDeviceMultiThread(int& ptfResult, CoreMask coreMask)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	uint8_t numOfChannels = dev->getTotalNumOfRxChannels();
	PTF_ASSERT(dev->openMultiRxChannels(numOfChannels*2.5, PfRingDevice::PerFlow) == true, "Couldn't open device with %d channels", (int)(numOfChannels*2.5));
	dev->close();
	PTF_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "There are still open RX channels after device close");
	int totalnumOfCores = getNumOfCores();
	int numOfCoresInUse = 0;
	CoreMask tempCoreMaske = coreMask;
	int i = 0;
	while ((tempCoreMaske != 0) && (i < totalnumOfCores))
	{
		if (tempCoreMaske & 1)
		{
			numOfCoresInUse++;
		}

		tempCoreMaske = tempCoreMaske >> 1;
		i++;
	}

	PTF_ASSERT(dev->openMultiRxChannels((uint8_t)numOfCoresInUse, PfRingDevice::PerFlow) == true, "Couldn't open device with %d channels", totalnumOfCores);
	PfRingPacketData packetDataMultiThread[totalnumOfCores];
	PTF_ASSERT(dev->startCaptureMultiThread(pfRingPacketsArriveMultiThread, packetDataMultiThread, coreMask), "Couldn't start capturing multi-thread");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PfRingDevice::PfRingStats aggrStats;
	aggrStats.recv = 0;
	aggrStats.drop = 0;

	PfRingDevice::PfRingStats stats;
	for (int i = 0; i < totalnumOfCores; i++)
	{
		if ((SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
			continue;

		PTF_PRINT_VERBOSE("Thread ID: %d", packetDataMultiThread[i].ThreadId);
		PTF_PRINT_VERBOSE("Total packets captured: %d", packetDataMultiThread[i].PacketCount);
		PTF_PRINT_VERBOSE("Eth packets: %d", packetDataMultiThread[i].EthCount);
		PTF_PRINT_VERBOSE("IP packets: %d", packetDataMultiThread[i].IpCount);
		PTF_PRINT_VERBOSE("TCP packets: %d", packetDataMultiThread[i].TcpCount);
		PTF_PRINT_VERBOSE("UDP packets: %d", packetDataMultiThread[i].UdpCount);
		dev->getThreadStatistics(SystemCores::IdToSystemCore[i], stats);
		aggrStats.recv += stats.recv;
		aggrStats.drop += stats.drop;
		PTF_PRINT_VERBOSE("Packets captured: %d", (int)stats.recv);
		PTF_PRINT_VERBOSE("Packets dropped: %d", (int)stats.drop);
		PTF_ASSERT(stats.recv == (uint32_t)packetDataMultiThread[i].PacketCount, "Stats received packet count is different than calculated packet count on thread %d", packetDataMultiThread[i].ThreadId);
	}

	dev->getStatistics(stats);
	PTF_ASSERT(aggrStats.recv == stats.recv, "Aggregated stats weren't calculated correctly: aggr recv = %d, calc recv = %d", (int)stats.recv, (int)aggrStats.recv);
	PTF_ASSERT(aggrStats.drop == stats.drop, "Aggregated stats weren't calculated correctly: aggr drop = %d, calc drop = %d", (int)stats.drop, (int)aggrStats.drop);

	for (int firstCoreId = 0; firstCoreId < totalnumOfCores; firstCoreId++)
	{
		for (int secondCoreId = firstCoreId+1; secondCoreId < totalnumOfCores; secondCoreId++)
		{
			map<uint32_t, pair<RawPacketVector, RawPacketVector> > res;
			intersectMaps<uint32_t, RawPacketVector, RawPacketVector>(packetDataMultiThread[firstCoreId].FlowKeys, packetDataMultiThread[secondCoreId].FlowKeys, res);
			PTF_ASSERT(res.size() == 0, "%d flows appear in core %d and core %d", (int)res.size(), firstCoreId, secondCoreId);
			if (PTF_IS_VERBOSE_MODE)
			{
				for (map<uint32_t, pair<RawPacketVector, RawPacketVector> >::iterator iter = res.begin(); iter != res.end(); iter++)
				{
					PTF_PRINT_VERBOSE("Same flow exists in core %d and core %d. Flow key = %X", firstCoreId, secondCoreId, iter->first);
					ostringstream stream;
					stream << "Core" << firstCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					PcapFileWriterDevice writerDev(stream.str().c_str());
					writerDev.open();
					writerDev.writePackets(iter->second.first);
					writerDev.close();

					ostringstream stream2;
					stream2 << "Core" << secondCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					PcapFileWriterDevice writerDev2(stream2.str().c_str());
					writerDev2.open();
					writerDev2.writePackets(iter->second.second);
					writerDev2.close();

					iter->second.first.clear();
					iter->second.second.clear();

				}
			}
		}
		PTF_PRINT_VERBOSE("Core %d\n========", firstCoreId);
		PTF_PRINT_VERBOSE("Total flows: %d", (int)packetDataMultiThread[firstCoreId].FlowKeys.size());

		if (PTF_IS_VERBOSE_MODE)
		{
			for(map<uint32_t, RawPacketVector>::iterator iter = packetDataMultiThread[firstCoreId].FlowKeys.begin(); iter != packetDataMultiThread[firstCoreId].FlowKeys.end(); iter++) {
				PTF_PRINT_VERBOSE("Key=%X; Value=%d", iter->first, (int)iter->second.size());
				iter->second.clear();
			}
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();

		dev->close();
	}

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestPfRingMultiThreadAllCores)
{
#ifdef USE_PF_RING
	int numOfCores = getNumOfCores();
	CoreMask coreMask = 0;
	for (int i = 0; i < numOfCores; i++)
	{
		coreMask |= SystemCores::IdToSystemCore[i].Mask;
	}

	TestPfRingDeviceMultiThread(ptfResult, coreMask);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif

}

PTF_TEST_CASE(TestPfRingMultiThreadSomeCores)
{
#ifdef USE_PF_RING
	int numOfCores = getNumOfCores();
	CoreMask coreMask = 0;
	for (int i = 0; i < numOfCores; i++)
	{
		if (i % 2 != 0)
			continue;
		coreMask |= SystemCores::IdToSystemCore[i].Mask;
	}

	TestPfRingDeviceMultiThread(ptfResult, coreMask);

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestPfRingSendPacket)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));
	PTF_ASSERT(dev->open(), "Could not open PF_RING device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    PTF_ASSERT(dev->getMtu() > 0, "Could not get device MTU");
    uint16_t mtu = dev->getMtu();
    int buffLen = mtu+1;
    uint8_t buff[buffLen];
    memset(buff, 0, buffLen);
    //LoggerPP::getInstance().supressErrors();
    //PTF_ASSERT(!dev->sendPacket(buff, buffLen), "Defected packet was sent successfully");
    //LoggerPP::getInstance().enableErrors();

    RawPacket rawPacket;
    int packetsSent = 0;
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacket))
    {
    	packetsRead++;

    	RawPacket origRawPacket = rawPacket;
    	//send packet as RawPacket
    	PTF_ASSERT_AND_RUN_COMMAND(dev->sendPacket(rawPacket), dev->close(), "Sent %d packets. Could not send another raw packet", (packetsRead-1)*3);

    	//send packet as raw data
    	PTF_ASSERT_AND_RUN_COMMAND(dev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()), dev->close(), "Sent %d packets. Could not send another raw data", (packetsRead-1)*3+1);

    	//send packet as parsed EthPacekt
    	Packet packet(&rawPacket);
    	PTF_ASSERT_AND_RUN_COMMAND(dev->sendPacket(packet), dev->close(), "Sent %d packets. Could not send another parsed packet", (packetsRead-1)*3+2);

   		packetsSent++;
    }

    PTF_ASSERT(packetsRead == packetsSent, "Unexpected number of packets sent. Expected (read from file): %d; Sent: %d", packetsRead, packetsSent);

    dev->close();

    fileReaderDev.close();

    // send some packets with single channel open
    PTF_ASSERT(dev->openSingleRxChannel(0), "Could not open PF_RING device with single channel 0");
    fileReaderDev.open();
    while(fileReaderDev.getNextPacket(rawPacket))
    	PTF_ASSERT(dev->sendPacket(rawPacket), "Could not send raw packet");

    dev->close();

    fileReaderDev.close();

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestPfRingSendPackets)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));
	PTF_ASSERT(dev->open(), "Could not open PF_RING device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    RawPacket rawPacketArr[10000];
    PointerVector<Packet> packetVec;
    const Packet* packetArr[10000];
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
    {
    	packetVec.pushBack(new Packet(&rawPacketArr[packetsRead]));
      	packetsRead++;
    }

    //send packets as RawPacket array
    int packetsSentAsRaw = dev->sendPackets(rawPacketArr, packetsRead);

    //send packets as parsed EthPacekt array
    std::copy(packetVec.begin(), packetVec.end(), packetArr);
    int packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead);

    PTF_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRaw);
    PTF_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);

    dev->close();
    fileReaderDev.close();

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestPfRingFilters)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PTF_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PTF_ASSERT(dev->isFilterCurrentlySet() == false, "Device indicating filter is set although we didn't set any filters yet");
	PTF_ASSERT(dev->clearFilter() == true, "clearFilter returned false although no filter was set yet");
	ProtoFilter protocolFilter(TCP);
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->setFilter(protocolFilter) == false, "Succeed setting a filter while device is closed");
	LoggerPP::getInstance().enableErrors();

	PTF_ASSERT(dev->open(), "Could not open PF_RING device");
	PTF_ASSERT(dev->setFilter(protocolFilter) == true, "Couldn't set TCP filter");

	// verfiy TCP filter
	SetFilterInstruction instruction = { 1, "" }; // instruction #1: verify all packets are of type TCP
	PTF_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PTF_ASSERT(instruction.Instruction == 1, "TCP protocol filter failed: some of the packets aren't of protocol TCP");

	instruction.Instruction = 2;
	instruction.Data = PcapGlobalArgs.ipToSendReceivePackets;
	IPFilter ipFilter(PcapGlobalArgs.ipToSendReceivePackets, SRC);
	PTF_ASSERT(dev->setFilter(ipFilter) == true, "Couldn't set IP filter");
	PTF_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PTF_ASSERT(instruction.Instruction == 2, "IP filter failed: some of the packets doens't match IP src filter");

	// remove filter and test again
	instruction.Instruction = 1;
	instruction.Data = "";
	PTF_ASSERT(dev->isFilterCurrentlySet() == true, "Device indicating filter isn't set although we set a filter");
	PTF_ASSERT(dev->clearFilter() == true, "clearfilter failed");
	PTF_ASSERT(dev->isFilterCurrentlySet() == false, "Device indicating filter still exists although we removed it");
	PTF_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PTF_ASSERT(instruction.Instruction == 0, "All packet are still of type TCP although filter was removed");

#else
	PTF_SKIP_TEST("PF_RING not configured");
#endif
}

PTF_TEST_CASE(TestDnsParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_DNS);
    PTF_ASSERT(readerDev.open(), "cannot open reader device");

    RawPacket rawPacket;
    int dnsPackets = 0;

    int packetsContainingDnsQuery = 0;
    int packetsContainingDnsAnswer = 0;
    int packetsContainingDnsAuthority = 0;
    int packetsContainingDnsAdditional = 0;

    int queriesWithNameGoogle = 0;
    int queriesWithNameMozillaOrg = 0; //aus3.mozilla.org
    int queriesWithTypeA = 0;
    int queriesWithTypeNotA = 0;
    int queriesWithClassIN = 0;

    int answersWithTypeCNAME = 0;
    int answersWithTypePTR = 0;
    int answersWithNameGoogleAnalytics = 0;
    int answersWithTtlLessThan30 = 0;
    int answersWithDataCertainIPv6 = 0;

    int authoritiesWithNameYaelPhone = 0;
    int authoritiesWithData10_0_0_2 = 0;

    int additionalWithEmptyName = 0;
    int additionalWithLongUglyName = 0;
    int additionalWithTypeNSEC = 0;

    while (readerDev.getNextPacket(rawPacket))
    {
    	dnsPackets++;
    	Packet packet(&rawPacket);
    	PTF_ASSERT_AND_RUN_COMMAND(packet.isPacketOfType(DNS), readerDev.close(), "Packet isn't of type DNS");

		DnsLayer* dnsLayer = packet.getLayerOfType<DnsLayer>();
		if (dnsLayer->getQueryCount() > 0)
		{
			packetsContainingDnsQuery++;

			if (dnsLayer->getQuery("aus3.mozilla.org", true) != NULL)
				queriesWithNameMozillaOrg++;
			if (dnsLayer->getQuery("www.google.com", true) != NULL)
				queriesWithNameGoogle++;

			bool isTypeA = false;
			bool isClassIN = false;

			for (DnsQuery* query = dnsLayer->getFirstQuery(); query != NULL; query = dnsLayer->getNextQuery(query))
			{
				if (query->getDnsType() == DNS_TYPE_A)
					isTypeA = true;
				if (query->getDnsClass() == DNS_CLASS_IN || query->getDnsClass() == DNS_CLASS_IN_QU)
					isClassIN = true;
			}

			if (isTypeA)
				queriesWithTypeA++;
			else
				queriesWithTypeNotA++;
			if (isClassIN)
				queriesWithClassIN++;
		}

		if (dnsLayer->getAnswerCount() > 0)
		{
			packetsContainingDnsAnswer++;

			if (dnsLayer->getAnswer("www.google-analytics.com", true) != NULL)
				answersWithNameGoogleAnalytics++;

			bool isTypeCNAME = false;
			bool isTypePTR = false;
			bool isTtlLessThan30 = false;

			for (DnsResource* answer = dnsLayer->getFirstAnswer(); answer != NULL; answer = dnsLayer->getNextAnswer(answer))
			{
				if (answer->getTTL() < 30)
					isTtlLessThan30 = true;
				if (answer->getDnsType() == DNS_TYPE_CNAME)
					isTypeCNAME = true;
				if (answer->getDnsType() == DNS_TYPE_PTR)
					isTypePTR = true;
				if (answer->getData()->toString() == "fe80::5a1f:aaff:fe4f:3f9d")
					answersWithDataCertainIPv6++;
			}

			if (isTypeCNAME)
				answersWithTypeCNAME++;
			if (isTypePTR)
				answersWithTypePTR++;
			if (isTtlLessThan30)
				answersWithTtlLessThan30++;
		}

		if (dnsLayer->getAuthorityCount() > 0)
		{
			packetsContainingDnsAuthority++;

			if (dnsLayer->getAuthority("Yaels-iPhone.local", true) != NULL)
				authoritiesWithNameYaelPhone++;

			for (DnsResource* auth = dnsLayer->getFirstAuthority(); auth != NULL; auth = dnsLayer->getNextAuthority(auth))
			{
				if (auth->getData()->toString() == "10.0.0.2")
				{
					authoritiesWithData10_0_0_2++;
					break;
				}
			}
		}

		if (dnsLayer->getAdditionalRecordCount() > 0)
		{
			packetsContainingDnsAdditional++;

			if (dnsLayer->getAdditionalRecord("", true) != NULL)
				additionalWithEmptyName++;

			if (dnsLayer->getAdditionalRecord("D.9.F.3.F.4.E.F.F.F.A.A.F.1.A.5.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa", true) != NULL)
				additionalWithLongUglyName++;

			bool isTypeNSEC = false;

			for (DnsResource* add = dnsLayer->getFirstAdditionalRecord(); add != NULL; add = dnsLayer->getNextAdditionalRecord(add))
			{
				if (add->getDnsType() == DNS_TYPE_NSEC)
					isTypeNSEC = true;
			}

			if (isTypeNSEC)
				additionalWithTypeNSEC++;
		}
    }

    PTF_ASSERT(dnsPackets == 464, "Number of DNS packets different than expected. Found: %d; Expected: 464", dnsPackets);

    // wireshark filter: dns.count.queries > 0
    PTF_ASSERT(packetsContainingDnsQuery == 450, "DNS query count different than expected. Found: %d; Expected: 450", packetsContainingDnsQuery);
    // wireshark filter: dns.count.answers > 0
    PTF_ASSERT(packetsContainingDnsAnswer == 224, "DNS answer count different than expected. Found: %d; Expected: 224", packetsContainingDnsAnswer);
    // wireshark filter: dns.count.auth_rr > 0
    PTF_ASSERT(packetsContainingDnsAuthority == 11, "DNS authority count different than expected. Found: %d; Expected: 11", packetsContainingDnsAuthority);
    // wireshark filter: dns.count.add_rr > 0
    PTF_ASSERT(packetsContainingDnsAdditional == 23, "DNS additional record count different than expected. Found: %d; Expected: 23", packetsContainingDnsAdditional);

    // wireshark filter: dns.qry.name == www.google.com
    PTF_ASSERT(queriesWithNameGoogle == 14, "DNS queries with name 'www.google.com' different than expected. Found: %d; Expected: 14", queriesWithNameGoogle);
    // wireshark filter: dns.qry.name == aus3.mozilla.org
    PTF_ASSERT(queriesWithNameMozillaOrg == 2, "DNS queries with name 'aus3.mozilla.org' different than expected. Found: %d; Expected: 2", queriesWithNameMozillaOrg);
    // wireshark filter: dns.qry.type == 1
    PTF_ASSERT(queriesWithTypeA == 436, "DNS queries with type A different than expected. Found: %d; Expected: 436", queriesWithTypeA);
    // wireshark filter: dns.qry.type > 0 and not (dns.qry.type == 1)
    PTF_ASSERT(queriesWithTypeNotA == 14, "DNS queries with type not A different than expected. Found: %d; Expected: 14", queriesWithTypeNotA);
    // wireshark filter: dns.qry.class == 1
    PTF_ASSERT(queriesWithClassIN == 450, "DNS queries with class IN different than expected. Found: %d; Expected: 450", queriesWithClassIN);

    // wireshark filter: dns.count.answers > 0 and dns.resp.type == 12
    PTF_ASSERT(answersWithTypePTR == 14, "DNS answers with type PTR different than expected. Found: %d; Expected: 14", answersWithTypePTR);
    // wireshark filter: dns.count.answers > 0 and dns.resp.type == 5
    PTF_ASSERT(answersWithTypeCNAME == 90, "DNS answers with type CNAME different than expected. Found: %d; Expected: 90", answersWithTypeCNAME);
    // wireshark filter: dns.count.answers > 0 and dns.resp.name == www.google-analytics.com
    PTF_ASSERT(answersWithNameGoogleAnalytics == 7, "DNS answers with name 'www.google-analytics.com' different than expected. Found: %d; Expected: 7", answersWithNameGoogleAnalytics);
    // wireshark filter: dns.count.answers > 0 and dns.aaaa == fe80::5a1f:aaff:fe4f:3f9d
    PTF_ASSERT(answersWithDataCertainIPv6 == 12, "DNS answers with IPv6 data of 'fe80::5a1f:aaff:fe4f:3f9d' different than expected. Found: %d; Expected: 12", answersWithDataCertainIPv6);
    // wireshark filter: dns.count.answers > 0 and dns.resp.ttl < 30
    PTF_ASSERT(answersWithTtlLessThan30 == 17, "DNS answers with TTL less than 30 different than expected. Found: %d; Expected: 17", answersWithTtlLessThan30);

    // wireshark filter: dns.count.auth_rr > 0 and dns.resp.name == Yaels-iPhone.local
    PTF_ASSERT(authoritiesWithNameYaelPhone == 9, "DNS authorities with name 'Yaels-iPhone.local' different than expected. Found: %d; Expected: 9", authoritiesWithNameYaelPhone);
    // wireshark filter: dns.count.auth_rr > 0 and dns.a == 10.0.0.2
    PTF_ASSERT(authoritiesWithData10_0_0_2 == 9, "DNS authorities with IPv4 data of '10.0.0.2' different than expected. Found: %d; Expected: 9", authoritiesWithData10_0_0_2);

    // wireshark filter: dns.count.add_rr > 0 and dns.resp.name == "<Root>"
    PTF_ASSERT(additionalWithEmptyName == 23, "DNS additional records with empty name different than expected. Found: %d; Expected: 23", additionalWithEmptyName);
    // wireshark filter: dns.count.add_rr > 0 and dns.resp.name == D.9.F.3.F.4.E.F.F.F.A.A.F.1.A.5.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
    PTF_ASSERT(additionalWithLongUglyName == 12, "DNS additional records with long ugly name different than expected. Found: %d; Expected: 12", additionalWithLongUglyName);
    // wireshark filter: dns.count.add_rr > 0 and dns.resp.type == 47
    PTF_ASSERT(additionalWithTypeNSEC == 14, "DNS additional records with type NSEC different than expected. Found: %d; Expected: 14", additionalWithTypeNSEC);


}


PTF_TEST_CASE(TestDpdkDevice)
{
#ifdef USE_DPDK
	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	PTF_ASSERT(devList.getDpdkDeviceList().size() == 0, "DpdkDevices initialized before DPDK is initialized");
	LoggerPP::getInstance().enableErrors();

	if(devList.getDpdkDeviceList().size() == 0)
	{
		CoreMask coreMask = 0;
		for (int i = 0; i < getNumOfCores(); i++)
			coreMask |= SystemCores::IdToSystemCore[i].Mask;
		PTF_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}

	PTF_ASSERT(devList.getDpdkLogLevel() == LoggerPP::Normal, "DPDK log level is in Debug and should be on Normal");
	devList.setDpdkLogLevel(LoggerPP::Debug);
	PTF_ASSERT(devList.getDpdkLogLevel() == LoggerPP::Debug, "DPDK log level is in Normal and should be on Debug");
	devList.setDpdkLogLevel(LoggerPP::Normal);

	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(PcapGlobalArgs.dpdkPort);
	PTF_ASSERT(dev != NULL, "DpdkDevice is NULL");

	PTF_ASSERT(dev->getMacAddress().isValid() == true, "Dev MAC addr isn't valid");
	PTF_ASSERT(dev->getMacAddress() != MacAddress::Zero, "Dev MAC addr is zero");
	PTF_ASSERT(dev->getTotalNumOfRxQueues() > 0, "Number of RX queues is zero");
	PTF_ASSERT(dev->getNumOfOpenedRxQueues() == 0, "Number of open RX queues isn't zero, it's %d", dev->getNumOfOpenedRxQueues());
	PTF_ASSERT(dev->getNumOfOpenedTxQueues() == 0, "Number of open TX queues isn't zero, it's %d", dev->getNumOfOpenedTxQueues());
	PTF_ASSERT(dev->getMtu() > 0, "Couldn't retrieve MTU");

	// Changing the MTU isn't supported for all PMDs so I can't use it in the unit-tests, as they may
	// fail on environment using such PMDs. I tested it on EM PMD and verified it works
//	uint16_t origMtu = dev->getMtu();
//	uint16_t newMtu = origMtu > 1600 ? 1500 : 9000;
//	PTF_ASSERT(dev->setMtu(newMtu) == true, "Couldn't set MTU to %d", newMtu);
//	PTF_ASSERT(dev->getMtu() == newMtu, "MTU isn't properly set");
//	PTF_ASSERT(dev->setMtu(origMtu) == true, "Couldn't set MTU back to original");

	if (dev->getPMDName() == "net_e1000_em")
	{
		uint64_t rssHF = 0;
		PTF_ASSERT(dev->isDeviceSupportRssHashFunction(rssHF) == true, "Not all RSS hash function are supported for pmd net_e1000_em");
		PTF_ASSERT(dev->getSupportedRssHashFunctions() == rssHF, "RSS hash functions supported by device is different than expected");
	}
	else if (dev->getPMDName() == "net_vmxnet3")
	{
		uint64_t rssHF = DpdkDevice::RSS_IPV4 | \
				DpdkDevice::RSS_NONFRAG_IPV4_TCP | \
				DpdkDevice::RSS_IPV6 | \
				DpdkDevice::RSS_NONFRAG_IPV6_TCP;

		PTF_ASSERT(dev->isDeviceSupportRssHashFunction(rssHF) == true, "Not all RSS hash function are supported for pmd vmxnet3");
		PTF_ASSERT(dev->getSupportedRssHashFunctions() == rssHF, "RSS hash functions supported by device is different than expected");
	}

	PTF_ASSERT(dev->open() == true, "Cannot open DPDK device");
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->open() == false, "Managed to open the device twice");
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedRxQueues() == 1, dev->close(), "More than 1 RX queues were opened");
	PTF_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedTxQueues() == 1, dev->close(), "More than 1 TX queues were opened");
	DpdkDevice::LinkStatus linkStatus;
	dev->getLinkStatus(linkStatus);
	PTF_ASSERT_AND_RUN_COMMAND(linkStatus.linkUp == true, dev->close(), "Link is down");
	PTF_ASSERT_AND_RUN_COMMAND(linkStatus.linkSpeedMbps > 0, dev->close(), "Link speed is 0");

	DpdkPacketData packetData;
	PTF_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData), dev->close(), "Could not start capturing on DpdkDevice[0]");
	PCAP_SLEEP(10);
	dev->stopCapture();

	PTF_PRINT_VERBOSE("Thread ID: %d", packetData.ThreadId);
	PTF_PRINT_VERBOSE("Total packets captured: %d", packetData.PacketCount);
	PTF_PRINT_VERBOSE("Eth packets: %d", packetData.EthCount);
	PTF_PRINT_VERBOSE("ARP packets: %d", packetData.ArpCount);
	PTF_PRINT_VERBOSE("IPv4 packets: %d", packetData.Ip4Count);
	PTF_PRINT_VERBOSE("IPv6 packets: %d", packetData.Ip6Count);
	PTF_PRINT_VERBOSE("TCP packets: %d", packetData.TcpCount);
	PTF_PRINT_VERBOSE("UDP packets: %d", packetData.UdpCount);
	PTF_PRINT_VERBOSE("HTTP packets: %d", packetData.HttpCount);

	DpdkDevice::DpdkDeviceStats stats;
	dev->getStatistics(stats);
	PTF_PRINT_VERBOSE("Packets captured according to stats: %lu", stats.aggregatedRxStats.packets);
	PTF_PRINT_VERBOSE("Bytes captured according to stats: %lu", stats.aggregatedRxStats.bytes);
	PTF_PRINT_VERBOSE("Packets dropped according to stats: %lu", stats.rxPacketsDropeedByHW);
	PTF_PRINT_VERBOSE("Erroneous packets according to stats: %lu", stats.rxErroneousPackets);
	for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
	{
		PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
		PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);

	}
	PTF_ASSERT_AND_RUN_COMMAND(packetData.PacketCount > 0, dev->close(), "No packets were captured");
	PTF_ASSERT_AND_RUN_COMMAND(packetData.ThreadId != -1, dev->close(), "Couldn't retrieve thread ID");

	int statsVsPacketCount = stats.aggregatedRxStats.packets > (uint64_t)packetData.PacketCount ? stats.aggregatedRxStats.packets-(uint64_t)packetData.PacketCount : (uint64_t)packetData.PacketCount-stats.aggregatedRxStats.packets;
	PTF_ASSERT_AND_RUN_COMMAND(statsVsPacketCount <= 20, dev->close(),
			"Stats received packet count (%lu) is different than calculated packet count (%d)",
			stats.aggregatedRxStats.packets,
			packetData.PacketCount);
	dev->close();
	dev->close();



#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestDpdkMultiThread)
{
#ifdef USE_DPDK
	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	LoggerPP::getInstance().enableErrors();

	if(devList.getDpdkDeviceList().size() == 0)
	{
		CoreMask coreMask = 0;
		for (int i = 0; i < getNumOfCores(); i++)
			coreMask |= SystemCores::IdToSystemCore[i].Mask;

		PTF_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(PcapGlobalArgs.dpdkPort);
	PTF_ASSERT(dev != NULL, "DpdkDevice is NULL");

	// take min value between number of cores and number of available RX queues
	int numOfRxQueuesToOpen = getNumOfCores()-1; //using num of cores minus one since 1 core is the master core and cannot be used
	if (dev->getTotalNumOfRxQueues() < numOfRxQueuesToOpen)
		numOfRxQueuesToOpen = dev->getTotalNumOfRxQueues();

	// verfiy num of RX queues is power of 2 due to DPDK limitation
	bool isRxQueuePowerOfTwo = !(numOfRxQueuesToOpen == 0) && !(numOfRxQueuesToOpen & (numOfRxQueuesToOpen - 1));
	while (!isRxQueuePowerOfTwo)
	{
		numOfRxQueuesToOpen--;
		isRxQueuePowerOfTwo = !(numOfRxQueuesToOpen == 0) && !(numOfRxQueuesToOpen & (numOfRxQueuesToOpen - 1));
	}

	if (dev->getTotalNumOfRxQueues() > 1)
	{
		LoggerPP::getInstance().supressErrors();
		PTF_ASSERT(dev->openMultiQueues(numOfRxQueuesToOpen+1, 1) == false, "Managed to open DPDK device with number of RX queues which isn't power of 2");
		LoggerPP::getInstance().enableErrors();
	}

	PTF_ASSERT_AND_RUN_COMMAND(dev->openMultiQueues(numOfRxQueuesToOpen, 1) == true, dev->close(), "Cannot open DPDK device '%s' with %d RX queues", dev->getDeviceName().c_str(), numOfRxQueuesToOpen);

	if (numOfRxQueuesToOpen > 1)
	{
		LoggerPP::getInstance().supressErrors();
		DpdkPacketData dummyPacketData;
		PTF_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &dummyPacketData) == false, dev->close(), "Managed to start capture on single thread although more than 1 RX queue is opened");
		LoggerPP::getInstance().enableErrors();
	}

	PTF_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedRxQueues() == numOfRxQueuesToOpen, dev->close(), "Num of opened RX queues is different from requested RX queues");
	PTF_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedTxQueues() == 1, dev->close(), "Num of opened TX queues is different than 1");

	DpdkPacketData packetDataMultiThread[getNumOfCores()];
	for (int i = 0; i < getNumOfCores(); i++)
		packetDataMultiThread[i].PacketCount = 0;

	CoreMask coreMask = 0;
	SystemCore masterCore = devList.getDpdkMasterCore();
	int j = 0;
	for (int i = 0; i < getNumOfCores(); i++)
	{
		if (j == numOfRxQueuesToOpen)
			break;

		if (i != masterCore.Id)
		{
			coreMask |= SystemCores::IdToSystemCore[i].Mask;
			j++;
		}
	}

	PTF_ASSERT_AND_RUN_COMMAND(dev->startCaptureMultiThreads(dpdkPacketsArriveMultiThread, packetDataMultiThread, coreMask), dev->close(), "Cannot start capturing on multi threads");
	PCAP_SLEEP(20);
	dev->stopCapture();
	uint64_t packetCount = 0;

	for (int i = 0; i < getNumOfCores(); i++)
	{
		if ((SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
			continue;

		PTF_PRINT_VERBOSE("Thread ID: %d", packetDataMultiThread[i].ThreadId);
		PTF_PRINT_VERBOSE("Total packets captured: %d", packetDataMultiThread[i].PacketCount);
		PTF_PRINT_VERBOSE("Eth packets: %d", packetDataMultiThread[i].EthCount);
		PTF_PRINT_VERBOSE("ARP packets: %d", packetDataMultiThread[i].ArpCount);
		PTF_PRINT_VERBOSE("IPv4 packets: %d", packetDataMultiThread[i].Ip4Count);
		PTF_PRINT_VERBOSE("IPv6 packets: %d", packetDataMultiThread[i].Ip6Count);
		PTF_PRINT_VERBOSE("TCP packets: %d", packetDataMultiThread[i].TcpCount);
		PTF_PRINT_VERBOSE("UDP packets: %d", packetDataMultiThread[i].UdpCount);
		packetCount += packetDataMultiThread[i].PacketCount;
	}

	PTF_ASSERT_AND_RUN_COMMAND(packetCount > 0, dev->close(), "No packets were captured on any thread");

	DpdkDevice::DpdkDeviceStats stats;
	dev->getStatistics(stats);
	PTF_PRINT_VERBOSE("Packets captured according to stats: %lu", stats.aggregatedRxStats.packets);
	PTF_PRINT_VERBOSE("Bytes captured according to stats: %lu", stats.aggregatedRxStats.bytes);
	PTF_PRINT_VERBOSE("Packets dropped according to stats: %lu", stats.rxPacketsDropeedByHW);
	PTF_PRINT_VERBOSE("Erroneous packets according to stats: %lu", stats.rxErroneousPackets);
	for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
	{
		PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
		PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);

	}
	PTF_ASSERT_AND_RUN_COMMAND(stats.aggregatedRxStats.packets >= packetCount, dev->close(), "Statistics from device differ from aggregated statistics on all threads");
	PTF_ASSERT_AND_RUN_COMMAND(stats.rxPacketsDropeedByHW == 0, dev->close(), "Some packets were dropped");

	for (int firstCoreId = 0; firstCoreId < getNumOfCores(); firstCoreId++)
	{
		if ((SystemCores::IdToSystemCore[firstCoreId].Mask & coreMask) == 0)
			continue;

		for (int secondCoreId = firstCoreId+1; secondCoreId < getNumOfCores(); secondCoreId++)
		{
			if ((SystemCores::IdToSystemCore[secondCoreId].Mask & coreMask) == 0)
				continue;

			map<uint32_t, pair<RawPacketVector, RawPacketVector> > res;
			intersectMaps<uint32_t, RawPacketVector, RawPacketVector>(packetDataMultiThread[firstCoreId].FlowKeys, packetDataMultiThread[secondCoreId].FlowKeys, res);
			PTF_ASSERT(res.size() == 0, "%d flows appear in core %d and core %d", (int)res.size(), firstCoreId, secondCoreId);
			if (PTF_IS_VERBOSE_MODE)
			{
				for (map<uint32_t, pair<RawPacketVector, RawPacketVector> >::iterator iter = res.begin(); iter != res.end(); iter++)
				{
					PTF_PRINT_VERBOSE("Same flow exists in core %d and core %d. Flow key = %X", firstCoreId, secondCoreId, iter->first);
					ostringstream stream;
					stream << "Core" << firstCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					PcapFileWriterDevice writerDev(stream.str().c_str());
					writerDev.open();
					writerDev.writePackets(iter->second.first);
					writerDev.close();

					ostringstream stream2;
					stream2 << "Core" << secondCoreId << "_Flow_" << std::hex << iter->first << ".pcap";
					PcapFileWriterDevice writerDev2(stream2.str().c_str());
					writerDev2.open();
					writerDev2.writePackets(iter->second.second);
					writerDev2.close();

					iter->second.first.clear();
					iter->second.second.clear();

				}
			}
		}
		PTF_PRINT_VERBOSE("Core %d\n========", firstCoreId);
		PTF_PRINT_VERBOSE("Total flows: %d", (int)packetDataMultiThread[firstCoreId].FlowKeys.size());

		if (PTF_IS_VERBOSE_MODE)
		{
			for(map<uint32_t, RawPacketVector>::iterator iter = packetDataMultiThread[firstCoreId].FlowKeys.begin(); iter != packetDataMultiThread[firstCoreId].FlowKeys.end(); iter++) {
				PTF_PRINT_VERBOSE("Key=%X; Value=%d", (int)iter->first, (int)iter->second.size());
				iter->second.clear();
			}
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();
	}



	dev->close();



#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestDpdkDeviceSendPackets)
{
#ifdef USE_DPDK
	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	LoggerPP::getInstance().enableErrors();

	if(devList.getDpdkDeviceList().size() == 0)
	{
		CoreMask coreMask = 0;
		for (int i = 0; i < getNumOfCores(); i++)
			coreMask |= SystemCores::IdToSystemCore[i].Mask;

		PTF_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(PcapGlobalArgs.dpdkPort);
	PTF_ASSERT(dev != NULL, "DpdkDevice is NULL");


	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->openMultiQueues(1, 255) == false, "Managed to open a DPDK device with 255 TX queues");
	LoggerPP::getInstance().enableErrors();

	DpdkDevice::DpdkDeviceConfiguration customConfig(128, 1024);
	PTF_ASSERT_AND_RUN_COMMAND(dev->openMultiQueues(1, dev->getTotalNumOfTxQueues(), customConfig) == true, dev->close(), "Cannot open DPDK device '%s' with %d TX queues", dev->getDeviceName().c_str(), dev->getTotalNumOfTxQueues());

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    PointerVector<Packet> packetVec;
    RawPacketVector rawPacketVec;
    Packet* packetArr[10000];
    uint16_t packetsRead = 0;
    RawPacket rawPacket;
    while(fileReaderDev.getNextPacket(rawPacket))
    {
    	if (packetsRead == 100)
    		break;
    	RawPacket* newRawPacket = new RawPacket(rawPacket);
    	rawPacketVec.pushBack(newRawPacket);
    	Packet* newPacket = new Packet(newRawPacket, false);
    	packetVec.pushBack(newPacket);
    	packetArr[packetsRead] = newPacket;

      	packetsRead++;
    }

    //send packets as parsed EthPacekt array
    int packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead, 0, false);
    PTF_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);

    //send packets are RawPacketVector
    int packetsSentAsRawVector = dev->sendPackets(rawPacketVec);
    PTF_ASSERT(packetsSentAsRawVector == packetsRead, "Not all packets were sent as raw vector. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRawVector);

    if (dev->getTotalNumOfTxQueues() > 1)
    {
        packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead, dev->getTotalNumOfTxQueues()-1);
        packetsSentAsRawVector = dev->sendPackets(rawPacketVec, dev->getTotalNumOfTxQueues()-1);
        PTF_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed to TX queue %d. Expected (read from file): %d; Sent: %d",
        		dev->getTotalNumOfTxQueues()-1, packetsRead, packetsSentAsParsed);
        PTF_ASSERT(packetsSentAsRawVector == packetsRead, "Not all packets were sent as raw vector to TX queue %d. Expected (read from file): %d; Sent: %d",
        		dev->getTotalNumOfTxQueues()-1, packetsRead, packetsSentAsRawVector);

    }

    LoggerPP::getInstance().supressErrors();
    PTF_ASSERT(dev->sendPackets(rawPacketVec, dev->getTotalNumOfTxQueues()+1) == 0, "Managed to send packets on TX queue that doesn't exist");
    LoggerPP::getInstance().enableErrors();

    PTF_ASSERT(dev->sendPacket(*(rawPacketVec.at(packetsRead/3)), 0) == true, "Couldn't send 1 raw packet");
    PTF_ASSERT(dev->sendPacket(*(packetArr[packetsRead/2]), 0) == true, "Couldn't send 1 parsed packet");

    dev->close();
    fileReaderDev.close();



#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestDpdkDeviceWorkerThreads)
{
#ifdef USE_DPDK
	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	LoggerPP::getInstance().enableErrors();

	CoreMask coreMask = 0;
	for (int i = 0; i < getNumOfCores(); i++)
		coreMask |= SystemCores::IdToSystemCore[i].Mask;

	if(devList.getDpdkDeviceList().size() == 0)
	{
		PTF_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");

	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(PcapGlobalArgs.dpdkPort);
	PTF_ASSERT(dev != NULL, "DpdkDevice is NULL");

	MBufRawPacketVector rawPacketVec;
	MBufRawPacket* mBufRawPacketArr[32] = {};
	size_t mBufRawPacketArrLen = 32;
	Packet* packetArr[32] = {};
	size_t packetArrLen = 32;

	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(dev->receivePackets(rawPacketVec, 0) == 0, "Managed to receive packets although device isn't opened");
	PTF_ASSERT(dev->receivePackets(packetArr, packetArrLen, 0) == 0, "Managed to receive packets although device isn't opened");
	PTF_ASSERT(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, 0) == 0, "Managed to receive packets although device isn't opened");

	PTF_ASSERT(dev->open() == true, "Couldn't open DPDK device");
	PTF_ASSERT(dev->receivePackets(rawPacketVec, dev->getTotalNumOfRxQueues()+1) == 0, "Managed to receive packets for RX queue that doesn't exist");
	PTF_ASSERT(dev->receivePackets(packetArr, packetArrLen, dev->getTotalNumOfRxQueues()+1) == 0, "Managed to receive packets for RX queue that doesn't exist");
	PTF_ASSERT(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, dev->getTotalNumOfRxQueues()+1) == 0, "Managed to receive packets for RX queue that doesn't exist");

	DpdkPacketData packetData;
	mBufRawPacketArrLen = 32;
	packetArrLen = 32;
	PTF_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData), dev->close(), "Could not start capturing on DpdkDevice");
	PTF_ASSERT(dev->receivePackets(rawPacketVec, 0) == 0, "Managed to receive packets although device is in capture mode");
	PTF_ASSERT(dev->receivePackets(packetArr, packetArrLen, 0) == 0, "Managed to receive packets although device is in capture mode");
	PTF_ASSERT(dev->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen, 0) == 0, "Managed to receive packets although device is in capture mode");
	LoggerPP::getInstance().enableErrors();
	dev->stopCapture();
	dev->close();
	
	PTF_ASSERT(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()) == true, "Cannot open DPDK device");

	int numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		dev->receivePackets(rawPacketVec, 0);
		PCAP_SLEEP(1);
		if (rawPacketVec.size() > 0)
			break;
		numOfAttempts++;
	}

	PTF_ASSERT(numOfAttempts < 10, "No packets were received using RawPacketVector");
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using RawPacketVector", (int)rawPacketVec.size(), numOfAttempts);

	numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		mBufRawPacketArrLen = dev->receivePackets(mBufRawPacketArr, 32, 0);
		PCAP_SLEEP(1);
		if (mBufRawPacketArrLen > 0)
			break;
		numOfAttempts++;
	}

	PTF_ASSERT(numOfAttempts < 10, "No packets were received using mBuf raw packet arr");
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using mBuf raw packet arr", (int)mBufRawPacketArrLen, numOfAttempts);
	for (int i = 0; i < 32; i++)
	{
		if (mBufRawPacketArr[i] != NULL)
			delete mBufRawPacketArr[i];
	}


	numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		packetArrLen = dev->receivePackets(packetArr, 32, 0);
		PCAP_SLEEP(1);
		if (packetArrLen > 0)
			break;
		numOfAttempts++;
	}

	PTF_ASSERT(numOfAttempts < 10, "No packets were received using packet arr");
	PTF_PRINT_VERBOSE("Captured %d packets in %d attempts using packet arr", (int)packetArrLen, numOfAttempts);
	for (int i = 0; i < 32; i++)
	{
		if (packetArr[i] != NULL)
			delete packetArr[i];
	}


	int numOfRxQueues = dev->getTotalNumOfRxQueues();
	pthread_mutex_t queueMutexArr[numOfRxQueues];
	for (int i = 0; i < numOfRxQueues; i++)
		pthread_mutex_init(&queueMutexArr[i], NULL);

	vector<DpdkWorkerThread*> workerThreadVec;
	CoreMask workerThreadCoreMask = 0;
	for (int i = 0; i < getNumOfCores(); i++)
	{
		SystemCore core = SystemCores::IdToSystemCore[i];
		if (core == devList.getDpdkMasterCore())
			continue;
		DpdkTestWorkerThread* newWorkerThread = new DpdkTestWorkerThread();
		int queueId = core.Id % numOfRxQueues;
		PTF_PRINT_VERBOSE("Assigning queue #%d to core %d", queueId, core.Id);
		newWorkerThread->init(dev, queueId, &queueMutexArr[queueId]);
		workerThreadVec.push_back((DpdkWorkerThread*)newWorkerThread);
		workerThreadCoreMask |= core.Mask;
	}
	PTF_PRINT_VERBOSE("Initiating %d worker threads", (int)workerThreadVec.size());

	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(devList.startDpdkWorkerThreads(0, workerThreadVec) == false, "Managed to start DPDK worker thread with core mask 0");
	LoggerPP::getInstance().enableErrors();

	PTF_ASSERT(devList.startDpdkWorkerThreads(workerThreadCoreMask, workerThreadVec) == true, "Couldn't start DPDK worker threads");
	PTF_PRINT_VERBOSE("Worker threads started");

	for (int i = 0; i < 10; i++)
	{
		DpdkDevice::DpdkDeviceStats stats;
		dev->getStatistics(stats);
		PTF_PRINT_VERBOSE("Packets captured   : %lu", stats.aggregatedRxStats.packets);
		PTF_PRINT_VERBOSE("Bytes captured     : %lu", stats.aggregatedRxStats.bytes);
		PTF_PRINT_VERBOSE("Bits per second    : %lu", stats.aggregatedRxStats.bytesPerSec*8);
		PTF_PRINT_VERBOSE("Packets per second : %lu", stats.aggregatedRxStats.packetsPerSec);
		PTF_PRINT_VERBOSE("Packets dropped    : %lu", stats.rxPacketsDropeedByHW);
		PTF_PRINT_VERBOSE("Erroneous packets  : %lu", stats.rxErroneousPackets);
		for (int i = 0; i < DPDK_MAX_RX_QUEUES; i++)
		{
			PTF_PRINT_VERBOSE("Packets captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].packets);
			PTF_PRINT_VERBOSE("Bytes captured on RX queue #%d according to stats: %lu", i, stats.rxStats[i].bytes);

		}

		PCAP_SLEEP(1);
	}


	PTF_PRINT_VERBOSE("Worker threads stopping");
	devList.stopDpdkWorkerThreads();
	PTF_PRINT_VERBOSE("Worker threads stopped");

	// we can't guarantee all threads receive packets, it depends on the NIC load balancing and the traffic. So we check that all threads were run and
	// that total amount of packets received by all threads is greater than zero

	int packetCount = 0;
	for (vector<DpdkWorkerThread*>::iterator iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
	{
		DpdkTestWorkerThread* thread = (DpdkTestWorkerThread*)(*iter);
		PTF_ASSERT(thread->threadRanAndStopped() == true, "Thread on core %d didn't run", thread->getCoreId());
		packetCount += thread->getPacketCount();
		PTF_PRINT_VERBOSE("Worker thread on core %d captured %d packets", thread->getCoreId(), thread->getPacketCount());
		delete thread;
	}

	for (int i = 0; i < numOfRxQueues; i++)
		pthread_mutex_destroy(&queueMutexArr[i]);


	PTF_PRINT_VERBOSE("Total packet count for all worker threads: %d", packetCount);

	PTF_ASSERT(packetCount > 0, "No packet were captured on any of the worker threads");

	dev->close();



#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestKniDevice)
{
#if defined(USE_DPDK) && defined(LINUX)

	if (PcapGlobalArgs.kniIp == "")
	{
		PTF_TRY(false, "KNI IP not provided, skipping test");
		PTF_SKIP_TEST("KNI IP not provided");
	}

	// Assume that DPDK was initialized correctly in DpdkDevice tests
	enum { KNI_TEST_MTU = 1540, KNI_NEW_MTU = 1500 };
	char buff[256];
	bool isLinkUp = true;
	KniDevice* device = NULL;
	KniDevice::KniDeviceConfiguration devConfig;
	snprintf(buff, sizeof(buff), KNI_TEST_NAME, KNI::DEVICE0);
	devConfig.name = buff;
	KniRequestsCallbacksMock::setCallbacks();
	if (KniDeviceList::callbackVersion() == KniDeviceList::CALLBACKS_NEW)
	{
		devConfig.callbacks = &KniRequestsCallbacksMock::cb_new;
	}
	else
	{
		devConfig.oldCallbacks = &KniRequestsCallbacksMock::cb_old;
	}
	devConfig.mac = MacAddress("00:11:33:55:77:99");
	devConfig.portId = KNI::TEST_PORT_ID0;
	devConfig.mtu = KNI_TEST_MTU;
	devConfig.bindKthread = false;
	KniDeviceList& kniDeviceList = KniDeviceList::getInstance();
	PTF_ASSERT(kniDeviceList.isInitialized(), "KNI module was not initialized properly");
	device = kniDeviceList.createDevice(devConfig, KNI::TEST_MEMPOOL_CAPACITY);
	PTF_ASSERT(device != NULL, "Could not create KNI device " KNI_TEST_NAME, KNI::DEVICE0);
	PTF_ASSERT(device->isInitialized(), "KNI device was not initialized correctly");
	PTF_ASSERT(device == kniDeviceList.getDeviceByPort(KNI::TEST_PORT_ID0),
		"Could not find KNI device " KNI_TEST_NAME " thru port id %d", KNI::DEVICE0, KNI::TEST_PORT_ID0);
	PTF_ASSERT(device == kniDeviceList.getDeviceByName(std::string(buff)),
		"Could not find KNI device " KNI_TEST_NAME " thru name \"%s\"", KNI::DEVICE0, buff);
	{
		std::string n = device->getName();
		PTF_ASSERT(n == buff,
			"Name of device reported by KNI <%s> do not match one provided in config structure <%s>", n.c_str(), buff);
	}
	{
		uint16_t port = device->getPort();
		PTF_ASSERT(port == KNI::TEST_PORT_ID0,
			"Port reported by KNI device <%u> do not match one provided in config structure <%d>", port, KNI::TEST_PORT_ID0);
	}
	PTF_ASSERT(device->getLinkState() == KniDevice::LINK_NOT_SUPPORTED,
		"Default link state after KNI device constrution must be LINK_NOT_SUPPORTED");
	{
		KniDevice::KniLinkState ls = device->getLinkState(KniDevice::INFO_RENEW);
		PTF_ASSERT(ls == KniDevice::LINK_DOWN || ls == KniDevice::LINK_UP,
			"Link state of KNI device after INFO_RENEW is not UP or DOWN");
		if (ls == KniDevice::LINK_DOWN)
			isLinkUp = false;
	}
	{
		MacAddress mac = device->getMacAddress();
		PTF_ASSERT(mac == devConfig.mac,
			"Cached MAC reported by KNI device <%s> is not as provided in config structure <%s>",
			mac.toString().c_str(),
			devConfig.mac.toString().c_str()
		);
		mac = device->getMacAddress(KniDevice::INFO_RENEW);
		PTF_ASSERT(mac == devConfig.mac,
			"MAC of KNI device reported by Linux Kernel <%s> is not as provided in config structure <%s>",
			mac.toString().c_str(),
			devConfig.mac.toString().c_str()
		);
	}
	{
		uint16_t mtu = device->getMtu();
		PTF_ASSERT(mtu == KNI_TEST_MTU,
			"Cached MTU reported by KNI device <%u> is not as provided in config structure <%d>", mtu, KNI_TEST_MTU);
		mtu = device->getMtu(KniDevice::INFO_RENEW);
		PTF_ASSERT(mtu == KNI_TEST_MTU,
			"MTU of KNI device reported by Linux Kernel <%u> is not as provided in config structure <%d>", mtu, KNI_TEST_MTU);
	}
	{
		KniDevice::KniPromiscuousMode pm = device->getPromiscuous();
		PTF_ASSERT(pm == KniDevice::PROMISC_DISABLE,
			"Default promiscuous mode of KNI device must be PROMISC_DISABLE");
		//? Note(echo-Mike): default promiscuous mode of net device is set by Linux config so it can't be tested
	}
	PTF_ASSERT(device->open(), "Failed to open KNI device");
	PTF_ASSERT(device->startRequestHandlerThread(0, 150000000),
		"KNI device can't start request handler thread");
	PCAP_SLEEP(2); // Wait for thread to start
	if (KniDeviceList::isCallbackSupported(KniDeviceList::CALLBACK_PROMISC))
	{
		bool modeSet = device->setPromiscuous(KniDevice::PROMISC_ENABLE);
		PTF_TRY(modeSet, "Could not set KNI device promiscuous mode ENABLE via setPromiscuous");
		if (modeSet)
		{
			KniDevice::KniPromiscuousMode pm = device->getPromiscuous(KniDevice::INFO_RENEW);
			PTF_TRY(pm == KniDevice::PROMISC_ENABLE,
				"Linux kernel yields promiscuous mode DISABLE after it was ENABLED by call to setPromiscuous on KNI device");
			modeSet = device->setPromiscuous(KniDevice::PROMISC_DISABLE);
			PTF_TRY(modeSet,
				"Could not set KNI device promiscuous mode DISABLE via setPromiscuous");
			if (modeSet)
			{
				pm = device->getPromiscuous(KniDevice::INFO_RENEW);
				PTF_TRY(pm == KniDevice::PROMISC_DISABLE,
					"Linux kernel yields promiscuous mode ENABLED after it was DISABLE by call to setPromiscuous on KNI device");
			}
		}
	}
	if (KniDeviceList::isCallbackSupported(KniDeviceList::CALLBACK_MTU))
	{
		bool mtuSet = device->setMtu(KNI_NEW_MTU);
		PTF_TRY(mtuSet, "Could not set KNI device MTU via setMtu");
		if (mtuSet)
		{
			uint16_t mtu = device->getMtu(KniDevice::INFO_RENEW);
			PTF_TRY(mtu == KNI_NEW_MTU,
				"Linux kernel yields MTU <%u> after it was changed to <%d> by call to setMtu on KNI device", mtu, KNI_NEW_MTU);
		}
	}
	if (KniDeviceList::isCallbackSupported(KniDeviceList::CALLBACK_MAC))
	{
		MacAddress kniNewMac = MacAddress("00:22:44:66:88:AA");
		bool macSet = device->setMacAddress(kniNewMac);
		PTF_TRY(macSet, "Could not set KNI device MAC via setMacAddress");
		if (macSet)
		{
			MacAddress mac = device->getMacAddress(KniDevice::INFO_RENEW);
			PTF_TRY(mac == kniNewMac,
				"Linux kernel yields MAC <%s> after it was changed to <%s> by call to setMacAddress on KNI device",
				mac.toString().c_str(),
				kniNewMac.toString().c_str()
			);
		}
	}
	if (KniDeviceList::isCallbackSupported(KniDeviceList::CALLBACK_LINK))
	{
		KniDevice::KniLinkState nls = isLinkUp ? KniDevice::LINK_DOWN : KniDevice::LINK_UP;
		KniDevice::KniLinkState ols = isLinkUp ? KniDevice::LINK_UP : KniDevice::LINK_DOWN;
		bool linkSet = device->setLinkState(nls);
		PTF_TRY(linkSet,
			"Could not set KNI device link state %s via setLinkState",
			isLinkUp ? "DOWN" : "UP"
		);
		if (linkSet)
		{
			KniDevice::KniLinkState ls = device->getLinkState(KniDevice::INFO_RENEW);
			PTF_TRY(ls == nls,
				"Linux kernel yields links state NOT %s after it was changed to %s by call to setLinkState on KNI device",
				isLinkUp ? "DOWN" : "UP",
				isLinkUp ? "DOWN" : "UP"
			);
			linkSet = device->setLinkState(ols);
			if (linkSet)
			{
				ls = device->getLinkState(KniDevice::INFO_RENEW);
				PTF_TRY(ls == ols,
					"Linux kernel yields links state NOT %s after it was changed to %s by call to setLinkState on KNI device",
					isLinkUp ? "UP" : "DOWN",
					isLinkUp ? "UP" : "DOWN"
				);
			}
			else
			{
				isLinkUp = !isLinkUp;
			}
		}
	}
	{
		KniDevice::KniLinkState ls = device->updateLinkState(isLinkUp ? KniDevice::LINK_DOWN : KniDevice::LINK_UP);
		switch (ls)
		{
			case KniDevice::LINK_NOT_SUPPORTED:
			{
				PTF_PRINT_VERBOSE("KNI updateLinkState not supported");
			} break;
			case KniDevice::LINK_ERROR:
			{
				PTF_PRINT_VERBOSE("KNI updateLinkState have failed with LINK_ERROR");
			} break;
			case KniDevice::LINK_DOWN:
			{	// If previous known state was UP -> yield an error
				PTF_ASSERT(!(isLinkUp == true), "KNI updateLinkState returned invalid previous state: DOWN");
			} break;
			case KniDevice::LINK_UP:
			{	// If previous known state was DOWN -> yield an error
				PTF_ASSERT(!(isLinkUp == false), "KNI updateLinkState returned invalid previous state: UP");
			} break;
		}
	}
	device->stopRequestHandlerThread();
	device->close();
	// Device will be destroyed later


#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestKniDeviceSendReceive)
{
#if defined(USE_DPDK) && defined(LINUX)

	if (PcapGlobalArgs.kniIp == "")
	{
		PTF_TRY(false, "KNI IP not provided, skipping test");
		PTF_SKIP_TEST("KNI IP not provided");
	}

	// Assume that DPDK was initialized correctly in DpdkDevice tests
	enum { KNI_MTU = 1500, BLOCK_TIMEOUT = 3 };
	char buff[256];
	KniDevice* device = NULL;
	unsigned int counter = 0;
	KniDevice::KniDeviceConfiguration devConfig;
	IPv4Address kniIp = PcapGlobalArgs.kniIp;
	PTF_ASSERT(kniIp.isValid(), "Invalid IP address provided for KNI interface");

	// KNI device setup
	snprintf(buff, sizeof(buff), KNI_TEST_NAME, KNI::DEVICE1);
	devConfig.name = buff;
	KniRequestsCallbacksMock::setCallbacks();
	if (KniDeviceList::callbackVersion() == KniDeviceList::CALLBACKS_NEW)
	{
		devConfig.callbacks = &KniRequestsCallbacksMock::cb_new;
	}
	else
	{
		devConfig.oldCallbacks = &KniRequestsCallbacksMock::cb_old;
	}
	devConfig.portId = KNI::TEST_PORT_ID1;
	devConfig.mtu = KNI_MTU;
	devConfig.bindKthread = false;

	KniDeviceList& kniDeviceList = KniDeviceList::getInstance();
	PTF_ASSERT(kniDeviceList.isInitialized(), "KNI module was not initialized properly");
	device = kniDeviceList.createDevice(devConfig, KNI::TEST_MEMPOOL_CAPACITY);
	PTF_ASSERT(device != NULL, "Could not create KNI device " KNI_TEST_NAME, KNI::DEVICE1);
	PTF_ASSERT(device->isInitialized(), "KNI device was not initialized correctly");
	PTF_ASSERT(device->open(), "Failed to open KNI device");
	PTF_ASSERT(device->startRequestHandlerThread(0, 250000000),
		"KNI device <" KNI_TEST_NAME "> can't start request handler thread", KNI::DEVICE1);
	PCAP_SLEEP(1); // Wait for thread to start

	// KNI device management
	PTF_ASSERT(KNI::setKniDeviceIp(kniIp, KNI::DEVICE1),
		"Failed to set KNI device " KNI_TEST_NAME " IP address <%s>", KNI::DEVICE1, kniIp.toString().c_str());
	PTF_ASSERT(device->setPromiscuous(KniDevice::PROMISC_ENABLE),
		"Could not set the promiscuous mode on KNI device " KNI_TEST_NAME ". Needed for tests.", KNI::DEVICE1);
	PTF_ASSERT(device->setLinkState(KniDevice::LINK_UP),
		"Could not set the link state UP on KNI device " KNI_TEST_NAME ". Needed for tests.", KNI::DEVICE1);

	// Other devices needed
	RawSocketDevice rsdevice(kniIp);
	PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
	PTF_ASSERT(rsdevice.open(), "Cannot open raw socket device for %s", kniIp.toString().c_str());

	{	// Receive test part
		RawPacket rawPacket;
		RawPacketVector rawPacketVec;
		MBufRawPacketVector mbufRawPacketVec;
		MBufRawPacket* mBufRawPacketArr[32] = {};
		size_t mBufRawPacketArrLen = 32;
		Packet* packetArr[32] = {};
		size_t packetArrLen = 32;
		PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for " EXAMPLE_PCAP_PATH);

		PTF_ASSERT(device->startCapture(KniRequestsCallbacksMock::onPacketsCallbackSingleBurst, &counter),
			"KNI failed to start capturing thread (single burst) on device " KNI_TEST_NAME, KNI::DEVICE1);
		LoggerPP::getInstance().supressErrors();
		PTF_ASSERT(!device->startCapture(KniRequestsCallbacksMock::onPacketsMock, NULL),
			"Managed to start second capturing thread on KNI device " KNI_TEST_NAME, KNI::DEVICE1);
		LoggerPP::getInstance().enableErrors();
		PCAP_SLEEP(1); // Give some time to start capture thread
		for (int i = 0; i < 10; ++i)
		{
			fileReaderDev.getNextPacket(rawPacket);
			RawPacket* newRawPacket = new RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		LoggerPP::getInstance().supressErrors();
		rsdevice.sendPackets(rawPacketVec);
		LoggerPP::getInstance().enableErrors();
		rawPacketVec.clear();
		PCAP_SLEEP(1); // Give some time to receive packets
		device->stopCapture();
		PTF_PRINT_VERBOSE("KNI have captured %u packets in single burst on device " KNI_TEST_NAME, counter, KNI::DEVICE1);
		counter = 0;
		PTF_ASSERT(device->startCapture(KniRequestsCallbacksMock::onPacketsCallback, &counter),
			"KNI failed to start capturing thread on device " KNI_TEST_NAME, KNI::DEVICE1);
		PCAP_SLEEP(1); // Give some time to start capture thread
		LoggerPP::getInstance().supressErrors();
		PTF_ASSERT(device->receivePackets(mbufRawPacketVec) == 0,
			"Managed to receive packets on KNI device while capturing via MBufRawPacketVector");
		PTF_ASSERT(device->receivePackets(mBufRawPacketArr, mBufRawPacketArrLen) == 0,
			"Managed to receive packets on KNI device while capturing via mBufRawPacketArr");
		PTF_ASSERT(device->receivePackets(packetArr, packetArrLen) == 0,
			"Managed to receive packets on KNI device while capturing via packetArr");
		LoggerPP::getInstance().enableErrors();
		for (int i = 0; i < 10; ++i)
		{
			fileReaderDev.getNextPacket(rawPacket);
			RawPacket* newRawPacket = new RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		LoggerPP::getInstance().supressErrors();
		rsdevice.sendPackets(rawPacketVec);
		LoggerPP::getInstance().enableErrors();
		rawPacketVec.clear();
		PCAP_SLEEP(1); // Give some time to receive packets
		device->stopCapture();
		PTF_PRINT_VERBOSE("KNI have captured %u packets on device " KNI_TEST_NAME, counter, KNI::DEVICE1);
		counter = 0;
		while (fileReaderDev.getNextPacket(rawPacket))
		{
			RawPacket* newRawPacket = new RawPacket(rawPacket);
			rawPacketVec.pushBack(newRawPacket);
		}
		LoggerPP::getInstance().supressErrors();
		rsdevice.sendPackets(rawPacketVec);
		LoggerPP::getInstance().enableErrors();
		rawPacketVec.clear();
		//? Note(echo-Mike): Some amount of packets are always queued inside kernel
		//? so blocking mode has a slight chance to obtain this packets
		int blockResult = device->startCaptureBlockingMode(KniRequestsCallbacksMock::onPacketsCallbackSingleBurst, &counter, BLOCK_TIMEOUT);
		switch (blockResult)
		{
			case -1:
			{
				PTF_PRINT_VERBOSE("KNI startCaptureBlockingMode have exited by timeout");
			} break;
			case 0:
			{
				PTF_PRINT_VERBOSE("KNI startCaptureBlockingMode have exited by an ERROR");
			} break;
			case 1:
			{
				PTF_PRINT_VERBOSE("KNI have captured %u packets (blocking mode) on device " KNI_TEST_NAME, counter, KNI::DEVICE1);
			} break;
		}
	}

	LoggerPP::getInstance().supressErrors();
	fileReaderDev.close();
	LoggerPP::getInstance().enableErrors();
	PTF_ASSERT(fileReaderDev.open(), "Cannot open file reader device for " EXAMPLE_PCAP_PATH " second time");

	{ // Send test part
		PointerVector<Packet> packetVec;
		RawPacketVector sendRawPacketVec;
		RawPacketVector receiveRawPacketVec;
		Packet* packetArr[10000];
		uint16_t packetsRead = 0;
		int packetsReceived = 0;
		RawPacket rawPacket;
		while(fileReaderDev.getNextPacket(rawPacket))
		{
			if (packetsRead == 100)
				break;
			RawPacket* newRawPacket = new RawPacket(rawPacket);
			sendRawPacketVec.pushBack(newRawPacket);
			Packet* newPacket = new Packet(newRawPacket, false);
			packetVec.pushBack(newPacket);
			packetArr[packetsRead] = newPacket;

			packetsRead++;
		}

		//send packets as parsed EthPacekt array
		int packetsSentAsParsed = device->sendPackets(packetArr, packetsRead);
		PTF_ASSERT(packetsSentAsParsed == packetsRead,
			"KNI Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d",
			packetsRead, packetsSentAsParsed
		);
		// Check raw device for packets to come
		{
			int unused;
			packetsReceived += rsdevice.receivePackets(receiveRawPacketVec, 3, unused);
			receiveRawPacketVec.clear();
		}
		PTF_ASSERT(packetsReceived != 0,
			"No packets received by RawSoacketDevice from KniDevice as parsed");
		packetsReceived = 0;

		//send packets are RawPacketVector
		int packetsSentAsRawVector = device->sendPackets(sendRawPacketVec);
		PTF_ASSERT(packetsSentAsRawVector == packetsRead,
			"KNI Not all packets were sent as raw vector. Expected (read from file): %d; Sent: %d",
			packetsRead, packetsSentAsRawVector
		);
		// Check raw device for packets to come
		{
			int unused;
			packetsReceived += rsdevice.receivePackets(receiveRawPacketVec, 3, unused);
			receiveRawPacketVec.clear();
		}
		PTF_ASSERT(packetsReceived != 0,
			"No packets received by RawSoacketDevice from KniDevice as parsed");
		packetsReceived = 0;

		//? Note (echo-Mike): this will not be checked by raw socket because there is
		//? a chance that packets will be thrown away before we can receive them
		PTF_ASSERT(device->sendPacket(*(sendRawPacketVec.at(packetsRead/3))) == true,
			"KNI Couldn't send 1 raw packet");
		PTF_ASSERT(device->sendPacket(*(packetArr[packetsRead/2])) == true,
			"KNI Couldn't send 1 parsed packet");
	}

	//! Note(echo-Mike): RawSocket device must be closed before KNI
	rsdevice.close();
	device->stopRequestHandlerThread();
	device->close();
	fileReaderDev.close();


#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
	
}

PTF_TEST_CASE(TestDpdkMbufRawPacket)
{
#ifdef USE_DPDK

	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	LoggerPP::getInstance().enableErrors();

	if(devList.getDpdkDeviceList().size() == 0)
	{
		CoreMask coreMask = 0;
		for (int i = 0; i < getNumOfCores(); i++)
			coreMask |= SystemCores::IdToSystemCore[i].Mask;

		PTF_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PTF_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(PcapGlobalArgs.dpdkPort);
	PTF_ASSERT(dev != NULL, "DpdkDevice is NULL");

	PTF_ASSERT(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()) == true, "Cannot open DPDK device");


	// Test load from PCAP to MBufRawPacket
	// ------------------------------------
	PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PTF_ASSERT(reader.open() == true, "Cannot open file '%s'", EXAMPLE2_PCAP_PATH);

	int tcpCount = 0;
	int udpCount = 0;
	int ip6Count = 0;
	int vlanCount = 0;
	int numOfPackets = 0;
	while (true)
	{
		MBufRawPacket mBufRawPacket;
		PTF_ASSERT(mBufRawPacket.init(dev) == true, "Couldn't init MBufRawPacket");
		if (!(reader.getNextPacket(mBufRawPacket)))
			break;

		numOfPackets++;

		Packet packet(&mBufRawPacket);
		if (packet.isPacketOfType(TCP))
			tcpCount++;
		if (packet.isPacketOfType(UDP))
			udpCount++;
		if (packet.isPacketOfType(IPv6))
			ip6Count++;
		if (packet.isPacketOfType(VLAN))
			vlanCount++;

		if (numOfPackets < 100)
			PTF_ASSERT(dev->sendPacket(packet, 0) == true, "Couldn't send packet");
	}

	PTF_ASSERT(numOfPackets == 4709, "Wrong num of packets read. Expected 4709 got %d", numOfPackets);

	PTF_ASSERT(tcpCount == 4321, "TCP count doesn't match: expected %d, got %d", 4321, tcpCount);
	PTF_ASSERT(udpCount == 269, "UDP count doesn't match: expected %d, got %d", 269, udpCount);
	PTF_ASSERT(ip6Count == 16, "IPv6 count doesn't match: expected %d, got %d", 16, ip6Count);
	PTF_ASSERT(vlanCount == 24, "VLAN count doesn't match: expected %d, got %d", 24, vlanCount);

	reader.close();

	// Test save MBufRawPacket to PCAP
	// -------------------------------
	MBufRawPacketVector rawPacketVec;
	int numOfAttempts = 0;
	while (numOfAttempts < 30)
	{
		bool foundTcpOrUdpPacket = false;
		for (int i = 0; i < dev->getNumOfOpenedRxQueues(); i++)
		{
			dev->receivePackets(rawPacketVec, 0);
			PCAP_SLEEP(1);
			for (MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
			{
				Packet packet(*iter);
				if ((packet.isPacketOfType(TCP) || packet.isPacketOfType(UDP)) && packet.isPacketOfType(IPv4))
				{
					foundTcpOrUdpPacket = true;
					break;
				}
			}
		}

		if (foundTcpOrUdpPacket)
			break;

		numOfAttempts++;
	}

	PTF_ASSERT(numOfAttempts < 30, "No packets were received");

	PcapFileWriterDevice writer(DPDK_PCAP_WRITE_PATH);
	PTF_ASSERT(writer.open() == true, "Couldn't open pcap writer");
	for (MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		PTF_ASSERT(writer.writePacket(**iter) == true, "Couldn't write raw packets to file");
	}
	writer.close();

	PcapFileReaderDevice reader2(DPDK_PCAP_WRITE_PATH);
	PTF_ASSERT(reader2.open() == true, "Cannot open file '%s'", DPDK_PCAP_WRITE_PATH);
	RawPacket rawPacket;
	int readerPacketCount = 0;
	while (reader2.getNextPacket(rawPacket))
		readerPacketCount++;
	reader2.close();

	PTF_ASSERT(readerPacketCount == (int)rawPacketVec.size(), "Not all packets captures were written successfully to pcap file");

	// Test packet manipulation
	// ------------------------

	MBufRawPacket* rawPacketToManipulate = NULL;
	for (MBufRawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		Packet packet(*iter);
		if ((packet.isPacketOfType(TCP) || packet.isPacketOfType(UDP)) && packet.isPacketOfType(IPv4))
		{
			TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
			if (tcpLayer != NULL && tcpLayer->getNextLayer() != NULL)
			{
				rawPacketToManipulate = (MBufRawPacket*)*iter;
				break;
			}

			UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
			if (udpLayer != NULL && udpLayer->getNextLayer() != NULL)
			{
				rawPacketToManipulate = (MBufRawPacket*)*iter;
				break;
			}
		}
	}

	PTF_ASSERT(rawPacketToManipulate != NULL, "Couldn't find TCP or UDP packet to manipulate");
	int initialRawPacketLen = rawPacketToManipulate->getRawDataLen();
	Packet packetToManipulate(rawPacketToManipulate);
	IPv4Layer* ipLayer = packetToManipulate.getLayerOfType<IPv4Layer>();
	
	// remove all layers above IP
	PTF_ASSERT(packetToManipulate.removeAllLayersAfter(ipLayer) == true, "Couldn't remove all layers above IP");

	PTF_ASSERT(ipLayer->getNextLayer() == NULL, "Couldn't remove all layers after TCP");
	PTF_ASSERT(rawPacketToManipulate->getRawDataLen() < initialRawPacketLen, "Raw packet size wasn't changed after removing layers");

	// create DNS packet out of this packet

	UdpLayer udpLayer(2233, 53);
	PTF_ASSERT(packetToManipulate.addLayer(&udpLayer), "Failed to add UdpLayer");

	DnsLayer dnsQueryLayer;
	dnsQueryLayer.getDnsHeader()->recursionDesired = true;
	dnsQueryLayer.getDnsHeader()->transactionID = htons(0xb179);
	DnsQuery* newQuery = dnsQueryLayer.addQuery("no-name", DNS_TYPE_A, DNS_CLASS_IN);
	PTF_ASSERT(newQuery != NULL, "Couldn't add query for dns layer");

	packetToManipulate.addLayer(&dnsQueryLayer);

	// change the query name and transmit the generated packet
	for (int i = 0; i < 10; i++)
	{
		// generate random string with random length < 40
		int nameLength = rand()%60;
		char name[nameLength+1];
		for (int j = 0; j < nameLength; ++j)
		{
			int randomChar = rand()%(26+26+10);
			if (randomChar < 26)
				name[j] = 'a' + randomChar;
	         else if (randomChar < 26+26)
				 name[j] = 'A' + randomChar - 26;
	         else
	        	 name[j] = '0' + randomChar - 26 - 26;
	     }
	     name[nameLength] = 0;

	     //set name for query
	     newQuery->setName(string(name));
	     packetToManipulate.computeCalculateFields();

	     //transmit packet
	     PTF_ASSERT(dev->sendPacket(packetToManipulate, 0) == true, "Couldn't send generated DNS packet #%d", i);
	}

	dev->close();


#else
	PTF_SKIP_TEST("DPDK not configured");
#endif
}

PTF_TEST_CASE(TestGetMacAddress)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(PcapGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PTF_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", PcapGlobalArgs.ipToSendReceivePackets.c_str());
    PTF_ASSERT(liveDev->open(), "Cannot open live device");

    //fetch all IP addresses from arp table
    std::string ipsInArpTableAsString;
#ifdef WIN32
    ipsInArpTableAsString = executeShellCommand("arp -a | for /f \"tokens=1\" \%i in ('findstr dynamic') do @echo \%i");
    ipsInArpTableAsString.erase(std::remove(ipsInArpTableAsString.begin(), ipsInArpTableAsString.end(), ' '), ipsInArpTableAsString.end() ) ;
#else
    ipsInArpTableAsString = executeShellCommand("arp -a | awk '{print $2}' | sed 's/.$//; s/^.//'");
#endif

    PTF_ASSERT(ipsInArpTableAsString != "", "Couldn't find IP addresses in arp-table to compare the result to. Aborting");

    // iterate all IP addresses and arping each one until one of them answers
    MacAddress result = MacAddress::Zero;
    std::stringstream sstream(ipsInArpTableAsString);
    std::string ip;
    double time = -1;
    while (std::getline(sstream, ip, '\n'))
    {
    	IPv4Address ipAddr(ip);
    	PTF_ASSERT(ipAddr.isValid(), "Got non-valid ip from arp-table: '%s'", ip.c_str());
    	LoggerPP::getInstance().supressErrors();
    	result = NetworkUtils::getInstance().getMacAddress(ipAddr, liveDev, time);
    	LoggerPP::getInstance().enableErrors();
    	if (result != MacAddress::Zero)
    	{
    		PTF_ASSERT_AND_RUN_COMMAND(time >= 0, liveDev->close(), "Time is zero");
    		result = NetworkUtils::getInstance().getMacAddress(ipAddr, liveDev, time, liveDev->getMacAddress(), liveDev->getIPv4Address());
    		PTF_ASSERT_AND_RUN_COMMAND(result != MacAddress::Zero, liveDev->close(), "Arping with MAC address and IPv4 address failed");
    		break;
    	}
    }

    PTF_ASSERT_AND_RUN_COMMAND(result != MacAddress::Zero, liveDev->close(), "Arping to all IPs in arp-table failed");

    liveDev->close();


}


struct TcpReassemblyStats
{
	std::string reassembledData;
	int numOfDataPackets;
	int curSide;
	int numOfMessagesFromSide[2];
	bool connectionsStarted;
	bool connectionsEnded;
	bool connectionsEndedManually;
	ConnectionData connData;

	TcpReassemblyStats() { clear(); }

	void clear() { reassembledData = ""; numOfDataPackets = 0; curSide = -1; numOfMessagesFromSide[0] = 0; numOfMessagesFromSide[1] = 0; connectionsStarted = false; connectionsEnded = false; connectionsEndedManually = false; }
};

typedef std::map<uint32_t, TcpReassemblyStats> TcpReassemblyMultipleConnStats;
typedef std::map<uint32_t, TcpReassemblyStats>::iterator TcpReassemblyMultipleConnStatsIter;

std::string readFileIntoString(std::string fileName)
{
	std::ifstream infile(fileName.c_str(), std::ios::binary);
	std::ostringstream ostrm;
	ostrm << infile.rdbuf();
	std::string res = ostrm.str();

	return res;
}

void saveStringToFile(std::string& str, std::string fileName)
{
    std::ofstream outfile(fileName.c_str());
    outfile << str;
    outfile.close();
}

void tcpReassemblyMsgReadyCallback(int sideIndex, TcpStreamData tcpData, void* userCookie)
{
	TcpReassemblyMultipleConnStats* stats = (TcpReassemblyMultipleConnStats*)userCookie;

	TcpReassemblyMultipleConnStatsIter iter = stats->find(tcpData.getConnectionData().flowKey);
	if (iter == stats->end())
	{
		stats->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyStats()));
		iter = stats->find(tcpData.getConnectionData().flowKey);
	}


	if (sideIndex != iter->second.curSide)
	{
		iter->second.numOfMessagesFromSide[sideIndex]++;
		iter->second.curSide = sideIndex;
	}

	iter->second.numOfDataPackets++;
	iter->second.reassembledData += std::string((char*)tcpData.getData(), tcpData.getDataLength());
	//printf("\n***** got %d bytes from side %d conn 0x%X *****\n", tcpData.getDataLength(), sideIndex, tcpData.getConnectionData().flowKey);
}

void tcpReassemblyConnectionStartCallback(ConnectionData connectionData, void* userCookie)
{
	TcpReassemblyMultipleConnStats* stats = (TcpReassemblyMultipleConnStats*)userCookie;

	TcpReassemblyMultipleConnStatsIter iter = stats->find(connectionData.flowKey);
	if (iter == stats->end())
	{
		stats->insert(std::make_pair(connectionData.flowKey, TcpReassemblyStats()));
		iter = stats->find(connectionData.flowKey);
	}

	iter->second.connectionsStarted = true;
	iter->second.connData = connectionData;

	//printf("conn 0x%X started\n", connectionData.flowKey);
}

void tcpReassemblyConnectionEndCallback(ConnectionData connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	TcpReassemblyMultipleConnStats* stats = (TcpReassemblyMultipleConnStats*)userCookie;

	TcpReassemblyMultipleConnStatsIter iter = stats->find(connectionData.flowKey);
	if (iter == stats->end())
	{
		stats->insert(std::make_pair(connectionData.flowKey, TcpReassemblyStats()));
		iter = stats->find(connectionData.flowKey);
	}

	if (reason == TcpReassembly::TcpReassemblyConnectionClosedManually)
		iter->second.connectionsEndedManually = true;
	else
		iter->second.connectionsEnded = true;

	//printf("conn 0x%X ended\n", connectionData.flowKey);
}

bool tcpReassemblyReadPcapIntoPacketVec(std::string pcapFileName, std::vector<RawPacket>& packetStream, std::string& errMsg)
{
	errMsg = "";
	packetStream.clear();

	PcapFileReaderDevice reader(pcapFileName.c_str());
	if (!reader.open())
	{
		errMsg = "Cannot open pcap file";
		return false;
	}

	RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket))
	{
		packetStream.push_back(rawPacket);
	}

	return true;
}

RawPacket tcpReassemblyAddRetransmissions(RawPacket rawPacket, int beginning, int numOfBytes)
{
	Packet packet(&rawPacket);

	TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
	if (tcpLayer == NULL)
		throw;

	IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
	if (ipLayer == NULL)
		throw;

	int tcpPayloadSize = ntohs(ipLayer->getIPv4Header()->totalLength)-ipLayer->getHeaderLen()-tcpLayer->getHeaderLen();

	if (numOfBytes <= 0)
		numOfBytes = tcpPayloadSize-beginning;

	uint8_t* newPayload = new uint8_t[numOfBytes];

	if (beginning + numOfBytes <= tcpPayloadSize)
	{
		memcpy(newPayload, tcpLayer->getLayerPayload()+beginning, numOfBytes);
	}
	else
	{
		int bytesToCopy = tcpPayloadSize-beginning;
		memcpy(newPayload, tcpLayer->getLayerPayload()+beginning, bytesToCopy);
		for (int i = bytesToCopy; i < numOfBytes; i++)
		{
			newPayload[i] = '*';
		}
	}

	Layer* layerToRemove = tcpLayer->getNextLayer();
	if (layerToRemove != NULL)
		packet.removeLayer(layerToRemove->getProtocol());

	tcpLayer->getTcpHeader()->sequenceNumber = htonl(ntohl(tcpLayer->getTcpHeader()->sequenceNumber) + beginning);

	PayloadLayer newPayloadLayer(newPayload, numOfBytes, false);
	packet.addLayer(&newPayloadLayer);

	packet.computeCalculateFields();

	delete [] newPayload;

	return *(packet.getRawPacket());
}

bool tcpReassemblyTest(std::vector<RawPacket>& packetStream, TcpReassemblyMultipleConnStats& results, bool monitorOpenCloseConns, bool closeConnsManually)
{
	TcpReassembly* tcpReassembly = NULL;

	if (monitorOpenCloseConns)
		tcpReassembly = new TcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);
	else
		tcpReassembly = new TcpReassembly(tcpReassemblyMsgReadyCallback, &results);

	for (std::vector<RawPacket>::iterator iter = packetStream.begin(); iter != packetStream.end(); iter++)
	{
		Packet packet(&(*iter));
		tcpReassembly->reassemblePacket(packet);
	}

//	for(TcpReassemblyMultipleConnStatsIter iter = results.begin(); iter != results.end(); iter++)
//	{
//		// replace \r\n with \n
//		size_t index = 0;
//		while (true)
//		{
//			 index = iter->second.reassembledData.find("\r\n", index);
//			 if (index == string::npos) break;
//			 iter->second.reassembledData.replace(index, 2, "\n");
//			 index += 1;
//		}
//	}

	if (closeConnsManually)
		tcpReassembly->closeAllConnections();

	delete tcpReassembly;

	return true;
}

PTF_TEST_CASE(TestTcpReassemblySanity)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv4Address expectedSrcIP(std::string("10.0.0.1"));
	IPv4Address expectedDstIP(std::string("81.218.72.15"));
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 10.0.0.1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 81.218.72.15");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1491516383, "Bad start time seconds, expected 1491516383");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 915793, "Bad start time microseconds, expected 915793");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}

PTF_TEST_CASE(TestTcpReassemblyRetran)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// retransmission includes exact same data
	RawPacket retPacket1 = tcpReassemblyAddRetransmissions(packetStream.at(4), 0, 0);
	// retransmission includes 10 bytes less than original data (missing bytes are from the beginning)
	RawPacket retPacket2 =  tcpReassemblyAddRetransmissions(packetStream.at(10), 10, 0);
	// retransmission includes 20 bytes less than original data (missing bytes are from the end)
	RawPacket retPacket3 =  tcpReassemblyAddRetransmissions(packetStream.at(13), 0, 1340);
	// retransmission includes 10 bytes more than original data (original data + 10 bytes)
	RawPacket retPacket4 =  tcpReassemblyAddRetransmissions(packetStream.at(21), 0, 1430);
	// retransmission includes 10 bytes less in the beginning and 20 bytes more at the end
	RawPacket retPacket5 =  tcpReassemblyAddRetransmissions(packetStream.at(28), 10, 1370);
	// retransmission includes 10 bytes less in the beginning and 15 bytes less at the end
	RawPacket retPacket6 =  tcpReassemblyAddRetransmissions(packetStream.at(34), 10, 91);

	packetStream.insert(packetStream.begin() + 5, retPacket1);
	packetStream.insert(packetStream.begin() + 12, retPacket2);
	packetStream.insert(packetStream.begin() + 16, retPacket3);
	packetStream.insert(packetStream.begin() + 25, retPacket4);
	packetStream.insert(packetStream.begin() + 33, retPacket5);
	packetStream.insert(packetStream.begin() + 40, retPacket6);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 21, "Num of data packets isn't 21, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_retransmission_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}

PTF_TEST_CASE(TestTcpReassemblyMissingData)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// remove 20 bytes from the beginning
	RawPacket missPacket1 = tcpReassemblyAddRetransmissions(packetStream.at(3), 20, 0);
	packetStream.insert(packetStream.begin() + 4, missPacket1);
	packetStream.erase(packetStream.begin() + 3);

	// remove 30 bytes from the end
	RawPacket missPacket2 = tcpReassemblyAddRetransmissions(packetStream.at(20), 0, 1390);
	packetStream.insert(packetStream.begin() + 21, missPacket2);
	packetStream.erase(packetStream.begin() + 20);

	// remove whole packets
	packetStream.erase(packetStream.begin() + 28);
	packetStream.erase(packetStream.begin() + 30);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 17, "Num of data packets isn't 21, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";



	// test flow without SYN packet
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// remove SYN and SYN/ACK packets
	packetStream.erase(packetStream.begin());
	packetStream.erase(packetStream.begin());

	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}

PTF_TEST_CASE(TestTcpReassemblyOutOfOrder)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// swap 2 consequent packets
	std::swap(packetStream[9], packetStream[10]);

	// swap 2 non-consequent packets
	RawPacket oooPacket1 = packetStream[18];
	packetStream.erase(packetStream.begin() + 18);
	packetStream.insert(packetStream.begin() + 23, oooPacket1);

	// reverse order of all packets in message
	for (int i = 0; i < 12; i++)
	{
		RawPacket oooPacketTemp = packetStream[35];
		packetStream.erase(packetStream.begin() + 35);
		packetStream.insert(packetStream.begin() + 24 + i, oooPacketTemp);
	}

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "OOO test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "OOO test: Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "OOO test: Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "OOO test: Num of messages from side 1 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "OOO test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "OOO test: Connection ended with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "OOO test: Connection wasn't ended manually");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_out_of_order_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "OOO test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";



	// test out-of-order + missing data
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// reverse order of all packets in message
	for (int i = 0; i < 12; i++)
	{
		RawPacket oooPacketTemp = packetStream[35];
		packetStream.erase(packetStream.begin() + 35);
		packetStream.insert(packetStream.begin() + 24 + i, oooPacketTemp);
	}

	// remove one packet
	packetStream.erase(packetStream.begin() + 29);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "OOO + missing data test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 18, "OOO + missing data test: Num of data packets isn't 18, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "OOO + missing data test: Num of messages from side 0 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "OOO + missing data test: Num of messages from side 1 isn't 2");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "OOO + missing data test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "OOO + missing data test: Connection ended with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "OOO + missing data test: Connection wasn't ended manually");

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output_ooo.txt"));

	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "OOO + missing data test: Reassembly data different than expected");


}

PTF_TEST_CASE(TestTcpReassemblyWithFIN_RST)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData = "";

	// test fin packet in end of connection
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "FIN test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 5, "FIN test: Num of data packets isn't 5, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "FIN test: Num of messages from side 0 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "FIN test: Num of messages from side 1 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "FIN test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "FIN test: Connection didn't end with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "FIN test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "FIN test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	// test rst packet in end of connection
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_rst.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "RST test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 2, "RST test: Num of data packets isn't 2, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "RST test: Num of messages from side 0 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "RST test: Num of messages from side 1 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "RST test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "RST test: Connection didn't end with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "RST test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_rst_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "RST test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	//test fin packet in end of connection that has also data
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "FIN with data test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 6, "FIN with data test: Num of data packets isn't 6, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "FIN with data test: Num of messages from side 0 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "FIN with data test: Num of messages from side 1 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "FIN with data test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "FIN with data test: Connection didn't end with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "FIN with data test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "FIN with data test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	// test missing data before fin
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// move second packet of server->client message to the end of the message (after FIN)
	RawPacket oooPacketTemp = packetStream[6];
	packetStream.erase(packetStream.begin() + 6);
	packetStream.insert(packetStream.begin() + 12, oooPacketTemp);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Missing data before FIN test: Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 5, "Missing data before FIN test: Num of data packets isn't 5, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "Missing data before FIN test: Num of messages from side 0 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "Missing data before FIN test: Num of messages from side 1 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Missing data before FIN test: Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "Missing data before FIN test: Connection didn't end with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "Missing data before FIN test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output2.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Missing data before FIN test: Reassembly data different than expected");


}

PTF_TEST_CASE(TestTcpReassemblyMalformedPkts)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData = "";

	// test retransmission with new data but payload doesn't really contain all the new data
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// take one of the packets and increase the IPv4 total length field
	Packet malPacket(&packetStream.at(8));
	IPv4Layer* ipLayer = malPacket.getLayerOfType<IPv4Layer>();
	PTF_ASSERT(ipLayer != NULL, "Cannot find the IPv4 layer of the packet");
	ipLayer->getIPv4Header()->totalLength = ntohs(htons(ipLayer->getIPv4Header()->totalLength) + 40);

//	PcapFileWriterDevice writer("pasdasda.pcap");
//	writer.open();
//
//	for (std::vector<RawPacket>::iterator iter = packetStream.begin(); iter != packetStream.end(); iter++)
//	{
//		writer.writePacket(*iter);
//	}
//
//	writer.close();

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 6, "Num of data packets isn't 6, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "Num of messages from side 0 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "Num of messages from side 1 isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connection wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "Connection didn't end with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}


PTF_TEST_CASE(TestTcpReassemblyMultipleConns)
{
	TcpReassemblyMultipleConnStats results;
	std::string errMsg;
	std::string expectedReassemblyData = "";

	TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

	std::vector<RawPacket> packetStream;
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/three_http_streams.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	RawPacket finPacket1 = packetStream.at(13);
	RawPacket finPacket2 = packetStream.at(15);

	packetStream.erase(packetStream.begin() + 13);
	packetStream.erase(packetStream.begin() + 14);

	for (std::vector<RawPacket>::iterator iter = packetStream.begin(); iter != packetStream.end(); iter++)
	{
		Packet packet(&(*iter));
		tcpReassembly.reassemblePacket(packet);
	}

	PTF_ASSERT(results.size() == 3, "Num of connections isn't 3");

	TcpReassemblyMultipleConnStatsIter iter = results.begin();

	PTF_ASSERT(iter->second.numOfDataPackets == 2, "Conn #1: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #1: Num of messages from side 0 isn't 1");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #1: Num of messages from side 1 isn't 1");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #1: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == true, "Conn #1: Connection didn't end with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == false, "Conn #1: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_1_output.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #1: Reassembly data different than expected");

	iter++;

	PTF_ASSERT(iter->second.numOfDataPackets == 2, "Conn #2: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #2: Num of messages from side 0 isn't 1");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #2: Num of messages from side 1 isn't 1");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #2: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == true, "Conn #2: Connection didn't end with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == false, "Conn #2: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_2_output.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #2: Reassembly data different than expected");

	iter++;

	PTF_ASSERT(iter->second.numOfDataPackets == 2, "Conn #3: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #3: Num of messages from side 0 isn't 1");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #3: Num of messages from side 1 isn't 1");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #3: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == false, "Conn #3: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_3_output.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #3: Reassembly data different than expected");


	// test getConnectionInformation and isConnectionOpen

	const std::vector<ConnectionData> managedConnections = tcpReassembly.getConnectionInformation();
	PTF_ASSERT(managedConnections.size() == 3, "Size of managed connection list isn't 3");
	std::vector<ConnectionData>::const_iterator connIter = managedConnections.begin();
	PTF_ASSERT(tcpReassembly.isConnectionOpen(*connIter) > 0, "Connection #1 is closed");

	connIter++;
	PTF_ASSERT(tcpReassembly.isConnectionOpen(*connIter) == 0, "Connection #2 is still open");

	connIter++;
	PTF_ASSERT(tcpReassembly.isConnectionOpen(*connIter) == 0, "Connection #3 is still open");

	ConnectionData dummyConn;
	dummyConn.flowKey = 0x12345678;
	PTF_ASSERT(tcpReassembly.isConnectionOpen(dummyConn) < 0, "Dummy connection exists");


	// close flow manually and verify it's closed

	tcpReassembly.closeConnection(iter->first);
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended supposedly ended with FIN or RST although ended manually");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections still isn't ended even though ended manually");


	// now send FIN packets of conn 3 and verify they are igonred

	tcpReassembly.reassemblePacket(&finPacket1);
	tcpReassembly.reassemblePacket(&finPacket2);

	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended supposedly ended with FIN or RST after FIN packets sent although ended manually before");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections isn't ended after FIN packets sent even though ended manually before");


}


PTF_TEST_CASE(TestTcpReassemblyIPv6)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 10, "Num of data packets isn't 10, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 3, "Num of messages from side 0 isn't 3");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 3, "Num of messages from side 1 isn't 3");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP(std::string("2001:618:1:8000::5"));
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 2001:618:1:8000::5");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551796, "Bad start time seconds, expected 1147551796");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 702602, "Bad start time microseconds, expected 702602");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}


PTF_TEST_CASE(TestTcpReassemblyIPv6MultConns)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	std::string expectedReassemblyData = "";

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/four_ipv6_http_streams.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 4, "Num of connections isn't 4");

	TcpReassemblyMultipleConnStatsIter iter = tcpReassemblyResults.begin();

	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP1(std::string("2001:618:1:8000::5"));
	IPv6Address expectedDstIP2(std::string("2001:638:902:1:202:b3ff:feee:5dc2"));

	PTF_ASSERT(iter->second.numOfDataPackets == 14, "Conn #1: Num of data packets isn't 14, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 3, "Conn #1: Num of messages from side 0 isn't 3");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 3, "Conn #1: Num of messages from side 1 isn't 3");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #1: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #1: Connection ended with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #1: Connections wasn't ended manually");
	PTF_ASSERT(iter->second.connData.srcIP != NULL, "Conn #1: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.dstIP != NULL, "Conn #1: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #1: Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #1: Source IP isn't 2001:618:1:8000::5");
	PTF_ASSERT(iter->second.connData.srcPort == 35995, "Conn #1: source port isn't 35995");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551795, "Bad start time seconds, expected 1147551795");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 526632, "Bad start time microseconds, expected 526632");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream4.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #1: Reassembly data different than expected");

	iter++;

	PTF_ASSERT(iter->second.numOfDataPackets == 10, "Conn #2: Num of data packets isn't 10, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #2: Num of messages from side 0 isn't 1");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #2: Num of messages from side 1 isn't 1");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #2: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #2: Connection ended with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #2: Connections wasn't ended manually");
	PTF_ASSERT(iter->second.connData.srcIP != NULL, "Conn #2: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.dstIP != NULL, "Conn #2: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #2: Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #2: Source IP isn't 2001:618:1:8000::5");
	PTF_ASSERT(iter->second.connData.srcPort == 35999, "Conn #2: source port isn't 35999");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551795, "Bad start time seconds, expected 1147551795");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 526632, "Bad start time microseconds, expected 526632");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");

	iter++;

	PTF_ASSERT(iter->second.numOfDataPackets == 2, "Conn #3: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #3: Num of messages from side 0 isn't 1");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #3: Num of messages from side 1 isn't 1");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #3: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections wasn't ended manually");
	PTF_ASSERT(iter->second.connData.srcIP != NULL, "Conn #3: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.dstIP != NULL, "Conn #3: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #3: Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP2), "Conn #3: Source IP isn't 2001:638:902:1:202:b3ff:feee:5dc2");
	PTF_ASSERT(iter->second.connData.srcPort == 40426, "Conn #3: source port isn't 40426");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551795, "Bad start time seconds, expected 1147551795");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 526632, "Bad start time microseconds, expected 526632");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream3.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #3: Reassembly data different than expected");

	iter++;

	PTF_ASSERT(iter->second.numOfDataPackets == 13, "Conn #4: Num of data packets isn't 13, it's %d", iter->second.numOfDataPackets);
	PTF_ASSERT(iter->second.numOfMessagesFromSide[0] == 4, "Conn #4: Num of messages from side 0 isn't 4");
	PTF_ASSERT(iter->second.numOfMessagesFromSide[1] == 4, "Conn #4: Num of messages from side 1 isn't 4");
	PTF_ASSERT(iter->second.connectionsStarted == true, "Conn #4: Connection wasn't opened");
	PTF_ASSERT(iter->second.connectionsEnded == false, "Conn #4: Connection ended with FIN or RST");
	PTF_ASSERT(iter->second.connectionsEndedManually == true, "Conn #4: Connections wasn't ended manually");
	PTF_ASSERT(iter->second.connData.srcIP != NULL, "Conn #4: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.dstIP != NULL, "Conn #4: Source IP is NULL");
	PTF_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #4: Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #4: Source IP isn't 2001:618:1:8000::5");
	PTF_ASSERT(iter->second.connData.srcPort == 35997, "Conn #4: source port isn't 35997");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551795, "Bad start time seconds, expected 1147551795");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 526632, "Bad start time microseconds, expected 526632");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream2.txt"));
	PTF_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #4: Reassembly data different than expected");


}


PTF_TEST_CASE(TestTcpReassemblyIPv6_OOO)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// swap 2 non-consequent packets
	RawPacket oooPacket1 = packetStream[10];
	packetStream.erase(packetStream.begin() + 10);
	packetStream.insert(packetStream.begin() + 12, oooPacket1);

	// swap additional 2 non-consequent packets
	oooPacket1 = packetStream[15];
	packetStream.erase(packetStream.begin() + 15);
	packetStream.insert(packetStream.begin() + 17, oooPacket1);

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PTF_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 10, "Num of data packets isn't 10, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 3, "Num of messages from side 0 isn't 3");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 3, "Num of messages from side 1 isn't 3");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP(std::string("2001:618:1:8000::5"));
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 2001:618:400::5199:cc70");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 2001:618:1:8000::5");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_sec == 1147551796, "Bad start time seconds, expected 1147551796");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.startTime.tv_usec == 702602, "Bad start time microseconds, expected 702602");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_sec == 0, "Bad end time seconds, expected 0");
	PTF_ASSERT(tcpReassemblyResults.begin()->second.connData.endTime.tv_usec == 0, "Bad end time microseconds, expected 0");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PTF_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");


}


void savePacketToFile(RawPacket& packet, std::string fileName)
{
    PcapFileWriterDevice writerDev(fileName.c_str());
    writerDev.open();
    writerDev.writePacket(packet);
    writerDev.close();
}

PTF_TEST_CASE(TestIPFragmentationSanity)
{
	std::vector<RawPacket> packetStream;
	std::string errMsg;

	// basic IPv4 reassembly test
	// ==========================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	IPReassembly ipReassembly;
	IPReassembly::ReassemblyStatus status;

	PTF_ASSERT(ipReassembly.getMaxCapacity() == PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE, "Max capacity isn't PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE");
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 0, "Capacity before reassembly isn't 0");

	Packet* result = NULL;

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4: First frag status isn't FIRST_FRAGMENT");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv4: Current capacity isn't 1");
		}
		else if (i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "IPv4: Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4: Frag status isn't FRAGMENT");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv4: Current capacity isn't 1");
		}
		else
		{
			PTF_ASSERT(result != NULL, "IPv4: Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv4: Last frag status isn't REASSEMBLED");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 0, "IPv4: Capacity after reassembly isn't 0");
		}
	}

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_reassembled.txt", bufferLength);

	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "IPv4: Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv4: Reassembled packet data is different than expected");

	delete result;
	delete [] buffer;


	// basic IPv6 reassembly test
	// ==========================

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1Frags;

	PTF_ASSERT(reader.getNextPackets(packet1Frags, 7) == 7, "IPv6: Cannot read 7 frags of packet 1");

	reader.close();

	result = NULL;

	for (size_t i = 0; i < packet1Frags.size(); i++)
	{
		Packet packet(packet1Frags.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6: First frag status isn't FIRST_FRAGMENT");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv6: Current capacity isn't 1");
		}
		else if (i < (packet1Frags.size()-1))
		{
			PTF_ASSERT(result == NULL, "IPv6: Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6: Frag status isn't FRAGMENT");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv6: Current capacity isn't 1");
		}
		else
		{
			PTF_ASSERT(result != NULL, "IPv6: Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6: Last frag status isn't REASSEMBLED");
			PTF_ASSERT(ipReassembly.getCurrentCapacity() == 0, "IPv6: Capacity after reassembly isn't 0");
		}
	}

	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", bufferLength);

	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "IPv6: Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv6: Reassembled packet data is different than expected");

	delete result;
	delete [] buffer;


	// non-fragment test
	// ==================

	packetStream.clear();
	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/VlanPackets.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	for (size_t i = 0; i < 20; i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PTF_ASSERT(result == &packet, "Non-fragment test: didn't get the same non-fragment packet in the result");
		PTF_ASSERT(status == IPReassembly::NON_FRAGMENT, "Non-fragment test: status isn't NON_FRAGMENT");
	}


	// non-IP test
	// ==================

	for (size_t i = 20; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PTF_ASSERT(result == &packet, "Non-IP test: didn't get the same non-IP packet in the result");
		PTF_ASSERT(status == IPReassembly::NON_IP_PACKET, "Non-IP test: status isn't NON_IP_PACKET");
	}


}


PTF_TEST_CASE(TestIPFragOutOfOrder)
{
	std::vector<RawPacket> packetStream;
	std::string errMsg;

	IPReassembly ipReassembly;
	IPReassembly::ReassemblyStatus status;

	Packet* result = NULL;

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_reassembled.txt", bufferLength);


	// First use-case: first and second fragments are swapped
	// ======================================================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// swap first and second packet
	std::swap(packetStream[0], packetStream[1]);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "First frag status isn't OUT_OF_ORDER_FRAGMENT");
		}
		else if (i == 1)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Second frag status isn't FIRST_FRAGMENT");
		}
		else if (i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag status isn't FRAGMENT");
		}
		else
		{
			PTF_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PTF_ASSERT(result != NULL, "Reassembled packet is NULL");
	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Second use-case: 6th and 10th fragments are swapped, as well as 3rd and 7th
	// ===========================================================================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	//swap 6th and 10th fragments
	std::swap(packetStream[5], packetStream[9]);

	//swap 3rd and 7th fragments
	std::swap(packetStream[2], packetStream[6]);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 2 || i == 3 || i == 4 || i == 5 || i == 7 || i == 8)
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 0)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "First frag status isn't FIRST_FRAGMENT");
		}
		else if (i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PTF_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Third use-case: last fragment comes before the end
	// ==================================================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	//swap 6th and last fragments
	std::swap(packetStream[5], packetStream[10]);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i >= 5 && i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 0)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "First frag status isn't FIRST_FRAGMENT");
		}
		else if (i < 5)
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PTF_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;
	result = NULL;

	packetStream.clear();


	// Fourth use-case: last fragment comes first
	// ==========================================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// move last frag from the end to the beginning
	RawPacket lastFrag = packetStream.at(10);
	packetStream.insert(packetStream.begin(), lastFrag);
	packetStream.erase(packetStream.begin() + 11);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 1)
		{
			PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Frag#%d status isn't FIRST_FRAGMENT", (int)i);
		}
		else if (i > 1 && i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PTF_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PTF_ASSERT(result != NULL, "Reassembled packet is NULL");
	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Fifth use-case: fragments come in reverse order
	// ===============================================

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// reverse order of fragments
	for (size_t i = 1; i < packetStream.size(); i++)
	{
		RawPacket curFrag = packetStream.at(i);
		packetStream.insert(packetStream.begin(), curFrag);
		packetStream.erase(packetStream.begin() + i + 1);
	}

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i < (packetStream.size()-1))
		{
			PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else
		{
			PTF_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PTF_ASSERT(result != NULL, "Reassembled packet is NULL");
	PTF_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();

	delete [] buffer;


	// Sixth use-case: IPv6: fragments 1 and 3 are swapped, as well as fragments 6 and 7
	// =================================================================================

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1Frags;

	PTF_ASSERT(reader.getNextPackets(packet1Frags, 7) == 7, "IPv6: Cannot read 7 frags of packet 1");

	reader.close();

	result = NULL;

	result = ipReassembly.processPacket(packet1Frags.at(2), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #3");
	PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#3 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(1), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #2");
	PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#2 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(0), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #1");
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Frag#1 status isn't FIRST_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(3), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #4");
	PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag#4 status isn't FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(4), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #5");
	PTF_ASSERT(status == IPReassembly::FRAGMENT, "Frag#5 status isn't FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(6), status);
	PTF_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #7");
	PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#7 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer2Length);

	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);

	PTF_ASSERT(buffer2Length == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), buffer2Length);
	PTF_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Reassembled packet data is different than expected");

	delete result;

	delete [] buffer2;



}

PTF_TEST_CASE(TestIPFragPartialData)
{
	std::vector<RawPacket> packetStream;
	std::string errMsg;

	IPReassembly ipReassembly;
	IPReassembly::ReassemblyStatus status;

	// IPv4 partial data
	// ~~~~~~~~~~~~~~~~~

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_partial.txt", bufferLength);

	PTF_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	for (size_t i = 0; i < 6; i++)
	{
		Packet packet(&packetStream.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	IPReassembly::IPv4PacketKey ip4Key(16991, IPv4Address(std::string("172.16.133.54")), IPv4Address(std::string("216.137.33.81")));
	Packet* partialPacket = ipReassembly.getCurrentPacket(ip4Key);

	PTF_ASSERT(partialPacket != NULL, "IPv4: Cannot retrieve partial packet");
	PTF_ASSERT(bufferLength == partialPacket->getRawPacket()->getRawDataLen(), "IPv4: Partial packet len (%d) is different than read packet len (%d)", partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv4: Partial packet data is different than expected");

	delete partialPacket;
	delete [] buffer;


	// IPv6 partial data
	// ~~~~~~~~~~~~~~~~~

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1_partial.txt", bufferLength);

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1PartialFrags;

	PTF_ASSERT(reader.getNextPackets(packet1PartialFrags, 5) == 5, "IPv6: Cannot read 5 first frags of packet 1");

	reader.close();

	for (size_t i = 0; i < 5; i++)
	{
		Packet packet(packet1PartialFrags.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	IPReassembly::IPv6PacketKey ip6Key(0x2c5323, IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), IPv6Address(std::string("ff02::fb")));
	partialPacket = ipReassembly.getCurrentPacket(ip6Key);
	PTF_ASSERT(bufferLength == partialPacket->getRawPacket()->getRawDataLen(), "IPv6: Partial packet len (%d) is different than read packet len (%d)", partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PTF_ASSERT(memcmp(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv6: Partial packet data is different than expected");

	PTF_ASSERT(partialPacket != NULL, "IPv6: Cannot retrieve partial packet");

	delete partialPacket;
	delete [] buffer;


}

PTF_TEST_CASE(TestIPFragMultipleFrags)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector ip4Packet1Frags;
	RawPacketVector ip4Packet2Frags;
	RawPacketVector ip4Packet3Frags;
	RawPacketVector ip4Packet4Frags;
	RawPacketVector ip4Packet5Vec;
	RawPacketVector ip4Packet6Frags;
	RawPacketVector ip4Packet7Vec;
	RawPacketVector ip4Packet8Frags;
	RawPacketVector ip4Packet9Vec;
	RawPacketVector ip6Packet1Frags;
	RawPacketVector ip6Packet2Frags;
	RawPacketVector ip6Packet3Frags;
	RawPacketVector ip6Packet4Frags;


	PTF_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PTF_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PTF_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 6");
	PTF_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PTF_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PTF_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");

	reader.close();
	reader2.close();

	Packet* ip4Packet1;
	Packet* ip4Packet2;
	Packet* ip4Packet3;
	Packet* ip4Packet4;
	Packet* ip4Packet5;
	Packet* ip4Packet6;
	Packet* ip4Packet7;
	Packet* ip4Packet8;
	Packet* ip4Packet9;
	Packet* ip6Packet1;
	Packet* ip6Packet2;
	Packet* ip6Packet3;
	Packet* ip6Packet4;


	IPReassembly ipReassembly;

	IPReassembly::ReassemblyStatus status;

	// read 1st frag in each packet

	ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet1 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip4Packet1 == NULL, "IPv4 Packet1 first frag - result isn't NULL");
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet2 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip4Packet2 == NULL, "IPv4 Packet2 first frag - result isn't NULL");
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet3 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip4Packet3 == NULL, "IPv4 Packet3 first frag - result isn't NULL");
	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet4 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 first frag - result isn't NULL");
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet6 first frag - status isn't FIRST_FRAGMENT");

	PTF_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 first frag - result isn't NULL");
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet8 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 first frag - result isn't NULL");
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(0), status);

	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet1 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 first frag - result isn't NULL");
	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet2 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 first frag - result isn't NULL");

	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet3 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip6Packet3 == NULL, "IPv6 Packet3 first frag - result isn't NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(0), status);
	PTF_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet4 first frag - status isn't FIRST_FRAGMENT");
	PTF_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 first frag - result isn't NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity after first fragment isn't 10");


	// read 2nd - 5th frag in each packet

	for (int i = 1; i < 5; i++)
	{
		ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet1 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet1 == NULL, "IPv4 Packet1 frag#%d - result isn't NULL", i);
		ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet2 == NULL, "IPv4 Packet2 frag#%d - result isn't NULL", i);
		ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet3 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet3 == NULL, "IPv4 Packet3 frag#%d - result isn't NULL", i);
		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 frag#%d - result isn't NULL", i);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet6 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 frag#%d - result isn't NULL", i);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet8 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 frag#%d - result isn't NULL", i);
		ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet1 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 frag#%d - result isn't NULL", i);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet3 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet3 == NULL, "IPv6 Packet3 frag#%d - result isn't NULL", i);
		ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 frag#%d - result isn't NULL", i);
	}

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity after 2nd-5th fragment isn't 10");


	// read 6th frag in IPv4 packets 1,2,3

	ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet1 frag#6 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet1 != NULL, "Packet1 frag#6 - result is NULL");
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet2 frag#6 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet2 != NULL, "Packet2 frag#6 - result is NULL");
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet3 frag#6 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet3 != NULL, "Packet3 frag#6 - result is NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 7, "Capacity after 6th fragment isn't 7");


	// read IPv4 packet5

	ip4Packet5 = ipReassembly.processPacket(ip4Packet5Vec.at(0), status);
	PTF_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet5 - status isn't NON_FRAGMENT");
	PTF_ASSERT(ip4Packet5 != NULL, "Packet5 - result is NULL");
	PTF_ASSERT(ip4Packet5->getRawPacket() == ip4Packet5Vec.at(0), "Packet5 - result ptr isn't equal to original packet ptr");


	// read 6th - 7th frag in IPv6 packets 1,4

	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet1 frag#6 - status isn't FRAGMENT");
	PTF_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 frag#6 - result isn't NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(5), status);
	PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#6 - status isn't FRAGMENT");
	PTF_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 frag#6 - result isn't NULL");
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(6), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet1 frag#7 - status isn't REASSEMBLED");
	PTF_ASSERT(ip6Packet1 != NULL, "IPv6 Packet1 frag#7 - result is NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(6), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet4 frag#7 - status isn't REASSEMBLED");
	PTF_ASSERT(ip6Packet4 != NULL, "IPv6 Packet4 frag#7 - result is NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 5, "Capacity after 6th fragment isn't 5");


	// read 6th - 9th frag in IPv4 packets 4,6,8 and IPv6 packet 2

	for (int i = 5; i < 9; i++)
	{
		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 frag#%d - result isn't NULL", i);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet6 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 frag#%d - result isn't NULL", i);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet8 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 frag#%d - result isn't NULL", i);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
	}


	// read 6th - 9th frag in IPv6 packet 3

	for (int i = 5; i < 8; i++)
	{
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet3 == NULL, "IPv6 Packet4 frag#%d - result isn't NULL", i);
	}

	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(8), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet3 frag#9 - status isn't REASSEMBLED");
	PTF_ASSERT(ip6Packet3 != NULL, "IPv6 Packet3 frag#9 - result is NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 4, "Capacity after IPv6 packet 3 reassembly isn't 4");


	// read IPv4 packet7

	ip4Packet7 = ipReassembly.processPacket(ip4Packet7Vec.at(0), status);
	PTF_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet7 - status isn't NON_FRAGMENT");
	PTF_ASSERT(ip4Packet7 != NULL, "Packet7 - result is NULL");
	PTF_ASSERT(ip4Packet7->getRawPacket() == ip4Packet7Vec.at(0), "Packet7 - result ptr isn't equal to original packet ptr");


	// read 10th frag in IPv4 packets 4,6,8

	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(9), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet4 frag#10 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet4 != NULL, "Packet4 frag#10 - result is NULL");
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(9), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet6 frag#10 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet6 != NULL, "Packet6 frag#10 - result is NULL");
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(9), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "Packet8 frag#10 - status isn't REASSEMBLED");
	PTF_ASSERT(ip4Packet8 != NULL, "Packet8 frag#10 - result is NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 1, "Capacity after 10th fragment isn't 1");


	// read IPv4 packet 9

	ip4Packet9 = ipReassembly.processPacket(ip4Packet9Vec.at(0), status);
	PTF_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet9 - status isn't NON_FRAGMENT");
	PTF_ASSERT(ip4Packet9 != NULL, "Packet9 - result is NULL");
	PTF_ASSERT(ip4Packet9->getRawPacket() == ip4Packet9Vec.at(0), "Packet9 - result ptr isn't equal to original packet ptr");


	// read 11th frag in IPv4 packets 4,6 (duplicated last frag)

	PTF_ASSERT(ipReassembly.processPacket(ip4Packet4Frags.at(10), status) == NULL, "Packet4 frag#11 - result isn't NULL");
	PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Packet4 frag#11 - status isn't OUT_OF_ORDER_FRAGMENT");
	PTF_ASSERT(ipReassembly.processPacket(ip4Packet6Frags.at(10), status) == NULL, "Packet6 frag#11 - result isn't NULL");
	PTF_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Packet6 frag#11 - status isn't OUT_OF_ORDER_FRAGMENT");


	// read 10th - 13th frag in IPv6 packet 2

	for (int i = 9; i < 12; i++)
	{
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PTF_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PTF_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
	}

	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(12), status);
	PTF_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet2 frag#13 - status isn't REASSEMBLED");
	PTF_ASSERT(ip6Packet2 != NULL, "IPv6 Packet2 frag#13 - result is NULL");

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 2, "Capacity after IPv6 packet 3 reassembly isn't 2");


	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet1.txt", buffer1Length);
	PTF_ASSERT(buffer1Length == ip4Packet1->getRawPacket()->getRawDataLen(), "IPv4 Packet1 len (%d) is different than read packet len (%d)", ip4Packet1->getRawPacket()->getRawDataLen(), buffer1Length);
	PTF_ASSERT(memcmp(ip4Packet1->getRawPacket()->getRawData(), buffer1, buffer1Length) == 0, "IPv4 packet1 data is different than expected");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet4.txt", buffer4Length);
	PTF_ASSERT(buffer4Length == ip4Packet4->getRawPacket()->getRawDataLen(), "IPv4 Packet4 len (%d) is different than read packet len (%d)", ip4Packet4->getRawPacket()->getRawDataLen(), buffer4Length);
	PTF_ASSERT(memcmp(ip4Packet4->getRawPacket()->getRawData(), buffer4, buffer4Length) == 0, "IPv4 packet4 data is different than expected");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet6.txt", buffer6Length);
	PTF_ASSERT(buffer6Length == ip4Packet6->getRawPacket()->getRawDataLen(), "IPv4 Packet6 len (%d) is different than read packet len (%d)", ip4Packet6->getRawPacket()->getRawDataLen(), buffer6Length);
	PTF_ASSERT(memcmp(ip4Packet6->getRawPacket()->getRawData(), buffer6, buffer6Length) == 0, "IPv4 packet6 data is different than expected");

	int buffer61Length = 0;
	uint8_t* buffer61 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer61Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet1->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);
	PTF_ASSERT(buffer61Length == ip6Packet1->getRawPacket()->getRawDataLen(), "IPv6 Packet1 len (%d) is different than read packet len (%d)", ip6Packet1->getRawPacket()->getRawDataLen(), buffer61Length);
	PTF_ASSERT(memcmp(ip6Packet1->getRawPacket()->getRawData(), buffer61, buffer61Length) == 0, "IPv6 packet1 data is different than expected");

	int buffer62Length = 0;
	uint8_t* buffer62 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet2.txt", buffer62Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet2->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(1448);
	PTF_ASSERT(buffer62Length == ip6Packet2->getRawPacket()->getRawDataLen(), "IPv6 Packet2 len (%d) is different than read packet len (%d)", ip6Packet2->getRawPacket()->getRawDataLen(), buffer62Length);
	PTF_ASSERT(memcmp(ip6Packet2->getRawPacket()->getRawData(), buffer62, buffer62Length) == 0, "IPv6 packet2 data is different than expected");


	delete ip4Packet1;
	delete ip4Packet2;
	delete ip4Packet3;
	delete ip4Packet4;
	delete ip4Packet5;
	delete ip4Packet6;
	delete ip4Packet7;
	delete ip4Packet8;
	delete ip4Packet9;
	delete ip6Packet1;
	delete ip6Packet2;
	delete ip6Packet3;
	delete ip6Packet4;

	delete buffer1;
	delete buffer4;
	delete buffer6;
	delete buffer61;
	delete buffer62;


}


void ipReassemblyOnFragmentsClean(const IPReassembly::PacketKey* key, void* userCookie)
{
	PointerVector<IPReassembly::PacketKey>* packetsRemoved = (PointerVector<IPReassembly::PacketKey>*)userCookie;
	packetsRemoved->pushBack(key->clone());
}

PTF_TEST_CASE(TestIPFragMapOverflow)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector ip4Packet1Frags;
	RawPacketVector ip4Packet2Frags;
	RawPacketVector ip4Packet3Frags;
	RawPacketVector ip4Packet4Frags;
	RawPacketVector ip4Packet5Vec;
	RawPacketVector ip4Packet6Frags;
	RawPacketVector ip4Packet7Vec;
	RawPacketVector ip4Packet8Frags;
	RawPacketVector ip4Packet9Vec;
	RawPacketVector ip6Packet1Frags;
	RawPacketVector ip6Packet2Frags;
	RawPacketVector ip6Packet3Frags;
	RawPacketVector ip6Packet4Frags;

	PTF_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PTF_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PTF_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 5");
	PTF_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PTF_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PTF_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");


	PointerVector<IPReassembly::PacketKey> packetsRemovedFromIPReassemblyEngine;

	IPReassembly ipReassembly(ipReassemblyOnFragmentsClean, &packetsRemovedFromIPReassemblyEngine, 3);

	PTF_ASSERT(ipReassembly.getMaxCapacity() == 3, "Max capacity isn't 3");
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 0, "Capacity before reassembly isn't 0");


	IPReassembly::ReassemblyStatus status;

	ipReassembly.processPacket(ip6Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(2), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(3), status);
	ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);

	PTF_ASSERT(ipReassembly.getMaxCapacity() == 3, "Max capacity isn't 3");
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 3, "Capacity after reassembly isn't 3");

	PTF_ASSERT(packetsRemovedFromIPReassemblyEngine.size() == 5, "Number of packets that have been removed isn't 5, it's %d", (int)packetsRemovedFromIPReassemblyEngine.size());

	IPReassembly::IPv4PacketKey* ip4Key = NULL;
	IPReassembly::IPv6PacketKey* ip6Key = NULL;

	// 1st packet removed should be ip6Packet1Frags
	ip6Key = dynamic_cast<IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(0));
	PTF_ASSERT(ip6Key != NULL, "First packet removed isn't IPv6");
	PTF_ASSERT(ip6Key->getFragmentID() == 0x2c5323, "First packet removed fragment ID isn't 0x2c5323");
	PTF_ASSERT(ip6Key->getSrcIP() == IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), "First packet removed src IP isn't fe80::21f:f3ff:fecd:f617");
	PTF_ASSERT(ip6Key->getDstIP() == IPv6Address(std::string("ff02::fb")), "First packet removed dst IP isn't ff02::fb");

	// 2nd packet removed should be ip4Packet2Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(1));
	PTF_ASSERT(ip4Key != NULL, "Second packet removed isn't IPv4");
	PTF_ASSERT(ip4Key->getIpID() == 0x1ea1, "Second packet removed ID isn't 0x1ea1");
	PTF_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Second packet removed src IP isn't 10.118.213.212");
	PTF_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Second packet removed dst IP isn't 10.118.213.211");

	// 3rd packet removed should be ip4Packet3Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(2));
	PTF_ASSERT(ip4Key != NULL, "Third packet removed isn't IPv4");
	PTF_ASSERT(ip4Key->getIpID() == 0x1ea2, "Third packet removed ID isn't 0x1ea2");
	PTF_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Third packet removed src IP isn't 10.118.213.212");
	PTF_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Third packet removed dst IP isn't 10.118.213.211");

	// 4th packet removed should be ip6Packet2Frags
	ip6Key = dynamic_cast<IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(3));
	PTF_ASSERT(ip6Key != NULL, "Fourth packet removed isn't IPv6");
	PTF_ASSERT(ip6Key->getFragmentID() == 0x98d687d1, "Fourth packet removed fragment ID isn't 0x98d687d1");
	PTF_ASSERT(ip6Key->getSrcIP() == IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), "Fourth packet removed src IP isn't fe80::21f:f3ff:fecd:f617");
	PTF_ASSERT(ip6Key->getDstIP() == IPv6Address(std::string("ff02::fb")), "Fourth packet removed dst IP isn't ff02::fb");

	// 5th packet removed should be ip4Packet4Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(4));
	PTF_ASSERT(ip4Key != NULL, "Fifth packet removed isn't IPv4");
	PTF_ASSERT(ip4Key->getIpID() == 0x1ea3, "Fifth packet removed ID isn't 0x1ea3");
	PTF_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Fifth packet removed src IP isn't 10.118.213.212");
	PTF_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Fifth packet removed dst IP isn't 10.118.213.211");


}


PTF_TEST_CASE(TestIPFragRemove)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PTF_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PTF_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector ip4Packet1Frags;
	RawPacketVector ip4Packet2Frags;
	RawPacketVector ip4Packet3Frags;
	RawPacketVector ip4Packet4Frags;
	RawPacketVector ip4Packet5Vec;
	RawPacketVector ip4Packet6Frags;
	RawPacketVector ip4Packet7Vec;
	RawPacketVector ip4Packet8Frags;
	RawPacketVector ip4Packet9Vec;
	RawPacketVector ip6Packet1Frags;
	RawPacketVector ip6Packet2Frags;
	RawPacketVector ip6Packet3Frags;
	RawPacketVector ip6Packet4Frags;

	PTF_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PTF_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PTF_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PTF_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 5");
	PTF_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PTF_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PTF_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PTF_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PTF_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PTF_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");

	IPReassembly ipReassembly;

	IPReassembly::ReassemblyStatus status;

	ipReassembly.processPacket(ip4Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet1Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(1), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(2), status);
	ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet4Frags.at(1), status);
	ipReassembly.processPacket(ip6Packet3Frags.at(0), status);
	ipReassembly.processPacket(ip4Packet1Frags.at(3), status);
	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	ipReassembly.processPacket(ip6Packet4Frags.at(0), status);

	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity before delete isn't 10");

	IPReassembly::IPv4PacketKey ip4Key;
	ip4Key.setSrcIP(IPv4Address(std::string("10.118.213.212")));
	ip4Key.setDstIP(IPv4Address(std::string("10.118.213.211")));

	ip4Key.setIpID(0x1ea0);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 9, "Capacity after 1st delete isn't 9");

	ip4Key.setIpID(0x1ea5);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 8, "Capacity after 2nd delete isn't 8");

	// IPv4 key doesn't exist
	ip4Key.setIpID(0x1ea9);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 8, "Capacity after delete with non-existing IPv4 packet isn't 8");

	ip4Key.setIpID(0x1ea4);
	ipReassembly.removePacket(ip4Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 7, "Capacity after 3rd delete isn't 7");

	IPReassembly::IPv6PacketKey ip6Key;
	ip6Key.setSrcIP(IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")));
	ip6Key.setDstIP(IPv6Address(std::string("ff02::fb")));

	ip6Key.setFragmentID(0x98d687d1);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after 4th delete isn't 6");

	// IPv6 key doesn't exist
	ip6Key.setFragmentID(0xaaaaaaaa);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after delete with non-existing IPv6 packet isn't 6");

	ip6Key.setFragmentID(0x2c5323);
	ipReassembly.removePacket(ip6Key);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 5, "Capacity after 5th delete isn't 5");

	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PTF_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after delete and 1st add isn't 6");


}

PTF_TEST_CASE(TestRawSockets)
{
	IPAddress::Ptr_t ipAddr = IPAddress::fromString(PcapGlobalArgs.ipToSendReceivePackets);
	PTF_ASSERT(ipAddr.get() != NULL && ipAddr.get()->isValid(), "IP address is not valid");
	RawSocketDevice rawSock(*(ipAddr.get()));

#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
	ProtocolType protocol = (ipAddr.get()->getType() == IPAddress::IPv4AddressType ? IPv4 : IPv6);
	bool sendSupported = false;
#elif LINUX
	ProtocolType protocol = Ethernet;
	bool sendSupported = true;
#else
	ProtocolType protocol = Ethernet;
	bool sendSupported = false;
	{
		LoggerPP::getInstance().supressErrors();
		RawPacket rawPacket;
		PTF_ASSERT(rawSock.open() == false, "Managed to open the raw sorcket on unsupoorted platform");
		PTF_ASSERT(rawSock.receivePacket(rawPacket, true, 10) == RawSocketDevice::RecvError, "Managed to receive a packet on an unsupported platform");
		PTF_ASSERT(rawSock.sendPacket(&rawPacket) == false, "Managed to send a packet on an unsupported platform");
		LoggerPP::getInstance().enableErrors();
	}



#endif

	PTF_ASSERT(rawSock.open() == true, "Couldn't open raw socket");

	// receive single packet
	for (int i = 0; i < 10; i++)
	{
		RawPacket rawPacket;
		PTF_ASSERT(rawSock.receivePacket(rawPacket, true, 10) == RawSocketDevice::RecvSuccess, "Couldn't receive packet on raw socket");
		Packet parsedPacket(&rawPacket);
		PTF_ASSERT(parsedPacket.isPacketOfType(protocol) == true, "Received packet is not of type 0x%X", protocol);
	}

	// receive multiple packets
	RawPacketVector packetVec;
	int failedRecv = 0;
	rawSock.receivePackets(packetVec, 20, failedRecv);
	PTF_ASSERT(packetVec.size() > 0, "Didn't receive packets on vec");
	for (RawPacketVector::VectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		Packet parsedPacket(*iter);
		PTF_ASSERT(parsedPacket.isPacketOfType(protocol) == true, "Received packet is not of type 0x%X", protocol);
	}

	// receive with timeout
	RawSocketDevice::RecvPacketResult res = RawSocketDevice::RecvSuccess;
	for (int i = 0; i < 30; i++)
	{
		RawPacket rawPacket;
		res = rawSock.receivePacket(rawPacket, true, 1);
		if (res == RawSocketDevice::RecvTimeout)
			break;
	}
	PTF_TRY(res == RawSocketDevice::RecvTimeout, "Didn't reach receive timeout");

	// receive non-blocking
	res = RawSocketDevice::RecvSuccess;
	for (int i = 0; i < 30; i++)
	{
		RawPacket rawPacket;
		res = rawSock.receivePacket(rawPacket, false, -1);
		if (res == RawSocketDevice::RecvWouldBlock)
			break;
	}
	PTF_TRY(res == RawSocketDevice::RecvWouldBlock, "Didn't get would block response");

	// close and reopen sockets, verify can't send and receive while closed
	rawSock.close();
	RawPacket tempPacket;
	LoggerPP::getInstance().supressErrors();
	PTF_ASSERT(rawSock.receivePacket(tempPacket, true, 10) == RawSocketDevice::RecvError, "Managed to receive packet while device is closed");
	PTF_ASSERT(rawSock.sendPacket(packetVec.at(0)) == false, "Managed to send packet while device is closed");
	LoggerPP::getInstance().enableErrors();

	PTF_ASSERT(rawSock.open() == true, "Couldn't reopen raw socket");

	// open another socket on the same interface
	RawSocketDevice rawSock2(*(ipAddr.get()));
	PTF_ASSERT(rawSock2.open() == true, "Couldn't open raw socket 2");

	// receive packet on 2 sockets
	for (int i = 0; i < 5; i++)
	{
		RawPacket rawPacket;
		PTF_ASSERT(rawSock.receivePacket(rawPacket, true, 5) == RawSocketDevice::RecvSuccess, "Couldn't receive packet on raw socket 1");
		Packet parsedPacket(&rawPacket);
		PTF_ASSERT(parsedPacket.isPacketOfType(protocol) == true, "Received packet 1 is not of type 0x%X", protocol);
		RawPacket rawPacket2;
		PTF_ASSERT(rawSock2.receivePacket(rawPacket2, true, 5) == RawSocketDevice::RecvSuccess, "Couldn't receive packet on raw socket 2");
		Packet parsedPacket2(&rawPacket2);
		PTF_ASSERT(parsedPacket2.isPacketOfType(protocol) == true, "Received packet 2 is not of type 0x%X", protocol);
	}

	if (sendSupported)
	{
		// send single packet
		PcapFileReaderDevice readerDev(EXAMPLE2_PCAP_PATH);
		PTF_ASSERT(readerDev.open() == true, "Coudln't open file");
		packetVec.clear();
		readerDev.getNextPackets(packetVec, 100);
		for (RawPacketVector::VectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
		{
			PTF_ASSERT(rawSock.sendPacket(*iter) == true, "Coudln't send raw packet on raw socket 1");
			PTF_ASSERT(rawSock2.sendPacket(*iter) == true, "Coudln't send raw packet on raw socket 2");
		}

		// send multiple packets
		PTF_ASSERT(rawSock.sendPackets(packetVec) == 100, "Couldn't send 100 packets in a vec");
	}
	else
	{
		// test send on unsupported platforms
		LoggerPP::getInstance().supressErrors();
		PTF_ASSERT(rawSock.sendPacket(packetVec.at(0)) == false, "Sent one packet on unsupported platform");
		PTF_ASSERT(rawSock.sendPackets(packetVec) == false, "Sent packets on unsupported platform");
		LoggerPP::getInstance().enableErrors();
	}

	rawSock.close();
	rawSock2.close();

}





static struct option PcapTestOptions[] =
{
	{"debug-mode", no_argument, 0, 'd'},
	{"use-ip",  required_argument, 0, 'i'},
	{"remote-ip", required_argument, 0, 'r'},
	{"remote-port", required_argument, 0, 'p'},
	{"dpdk-port", required_argument, 0, 'k' },
	{"no-networking", no_argument, 0, 'n' },
	{"verbose", no_argument, 0, 'v' },
	{"mem-verbose", no_argument, 0, 'm' },
	{"kni-ip", no_argument, 0, 'a' },
	{"skip-mem-leak-check", no_argument, 0, 's' },
	{"tags",  required_argument, 0, 't'},
    {0, 0, 0, 0}
};

void print_usage()
{
    printf("Usage: Pcap++Test -i ip_to_use | -n [-d] [-s] [-m] [-r ip_addr] [-p port] [-k dpdk_port] [-a ip_addr] [-t tags]\n\n"
    		"Flags:\n"
    		"-i --use-ip              IP to use for sending and receiving packets\n"
    		"-d --debug-mode          Set log level to DEBUG\n"
    		"-r --remote-ip	          IP of remote machine running rpcapd to test remote capture\n"
    		"-p --remote-port         Port of remote machine running rpcapd to test remote capture\n"
    		"-k --dpdk-port           The DPDK NIC port to test. Required if compiling with DPDK\n"
    		"-n --no-networking       Do not run tests that requires networking\n"
			"-v --verbose             Run in verbose mode (emits more output in several tests)\n"
			"-m --mem-verbose         Output information about each memory allocation and deallocation\n"			
            "-s --skip-mem-leak-check Skip memory leak check\n"
    		"-a --kni-ip              IP address for KNI device tests to use must not be the same\n"
			"                         as any of existing network interfaces in your system.\n"
			"                         If this parameter is omitted KNI tests will be skipped. Must be an IPv4.\n"
			"                         For Linux systems only\n"
			"-t --tags                A list of semicolon separated tags for tests to run\n"
    		);
}

int main(int argc, char* argv[])
{
	PcapGlobalArgs.ipToSendReceivePackets = "";
	PcapGlobalArgs.debugMode = false;
	PcapGlobalArgs.dpdkPort = -1;
	PcapGlobalArgs.kniIp = "";

	std::string userTags = "", configTags = "";
	bool runWithNetworking = true;
	bool memVerbose = false;
	bool skipMemLeakCheck = false;

	int optionIndex = 0;
	char opt = 0;
	while((opt = getopt_long (argc, argv, "di:r:p:k:a:nvmst:", PcapTestOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'a':
				PcapGlobalArgs.kniIp = optarg;
				break;
			case 'i':
				PcapGlobalArgs.ipToSendReceivePackets = optarg;
				break;
			case 'd':
				PcapGlobalArgs.debugMode = true;
				break;
			case 'r':
				PcapGlobalArgs.remoteIp = optarg;
				break;
			case 'p':
				PcapGlobalArgs.remotePort = (uint16_t)atoi(optarg);
				break;
			case 'k':
				PcapGlobalArgs.dpdkPort = (int)atoi(optarg);
				break;
			case 'n':
				runWithNetworking = false;
				break;
			case 'v':
				PTF_SET_VERBOSE_MODE(true);
				break;
			case 't':
				userTags = optarg;
				break;
			case 's':
				skipMemLeakCheck = true;
				break;
			case 'm':
				memVerbose = true;
				break;
			default:
				print_usage();
				exit(1);
		}
	}

	if (!runWithNetworking)
	{
		if (userTags != "")
			userTags += ";";

		userTags += "no_network";
		printf("Running only tests that don't require network connection\n");
	}
	
	#ifdef NDEBUG
	skipMemLeakCheck = true;
	printf("Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks like a memory leak:\n");
	printf("     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958\n");
	#endif

	if (skipMemLeakCheck)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "skip_mem_leak_check";
		printf("Skipping memory leak check for all test cases\n");
	}

	if (memVerbose)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "mem_leak_check_verbose";
		printf("Turning on verbose information on memory allocations\n");
	}

#ifdef USE_DPDK
	if (PcapGlobalArgs.dpdkPort == -1)
	{
		printf("When testing with DPDK you must provide the DPDK NIC port to test\n\n");
		print_usage();
		exit(1);
	}
#endif // USE_DPDK

	if (PcapGlobalArgs.debugMode)
		LoggerPP::getInstance().setAllModlesToLogLevel(LoggerPP::Debug);

	printf("PcapPlusPlus version: %s\n", getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Git info: %s\n", getGitInfo().c_str());
	printf("Using ip: %s\n", PcapGlobalArgs.ipToSendReceivePackets.c_str());
	printf("Debug mode: %s\n", PcapGlobalArgs.debugMode ? "on" : "off");
#ifdef USE_DPDK
	printf("Using DPDK port: %d\n", PcapGlobalArgs.dpdkPort);
	if (PcapGlobalArgs.kniIp == "")
		printf("DPDK KNI tests: skipped\n");
	else
		printf("Using IP address for KNI: %s\n", PcapGlobalArgs.kniIp.c_str());
#endif
	printf("Starting tests...\n");

	char errString[1000];
	//LoggerPP::getInstance().setErrorString(errString, 1000);
	PcapGlobalArgs.errString = errString;

	PTF_START_RUNNING_TESTS(userTags, configTags);

	PcapLiveDeviceList::getInstance();

	PTF_RUN_TEST(TestIPAddress, "no_network;ip");
	PTF_RUN_TEST(TestMacAddress, "no_network;mac");
	PTF_RUN_TEST(TestPcapFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapSllFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapRawIPFileReadWrite, "no_network;pcap");
	PTF_RUN_TEST(TestPcapFileAppend, "no_network;pcap");
	PTF_RUN_TEST(TestPcapNgFileReadWrite, "no_network;pcap;pcapng");
	PTF_RUN_TEST(TestPcapNgFileReadWriteAdv, "no_network;pcap;pcapng");
	PTF_RUN_TEST(TestPcapLiveDeviceList, "no_network;live_device;skip_mem_leak_check");
	PTF_RUN_TEST(TestPcapLiveDeviceListSearch, "live_device");
	PTF_RUN_TEST(TestPcapLiveDevice, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceNoNetworking, "no_network;live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceStatsMode, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceBlockingMode, "live_device");
	PTF_RUN_TEST(TestPcapLiveDeviceSpecialCfg, "live_device");
	PTF_RUN_TEST(TestWinPcapLiveDevice, "live_device;winpcap");
	PTF_RUN_TEST(TestPcapLiveDeviceByInvalidIp, "no_network;live_device");
	PTF_RUN_TEST(TestPcapFiltersLive, "filters");
	PTF_RUN_TEST(TestPcapFilters_General_BPFStr, "no_network;filters;skip_mem_leak_check");
	PTF_RUN_TEST(TestPcapFiltersOffline, "no_network;filters");
	PTF_RUN_TEST(TestSendPacket, "send");
	PTF_RUN_TEST(TestSendPackets, "send");
	PTF_RUN_TEST(TestRemoteCapture, "remote_capture;winpcap");
	PTF_RUN_TEST(TestHttpRequestParsing, "no_network;http");
	PTF_RUN_TEST(TestHttpResponseParsing, "no_network;http");
	PTF_RUN_TEST(TestPrintPacketAndLayers, "no_network;print");
	PTF_RUN_TEST(TestPfRingDevice, "pf_ring");
	PTF_RUN_TEST(TestPfRingDeviceSingleChannel, "pf_ring");
	PTF_RUN_TEST(TestPfRingMultiThreadAllCores, "pf_ring");
	PTF_RUN_TEST(TestPfRingMultiThreadSomeCores, "pf_ring");
	PTF_RUN_TEST(TestPfRingSendPacket, "pf_ring");
	PTF_RUN_TEST(TestPfRingSendPackets, "pf_ring");
	PTF_RUN_TEST(TestPfRingFilters, "pf_ring");
	PTF_RUN_TEST(TestDnsParsing, "no_network;dns");
	PTF_RUN_TEST(TestDpdkDevice, "dpdk");
	PTF_RUN_TEST(TestDpdkMultiThread, "dpdk");
	PTF_RUN_TEST(TestDpdkDeviceSendPackets, "dpdk");
	PTF_RUN_TEST(TestKniDevice, "dpdk;kni");
	PTF_RUN_TEST(TestKniDeviceSendReceive, "dpdk;kni");
	PTF_RUN_TEST(TestDpdkMbufRawPacket, "dpdk");
	PTF_RUN_TEST(TestDpdkDeviceWorkerThreads, "dpdk");
	PTF_RUN_TEST(TestGetMacAddress, "mac");
	PTF_RUN_TEST(TestTcpReassemblySanity, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyRetran, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMissingData, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyOutOfOrder, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyWithFIN_RST, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMalformedPkts, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyMultipleConns, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6MultConns, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestTcpReassemblyIPv6_OOO, "no_network;tcp_reassembly");
	PTF_RUN_TEST(TestIPFragmentationSanity, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragOutOfOrder, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragPartialData, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragMultipleFrags, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragMapOverflow, "no_network;ip_frag");
	PTF_RUN_TEST(TestIPFragRemove, "no_network;ip_frag");
	PTF_RUN_TEST(TestRawSockets, "raw_sockets");

	PTF_END_RUNNING_TESTS;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif