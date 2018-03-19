#include <memory>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <map>
#include <debug_new.h>
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
#include <NetworkUtils.h>
#ifndef WIN32 //for using ntohl, ntohs, etc.
#include <in.h>
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


#define PCAPP_TEST(TestName) bool TestName(PcapTestArgs const& args)

#define PCAPP_ASSERT(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		return false; \
	}

#define PCAPP_ASSERT_AND_RUN_COMMAND(exp, command, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		command; \
		return false; \
	}

bool isUnitTestDebugMode = false;

#define PCAPP_IS_UNIT_TEST_DEBUG_ENABLED isUnitTestDebugMode

#define PCAPP_UNIT_TEST_SET_DEBUG_MODE(flag) isUnitTestDebugMode = flag

#define PCAPP_DEBUG_PRINT(format, ...) do { \
		if(isUnitTestDebugMode) { \
			printf(format "\n", ## __VA_ARGS__); \
		} \
} while(0)

#define PCAPP_TEST_PASSED printf("%-30s: PASSED\n", __FUNCTION__); return true

#define PCAPP_START_RUNNING_TESTS(runWithNetworking) \
	bool allTestsPassed = true; \
	bool networking =  runWithNetworking;

#define PCAPP_RUN_TEST(TestName, args, requiresNetworking) \
		if (networking || (!networking && !requiresNetworking)) \
			allTestsPassed &= TestName(args)

#define PCAPP_END_RUNNING_TESTS \
		if (allTestsPassed) \
		{ \
			printf("ALL TESTS PASSED!!\n"); \
			return 0; \
		} \
		else \
		{ \
			printf("NOT ALL TESTS PASSED!!\n"); \
			return 1; \
		}

struct PcapTestArgs
{
	string ipToSendReceivePackets;
	bool debugMode;
	string remoteIp;
	uint16_t remotePort;
	int dpdkPort;
	char* errString;
	bool runWithNetworking;
};

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
		PCAPP_ASSERT(m_Initialized == true, "Thread %d was not initialized", coreId);

		m_CoreId = coreId;

		PCAPP_ASSERT(m_DpdkDevice != NULL, "DpdkDevice is NULL");

		PCAPP_DEBUG_PRINT("Worker thread on core %d is starting", m_CoreId);

		m_PacketCount = 0;
		while (!m_Stop)
		{
			RawPacketVector packetVec;
			pthread_mutex_lock(m_QueueLock);
			bool res = m_DpdkDevice->receivePackets(packetVec, m_QueueId);
			pthread_mutex_unlock(m_QueueLock);
			PCAPP_ASSERT(res == true, "Couldn't receive packets on thread %d", m_CoreId);
			m_PacketCount += packetVec.size();
		}

		PCAPP_DEBUG_PRINT("Worker thread on %d stopped", m_CoreId);

		m_RanAndStopped = true;
		return true;
	}

	void stop() { m_Stop = true; }

	uint32_t getCoreId() { return m_CoreId; }

	int getPacketCount() { return m_PacketCount; }

	bool threadRanAndStopped() { return m_RanAndStopped; }
};
#endif

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

bool packetArrivesBlockingModeStartCapture(RawPacket* pRawPacket, PcapLiveDevice* dev, void* userCookie)
{
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5) == 0, "Managed to start capturing blocking mode from blocking callback");
	int temp = 0;
	PCAPP_ASSERT(dev->startCapture(packetArrives, &temp) == 0, "Managed to start capturing non-blocking mode from blocking callback");
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



PCAPP_TEST(TestIPAddress)
{
	IPAddress::Ptr_t ip4Addr = IPAddress::fromString((char*)"10.0.0.4");
	PCAPP_ASSERT(ip4Addr.get() != NULL, "IPv4 address is NULL");
	PCAPP_ASSERT(ip4Addr->getType() == IPAddress::IPv4AddressType, "IPv4 address is not of type IPv4Address");
	PCAPP_ASSERT(strcmp(ip4Addr->toString().c_str(), "10.0.0.4") == 0, "IPv4 toString doesn't return the correct string");
	IPv4Address* ip4AddrAfterCast = static_cast<IPv4Address*>(ip4Addr.get());
	PCAPP_ASSERT(ntohl(ip4AddrAfterCast->toInt()) == 0x0A000004, "toInt() gave wrong result: %X", ip4AddrAfterCast->toInt());
	IPv4Address secondIPv4Address(string("1.1.1.1"));
	secondIPv4Address = *ip4AddrAfterCast;
	PCAPP_ASSERT(secondIPv4Address.isValid() == true, "Valid address identified as non-valid");
	PCAPP_ASSERT((*ip4AddrAfterCast) == secondIPv4Address, "IPv4Address assignment operator didn't work");

	IPv4Address badAddress(std::string("sdgdfgd"));
	PCAPP_ASSERT(badAddress.isValid() == false, "Non-valid address identified as valid");
	IPv4Address anotherBadAddress = IPv4Address(std::string("321.123.1000.1"));
	PCAPP_ASSERT(anotherBadAddress.isValid() == false, "Non-valid address copied by copy c'tor identified as valid");

	string ip6AddrString("2607:f0d0:1002:51::4");
	IPAddress::Ptr_t ip6Addr = IPAddress::fromString(ip6AddrString);
	PCAPP_ASSERT(ip6Addr.get() != NULL, "IPv6 address is NULL");
	PCAPP_ASSERT(ip6Addr->getType() == IPAddress::IPv6AddressType, "IPv6 address is not of type IPv6Address");
	PCAPP_ASSERT(strcmp(ip6Addr->toString().c_str(), "2607:f0d0:1002:51::4") == 0, "IPv6 toString doesn't return the correct string");
	IPv6Address* ip6AddrAfterCast = static_cast<IPv6Address*>(ip6Addr.get());
	size_t length = 0;
	uint8_t* addrAsByteArray;
	ip6AddrAfterCast->copyTo(&addrAsByteArray, length);
	PCAPP_ASSERT(length == 16, "IPv6 packet length is wrong. Expected 16, got %d", (int)length);
	uint8_t expectedByteArray[16] = { 0x26, 0x07, 0xF0, 0xD0, 0x10, 0x02, 0x00, 0x51, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
	for (int i = 0; i < 16; i++)
		PCAPP_ASSERT(addrAsByteArray[i] == expectedByteArray[i], "Failed to convert IPv6 address to byte array; byte #%d: expected 0x%X got 0x%X", i, expectedByteArray[i], addrAsByteArray[i]);

	delete [] addrAsByteArray;
	ip6Addr = IPAddress::fromString(string("2607:f0d0:1002:0051:0000:0000:0000:0004"));
	PCAPP_ASSERT(ip6Addr.get() != NULL, "IPv6 address is NULL");
	PCAPP_ASSERT(ip6Addr->getType() == IPAddress::IPv6AddressType, "IPv6 address is not of type IPv6Address");
	PCAPP_ASSERT(strcmp(ip6Addr->toString().c_str(), "2607:f0d0:1002:0051:0000:0000:0000:0004") == 0, "IPv6 toString doesn't return the correct string");
	IPv6Address secondIPv6Address(string("2607:f0d0:1002:52::5"));
	ip6AddrAfterCast = static_cast<IPv6Address*>(ip6Addr.get());
	secondIPv6Address = *ip6AddrAfterCast;
	PCAPP_ASSERT(ip6Addr->isValid() == true, "Valid IPv6 address identified as non-valid");
	PCAPP_ASSERT((*ip6AddrAfterCast) == secondIPv6Address, "IPv6Address assignment operator didn't work");

	char badIp6AddressStr[] = "lasdfklsdkfdls";
	IPv6Address badIp6Address(badIp6AddressStr);
	PCAPP_ASSERT(badIp6Address.isValid() == false, "Non-valid IPv6 address identified as valid");
	IPv6Address anotherBadIp6Address = badIp6Address;
	PCAPP_ASSERT(anotherBadIp6Address.isValid() == false, "Non-valid IPv6 address copied by copy c'tor identified as valid");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestMacAddress)
{
	MacAddress macAddr1(0x11,0x2,0x33,0x4,0x55,0x6);
	PCAPP_ASSERT(macAddr1.isValid(), "macAddr1 is not valid");
	MacAddress macAddr2(0x11,0x2,0x33,0x4,0x55,0x6);
	PCAPP_ASSERT(macAddr2.isValid(), "macAddr2 is not valid");
	PCAPP_ASSERT(macAddr1 == macAddr2, "Equal operator failed");

	MacAddress macAddr3(string("11:02:33:04:55:06"));
	PCAPP_ASSERT(macAddr3.isValid(), "macAddr3 is not valid");
	PCAPP_ASSERT(macAddr1 == macAddr3, "Different c'tors with same MAC address (string and by octets) give different addresses");

	uint8_t addrAsArr[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	MacAddress macAddr4(addrAsArr);
	PCAPP_ASSERT(macAddr4.isValid(), "macAddr4 is not valid");
	PCAPP_ASSERT(macAddr1 == macAddr4, "Different c'tors with same MAC address (from arr and by octets) give different addresses");

	string macAsStr = macAddr1.toString();
	PCAPP_ASSERT(macAsStr == string("11:02:33:04:55:06"), "String representation failure: expected '%s', got '%s'", "11:02:33:04:55:06", macAddr1.toString().c_str());

	uint8_t* arrToCopyTo = NULL;
	macAddr3.copyTo(&arrToCopyTo);
	PCAPP_ASSERT(arrToCopyTo[0] == 0x11 && arrToCopyTo[1] == 0x02 && arrToCopyTo[2] == 0x33 && arrToCopyTo[3] == 0x04 && arrToCopyTo[4] == 0x55 && arrToCopyTo[5] == 0x06, "Copy MacAddress to array failed");

	delete [] arrToCopyTo;

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestPcapFileReadWrite)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
    PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");
    PCAPP_ASSERT(writerDev.open(), "cannot open writer device");
    PCAPP_ASSERT(readerDev.getFileName() == EXAMPLE_PCAP_PATH, "Reader file name different than expected");
    PCAPP_ASSERT(writerDev.getFileName() == EXAMPLE_PCAP_WRITE_PATH, "Writer file name different than expected");
    PCAPP_ASSERT(readerDev.getFileSize() == 3812643, "Reader file size different than expected. Expected: %d, got: %d", 3812643, (int)readerDev.getFileSize());
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
    PCAPP_ASSERT(readerStatistics.ps_recv == 4631, "Incorrect number of packets read from file. Expected: 4631; read: %d", readerStatistics.ps_recv);
    PCAPP_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PCAPP_ASSERT(writerStatistics.ps_recv == 4631, "Incorrect number of packets written to file. Expected: 4631; read: %d", writerStatistics.ps_recv);
    PCAPP_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PCAPP_ASSERT(ethCount == 4631, "Incorrect number of Ethernet packets read. Expected: 4631; read: %d", ethCount);
    PCAPP_ASSERT(sllCount == 0, "Incorrect number of SLL packets read. Expected: 0; read: %d", sllCount);
    PCAPP_ASSERT(ipCount == 4631, "Incorrect number of IPv4 packets read. Expected: 4631; read: %d", ipCount);
    PCAPP_ASSERT(tcpCount == 4492, "Incorrect number of IPv4 packets read. Expected: 4492; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 139, "Incorrect number of IPv4 packets read. Expected: 139; read: %d", udpCount);

    readerDev.close();
    writerDev.close();

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapSllFileReadWrite)
{
    PcapFileReaderDevice readerDev(SLL_PCAP_PATH);
    PcapFileWriterDevice writerDev(SLL_PCAP_WRITE_PATH, LINKTYPE_LINUX_SLL);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");
    PCAPP_ASSERT(writerDev.open(), "cannot open writer device");
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
    PCAPP_ASSERT(readerStatistics.ps_recv == 518, "Incorrect number of packets read from file. Expected: 518; read: %d", readerStatistics.ps_recv);
    PCAPP_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PCAPP_ASSERT(writerStatistics.ps_recv == 518, "Incorrect number of packets written to file. Expected: 518; written: %d", writerStatistics.ps_recv);
    PCAPP_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PCAPP_ASSERT(ethCount == 0, "Incorrect number of Ethernet packets read. Expected: 0; read: %d", ethCount);
    PCAPP_ASSERT(sllCount == 518, "Incorrect number of SLL packets read. Expected: 518; read: %d", sllCount);
    PCAPP_ASSERT(ipCount == 510, "Incorrect number of IPv4 packets read. Expected: 510; read: %d", ipCount);
    PCAPP_ASSERT(tcpCount == 483, "Incorrect number of TCP packets read. Expected: 483; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 28, "Incorrect number of UDP packets read. Expected: 28; read: %d", udpCount);

    readerDev.close();
    writerDev.close();

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapRawIPFileReadWrite)
{
	LoggerPP::getInstance().supressErrors();
	PcapFileWriterDevice tempWriter(RAW_IP_PCAP_WRITE_PATH, LINKTYPE_RAW);
	PCAPP_ASSERT(tempWriter.open() == false, "managed to open pcap writer device with link type LINKTYPE_RAW");
	LoggerPP::getInstance().enableErrors();

    PcapFileReaderDevice readerDev(RAW_IP_PCAP_PATH);
    PcapFileWriterDevice writerDev(RAW_IP_PCAP_WRITE_PATH, LINKTYPE_DLT_RAW1);
    PcapNgFileWriterDevice writerNgDev(RAW_IP_PCAPNG_PATH);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");
    PCAPP_ASSERT(writerDev.open(), "cannot open writer device");
    PCAPP_ASSERT(writerNgDev.open(), "cannot open writer-ng device");
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
    PCAPP_ASSERT(readerStatistics.ps_recv == 100, "Incorrect number of packets read from file. Expected: 100; read: %d", readerStatistics.ps_recv);
    PCAPP_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PCAPP_ASSERT(writerStatistics.ps_recv == 100, "Incorrect number of packets written to file. Expected: 100; written: %d", writerStatistics.ps_recv);
    PCAPP_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    writerNgDev.getStatistics(writerNgStatistics);
    PCAPP_ASSERT(writerNgStatistics.ps_recv == 100, "Incorrect number of packets written to pcap-ng file. Expected: 100; written: %d", writerNgStatistics.ps_recv);
    PCAPP_ASSERT(writerNgStatistics.ps_drop == 0, "Packets were not written properly to pcap-ng file. Number of packets dropped: %d", writerNgStatistics.ps_drop);

    PCAPP_ASSERT(ethCount == 0, "Incorrect number of Ethernet packets read. Expected: 0; read: %d", ethCount);
    PCAPP_ASSERT(ipv4Count == 50, "Incorrect number of IPv4 packets read. Expected: 50; read: %d", ipv4Count);
    PCAPP_ASSERT(ipv6Count == 50, "Incorrect number of IPv6 packets read. Expected: 50; read: %d", ipv6Count);
    PCAPP_ASSERT(tcpCount == 92, "Incorrect number of TCP packets read. Expected: 92; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 8, "Incorrect number of UDP packets read. Expected: 8; read: %d", udpCount);

    readerDev.close();
    writerDev.close();
    writerNgDev.close();

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapFileAppend)
{
	// opening the file for the first time just to delete all packets in it
	PcapFileWriterDevice wd(EXAMPLE_PCAP_WRITE_PATH);
	PCAPP_ASSERT(wd.open() == true, "Cannot open writer dev");
	wd.close();

	for (int i = 0; i < 5; i++)
	{
		PcapFileReaderDevice readerDev(EXAMPLE_PCAP_PATH);
		PcapFileWriterDevice writerDev(EXAMPLE_PCAP_WRITE_PATH);
		PCAPP_ASSERT(writerDev.open(true) == true, "Cannot open the pcap file in append mode, iteration #%d", i);
		PCAPP_ASSERT(readerDev.open(), "cannot open reader device, iteration #%d", i);

		RawPacket rawPacket;
	    while (readerDev.getNextPacket(rawPacket))
	    {
	    	writerDev.writePacket(rawPacket);
	    }

	    writerDev.close();
	    readerDev.close();
	}

	PcapFileReaderDevice readerDev(EXAMPLE_PCAP_WRITE_PATH);
	PCAPP_ASSERT(readerDev.open(), "cannot open reader device to read result file");
	int counter = 0;
	RawPacket rawPacket;
    while (readerDev.getNextPacket(rawPacket))
    	counter++;

    PCAPP_ASSERT(counter == (4631*5), "Number of read packets different than expected. Read: %d, expected: %d", counter, 4631*6);

    LoggerPP::getInstance().supressErrors();
    PcapFileWriterDevice writerDev2(EXAMPLE_PCAP_WRITE_PATH, LINKTYPE_LINUX_SLL);
    PCAPP_ASSERT(writerDev2.open(true) == false, "Managed to open file in append mode even though link layer types are different");
    LoggerPP::getInstance().enableErrors();

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapNgFileReadWrite)
{
    PcapNgFileReaderDevice readerDev(EXAMPLE_PCAPNG_PATH);
    PcapNgFileWriterDevice writerDev(EXAMPLE_PCAPNG_WRITE_PATH);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");
    PCAPP_ASSERT(writerDev.open(), "cannot open writer device");
    PCAPP_ASSERT(readerDev.getFileName() == EXAMPLE_PCAPNG_PATH, "Reader file name different than expected");
    PCAPP_ASSERT(writerDev.getFileName() == EXAMPLE_PCAPNG_WRITE_PATH, "Writer file name different than expected");
    PCAPP_ASSERT(readerDev.getFileSize() == 20704, "Reader file size different than expected. Expected: %d, got: %d", 20704, (int)readerDev.getFileSize());
    PCAPP_ASSERT(readerDev.getOS() == "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)", "OS read incorrectly");
    PCAPP_ASSERT(readerDev.getCaptureApplication() == "Dumpcap 1.12.6 (v1.12.6-0-gee1fce6 from master-1.12)", "User app read incorrectly");
    PCAPP_ASSERT(readerDev.getCaptureFileComment() == "", "File comment isn't empty");
    PCAPP_ASSERT(readerDev.getHardware() == "", "Hardware string isn't empty");
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

		PCAPP_ASSERT(writerDev.writePacket(rawPacket) == true, "Couldn't write packet #%d", packetCount);
    }

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PCAPP_ASSERT(readerStatistics.ps_recv == 64, "Incorrect number of packets read from file. Expected: 64; read: %d", readerStatistics.ps_recv);
    PCAPP_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PCAPP_ASSERT(writerStatistics.ps_recv == 64, "Incorrect number of packets written to file. Expected: 64; written: %d", writerStatistics.ps_recv);
    PCAPP_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    PCAPP_ASSERT(ethLinkLayerCount == 62, "Incorrect number of Ethernet link-type packets read. Expected: 62; read: %d", ethLinkLayerCount);
    PCAPP_ASSERT(nullLinkLayerCount == 2, "Incorrect number of Null link-type packets read. Expected: 2; read: %d", nullLinkLayerCount);
    PCAPP_ASSERT(otherLinkLayerCount == 0, "Incorrect number of other link-type packets read. Expected: 0; read: %d", otherLinkLayerCount);
    PCAPP_ASSERT(ethCount == 62, "Incorrect number of Ethernet packets read. Expected: 62; read: %d", ethCount);
    PCAPP_ASSERT(nullLoopbackCount == 2, "Incorrect number of Null/Loopback packets read. Expected: 2; read: %d", nullLoopbackCount);
    PCAPP_ASSERT(ipCount == 64, "Incorrect number of IPv4 packets read. Expected: 64; read: %d", ipCount);
    PCAPP_ASSERT(tcpCount == 32, "Incorrect number of TCP packets read. Expected: 32; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 32, "Incorrect number of UDP packets read. Expected: 32; read: %d", udpCount);

    readerDev.close();
    writerDev.close();

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapNgFileReadWriteAdv)
{
	PcapNgFileReaderDevice readerDev(EXAMPLE2_PCAPNG_PATH);

	// negative tests
	readerDev.close();
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(readerDev.getOS() == "", "Managed to read OS before device is opened");
	LoggerPP::getInstance().enableErrors();
	// --------------

	PCAPP_ASSERT(readerDev.open(), "cannot open reader device");
    PCAPP_ASSERT(readerDev.getOS() == "Linux 3.18.1-1-ARCH", "OS read incorrectly");
    PCAPP_ASSERT(readerDev.getCaptureApplication() == "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", "User app read incorrectly");
    PCAPP_ASSERT(readerDev.getCaptureFileComment() == "CLIENT_RANDOM E39B5BF4903C68684E8512FB2F60213E9EE843A0810B4982B607914D8092D482 95A5D39B02693BC1FB39254B179E9293007F6D37C66172B1EE4EF0D5E25CE1DABE878B6143DC3B266883E51A75E99DF9                                                   ", "File comment read incorrectly");
    PCAPP_ASSERT(readerDev.getHardware() == "", "Hardware string isn't empty");

    PcapNgFileWriterDevice writerDev(EXAMPLE2_PCAPNG_WRITE_PATH);

	// negative tests
    writerDev.close();
    // --------------

    PCAPP_ASSERT(writerDev.open(readerDev.getOS().c_str(), "My Hardware", readerDev.getCaptureApplication().c_str(), "This is a comment in a pcap-ng file") == true, "Couldn't open writer file");

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
			PCAPP_ASSERT(pktComment.compare(0, 8, "Packet #") == 0, "Packet comment is '%s' and is not the expected one", pktComment.c_str());
			commentCount++;
		}

		PCAPP_ASSERT(writerDev.writePacket(rawPacket, pktComment.c_str()) == true, "Couldn't write packet #%d", packetCount);
    }

    PCAPP_ASSERT(packetCount == 159, "Incorrect number of packets read. Expected: 159; read: %d", packetCount);
    PCAPP_ASSERT(capLenNotMatchOrigLen == 39, "Incorrect number of packets where captured length doesn't match original length. Expected: 39; read: %d", capLenNotMatchOrigLen);
    PCAPP_ASSERT(ethCount == 59, "Incorrect number of Ethernet packets read. Expected: 59; read: %d", ethCount);
    PCAPP_ASSERT(sllCount == 100, "Incorrect number of SLL packets read. Expected: 100; read: %d", sllCount);
    PCAPP_ASSERT(ip4Count == 155, "Incorrect number of IPv4 packets read. Expected: 155; read: %d", ip4Count);
    PCAPP_ASSERT(ip6Count == 4, "Incorrect number of IPv6 packets read. Expected: 4; read: %d", ip6Count);
    PCAPP_ASSERT(tcpCount == 159, "Incorrect number of TCP packets read. Expected: 159; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 0, "Incorrect number of UDP packets read. Expected: 0; read: %d", udpCount);
    PCAPP_ASSERT(httpCount == 1, "Incorrect number of HTTP packets read. Expected: 1; read: %d", httpCount);
    PCAPP_ASSERT(commentCount == 100, "Incorrect number of packets with comment read. Expected: 100; read: %d", commentCount);

    pcap_stat readerStatistics;
    pcap_stat writerStatistics;

    readerDev.getStatistics(readerStatistics);
    PCAPP_ASSERT(readerStatistics.ps_recv == 159, "Incorrect number of packets read from file. Expected: 159; read: %d", readerStatistics.ps_recv);
    PCAPP_ASSERT(readerStatistics.ps_drop == 0, "Packets were not read properly from file. Number of packets dropped: %d", readerStatistics.ps_drop);

    writerDev.getStatistics(writerStatistics);
    PCAPP_ASSERT(writerStatistics.ps_recv == 159, "Incorrect number of packets written to file. Expected: 159; written: %d", writerStatistics.ps_recv);
    PCAPP_ASSERT(writerStatistics.ps_drop == 0, "Packets were not written properly to file. Number of packets dropped: %d", writerStatistics.ps_drop);

    readerDev.close();
    writerDev.close();

    // -------

    PcapNgFileReaderDevice readerDev2(EXAMPLE2_PCAPNG_WRITE_PATH);
    PcapNgFileReaderDevice readerDev3(EXAMPLE2_PCAPNG_PATH);

    PCAPP_ASSERT(readerDev2.open(), "cannot open reader device 2");
    PCAPP_ASSERT(readerDev3.open(), "cannot open reader device 3");

    PCAPP_ASSERT(readerDev2.getOS() == "Linux 3.18.1-1-ARCH\0", "OS read incorrectly");
    PCAPP_ASSERT(readerDev2.getCaptureApplication() == "Dumpcap (Wireshark) 1.99.1 (Git Rev Unknown from unknown)", "User app read incorrectly");
    PCAPP_ASSERT(readerDev2.getCaptureFileComment() == "This is a comment in a pcap-ng file", "File comment read incorrectly");
    PCAPP_ASSERT(readerDev2.getHardware() == "My Hardware", "Hardware read incorrectly");

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
			PCAPP_ASSERT(pktComment.compare(0, 8, "Packet #") == 0, "Packet comment is '%s' and is not the expected one", pktComment.c_str());
			commentCount++;
		}

		readerDev3.getNextPacket(rawPacket2);

		if (rawPacket.getPacketTimeStamp().tv_sec < rawPacket2.getPacketTimeStamp().tv_sec)
		{
			PCAPP_ASSERT((rawPacket2.getPacketTimeStamp().tv_sec - rawPacket.getPacketTimeStamp().tv_sec) < 2, "Timestamps are differ in more than 2 secs");
		}
		else
		{
			PCAPP_ASSERT((rawPacket.getPacketTimeStamp().tv_sec - rawPacket2.getPacketTimeStamp().tv_sec) < 2, "Timestamps are differ in more than 2 secs");
		}

		if (rawPacket.getPacketTimeStamp().tv_usec < rawPacket2.getPacketTimeStamp().tv_usec)
		{
			PCAPP_ASSERT((rawPacket2.getPacketTimeStamp().tv_usec - rawPacket.getPacketTimeStamp().tv_usec) < 100, "Timestamps are differ in more than 100 usecs");
		}
		else
		{
			PCAPP_ASSERT((rawPacket.getPacketTimeStamp().tv_usec - rawPacket2.getPacketTimeStamp().tv_usec) < 100, "Timestamps are differ in more than 100 usecs");
		}

    }

    PCAPP_ASSERT(packetCount == 159, "Read cycle 2: Incorrect number of packets read. Expected: 159; read: %d", packetCount);
    PCAPP_ASSERT(ethCount == 59, "Read cycle 2: Incorrect number of Ethernet packets read. Expected: 59; read: %d", ethCount);
    PCAPP_ASSERT(sllCount == 100, "Read cycle 2: Incorrect number of SLL packets read. Expected: 100; read: %d", sllCount);
    PCAPP_ASSERT(ip4Count == 155, "Read cycle 2: Incorrect number of IPv4 packets read. Expected: 155; read: %d", ip4Count);
    PCAPP_ASSERT(ip6Count == 4, "Read cycle 2: Incorrect number of IPv6 packets read. Expected: 4; read: %d", ip6Count);
    PCAPP_ASSERT(tcpCount == 159, "Read cycle 2: Incorrect number of TCP packets read. Expected: 159; read: %d", tcpCount);
    PCAPP_ASSERT(udpCount == 0, "Read cycle 2: Incorrect number of UDP packets read. Expected: 0; read: %d", udpCount);
    PCAPP_ASSERT(httpCount == 1, "Read cycle 2: Incorrect number of HTTP packets read. Expected: 1; read: %d", httpCount);
    PCAPP_ASSERT(commentCount == 100, "Read cycle 2: Incorrect number of packets with comment read. Expected: 100; read: %d", commentCount);

    readerDev2.close();
    readerDev3.close();

    PcapNgFileWriterDevice appendDev(EXAMPLE2_PCAPNG_WRITE_PATH);
    PCAPP_ASSERT(appendDev.open(true) == true, "Couldn't open file in append mode");

    PCAPP_ASSERT(appendDev.writePacket(rawPacket2, "Additional packet #1") == true, "Couldn't append packet #1");
    PCAPP_ASSERT(appendDev.writePacket(rawPacket2, "Additional packet #2") == true, "Couldn't append packet #2");

    appendDev.close();


    PcapNgFileReaderDevice readerDev4(EXAMPLE2_PCAPNG_WRITE_PATH);
    PCAPP_ASSERT(readerDev4.open(), "cannot open reader device 4");

    packetCount = 0;

    while (readerDev4.getNextPacket(rawPacket, pktComment))
    {
    	packetCount++;
    }

    PCAPP_ASSERT(packetCount == 161, "Number of packets after append != 161, it's %d", packetCount);

    // -------

    IFileReaderDevice* genericReader = IFileReaderDevice::getReader(EXAMPLE2_PCAP_PATH);
    PCAPP_ASSERT(dynamic_cast<PcapFileReaderDevice*>(genericReader) != NULL, "Reader isn't of type PcapFileReaderDevice");
    PCAPP_ASSERT(dynamic_cast<PcapNgFileReaderDevice*>(genericReader) == NULL, "Reader is wrongly of type PcapNgFileReaderDevice");
    delete genericReader;

    genericReader = IFileReaderDevice::getReader(EXAMPLE2_PCAPNG_PATH);
    PCAPP_ASSERT(dynamic_cast<PcapFileReaderDevice*>(genericReader) == NULL, "Reader is wrongly of type PcapFileReaderDevice");
    PCAPP_ASSERT(dynamic_cast<PcapNgFileReaderDevice*>(genericReader) != NULL, "Reader isn't of type PcapNgFileReaderDevice");
    delete genericReader;

    // -------

    PcapNgFileReaderDevice readerDev5(EXAMPLE2_PCAPNG_PATH);
    PCAPP_ASSERT(readerDev5.open(), "cannot open reader device 5");
    PCAPP_ASSERT(readerDev5.setFilter("bla bla bla") == false, "Managed to set illegal filter");
    PCAPP_ASSERT(readerDev5.setFilter("src net 130.217.250.129") == true, "Couldn't set filter");

    packetCount = 0;

    while (readerDev5.getNextPacket(rawPacket, pktComment))
    {
        packetCount++;
    }

    PCAPP_ASSERT(packetCount == 14, "Number of packets matched to filter != 14, it's %d", packetCount);

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapLiveDeviceList)
{
    vector<PcapLiveDevice*> devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    PCAPP_ASSERT(!devList.empty(), "Device list is empty");

    IPv4Address defaultGateway = IPv4Address::Zero;
    for(vector<PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
    	PCAPP_ASSERT(!((*iter)->getName() == NULL), "Device name is NULL");
    	if (defaultGateway == IPv4Address::Zero)
    		defaultGateway = (*iter)->getDefaultGateway();

    }

    PCAPP_ASSERT(defaultGateway != IPv4Address::Zero, "Couldn't find default gateway for any of the interfaces");

    std::vector<IPv4Address> dnsServers = PcapLiveDeviceList::getInstance().getDnsServers();
    //PCAPP_ASSERT(dnsServers.size() > 0, "DNS server list is empty");

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapLiveDeviceListSearch)
{
	PcapLiveDevice* liveDev = NULL;
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());

    string devName(liveDev->getName());
    PcapLiveDevice* liveDev2 = NULL;
    liveDev2 = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(devName);
    PCAPP_ASSERT(liveDev2 != NULL, "Couldn't find device by name (search returned null)");
    PCAPP_ASSERT(strcmp(liveDev->getName(), liveDev2->getName()) == 0, "Search by device name didn't bring the right result");

    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("255.255.255.250");
    PCAPP_ASSERT(liveDev == NULL, "Illegal device found with IP=255.255.255.250");

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapLiveDevice)
{
	PcapLiveDevice* liveDev = NULL;
    IPv4Address ipToSearch(args.ipToSendReceivePackets.c_str());
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
    PCAPP_ASSERT(liveDev->getMtu() > 0, "Could not get live device MTU");
    PCAPP_ASSERT(liveDev->open(), "Cannot open live device");
    int packetCount = 0;
    int numOfTimeStatsWereInvoked = 0;
    PCAPP_ASSERT(liveDev->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
    PCAP_SLEEP(20);
    liveDev->stopCapture();
    PCAPP_ASSERT(packetCount > 0, "No packets were captured");
    PCAPP_ASSERT(numOfTimeStatsWereInvoked > 18, "Stat callback was called less than expected: %d", numOfTimeStatsWereInvoked);
    pcap_stat statistics;
    liveDev->getStatistics(statistics);
    //Bad test - on high traffic libpcap/winpcap sometimes drop packets
    //PCAPP_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    liveDev->close();

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapLiveDeviceNoNetworking)
{
	PcapLiveDevice* liveDev = NULL;

    vector<PcapLiveDevice*> devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    PCAPP_ASSERT(!devList.empty(), "Device list is empty");

    for(vector<PcapLiveDevice*>::iterator iter = devList.begin(); iter != devList.end(); iter++)
    {
    	if (!(*iter)->getLoopback() && (*iter)->getIPv4Address() != IPv4Address::Zero)
    	{
    		liveDev = *iter;
    		break;
    	}
    }

    PCAPP_ASSERT(liveDev != NULL, "Cannot find a non-loopback device with IPv4 address");
    PCAPP_ASSERT(liveDev->getName() != NULL, "Device has no name");
    PCAPP_ASSERT(liveDev->getMtu() > 0, "Cannot get MTU for device '%s'", liveDev->getName());
    PCAPP_ASSERT(liveDev->getMacAddress() != MacAddress::Zero, "Cannot find MAC address for device '%s'", liveDev->getName());

    PCAPP_TEST_PASSED;
}
 
PCAPP_TEST(TestPcapLiveDeviceStatsMode)
{
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev->open(), "Cannot open live device");
	int numOfTimeStatsWereInvoked = 0;
	PCAPP_ASSERT(liveDev->startCapture(1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
	sendURLRequest("www.ebay.com");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PCAPP_ASSERT(numOfTimeStatsWereInvoked >= 4, "Stat callback was called less than expected: %d", numOfTimeStatsWereInvoked);
    pcap_stat statistics;
    liveDev->getStatistics(statistics);
    PCAPP_ASSERT(statistics.ps_recv > 2, "No packets were captured");
    //Bad test - on high traffic libpcap/winpcap sometimes drop packets
    //PCAPP_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    liveDev->close();
    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapLiveDeviceBlockingMode)
{
	// open device
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev != NULL, "Step 0: Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev->open(), "Step 0: Cannot open live device");

	// sanity - test blocking mode returns with timeout
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 5) == -1, "Step 1: Capture blocking mode with timeout 5 sec didn't return on timeout");

	// sanity - test blocking mode returns before timeout
	int packetCount = 0;
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 2: Capture blocking mode didn't return on callback");
	PCAPP_ASSERT(packetCount == 5, "Step 2: Capture blocking mode didn't return packet count 5");

	// verify stop capture doesn't do any effect on blocking mode
	liveDev->stopCapture();
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1) == -1, "Step 3: Capture blocking mode with timeout 1 sec after stop capture didn't return on timeout");
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 3: Testing capture blocking mode after stop capture didn't return on callback");
	PCAPP_ASSERT(packetCount == 5, "Step 3: Capture blocking mode after stop capture didn't return packet count 5");

	// verify it's possible to capture non-blocking mode after blocking mode
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCapture(packetArrives, &packetCount) == true, "Step 4: Couldn't start non-blocking capture");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PCAPP_ASSERT(packetCount > 0, "Step 4: Couldn't capture any packet on non-blocking capture");

	// verify it's possible to capture blocking mode after non-blocking mode
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeNoTimeout, &packetCount, 30) == 1, "Step 5: Capture blocking mode after non-blocking mode didn't return on callback");
	PCAPP_ASSERT(packetCount == 5, "Step 5: Capture blocking mode after non-blocking mode didn't return packet count 5, it returned %d", packetCount);

	// try to start capture from within the callback, verify no error
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStartCapture, &packetCount, 30) == 1, "Step 6: Capture blocking mode when trying start capture from callback didn't return on callback");
	PCAPP_ASSERT(packetCount == 5, "Step 6: Capture blocking mode when callback calls start capture didn't return packet count 5");

	// try to stop capture from within the callback, verify no impact on capturing
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeStopCapture, &packetCount, 10) == 1, "Step 7: Capture blocking mode when trying to stop capture from callback didn't return on callback");
	PCAPP_ASSERT(packetCount == 5, "Step 7: Capture blocking mode when callback calls stop capture didn't return packet count 5");

	// verify it's possible to capture non-blocking after the mess done in previous lines
	packetCount = 0;
	PCAPP_ASSERT(liveDev->startCapture(packetArrives, &packetCount) == true, "Step 8: Couldn't start non-blocking capture after blocking mode with stop capture in callback");

	// verify an error returns if trying capture blocking while non-blocking is running
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(liveDev->startCaptureBlockingMode(packetArrivesBlockingModeTimeout, NULL, 1) == 0, "Step 9: Capture blocking mode while non-blocking is running didn't return an error");
	LoggerPP::getInstance().enableErrors();
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PCAPP_ASSERT(packetCount > 0, "Step 9: Couldn't capture any packet on non-blocking capture 2");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestWinPcapLiveDevice)
{
#ifdef WIN32
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev->getDeviceType() == PcapLiveDevice::WinPcapDevice, "Live device is not of type LibPcapDevice");

	WinPcapLiveDevice* pWinPcapLiveDevice = static_cast<WinPcapLiveDevice*>(liveDev);
	int defaultDataToCopy = pWinPcapLiveDevice->getMinAmountOfDataToCopyFromKernelToApplication();
	PCAPP_ASSERT(defaultDataToCopy == 16000, "Data to copy isn't at its default size (16000)");
	PCAPP_ASSERT(pWinPcapLiveDevice->open(), "Cannot open live device");
	PCAPP_ASSERT(pWinPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(100000), "Set data to copy to 100000 failed. Error string: %s", args.errString);
    int packetCount = 0;
    int numOfTimeStatsWereInvoked = 0;
    PCAPP_ASSERT(pWinPcapLiveDevice->startCapture(&packetArrives, (void*)&packetCount, 1, &statsUpdate, (void*)&numOfTimeStatsWereInvoked), "Cannot start capture");
	for (int i = 0; i < 5; i++)
		sendURLRequest("www.ebay.com");
	pcap_stat statistics;
	pWinPcapLiveDevice->getStatistics(statistics);
    PCAPP_ASSERT(statistics.ps_recv > 20, "No packets were captured");
    PCAPP_ASSERT(statistics.ps_drop == 0, "Packets were dropped: %d", statistics.ps_drop);
    pWinPcapLiveDevice->stopCapture();
	PCAPP_ASSERT(pWinPcapLiveDevice->setMinAmountOfDataToCopyFromKernelToApplication(defaultDataToCopy), "Could not set data to copy back to default value. Error string: %s", args.errString);
	pWinPcapLiveDevice->close();
#else
	PcapLiveDevice* liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(liveDev->getDeviceType() == PcapLiveDevice::LibPcapDevice, "Live device is not of type LibPcapDevice");
#endif

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPcapFilters)
{
	PcapLiveDevice* liveDev = NULL;
    IPv4Address ipToSearch(args.ipToSendReceivePackets.c_str());
    liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());

    string filterAsString;
    PCAPP_ASSERT(liveDev->open(), "Cannot open live device");
    RawPacketVector capturedPackets;

    //-----------
    //IP filter
    //-----------
    string filterAddrAsString(args.ipToSendReceivePackets);
    IPFilter ipFilter(filterAddrAsString, DST);
    ipFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ipFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(sendURLRequest("www.google.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");


	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PCAPP_ASSERT(packet.isPacketOfType(IPv4), "Filter '%s', Packet captured isn't of type IP", filterAsString.c_str());
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ipv4Layer->getIPv4Header()->ipDst == ipToSearch.toInt(), "'IP Filter' failed. Packet IP dst is %X, expected %X", ipv4Layer->getIPv4Header()->ipDst, ipToSearch.toInt());
	}

    //------------
    //Port filter
    //------------
    uint16_t filterPort = 80;
    PortFilter portFilter(filterPort, SRC);
    portFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(portFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(sendURLRequest("www.yahoo.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PCAPP_ASSERT(packet.isPacketOfType(TCP), "Filter '%s', Packet captured isn't of type TCP", filterAsString.c_str());
		TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
		PCAPP_ASSERT(ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80, "'Port Filter' failed. Packet port src is %d, expected 80", pTcpLayer->getTcpHeader()->portSrc);
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
    PCAPP_ASSERT(liveDev->setFilter(andFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(sendURLRequest("www.walla.co.il"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		PCAPP_ASSERT(packet.isPacketOfType(TCP), "Filter '%s', Packet captured isn't of type TCP", filterAsString.c_str());
		TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
		IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80, "'And Filter' failed. Packet port src is %d, expected 80", pTcpLayer->getTcpHeader()->portSrc);
		PCAPP_ASSERT(pIPv4Layer->getIPv4Header()->ipDst == ipToSearch.toInt(), "Filter failed. Packet IP dst is %X, expected %X", pIPv4Layer->getIPv4Header()->ipDst, ipToSearch.toInt());
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
    PCAPP_ASSERT(liveDev->setFilter(orFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(sendURLRequest("www.youtube.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		if (packet.isPacketOfType(TCP))
		{
			TcpLayer* pTcpLayer = packet.getLayerOfType<TcpLayer>();
			bool srcPortMatch = ntohs(pTcpLayer->getTcpHeader()->portSrc) == 80;
			IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
			bool srcIpMatch = pIPv4Layer->getIPv4Header()->ipSrc == ipToSearch.toInt();
			PCAPP_ASSERT(srcIpMatch || srcPortMatch, "'Or Filter' failed. Src port is: %d; Src IP is: %X, Expected: port 80 or IP %s", ntohs(pTcpLayer->getTcpHeader()->portSrc), pIPv4Layer->getIPv4Header()->ipSrc, args.ipToSendReceivePackets.c_str());
		} else
		if (packet.isPacketOfType(IP))
		{
			IPv4Layer* pIPv4Layer = packet.getLayerOfType<IPv4Layer>();
			PCAPP_ASSERT(pIPv4Layer->getIPv4Header()->ipSrc == ipToSearch.toInt(), "Filter failed. Packet IP src is %X, expected %X", pIPv4Layer->getIPv4Header()->ipSrc, ipToSearch.toInt());
		}
		else
			PCAPP_ASSERT(true, "Filter '%s', Packet isn't of type IP or TCP", filterAddrAsString.c_str());
	}
	capturedPackets.clear();

    //----------
    //Not filter
    //----------
    NotFilter notFilter(&ipFilter);
    notFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(notFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(sendURLRequest("www.ebay.com"), "Could not send URL request for filter '%s'", filterAsString.c_str());
    //let the capture work for couple of seconds
	PCAP_SLEEP(2);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() >= 2, "Captured less than 2 packets (HTTP request and response)");
	for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		Packet packet(*iter);
		if (packet.isPacketOfType(IPv4))
		{
			IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
			PCAPP_ASSERT(ipv4Layer->getIPv4Header()->ipSrc != ipToSearch.toInt(), "'Not Filter' failed. Packet IP src is %X, the same as %X", ipv4Layer->getIPv4Header()->ipSrc, ipToSearch.toInt());
		}
	}
	capturedPackets.clear();

    //-----------------
    //VLAN filter
    //-----------------
	VlanFilter vlanFilter(118);
	vlanFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(vlanFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    RawPacket rawPacket;
    while (fileReaderDev.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev.close();
    PCAP_SLEEP(2);
    liveDev->stopCapture();

    PCAPP_ASSERT(capturedPackets.size() >= 12, "VLAN filter test: Captured: %d packets. Expected: > %d packets", (int)capturedPackets.size(), 12);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(VLAN), "VLAN filter test: one of the captured packets isn't of type VLAN");
    	VlanLayer* vlanLayer = packet.getLayerOfType<VlanLayer>();
    	PCAPP_ASSERT(vlanLayer->getVlanID() == 118, "VLAN filter test: VLAN ID != 118, it's: %d", vlanLayer->getVlanID());
    }

    capturedPackets.clear();

    //--------------------
    //MacAddress filter
    //--------------------
    MacAddress macAddrToFilter("00:13:c3:df:ae:18");
    MacAddressFilter macAddrFilter(macAddrToFilter, DST);
    macAddrFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(macAddrFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev.close();
    PCAP_SLEEP(2);
    liveDev->stopCapture();

    PCAPP_ASSERT(capturedPackets.size() == 5, "MacAddress test: Captured: %d packets. Expected: %d packets", (int)capturedPackets.size(), 5);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	EthLayer* ethLayer = packet.getLayerOfType<EthLayer>();
    	PCAPP_ASSERT(ethLayer->getDestMac() == macAddrToFilter, "MacAddress test: dest MAC different than expected, it's: '%s'", ethLayer->getDestMac().toString().c_str());
    }

    capturedPackets.clear();

    //--------------------
    //EtherType filter
    //--------------------
    EtherTypeFilter ethTypeFiler(PCPP_ETHERTYPE_VLAN);
    ethTypeFiler.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ethTypeFiler), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev.close();
    PCAP_SLEEP(2);
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 24, "EthTypeFilter test: Captured less than %d packets", 24);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(VLAN), "EthTypeFilter test: one of the captured packets isn't of type VLAN");
    }

    capturedPackets.clear();


    //--------------------
    //IpV4 ID filter
    //--------------------
    uint16_t ipID(0x9900);
    IpV4IDFilter ipIDFiler(ipID, GREATER_THAN);
    ipIDFiler.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ipIDFiler), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PcapFileReaderDevice fileReaderDev2(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 1423, "IpV4IDFilter test: Captured less than %d packets", 1423);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(IPv4), "IpV4IDFilter test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ntohs(ipv4Layer->getIPv4Header()->ipId) > ipID, "IpV4IDFilter test: IP ID less than %d, it's %d", ipID, ntohs(ipv4Layer->getIPv4Header()->ipId));
    }

    capturedPackets.clear();

    //-------------------------
    //IpV4 Total Length filter
    //-------------------------
    uint16_t totalLength(576);
    IpV4TotalLengthFilter ipTotalLengthFiler(totalLength, LESS_OR_EQUAL);
    ipTotalLengthFiler.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ipTotalLengthFiler), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 2066, "IpV4TotalLengthFilter test: Captured less than %d packets", 2066);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(IPv4), "IpV4TotalLengthFilter test: one of the captured packets isn't of type IPv4");
		IPv4Layer* ipv4Layer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ntohs(ipv4Layer->getIPv4Header()->totalLength) <= totalLength, "IpV4TotalLengthFilter test: IP total length more than %d, it's %d", totalLength, ntohs(ipv4Layer->getIPv4Header()->totalLength));
    }

    capturedPackets.clear();


    //-------------------------
    //TCP window size filter
    //-------------------------
    uint16_t windowSize(8312);
    TcpWindowSizeFilter tcpWindowSizeFilter(windowSize, NOT_EQUALS);
    tcpWindowSizeFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(tcpWindowSizeFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 4249, "TcpWindowSizeFilter test: Captured less than %d packets", 4249);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(TCP), "TcpWindowSizeFilter test: one of the captured packets isn't of type TCP");
		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
		PCAPP_ASSERT(ntohs(tcpLayer->getTcpHeader()->windowSize) != windowSize, "TcpWindowSizeFilter test: TCP window size equals %d", windowSize);
    }

    capturedPackets.clear();


    //-------------------------
    //UDP length filter
    //-------------------------
    uint16_t udpLength(46);
    UdpLengthFilter udpLengthFilter(udpLength, EQUALS);
    udpLengthFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(udpLengthFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 4, "UdpLengthFilter test: Captured less than %d packets", 4);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(UDP), "UdpLengthFilter test: one of the captured packets isn't of type UDP");
    	UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
		PCAPP_ASSERT(ntohs(udpLayer->getUdpHeader()->length) == udpLength, "UdpLengthFilter test: UDP length != %d, it's %d", udpLength, ntohs(udpLayer->getUdpHeader()->length));
    }

    capturedPackets.clear();


    //-------------------------
    //TCP flags filter
    //-------------------------
    uint8_t tcpFlagsBitMask(TcpFlagsFilter::tcpSyn|TcpFlagsFilter::tcpAck);
    TcpFlagsFilter tcpFlagsFilter(tcpFlagsBitMask, TcpFlagsFilter::MatchAll);
    tcpFlagsFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(tcpFlagsFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
	sendURLRequest("www.cnn.com");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() > 0, "TcpFlagsFilter test #1: Captured 0 packets");
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(TCP), "TcpFlagsFilter test #1: one of the captured packets isn't of type TCP");
    	TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
    	PCAPP_ASSERT(tcpLayer->getTcpHeader()->synFlag == 1 && tcpLayer->getTcpHeader()->ackFlag == 1, "TcpFlagsFilter test #1: TCP packet isn't a SYN/ACK packet");
    }

    capturedPackets.clear();
    tcpFlagsFilter.setTcpFlagsBitMask(tcpFlagsBitMask, TcpFlagsFilter::MatchOneAtLeast);
    tcpFlagsFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(tcpFlagsFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
	sendURLRequest("www.bbc.com");
	PCAP_SLEEP(5);
	liveDev->stopCapture();
	PCAPP_ASSERT(capturedPackets.size() > 0, "TcpFlagsFilter test #2: Captured 0 packets");
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(TCP), "TcpFlagsFilter test #2: one of the captured packets isn't of type TCP");
    	TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
    	PCAPP_ASSERT(tcpLayer->getTcpHeader()->synFlag == 1 || tcpLayer->getTcpHeader()->ackFlag == 1, "TcpFlagsFilter test #2: TCP packet isn't a SYN or ACK packet");
    }

    capturedPackets.clear();

    //-------------------------
    //IP filter with mask
    //-------------------------
    IPFilter ipFilterWithMask("212.199.202.9", SRC, "255.255.255.0");
    ipFilterWithMask.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ipFilterWithMask), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 2536, "IPFilter with mask test: Captured less than %d packets", 2536);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(IPv4), "IPFilter with mask test: one of the captured packets isn't of type IPv4");
    	IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ipLayer->getSrcIpAddress().matchSubnet(IPv4Address(string("212.199.202.9")), "255.255.255.0"), "IPFilter with mask test: packet doesn't match subnet mask. IP src: '%s'", ipLayer->getSrcIpAddress().toString().c_str());
    }

    capturedPackets.clear();

    ipFilterWithMask.setLen(24);
    ipFilterWithMask.setAddr("212.199.202.9");
    ipFilterWithMask.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(ipFilterWithMask), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 2536, "IPFilter with mask test #2: Captured less than %d packets", 2536);
    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(IPv4), "IPFilter with mask test #2: one of the captured packets isn't of type IPv4");
    	IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();
		PCAPP_ASSERT(ipLayer->getSrcIpAddress().matchSubnet(IPv4Address(string("212.199.202.9")), "255.255.255.0"), "IPFilter with mask test: packet doesn't match subnet mask. IP src: '%s'", ipLayer->getSrcIpAddress().toString().c_str());
    }
    capturedPackets.clear();

    //-------------
    //Port range
    //-------------
    PortRangeFilter portRangeFilter(40000, 50000, SRC);
    portRangeFilter.parseToString(filterAsString);
    PCAPP_ASSERT(liveDev->setFilter(portRangeFilter), "Could not set filter: %s", filterAsString.c_str());
    PCAPP_ASSERT(liveDev->startCapture(capturedPackets), "Cannot start capture for filter '%s'", filterAsString.c_str());
    PCAPP_ASSERT(fileReaderDev2.open(), "Cannot open file reader device for filter '%s'", filterAsString.c_str());
    while (fileReaderDev2.getNextPacket(rawPacket))
    {
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send packet. Testing filter: '%s'", filterAsString.c_str());
    }
    fileReaderDev2.close();
    liveDev->stopCapture();
    PCAPP_ASSERT(capturedPackets.size() >= 1464, "PortRangeFilter: Captured less than %d packets", 1899);

    for (RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
    {
    	Packet packet(*iter);
    	PCAPP_ASSERT(packet.isPacketOfType(TCP) || packet.isPacketOfType(UDP), "PortRangeFilter: one of the captured packets isn't of type TCP or UDP");
    	if (packet.isPacketOfType(TCP))
    	{
    		TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
    		uint16_t portSrc = ntohs(tcpLayer->getTcpHeader()->portSrc);
    		PCAPP_ASSERT(portSrc >= 40000 && portSrc <=50000, "PortRangeFilter: TCP packet source port is out of range (40000-50000). Src port: %d", portSrc);
    	}
    	else if (packet.isPacketOfType(UDP))
    	{
    		UdpLayer* udpLayer = packet.getLayerOfType<UdpLayer>();
    		uint16_t portSrc = ntohs(udpLayer->getUdpHeader()->portSrc);
    		PCAPP_ASSERT(portSrc >= 40000 && portSrc <=50000, "PortRangeFilter: UDP packet source port is out of range (40000-50000). Src port: %d", portSrc);
    	}
    }
    capturedPackets.clear();

    liveDev->close();
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestSendPacket)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(args.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
    PCAPP_ASSERT(liveDev->open(), "Cannot open live device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    PCAPP_ASSERT(liveDev->getMtu() > 0, "Could not get live device MTU");
    uint16_t mtu = liveDev->getMtu();
    int buffLen = mtu+1;
    uint8_t* buff = new uint8_t[buffLen];
    memset(buff, 0, buffLen);
    PCAPP_ASSERT(!liveDev->sendPacket(buff, buffLen), "Defected packet was sent successfully");

    RawPacket rawPacket;
    int packetsSent = 0;
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacket))
    {
    	packetsRead++;

    	//send packet as RawPacket
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket), "Could not send raw packet");

    	//send packet as raw data
    	PCAPP_ASSERT(liveDev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()), "Could not send raw data");

    	//send packet as parsed EthPacekt
    	Packet packet(&rawPacket);
    	PCAPP_ASSERT(liveDev->sendPacket(&packet), "Could not send parsed packet");

   		packetsSent++;
    }

    PCAPP_ASSERT(packetsRead == packetsSent, "Unexpected number of packets sent. Expected (read from file): %d; Sent: %d", packetsRead, packetsSent);

    liveDev->close();
    fileReaderDev.close();

	delete[] buff;

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestSendPackets)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(args.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
    PCAPP_ASSERT(liveDev->open(), "Cannot open live device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

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

    PCAPP_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRaw);
    PCAPP_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);

    liveDev->close();
    fileReaderDev.close();

    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestRemoteCapture)
{
#ifdef WIN32
	bool useRemoteDevicesFromArgs = (args.remoteIp != "") && (args.remotePort > 0);
	string remoteDeviceIP = (useRemoteDevicesFromArgs ? args.remoteIp : args.ipToSendReceivePackets);
	uint16_t remoteDevicePort = (useRemoteDevicesFromArgs ? args.remotePort : 12321);

	HANDLE rpcapdHandle = NULL;
	if (!useRemoteDevicesFromArgs)
	{
		rpcapdHandle = activateRpcapdServer(remoteDeviceIP, remoteDevicePort);
		PCAPP_ASSERT(rpcapdHandle != NULL, "Could not create rpcapd process. Error was: %lu", GetLastError());

	}

	IPv4Address remoteDeviceIPAddr(remoteDeviceIP);
	PcapRemoteDeviceList* remoteDevices = PcapRemoteDeviceList::getRemoteDeviceList(&remoteDeviceIPAddr, remoteDevicePort);
	PCAPP_ASSERT_AND_RUN_COMMAND(remoteDevices != NULL, terminateRpcapdServer(rpcapdHandle), "Error on retrieving remote devices on IP: %s port: %d. Error string was: %s", remoteDeviceIP.c_str(), remoteDevicePort, args.errString);
	for (PcapRemoteDeviceList::RemoteDeviceListIterator remoteDevIter = remoteDevices->begin(); remoteDevIter != remoteDevices->end(); remoteDevIter++)
	{
		PCAPP_ASSERT_AND_RUN_COMMAND((*remoteDevIter)->getName() != NULL, terminateRpcapdServer(rpcapdHandle), "One of the remote devices has no name");
	}
	PCAPP_ASSERT_AND_RUN_COMMAND(remoteDevices->getRemoteMachineIpAddress()->toString() == remoteDeviceIP, terminateRpcapdServer(rpcapdHandle), "Remote machine IP got from device list doesn't match provided IP");
	PCAPP_ASSERT_AND_RUN_COMMAND(remoteDevices->getRemoteMachinePort() == remoteDevicePort, terminateRpcapdServer(rpcapdHandle), "Remote machine port got from device list doesn't match provided port");

	PcapRemoteDevice* pRemoteDevice = remoteDevices->getRemoteDeviceByIP(&remoteDeviceIPAddr);
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getDeviceType() == PcapLiveDevice::RemoteDevice, terminateRpcapdServer(rpcapdHandle), "Remote device type isn't 'RemoteDevice'");
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getMtu() == 0, terminateRpcapdServer(rpcapdHandle), "MTU of remote device isn't 0");
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getMacAddress() == MacAddress::Zero, terminateRpcapdServer(rpcapdHandle), "MAC address of remote device isn't zero");
	LoggerPP::getInstance().enableErrors();
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getRemoteMachineIpAddress()->toString() == remoteDeviceIP, terminateRpcapdServer(rpcapdHandle), "Remote machine IP got from device doesn't match provided IP");
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->getRemoteMachinePort() == remoteDevicePort, terminateRpcapdServer(rpcapdHandle), "Remote machine port got from device doesn't match provided port");
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->open(), terminateRpcapdServer(rpcapdHandle), "Could not open the remote device. Error was: %s", args.errString);
	RawPacketVector capturedPackets;
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->startCapture(capturedPackets), terminateRpcapdServer(rpcapdHandle), "Couldn't start capturing on remote device '%s'. Error was: %s", pRemoteDevice->getName(), args.errString);

	if (!useRemoteDevicesFromArgs)
		PCAPP_ASSERT_AND_RUN_COMMAND(sendURLRequest("www.yahoo.com"), terminateRpcapdServer(rpcapdHandle), "Couldn't send URL");

	PCAP_SLEEP(20);
	pRemoteDevice->stopCapture();

	//send single packet
	PCAPP_ASSERT_AND_RUN_COMMAND(pRemoteDevice->sendPacket(*capturedPackets.front()), terminateRpcapdServer(rpcapdHandle), "Couldn't send a packet. Error was: %s", args.errString);

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
	PCAPP_ASSERT_AND_RUN_COMMAND(packetsSent == (int)packetsToSend.size(), terminateRpcapdServer(rpcapdHandle), "%d packets sent out of %d. Error was: %s", packetsSent, packetsToSend.size(), args.errString);

	//check statistics
	pcap_stat stats;
	pRemoteDevice->getStatistics(stats);
	PCAPP_ASSERT_AND_RUN_COMMAND(stats.ps_recv == capturedPacketsSize, terminateRpcapdServer(rpcapdHandle),
			"Statistics returned from rpcapd doesn't equal the captured packets vector size. Stats: %d; Vector size: %d",
			stats.ps_recv, capturedPacketsSize);

	pRemoteDevice->close();

	terminateRpcapdServer(rpcapdHandle);

	delete remoteDevices;
#endif

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestHttpRequestParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_REQUEST);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");

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
		PCAPP_ASSERT(httpReqLayer->getFirstLine() != NULL, "HTTP first line is null in packet #%d, HTTP request #%d", packetCount, httpPackets);
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
			PCAPP_ASSERT(httpReqLayer->getFirstLine()->getVersion() == OneDotOne, "HTTP version is different than 1.1 in packet #%d, HTTP request #%d", packetCount, httpPackets);
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

    PCAPP_ASSERT(packetCount == 385, "Packet count is wrong. Actual: %d; Expected: %d", packetCount, 385);

    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ")
    PCAPP_ASSERT(httpPackets == 385, "HTTP packet count is wrong. Actual: %d; Expected: %d", httpPackets, 385);


    PCAPP_ASSERT(otherMethodReqs == 0, "Parsed %d HTTP requests with unexpected method", otherMethodReqs);

    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET ")
    PCAPP_ASSERT(getReqs == 217, "Number of GET requests different than expected. Actual: %d; Expected: %d", getReqs, 217);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "POST ")
    PCAPP_ASSERT(postReqs == 156, "Number of POST requests different than expected. Actual: %d; Expected: %d", postReqs, 156);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "OPTIONS ")
    PCAPP_ASSERT(optionsReqs == 7, "Number of OPTIONS requests different than expected. Actual: %d; Expected: %d", optionsReqs, 7);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "HEAD ")
    PCAPP_ASSERT(headReqs == 5, "Number of HEAD requests different than expected. Actual: %d; Expected: %d", headReqs, 5);


    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST ") && (tcp matches "home.*HTTP/1.1")
    PCAPP_ASSERT(homeReqs == 13, "Number of requests with URI contains 'home' is different than expected. Actual: %d; Expected: %d", homeReqs, 13);
    // Wireshark filter: http.request.full_uri contains .swf
    PCAPP_ASSERT(swfReqs == 4, "Number of requests with URI contains '.swf' is different than expected. Actual: %d; Expected: %d", swfReqs, 4);

    // Wireshark filter: tcp contains "Host: www.google.com"
    PCAPP_ASSERT(googleReqs == 12, "Number of requests from www.google.com is different than expected. Actual: %d; Expected: %d", googleReqs, 12);
    // Wireshark filter: tcp contains "Host: www.yad2.co.il"
    PCAPP_ASSERT(yad2Reqs == 15, "Number of requests from www.yad2.co.il is different than expected. Actual: %d; Expected: %d", yad2Reqs, 15);
    // Wireshark filter: tcp contains "Host: www.winwin.co.il"
    PCAPP_ASSERT(winwinReqs == 20, "Number of requests from www.winwin.co.il is different than expected. Actual: %d; Expected: %d", winwinReqs, 20);


    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Firefox/33.0")
    PCAPP_ASSERT(ffReqs == 233, "Number of Firefox requests is different than expected. Actual: %d; Expected: %d", ffReqs, 233);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Chrome/38.0")
    PCAPP_ASSERT(chromeReqs == 82, "Number of Chrome requests is different than expected. Actual: %d; Expected: %d", chromeReqs, 82);
    // Wireshark filter: (tcp.dstport == 80 || tcp.dstport == 8080) && (tcp contains "GET " || tcp contains "POST " || tcp contains "HEAD " || tcp contains "OPTIONS ") && (tcp contains "Trident/7.0")
    PCAPP_ASSERT(ieReqs == 55, "Number of IE requests is different than expected. Actual: %d; Expected: %d", ieReqs, 55);

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestHttpResponseParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_HTTP_RESPONSE);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");

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
		PCAPP_ASSERT(httpResLayer->getFirstLine() != NULL, "HTTP first line is null in packet #%d, HTTP request #%d", packetCount, httpResponsePackets);
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

    PCAPP_ASSERT(packetCount == 682, "Packet count is different than expected. Found: %d; Expected: 682", packetCount);

    // *** wireshark has a bug there and displays 1 less packet as http response. Missing packet IP ID is 10419 ***
    // ************************************************************************************************************

    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080)
    PCAPP_ASSERT(httpResponsePackets == 682, "HTTP response count is different than expected. Found: %d; Expected: 682", httpResponsePackets);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 200
    PCAPP_ASSERT(statusCodes[HttpResponseLayer::Http200OK] == 592, "HTTP response with 200 OK count is different than expected. Found: %d; Expected: 592", statusCodes[HttpResponseLayer::Http200OK]);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 302
    PCAPP_ASSERT(statusCodes[HttpResponseLayer::Http302] == 15, "HTTP response with 302 count is different than expected. Found: %d; Expected: 15", statusCodes[HttpResponseLayer::Http302]);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.response.code == 304
    PCAPP_ASSERT(statusCodes[HttpResponseLayer::Http304NotModified] == 26, "HTTP response with 304 count is different than expected. Found: %d; Expected: 26", statusCodes[HttpResponseLayer::Http304NotModified]);

    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type == "text/html"
    PCAPP_ASSERT(textHtmlCount == 38, "HTTP responses with content-type=='text/html' is different than expected. Expected: %d; Actual: %d", 38, textHtmlCount);
    // wireshark filter: http.response && (tcp.srcport == 80 || tcp.srcport == 8080) && http.content_type contains "image/"
    PCAPP_ASSERT(imageCount == 369, "HTTP responses with content-type=='image/*' is different than expected. Expected: %d; Actual: %d", 369, imageCount);

    // wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && (tcp contains "Transfer-Encoding:  chunked" || tcp contains "Transfer-Encoding: chunked" || tcp contains "transfer-encoding: chunked")
    PCAPP_ASSERT(chunkedCount == 45, "HTTP responses with transfer-encoding=='chunked' is different than expected. Expected: %d; Actual: %d", 45, chunkedCount);
    // wireshark filter: (tcp.srcport == 80 || tcp.srcport == 8080) && tcp contains "HTTP/1." && tcp contains "Content-Encoding: gzip"
    PCAPP_ASSERT(gzipCount == 148, "HTTP responses with content-encoding=='gzip' is different than expected. Expected: %d; Actual: %d", 148, gzipCount);

    // wireshark filter: http.content_length > 100000
    PCAPP_ASSERT(bigResponses == 14, "HTTP responses with content-length > 100K is different than expected. Expected: %d; Actual: %d", 14, bigResponses);

//    printf("Total HTTP response packets: %d\n", httpResponsePackets);
//    printf("200 OK packets: %d\n", statusCodes[HttpResponseLayer::Http200OK]);
//    printf("302 packets: %d\n", statusCodes[HttpResponseLayer::Http302]);
//    printf("304 Not Modified packets: %d\n", statusCodes[HttpResponseLayer::Http304NotModified]);
//    printf("text/html responses: %d\n", textHtmlCount);
//    printf("image responses: %d\n", imageCount);
//    printf("gzip responses: %d\n", gzipCount);
//    printf("chunked responses: %d\n", chunkedCount);
//    printf("big responses: %d\n", bigResponses);

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPrintPacketAndLayers)
{
	PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PCAPP_ASSERT(reader.open(), "Cannot open reader device for '%s'", EXAMPLE2_PCAP_PATH);
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

	PCAPP_ASSERT(referenceBufferAsString == outputStream.str(), "Output is different than reference file");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPfRingDevice)
{
#ifdef USE_PF_RING

	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PCAPP_ASSERT(devList.getPfRingDevicesList().size() > 0, "PF_RING device list contains 0 devices");
	PCAPP_ASSERT(devList.getPfRingVersion() != "", "Couldn't retrieve PF_RING version");
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PCAPP_ASSERT(dev != NULL, "Couldn't find PF_RING device with name '%s'", pcapLiveDev->getName());
	PCAPP_ASSERT(dev->getMacAddress().isValid() == true, "Dev MAC addr isn't valid");
	PCAPP_ASSERT(dev->getMacAddress() != MacAddress::Zero, "Dev MAC addr is zero");
	PCAPP_ASSERT(dev->getInterfaceIndex() > 0, "Dev interface index is zero");
	PCAPP_ASSERT(dev->getTotalNumOfRxChannels() > 0, "Number of RX channels is zero");
	PCAPP_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "Number of open RX channels isn't zero");
	PCAPP_ASSERT(dev->open() == true, "Cannot open PF_RING device");
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->open() == false, "Managed to open the device twice");
	LoggerPP::getInstance().enableErrors();
	PCAPP_ASSERT(dev->getNumOfOpenedRxChannels() == 1, "After device is open number of open RX channels != 1, it's %d", dev->getNumOfOpenedRxChannels());

	PfRingPacketData packetData;
	PCAPP_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData), "Couldn't start capturing");
	PCAP_SLEEP(5); //TODO: put this on 10-20 sec
	dev->stopCapture();
	PCAPP_ASSERT(packetData.PacketCount > 0, "No packets were captured");
	PCAPP_ASSERT(packetData.ThreadId != -1, "Couldn't retrieve thread ID");

	pcap_stat stats;
	stats.ps_recv = 0;
	stats.ps_drop = 0;
	stats.ps_ifdrop = 0;
	dev->getStatistics(stats);
	PCAPP_ASSERT(stats.ps_recv == (uint32_t)packetData.PacketCount, "Stats received packet count is different than calculated packet count");
	dev->close();

	PCAPP_DEBUG_PRINT("Thread ID: %d", packetData.ThreadId);
	PCAPP_DEBUG_PRINT("Total packets captured: %d", packetData.PacketCount);
	PCAPP_DEBUG_PRINT("Eth packets: %d", packetData.EthCount);
	PCAPP_DEBUG_PRINT("IP packets: %d", packetData.IpCount);
	PCAPP_DEBUG_PRINT("TCP packets: %d", packetData.TcpCount);
	PCAPP_DEBUG_PRINT("UDP packets: %d", packetData.UdpCount);
	PCAPP_DEBUG_PRINT("Device statistics:");
	PCAPP_DEBUG_PRINT("Packets captured: %d", stats.ps_recv);
	PCAPP_DEBUG_PRINT("Packets dropped: %d", stats.ps_drop);

//	test filters
#endif

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPfRingDeviceSingleChannel)
{
#ifdef USE_PF_RING

	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PfRingPacketData packetData;
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels()+1) == false, "Wrongly succeeded opening the device on a RX channel [%d] that doesn't exist open device on RX channel", dev->getTotalNumOfRxChannels()+1);
	LoggerPP::getInstance().enableErrors();
	PCAPP_ASSERT(dev->openSingleRxChannel(dev->getTotalNumOfRxChannels()-1) == true, "Couldn't open device on RX channel %d", dev->getTotalNumOfRxChannels());
	PCAPP_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArrive, &packetData), "Couldn't start capturing");
	PCAP_SLEEP(5); //TODO: put this on 10-20 sec
	dev->stopCapture();
	PCAPP_ASSERT(packetData.PacketCount > 0, "No packets were captured");
	PCAPP_ASSERT(packetData.ThreadId != -1, "Couldn't retrieve thread ID");
	pcap_stat stats;
	dev->getStatistics(stats);
	PCAPP_ASSERT(stats.ps_recv == (uint32_t)packetData.PacketCount, "Stats received packet count is different than calculated packet count");
	PCAPP_DEBUG_PRINT("Thread ID: %d", packetData.ThreadId);
	PCAPP_DEBUG_PRINT("Total packets captured: %d", packetData.PacketCount);
	PCAPP_DEBUG_PRINT("Eth packets: %d", packetData.EthCount);
	PCAPP_DEBUG_PRINT("IP packets: %d", packetData.IpCount);
	PCAPP_DEBUG_PRINT("TCP packets: %d", packetData.TcpCount);
	PCAPP_DEBUG_PRINT("UDP packets: %d", packetData.UdpCount);
	PCAPP_DEBUG_PRINT("Packets captured: %d", stats.ps_recv);
	PCAPP_DEBUG_PRINT("Packets dropped: %d", stats.ps_drop);

	dev->close();
	PCAPP_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "There are still open RX channels after device close");

#endif
	PCAPP_TEST_PASSED;
}


bool TestPfRingDeviceMultiThread(CoreMask coreMask, PcapTestArgs args)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	uint8_t numOfChannels = dev->getTotalNumOfRxChannels();
	PCAPP_ASSERT(dev->openMultiRxChannels(numOfChannels*2.5, PfRingDevice::PerFlow) == true, "Couldn't open device with %d channels", (int)(numOfChannels*2.5));
	dev->close();
	PCAPP_ASSERT(dev->getNumOfOpenedRxChannels() == 0, "There are still open RX channels after device close");
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

	PCAPP_ASSERT(dev->openMultiRxChannels((uint8_t)numOfCoresInUse, PfRingDevice::PerFlow) == true, "Couldn't open device with %d channels", totalnumOfCores);
	PfRingPacketData packetDataMultiThread[totalnumOfCores];
	PCAPP_ASSERT(dev->startCaptureMultiThread(pfRingPacketsArriveMultiThread, packetDataMultiThread, coreMask), "Couldn't start capturing multi-thread");
	PCAP_SLEEP(10);
	dev->stopCapture();
	pcap_stat aggrStats;
	aggrStats.ps_recv = 0;
	aggrStats.ps_drop = 0;
	aggrStats.ps_ifdrop = 0;

	pcap_stat stats;
	for (int i = 0; i < totalnumOfCores; i++)
	{
		if ((SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
			continue;

		PCAPP_DEBUG_PRINT("Thread ID: %d", packetDataMultiThread[i].ThreadId);
		PCAPP_DEBUG_PRINT("Total packets captured: %d", packetDataMultiThread[i].PacketCount);
		PCAPP_DEBUG_PRINT("Eth packets: %d", packetDataMultiThread[i].EthCount);
		PCAPP_DEBUG_PRINT("IP packets: %d", packetDataMultiThread[i].IpCount);
		PCAPP_DEBUG_PRINT("TCP packets: %d", packetDataMultiThread[i].TcpCount);
		PCAPP_DEBUG_PRINT("UDP packets: %d", packetDataMultiThread[i].UdpCount);
		dev->getThreadStatistics(SystemCores::IdToSystemCore[i], stats);
		aggrStats.ps_recv += stats.ps_recv;
		aggrStats.ps_drop += stats.ps_drop;
		PCAPP_DEBUG_PRINT("Packets captured: %d", stats.ps_recv);
		PCAPP_DEBUG_PRINT("Packets dropped: %d", stats.ps_drop);
		PCAPP_ASSERT(stats.ps_recv == (uint32_t)packetDataMultiThread[i].PacketCount, "Stats received packet count is different than calculated packet count on thread %d", packetDataMultiThread[i].ThreadId);
	}

	dev->getStatistics(stats);
	PCAPP_ASSERT(aggrStats.ps_recv == stats.ps_recv, "Aggregated stats weren't calculated correctly: aggr recv = %d, calc recv = %d", stats.ps_recv, aggrStats.ps_recv);
	PCAPP_ASSERT(aggrStats.ps_drop == stats.ps_drop, "Aggregated stats weren't calculated correctly: aggr drop = %d, calc drop = %d", stats.ps_drop, aggrStats.ps_drop);

	for (int firstCoreId = 0; firstCoreId < totalnumOfCores; firstCoreId++)
	{
		for (int secondCoreId = firstCoreId+1; secondCoreId < totalnumOfCores; secondCoreId++)
		{
			map<uint32_t, pair<RawPacketVector, RawPacketVector> > res;
			intersectMaps<uint32_t, RawPacketVector, RawPacketVector>(packetDataMultiThread[firstCoreId].FlowKeys, packetDataMultiThread[secondCoreId].FlowKeys, res);
			PCAPP_ASSERT(res.size() == 0, "%d flows appear in core %d and core %d", (int)res.size(), firstCoreId, secondCoreId);
			if (PCAPP_IS_UNIT_TEST_DEBUG_ENABLED)
			{
				for (map<uint32_t, pair<RawPacketVector, RawPacketVector> >::iterator iter = res.begin(); iter != res.end(); iter++)
				{
					PCAPP_DEBUG_PRINT("Same flow exists in core %d and core %d. Flow key = %X", firstCoreId, secondCoreId, iter->first);
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
		PCAPP_DEBUG_PRINT("Core %d\n========", firstCoreId);
		PCAPP_DEBUG_PRINT("Total flows: %d", (int)packetDataMultiThread[firstCoreId].FlowKeys.size());

		if (PCAPP_IS_UNIT_TEST_DEBUG_ENABLED)
		{
			for(map<uint32_t, RawPacketVector>::iterator iter = packetDataMultiThread[firstCoreId].FlowKeys.begin(); iter != packetDataMultiThread[firstCoreId].FlowKeys.end(); iter++) {
				PCAPP_DEBUG_PRINT("Key=%X; Value=%d", iter->first, (int)iter->second.size());
				iter->second.clear();
			}
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();

		dev->close();
	}
#endif

	return true;
}

PCAPP_TEST(TestPfRingMultiThreadAllCores)
{
#ifdef USE_PF_RING
	int numOfCores = getNumOfCores();
	CoreMask coreMask = 0;
	for (int i = 0; i < numOfCores; i++)
	{
		coreMask |= SystemCores::IdToSystemCore[i].Mask;
	}

	if (TestPfRingDeviceMultiThread(coreMask, args))
	{
		PCAPP_TEST_PASSED;
	}

	return false;
#else
	PCAPP_TEST_PASSED;
#endif

}

PCAPP_TEST(TestPfRingMultiThreadSomeCores)
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

	if (TestPfRingDeviceMultiThread(coreMask, args))
	{
		PCAPP_TEST_PASSED;
	}

	return false;
#else
	PCAPP_TEST_PASSED;
#endif
}

PCAPP_TEST(TestPfRingSendPacket)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));
	PCAPP_ASSERT(dev->open(), "Could not open PF_RING device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    PCAPP_ASSERT(dev->getMtu() > 0, "Could not get device MTU");
    uint16_t mtu = dev->getMtu();
    int buffLen = mtu+1;
    uint8_t buff[buffLen];
    memset(buff, 0, buffLen);
    //LoggerPP::getInstance().supressErrors();
    //PCAPP_ASSERT(!dev->sendPacket(buff, buffLen), "Defected packet was sent successfully");
    //LoggerPP::getInstance().enableErrors();

    RawPacket rawPacket;
    int packetsSent = 0;
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacket))
    {
    	packetsRead++;

    	RawPacket origRawPacket = rawPacket;
    	//send packet as RawPacket
    	PCAPP_ASSERT_AND_RUN_COMMAND(dev->sendPacket(rawPacket), dev->close(), "Sent %d packets. Could not send another raw packet", (packetsRead-1)*3);

    	//send packet as raw data
    	PCAPP_ASSERT_AND_RUN_COMMAND(dev->sendPacket(rawPacket.getRawData(), rawPacket.getRawDataLen()), dev->close(), "Sent %d packets. Could not send another raw data", (packetsRead-1)*3+1);

    	//send packet as parsed EthPacekt
    	Packet packet(&rawPacket);
    	PCAPP_ASSERT_AND_RUN_COMMAND(dev->sendPacket(packet), dev->close(), "Sent %d packets. Could not send another parsed packet", (packetsRead-1)*3+2);

   		packetsSent++;
    }

    PCAPP_ASSERT(packetsRead == packetsSent, "Unexpected number of packets sent. Expected (read from file): %d; Sent: %d", packetsRead, packetsSent);

    dev->close();

    fileReaderDev.close();

    // send some packets with single channel open
    PCAPP_ASSERT(dev->openSingleRxChannel(0), "Could not open PF_RING device with single channel 0");
    fileReaderDev.open();
    while(fileReaderDev.getNextPacket(rawPacket))
    	PCAPP_ASSERT(dev->sendPacket(rawPacket), "Could not send raw packet");

    dev->close();

    fileReaderDev.close();

#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPfRingSendPackets)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));
	PCAPP_ASSERT(dev->open(), "Could not open PF_RING device");

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

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

    PCAPP_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRaw);
    PCAPP_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);

    dev->close();
    fileReaderDev.close();

#endif
    PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestPfRingFilters)
{
#ifdef USE_PF_RING
	PfRingDeviceList& devList = PfRingDeviceList::getInstance();
	PcapLiveDevice* pcapLiveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.ipToSendReceivePackets.c_str());
	PCAPP_ASSERT(pcapLiveDev != NULL, "Couldn't find the pcap device matching to IP address '%s'", args.ipToSendReceivePackets.c_str());
	PfRingDevice* dev = devList.getPfRingDeviceByName(string(pcapLiveDev->getName()));

	PCAPP_ASSERT(dev->isFilterCurrentlySet() == false, "Device indicating filter is set although we didn't set any filters yet");
	PCAPP_ASSERT(dev->removeFilter() == true, "RemoveFilter returned false although no filter was set yet");
	ProtoFilter protocolFilter(TCP);
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->setFilter(protocolFilter) == false, "Succeed setting a filter while device is closed");
	LoggerPP::getInstance().enableErrors();

	PCAPP_ASSERT(dev->open(), "Could not open PF_RING device");
	PCAPP_ASSERT(dev->setFilter(protocolFilter) == true, "Couldn't set TCP filter");

	// verfiy TCP filter
	SetFilterInstruction instruction = { 1, "" }; // instruction #1: verify all packets are of type TCP
	PCAPP_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PCAPP_ASSERT(instruction.Instruction == 1, "TCP protocol filter failed: some of the packets aren't of protocol TCP");

	instruction.Instruction = 2;
	instruction.Data = args.ipToSendReceivePackets;
	IPFilter ipFilter(args.ipToSendReceivePackets, SRC);
	PCAPP_ASSERT(dev->setFilter(ipFilter) == true, "Couldn't set IP filter");
	PCAPP_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PCAPP_ASSERT(instruction.Instruction == 2, "IP filter failed: some of the packets doens't match IP src filter");

	// remove filter and test again
	instruction.Instruction = 1;
	instruction.Data = "";
	PCAPP_ASSERT(dev->isFilterCurrentlySet() == true, "Device indicating filter isn't set although we set a filter");
	PCAPP_ASSERT(dev->removeFilter() == true, "Remove filter failed");
	PCAPP_ASSERT(dev->isFilterCurrentlySet() == false, "Device indicating filter still exists although we removed it");
	PCAPP_ASSERT(dev->startCaptureSingleThread(pfRingPacketsArriveSetFilter, &instruction), "Couldn't start capturing");
	PCAP_SLEEP(10);
	dev->stopCapture();
	PCAPP_ASSERT(instruction.Instruction == 0, "All packet are still of type TCP although filter was removed");
#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestDnsParsing)
{
    PcapFileReaderDevice readerDev(EXAMPLE_PCAP_DNS);
    PCAPP_ASSERT(readerDev.open(), "cannot open reader device");

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
    	PCAPP_ASSERT_AND_RUN_COMMAND(packet.isPacketOfType(DNS), readerDev.close(), "Packet isn't of type DNS");

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
				if (answer->getDataAsString() == "fe80::5a1f:aaff:fe4f:3f9d")
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
				if (auth->getDataAsString() == "10.0.0.2")
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

    PCAPP_ASSERT(dnsPackets == 464, "Number of DNS packets different than expected. Found: %d; Expected: 464", dnsPackets);

    // wireshark filter: dns.count.queries > 0
    PCAPP_ASSERT(packetsContainingDnsQuery == 450, "DNS query count different than expected. Found: %d; Expected: 450", packetsContainingDnsQuery);
    // wireshark filter: dns.count.answers > 0
    PCAPP_ASSERT(packetsContainingDnsAnswer == 224, "DNS answer count different than expected. Found: %d; Expected: 224", packetsContainingDnsAnswer);
    // wireshark filter: dns.count.auth_rr > 0
    PCAPP_ASSERT(packetsContainingDnsAuthority == 11, "DNS authority count different than expected. Found: %d; Expected: 11", packetsContainingDnsAuthority);
    // wireshark filter: dns.count.add_rr > 0
    PCAPP_ASSERT(packetsContainingDnsAdditional == 23, "DNS additional record count different than expected. Found: %d; Expected: 23", packetsContainingDnsAdditional);

    // wireshark filter: dns.qry.name == www.google.com
    PCAPP_ASSERT(queriesWithNameGoogle == 14, "DNS queries with name 'www.google.com' different than expected. Found: %d; Expected: 14", queriesWithNameGoogle);
    // wireshark filter: dns.qry.name == aus3.mozilla.org
    PCAPP_ASSERT(queriesWithNameMozillaOrg == 2, "DNS queries with name 'aus3.mozilla.org' different than expected. Found: %d; Expected: 2", queriesWithNameMozillaOrg);
    // wireshark filter: dns.qry.type == 1
    PCAPP_ASSERT(queriesWithTypeA == 436, "DNS queries with type A different than expected. Found: %d; Expected: 436", queriesWithTypeA);
    // wireshark filter: dns.qry.type > 0 and not (dns.qry.type == 1)
    PCAPP_ASSERT(queriesWithTypeNotA == 14, "DNS queries with type not A different than expected. Found: %d; Expected: 14", queriesWithTypeNotA);
    // wireshark filter: dns.qry.class == 1
    PCAPP_ASSERT(queriesWithClassIN == 450, "DNS queries with class IN different than expected. Found: %d; Expected: 450", queriesWithClassIN);

    // wireshark filter: dns.count.answers > 0 and dns.resp.type == 12
    PCAPP_ASSERT(answersWithTypePTR == 14, "DNS answers with type PTR different than expected. Found: %d; Expected: 14", answersWithTypePTR);
    // wireshark filter: dns.count.answers > 0 and dns.resp.type == 5
    PCAPP_ASSERT(answersWithTypeCNAME == 90, "DNS answers with type CNAME different than expected. Found: %d; Expected: 90", answersWithTypeCNAME);
    // wireshark filter: dns.count.answers > 0 and dns.resp.name == www.google-analytics.com
    PCAPP_ASSERT(answersWithNameGoogleAnalytics == 7, "DNS answers with name 'www.google-analytics.com' different than expected. Found: %d; Expected: 7", answersWithNameGoogleAnalytics);
    // wireshark filter: dns.count.answers > 0 and dns.aaaa == fe80::5a1f:aaff:fe4f:3f9d
    PCAPP_ASSERT(answersWithDataCertainIPv6 == 12, "DNS answers with IPv6 data of 'fe80::5a1f:aaff:fe4f:3f9d' different than expected. Found: %d; Expected: 12", answersWithDataCertainIPv6);
    // wireshark filter: dns.count.answers > 0 and dns.resp.ttl < 30
    PCAPP_ASSERT(answersWithTtlLessThan30 == 17, "DNS answers with TTL less than 30 different than expected. Found: %d; Expected: 17", answersWithTtlLessThan30);

    // wireshark filter: dns.count.auth_rr > 0 and dns.resp.name == Yaels-iPhone.local
    PCAPP_ASSERT(authoritiesWithNameYaelPhone == 9, "DNS authorities with name 'Yaels-iPhone.local' different than expected. Found: %d; Expected: 9", authoritiesWithNameYaelPhone);
    // wireshark filter: dns.count.auth_rr > 0 and dns.a == 10.0.0.2
    PCAPP_ASSERT(authoritiesWithData10_0_0_2 == 9, "DNS authorities with IPv4 data of '10.0.0.2' different than expected. Found: %d; Expected: 9", authoritiesWithData10_0_0_2);

    // wireshark filter: dns.count.add_rr > 0 and dns.resp.name == "<Root>"
    PCAPP_ASSERT(additionalWithEmptyName == 23, "DNS additional records with empty name different than expected. Found: %d; Expected: 23", additionalWithEmptyName);
    // wireshark filter: dns.count.add_rr > 0 and dns.resp.name == D.9.F.3.F.4.E.F.F.F.A.A.F.1.A.5.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
    PCAPP_ASSERT(additionalWithLongUglyName == 12, "DNS additional records with long ugly name different than expected. Found: %d; Expected: 12", additionalWithLongUglyName);
    // wireshark filter: dns.count.add_rr > 0 and dns.resp.type == 47
    PCAPP_ASSERT(additionalWithTypeNSEC == 14, "DNS additional records with type NSEC different than expected. Found: %d; Expected: 14", additionalWithTypeNSEC);

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestDpdkDevice)
{
#ifdef USE_DPDK
	LoggerPP::getInstance().supressErrors();
	DpdkDeviceList& devList = DpdkDeviceList::getInstance();
	PCAPP_ASSERT(devList.getDpdkDeviceList().size() == 0, "DpdkDevices initialized before DPDK is initialized");
	LoggerPP::getInstance().enableErrors();

	if(devList.getDpdkDeviceList().size() == 0)
	{
		CoreMask coreMask = 0;
		for (int i = 0; i < getNumOfCores(); i++)
			coreMask |= SystemCores::IdToSystemCore[i].Mask;
		PCAPP_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}

	PCAPP_ASSERT(devList.getDpdkLogLevel() == LoggerPP::Normal, "DPDK log level is in Debug and should be on Normal");
	devList.setDpdkLogLevel(LoggerPP::Debug);
	PCAPP_ASSERT(devList.getDpdkLogLevel() == LoggerPP::Debug, "DPDK log level is in Normal and should be on Debug");
	devList.setDpdkLogLevel(LoggerPP::Normal);

	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(args.dpdkPort);
	PCAPP_ASSERT(dev != NULL, "DpdkDevice is NULL");

	PCAPP_ASSERT(dev->getMacAddress().isValid() == true, "Dev MAC addr isn't valid");
	PCAPP_ASSERT(dev->getMacAddress() != MacAddress::Zero, "Dev MAC addr is zero");
	PCAPP_ASSERT(dev->getTotalNumOfRxQueues() > 0, "Number of RX queues is zero");
	PCAPP_ASSERT(dev->getNumOfOpenedRxQueues() == 0, "Number of open RX queues isn't zero, it's %d", dev->getNumOfOpenedRxQueues());
	PCAPP_ASSERT(dev->getNumOfOpenedTxQueues() == 0, "Number of open TX queues isn't zero, it's %d", dev->getNumOfOpenedTxQueues());
	PCAPP_ASSERT(dev->getMtu() > 0, "Couldn't retrieve MTU");

	// Changing the MTU isn't supported for all PMDs so I can't use it in the unit-tests, as they may
	// fail on environment using such PMDs. I tested it on EM PMD and verified it works
//	uint16_t origMtu = dev->getMtu();
//	uint16_t newMtu = origMtu > 1600 ? 1500 : 9000;
//	PCAPP_ASSERT(dev->setMtu(newMtu) == true, "Couldn't set MTU to %d", newMtu);
//	PCAPP_ASSERT(dev->getMtu() == newMtu, "MTU isn't properly set");
//	PCAPP_ASSERT(dev->setMtu(origMtu) == true, "Couldn't set MTU back to original");

	PCAPP_ASSERT(dev->open() == true, "Cannot open DPDK device");
	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->open() == false, "Managed to open the device twice");
	LoggerPP::getInstance().enableErrors();
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedRxQueues() == 1, dev->close(), "More than 1 RX queues were opened");
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedTxQueues() == 1, dev->close(), "More than 1 TX queues were opened");
	DpdkDevice::LinkStatus linkStatus;
	dev->getLinkStatus(linkStatus);
	PCAPP_ASSERT_AND_RUN_COMMAND(linkStatus.linkUp == true, dev->close(), "Link is down");
	PCAPP_ASSERT_AND_RUN_COMMAND(linkStatus.linkSpeedMbps > 0, dev->close(), "Link speed is 0");

	DpdkPacketData packetData;
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData), dev->close(), "Could not start capturing on DpdkDevice[0]");
	PCAP_SLEEP(10);
	dev->stopCapture();

	PCAPP_DEBUG_PRINT("Thread ID: %d", packetData.ThreadId);
	PCAPP_DEBUG_PRINT("Total packets captured: %d", packetData.PacketCount);
	PCAPP_DEBUG_PRINT("Eth packets: %d", packetData.EthCount);
	PCAPP_DEBUG_PRINT("ARP packets: %d", packetData.ArpCount);
	PCAPP_DEBUG_PRINT("IPv4 packets: %d", packetData.Ip4Count);
	PCAPP_DEBUG_PRINT("IPv6 packets: %d", packetData.Ip6Count);
	PCAPP_DEBUG_PRINT("TCP packets: %d", packetData.TcpCount);
	PCAPP_DEBUG_PRINT("UDP packets: %d", packetData.UdpCount);
	PCAPP_DEBUG_PRINT("HTTP packets: %d", packetData.HttpCount);

	pcap_stat stats;
	stats.ps_recv = 0;
	stats.ps_drop = 0;
	stats.ps_ifdrop = 0;
	dev->getStatistics(stats);
	PCAPP_DEBUG_PRINT("Packets captured according to stats: %d", stats.ps_recv);
	PCAPP_DEBUG_PRINT("Packets dropped according to stats: %d", stats.ps_drop);

	PCAPP_ASSERT_AND_RUN_COMMAND(packetData.PacketCount > 0, dev->close(), "No packets were captured");
	PCAPP_ASSERT_AND_RUN_COMMAND(packetData.ThreadId != -1, dev->close(), "Couldn't retrieve thread ID");

	int statsVsPacketCount = stats.ps_recv > (uint32_t)packetData.PacketCount ? stats.ps_recv-(uint32_t)packetData.PacketCount : (uint32_t)packetData.PacketCount-stats.ps_recv;
	PCAPP_ASSERT_AND_RUN_COMMAND(statsVsPacketCount <= 20, dev->close(),
			"Stats received packet count (%d) is different than calculated packet count (%d)",
			stats.ps_recv,
			packetData.PacketCount);
	dev->close();
	dev->close();
#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestDpdkMultiThread)
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

		PCAPP_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(args.dpdkPort);
	PCAPP_ASSERT(dev != NULL, "DpdkDevice is NULL");

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
		PCAPP_ASSERT(dev->openMultiQueues(numOfRxQueuesToOpen+1, 1) == false, "Managed to open DPDK device with number of RX queues which isn't power of 2");
		LoggerPP::getInstance().enableErrors();
	}

	PCAPP_ASSERT_AND_RUN_COMMAND(dev->openMultiQueues(numOfRxQueuesToOpen, 1) == true, dev->close(), "Cannot open DPDK device '%s' with %d RX queues", dev->getDeviceName().c_str(), numOfRxQueuesToOpen);

	if (numOfRxQueuesToOpen > 1)
	{
		LoggerPP::getInstance().supressErrors();
		DpdkPacketData dummyPacketData;
		PCAPP_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &dummyPacketData) == false, dev->close(), "Managed to start capture on single thread although more than 1 RX queue is opened");
		LoggerPP::getInstance().enableErrors();
	}

	PCAPP_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedRxQueues() == numOfRxQueuesToOpen, dev->close(), "Num of opened RX queues is different from requested RX queues");
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->getNumOfOpenedTxQueues() == 1, dev->close(), "Num of opened TX queues is different than 1");

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

	PCAPP_ASSERT_AND_RUN_COMMAND(dev->startCaptureMultiThreads(dpdkPacketsArriveMultiThread, packetDataMultiThread, coreMask), dev->close(), "Cannot start capturing on multi threads");
	PCAP_SLEEP(20);
	dev->stopCapture();
	pcap_stat aggrStats;
	aggrStats.ps_recv = 0;
	aggrStats.ps_drop = 0;
	aggrStats.ps_ifdrop = 0;


	for (int i = 0; i < getNumOfCores(); i++)
	{
		if ((SystemCores::IdToSystemCore[i].Mask & coreMask) == 0)
			continue;

		PCAPP_DEBUG_PRINT("Thread ID: %d", packetDataMultiThread[i].ThreadId);
		PCAPP_DEBUG_PRINT("Total packets captured: %d", packetDataMultiThread[i].PacketCount);
		PCAPP_DEBUG_PRINT("Eth packets: %d", packetDataMultiThread[i].EthCount);
		PCAPP_DEBUG_PRINT("ARP packets: %d", packetDataMultiThread[i].ArpCount);
		PCAPP_DEBUG_PRINT("IPv4 packets: %d", packetDataMultiThread[i].Ip4Count);
		PCAPP_DEBUG_PRINT("IPv6 packets: %d", packetDataMultiThread[i].Ip6Count);
		PCAPP_DEBUG_PRINT("TCP packets: %d", packetDataMultiThread[i].TcpCount);
		PCAPP_DEBUG_PRINT("UDP packets: %d", packetDataMultiThread[i].UdpCount);
		aggrStats.ps_recv += packetDataMultiThread[i].PacketCount;
	}

	PCAPP_ASSERT_AND_RUN_COMMAND(aggrStats.ps_recv > 0, dev->close(), "No packets were captured on any thread");

	pcap_stat stats;
	dev->getStatistics(stats);
	PCAPP_DEBUG_PRINT("Packets captured according to stats: %d", stats.ps_recv);
	PCAPP_DEBUG_PRINT("Packets dropped according to stats: %d", stats.ps_drop);
	PCAPP_ASSERT_AND_RUN_COMMAND(stats.ps_recv >= aggrStats.ps_recv, dev->close(), "Statistics from device differ from aggregated statistics on all threads");
	PCAPP_ASSERT_AND_RUN_COMMAND(stats.ps_drop == 0, dev->close(), "Some packets were dropped");

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
			PCAPP_ASSERT(res.size() == 0, "%d flows appear in core %d and core %d", (int)res.size(), firstCoreId, secondCoreId);
			if (PCAPP_IS_UNIT_TEST_DEBUG_ENABLED)
			{
				for (map<uint32_t, pair<RawPacketVector, RawPacketVector> >::iterator iter = res.begin(); iter != res.end(); iter++)
				{
					PCAPP_DEBUG_PRINT("Same flow exists in core %d and core %d. Flow key = %X", firstCoreId, secondCoreId, iter->first);
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
		PCAPP_DEBUG_PRINT("Core %d\n========", firstCoreId);
		PCAPP_DEBUG_PRINT("Total flows: %d", (int)packetDataMultiThread[firstCoreId].FlowKeys.size());

		if (PCAPP_IS_UNIT_TEST_DEBUG_ENABLED)
		{
			for(map<uint32_t, RawPacketVector>::iterator iter = packetDataMultiThread[firstCoreId].FlowKeys.begin(); iter != packetDataMultiThread[firstCoreId].FlowKeys.end(); iter++) {
				PCAPP_DEBUG_PRINT("Key=%X; Value=%d", (int)iter->first, (int)iter->second.size());
				iter->second.clear();
			}
		}

		packetDataMultiThread[firstCoreId].FlowKeys.clear();
	}



	dev->close();
#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestDpdkDeviceSendPackets)
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

		PCAPP_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(args.dpdkPort);
	PCAPP_ASSERT(dev != NULL, "DpdkDevice is NULL");


	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->openMultiQueues(1, 255) == false, "Managed to open a DPDK device with 255 TX queues");
	LoggerPP::getInstance().enableErrors();

	DpdkDevice::DpdkDeviceConfiguration customConfig(128, 1024);
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->openMultiQueues(1, dev->getTotalNumOfTxQueues(), customConfig) == true, dev->close(), "Cannot open DPDK device '%s' with %d TX queues", dev->getDeviceName().c_str(), dev->getTotalNumOfTxQueues());

    PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_PATH);
    PCAPP_ASSERT(fileReaderDev.open(), "Cannot open file reader device");

    RawPacket rawPacketArr[10000];
    PointerVector<Packet> packetVec;
    RawPacketVector rawPacketVec;
    const Packet* packetArr[10000];
    int packetsRead = 0;
    while(fileReaderDev.getNextPacket(rawPacketArr[packetsRead]))
    {
    	packetVec.pushBack(new Packet(&rawPacketArr[packetsRead]));
    	rawPacketVec.pushBack(new RawPacket(rawPacketArr[packetsRead]));
      	packetsRead++;
    }

    //send packets as RawPacket array
    int freeMBufsBefore = dev->getAmountOfFreeMbufs();
    int packetsSentAsRaw = dev->sendPackets(rawPacketArr, packetsRead);
    int freeMBufsAfter = dev->getAmountOfFreeMbufs();
    PCAPP_ASSERT(freeMBufsBefore == freeMBufsAfter, "MBuf leakage happened in sending RawPacket array");

    //send packets as parsed EthPacekt array
    std::copy(packetVec.begin(), packetVec.end(), packetArr);
    freeMBufsBefore = dev->getAmountOfFreeMbufs();
    int packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead);
    freeMBufsAfter = dev->getAmountOfFreeMbufs();
    PCAPP_ASSERT(freeMBufsBefore == freeMBufsAfter, "MBuf leakage happened in sending EthPacekt array");

    //send packets are RawPacketVector
    freeMBufsBefore = dev->getAmountOfFreeMbufs();
    int packetsSentAsRawVector = dev->sendPackets(rawPacketVec);
    freeMBufsAfter = dev->getAmountOfFreeMbufs();
    PCAPP_ASSERT(freeMBufsBefore == freeMBufsAfter, "MBuf leakage happened in sending RawPacketVector");

    PCAPP_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRaw);
    PCAPP_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsParsed);
    PCAPP_ASSERT(packetsSentAsRawVector == packetsRead, "Not all packets were sent as raw vector. Expected (read from file): %d; Sent: %d", packetsRead, packetsSentAsRawVector);

    if (dev->getTotalNumOfTxQueues() > 1)
    {
        packetsSentAsRaw = dev->sendPackets(rawPacketArr, packetsRead, dev->getTotalNumOfTxQueues()-1);
        packetsSentAsParsed = dev->sendPackets(packetArr, packetsRead, dev->getTotalNumOfTxQueues()-1);
        packetsSentAsRawVector = dev->sendPackets(rawPacketVec, dev->getTotalNumOfTxQueues()-1);
        PCAPP_ASSERT(packetsSentAsRaw == packetsRead, "Not all packets were sent as raw to TX queue %d. Expected (read from file): %d; Sent: %d",
        		dev->getTotalNumOfTxQueues()-1, packetsRead, packetsSentAsRaw);
        PCAPP_ASSERT(packetsSentAsParsed == packetsRead, "Not all packets were sent as parsed to TX queue %d. Expected (read from file): %d; Sent: %d",
        		dev->getTotalNumOfTxQueues()-1, packetsRead, packetsSentAsParsed);
        PCAPP_ASSERT(packetsSentAsRawVector == packetsRead, "Not all packets were sent as raw vector to TX queue %d. Expected (read from file): %d; Sent: %d",
        		dev->getTotalNumOfTxQueues()-1, packetsRead, packetsSentAsRawVector);

    }

    LoggerPP::getInstance().supressErrors();
    PCAPP_ASSERT(dev->sendPackets(rawPacketArr, packetsRead, dev->getTotalNumOfTxQueues()+1) == 0, "Managed to send packets on TX queue that doesn't exist");
    LoggerPP::getInstance().enableErrors();

    freeMBufsBefore = dev->getAmountOfFreeMbufs();
    PCAPP_ASSERT(dev->sendPacket(rawPacketArr[2000], 0) == true, "Couldn't send 1 raw packet");
    PCAPP_ASSERT(dev->sendPacket(*(packetArr[3000]), 0) == true, "Couldn't send 1 parsed packet");
    freeMBufsAfter = dev->getAmountOfFreeMbufs();
    PCAPP_ASSERT(freeMBufsBefore == freeMBufsAfter, "MBuf leakage happened in sending one packet");

    dev->close();
    fileReaderDev.close();
#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestDpdkDeviceWorkerThreads)
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
		PCAPP_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");

	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(args.dpdkPort);
	PCAPP_ASSERT(dev != NULL, "DpdkDevice is NULL");

	RawPacketVector rawPacketVec;
	MBufRawPacket* mBufRawPacketArr = NULL;
	int mBufRawPacketArrLen = 0;
	Packet* packetArr = NULL;
	int packetArrLen = 0;

	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(dev->receivePackets(rawPacketVec, 0) == false, "Managed to receive packets although device isn't opened");
	PCAPP_ASSERT(dev->receivePackets(&packetArr, packetArrLen, 0) == false, "Managed to receive packets although device isn't opened");
	PCAPP_ASSERT(dev->receivePackets(&mBufRawPacketArr, mBufRawPacketArrLen, 0) == false, "Managed to receive packets although device isn't opened");

	PCAPP_ASSERT(dev->open() == true, "Couldn't open DPDK device");
	PCAPP_ASSERT(dev->receivePackets(rawPacketVec, dev->getTotalNumOfRxQueues()+1) == false, "Managed to receive packets for RX queue that doesn't exist");
	PCAPP_ASSERT(dev->receivePackets(&packetArr, packetArrLen, dev->getTotalNumOfRxQueues()+1) == false, "Managed to receive packets for RX queue that doesn't exist");
	PCAPP_ASSERT(dev->receivePackets(&mBufRawPacketArr, mBufRawPacketArrLen, dev->getTotalNumOfRxQueues()+1) == false, "Managed to receive packets for RX queue that doesn't exist");

	{
		int myArraySize = 4 * 64; // 4 * RX_BURST_SIZE must be enough
		int newArraySize = myArraySize;
		MBufRawPacket* mBufRawPacketArrToReuse = new MBufRawPacket[myArraySize];
		MBufRawPacket* ptrCopy = mBufRawPacketArrToReuse;
		dev->receivePackets(&mBufRawPacketArrToReuse, newArraySize, 0, true);
		if (newArraySize)
		{
			bool integrity = true;
			for (size_t i = 0; i < (size_t)newArraySize; ++i)
			{
				integrity &= mBufRawPacketArrToReuse[i].isPacketSet();
			}
			PCAPP_ASSERT_AND_RUN_COMMAND(integrity == true,
				delete[] ptrCopy,
				"Some packets in reused MbufRawPacket array are not set but reported as if they are.");
		}
		else
		{
			PCAPP_ASSERT_AND_RUN_COMMAND(mBufRawPacketArrToReuse != NULL, 
				delete[] ptrCopy,
				"Memory leak have happened during reuse of MbufRawPacket array.");
		}
		delete[] ptrCopy;
	}

	DpdkPacketData packetData;
	PCAPP_ASSERT_AND_RUN_COMMAND(dev->startCaptureSingleThread(dpdkPacketsArrive, &packetData), dev->close(), "Could not start capturing on DpdkDevice");
	PCAPP_ASSERT(dev->receivePackets(rawPacketVec, 0) == false, "Managed to receive packets although device is in capture mode");
	PCAPP_ASSERT(dev->receivePackets(&packetArr, packetArrLen, 0) == false, "Managed to receive packets although device is in capture mode");
	PCAPP_ASSERT(dev->receivePackets(&mBufRawPacketArr, mBufRawPacketArrLen, 0) == false, "Managed to receive packets although device is in capture mode");
	LoggerPP::getInstance().enableErrors();
	dev->stopCapture();
	dev->close();
	
	PCAPP_ASSERT(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()) == true, "Cannot open DPDK device");

	int numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		PCAPP_ASSERT(dev->receivePackets(rawPacketVec, 0) == true, "Couldn't receive packets");
		PCAP_SLEEP(1);
		if (rawPacketVec.size() > 0)
			break;
		numOfAttempts++;
	}

	PCAPP_ASSERT(numOfAttempts < 10, "No packets were received using RawPacketVector");
	PCAPP_DEBUG_PRINT("Captured %d packets in %d attempts using RawPacketVector", (int)rawPacketVec.size(), numOfAttempts);

	numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		PCAPP_ASSERT(dev->receivePackets(&mBufRawPacketArr, mBufRawPacketArrLen, 0) == true, "Couldn't receive packets");
		PCAP_SLEEP(1);
		if (mBufRawPacketArrLen > 0 && mBufRawPacketArr != NULL)
			break;
		numOfAttempts++;
	}

	PCAPP_ASSERT(numOfAttempts < 10, "No packets were received using mBuf raw packet arr");
	PCAPP_DEBUG_PRINT("Captured %d packets in %d attempts using mBuf raw packet arr", mBufRawPacketArrLen, numOfAttempts);
	delete [] mBufRawPacketArr;

	numOfAttempts = 0;
	while (numOfAttempts < 10)
	{
		PCAPP_ASSERT(dev->receivePackets(&packetArr, packetArrLen, 0) == true, "Couldn't receive packets");
		PCAP_SLEEP(1);
		if (packetArrLen > 0 && packetArr != NULL)
			break;
		numOfAttempts++;
	}

	PCAPP_ASSERT(numOfAttempts < 10, "No packets were received using packet arr");
	PCAPP_DEBUG_PRINT("Captured %d packets in %d attempts using packet arr", packetArrLen, numOfAttempts);
	delete [] packetArr;

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
		PCAPP_DEBUG_PRINT("Assigning queue #%d to core %d", queueId, core.Id);
		newWorkerThread->init(dev, queueId, &queueMutexArr[queueId]);
		workerThreadVec.push_back((DpdkWorkerThread*)newWorkerThread);
		workerThreadCoreMask |= core.Mask;
	}
	PCAPP_DEBUG_PRINT("Initiating %d worker threads", (int)workerThreadVec.size());

	LoggerPP::getInstance().supressErrors();
	PCAPP_ASSERT(devList.startDpdkWorkerThreads(0, workerThreadVec) == false, "Managed to start DPDK worker thread with core mask 0");
	LoggerPP::getInstance().enableErrors();

	PCAPP_ASSERT(devList.startDpdkWorkerThreads(workerThreadCoreMask, workerThreadVec) == true, "Couldn't start DPDK worker threads");
	PCAPP_DEBUG_PRINT("Worker threads started");

	PCAP_SLEEP(10);

	PCAPP_DEBUG_PRINT("Worker threads stopping");
	devList.stopDpdkWorkerThreads();
	PCAPP_DEBUG_PRINT("Worker threads stopped");

	// we can't guarantee all threads receive packets, it depends on the NIC load balancing and the traffic. So we check that all threads were run and
	// that total amount of packets received by all threads is greater than zero

	int packetCount = 0;
	for (vector<DpdkWorkerThread*>::iterator iter = workerThreadVec.begin(); iter != workerThreadVec.end(); iter++)
	{
		DpdkTestWorkerThread* thread = (DpdkTestWorkerThread*)(*iter);
		PCAPP_ASSERT(thread->threadRanAndStopped() == true, "Thread on core %d didn't run", thread->getCoreId());
		packetCount += thread->getPacketCount();
		PCAPP_DEBUG_PRINT("Worker thread on core %d captured %d packets", thread->getCoreId(), thread->getPacketCount());
		delete thread;
	}

	for (int i = 0; i < numOfRxQueues; i++)
		pthread_mutex_destroy(&queueMutexArr[i]);


	PCAPP_DEBUG_PRINT("Total packet count for all worker threads: %d", packetCount);

	PCAPP_ASSERT(packetCount > 0, "No packet were captured on any of the worker threads");

	dev->close();

#endif
	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestDpdkMbufRawPacket)
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

		PCAPP_ASSERT(DpdkDeviceList::initDpdk(coreMask, 16383) == true, "Couldn't initialize DPDK with core mask %X", coreMask);
		PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	}
	PCAPP_ASSERT(devList.getDpdkDeviceList().size() > 0, "No DPDK devices");
	DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(args.dpdkPort);
	PCAPP_ASSERT(dev != NULL, "DpdkDevice is NULL");

	PCAPP_ASSERT(dev->openMultiQueues(dev->getTotalNumOfRxQueues(), dev->getTotalNumOfTxQueues()) == true, "Cannot open DPDK device");


	// Test load from PCAP to MBufRawPacket
	// ------------------------------------
	PcapFileReaderDevice reader(EXAMPLE2_PCAP_PATH);
	PCAPP_ASSERT(reader.open() == true, "Cannot open file '%s'", EXAMPLE2_PCAP_PATH);

	int tcpCount = 0;
	int udpCount = 0;
	int ip6Count = 0;
	int vlanCount = 0;
	int numOfPackets = 0;
	while (true)
	{
		MBufRawPacket mBufRawPacket;
		PCAPP_ASSERT(mBufRawPacket.init(dev) == true, "Couldn't init MBufRawPacket");
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

		PCAPP_ASSERT(dev->sendPacket(packet, 0) == true, "Couldn't send packet");
	}

	PCAPP_ASSERT(numOfPackets == 4709, "Wrong num of packets read. Expected 4709 got %d", numOfPackets);

	PCAPP_ASSERT(tcpCount == 4321, "TCP count doesn't match: expected %d, got %d", 4321, tcpCount);
	PCAPP_ASSERT(udpCount == 269, "UDP count doesn't match: expected %d, got %d", 269, udpCount);
	PCAPP_ASSERT(ip6Count == 16, "IPv6 count doesn't match: expected %d, got %d", 16, ip6Count);
	PCAPP_ASSERT(vlanCount == 24, "VLAN count doesn't match: expected %d, got %d", 24, vlanCount);

	reader.close();

	// Test save MBufRawPacket to PCAP
	// -------------------------------
	RawPacketVector rawPacketVec;
	int numOfAttempts = 0;
	while (numOfAttempts < 30)
	{
		bool foundTcpOrUdpPacket = false;
		for (int i = 0; i < dev->getNumOfOpenedRxQueues(); i++)
		{
			PCAPP_ASSERT(dev->receivePackets(rawPacketVec, 0) == true, "Couldn't receive packets");
			PCAP_SLEEP(1);
			for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
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

	PCAPP_ASSERT(numOfAttempts < 30, "No packets were received");

	PcapFileWriterDevice writer(DPDK_PCAP_WRITE_PATH);
	PCAPP_ASSERT(writer.open() == true, "Couldn't open pcap writer");
	PCAPP_ASSERT(writer.writePackets(rawPacketVec) == true, "Couldn't write raw packets to file");
	writer.close();

	PcapFileReaderDevice reader2(DPDK_PCAP_WRITE_PATH);
	PCAPP_ASSERT(reader2.open() == true, "Cannot open file '%s'", DPDK_PCAP_WRITE_PATH);
	RawPacket rawPacket;
	int readerPacketCount = 0;
	while (reader2.getNextPacket(rawPacket))
		readerPacketCount++;
	reader2.close();

	PCAPP_ASSERT(readerPacketCount == (int)rawPacketVec.size(), "Not all packets captures were written successfully to pcap file");

	// Test packet manipulation
	// ------------------------

	MBufRawPacket* rawPacketToManipulate = NULL;
	for (RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
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

	PCAPP_ASSERT(rawPacketToManipulate != NULL, "Couldn't find TCP or UDP packet to manipulate");
	int initialRawPacketLen = rawPacketToManipulate->getRawDataLen();
	Packet packetToManipulate(rawPacketToManipulate);
	IPv4Layer* ipLayer = packetToManipulate.getLayerOfType<IPv4Layer>();
	Layer* layerToDelete = ipLayer->getNextLayer();
	// remove all layers above IP
	while (layerToDelete != NULL)
	{
		Layer* nextLayer = layerToDelete->getNextLayer();
		PCAPP_ASSERT(packetToManipulate.removeLayer(layerToDelete) == true, "Couldn't remove layer");
		layerToDelete = nextLayer;
	}
	PCAPP_ASSERT(ipLayer->getNextLayer() == NULL, "Couldn't remove all layers after TCP");
	PCAPP_ASSERT(rawPacketToManipulate->getRawDataLen() < initialRawPacketLen, "Raw packet size wasn't changed after removing layers");

	// create DNS packet out of this packet

	UdpLayer udpLayer(2233, 53);
	PCAPP_ASSERT(packetToManipulate.addLayer(&udpLayer), "Failed to add UdpLayer");

	DnsLayer dnsQueryLayer;
	dnsQueryLayer.getDnsHeader()->recursionDesired = true;
	dnsQueryLayer.getDnsHeader()->transactionID = htons(0xb179);
	DnsQuery* newQuery = dnsQueryLayer.addQuery("no-name", DNS_TYPE_A, DNS_CLASS_IN);
	PCAPP_ASSERT(newQuery != NULL, "Couldn't add query for dns layer");

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
	     PCAPP_ASSERT(dev->sendPacket(packetToManipulate, 0) == true, "Couldn't send generated DNS packet #%d", i);
	}

	dev->close();

#endif
	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestGetMacAddress)
{
	PcapLiveDevice* liveDev = NULL;
	IPv4Address ipToSearch(args.ipToSendReceivePackets.c_str());
	liveDev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
    PCAPP_ASSERT(liveDev != NULL, "Device used in this test %s doesn't exist", args.ipToSendReceivePackets.c_str());
    PCAPP_ASSERT(liveDev->open(), "Cannot open live device");

    //fetch all IP addresses from arp table
    std::string ipsInArpTableAsString;
#ifdef WIN32
    ipsInArpTableAsString = executeShellCommand("arp -a | for /f \"tokens=1\" \%i in ('findstr dynamic') do @echo \%i");
    ipsInArpTableAsString.erase(std::remove(ipsInArpTableAsString.begin(), ipsInArpTableAsString.end(), ' '), ipsInArpTableAsString.end() ) ;
#else
    ipsInArpTableAsString = executeShellCommand("arp -a | awk '{print $2}' | sed 's/.$//; s/^.//'");
#endif

    PCAPP_ASSERT(ipsInArpTableAsString != "", "Couldn't find IP addresses in arp-table to compare the result to. Aborting");

    // iterate all IP addresses and arping each one until one of them answers
    MacAddress result = MacAddress::Zero;
    std::stringstream sstream(ipsInArpTableAsString);
    std::string ip;
    double time = -1;
    while (std::getline(sstream, ip, '\n'))
    {
    	IPv4Address ipAddr(ip);
    	PCAPP_ASSERT(ipAddr.isValid(), "Got non-valid ip from arp-table: '%s'", ip.c_str());
    	LoggerPP::getInstance().supressErrors();
    	result = NetworkUtils::getInstance().getMacAddress(ipAddr, liveDev, time);
    	LoggerPP::getInstance().enableErrors();
    	if (result != MacAddress::Zero)
    	{
    		PCAPP_ASSERT_AND_RUN_COMMAND(time >= 0, liveDev->close(), "Time is zero");
    		result = NetworkUtils::getInstance().getMacAddress(ipAddr, liveDev, time, liveDev->getMacAddress(), liveDev->getIPv4Address());
    		PCAPP_ASSERT_AND_RUN_COMMAND(result != MacAddress::Zero, liveDev->close(), "Arping with MAC address and IPv4 address failed");
    		break;
    	}
    }

    PCAPP_ASSERT_AND_RUN_COMMAND(result != MacAddress::Zero, liveDev->close(), "Arping to all IPs in arp-table failed");

    liveDev->close();

	PCAPP_TEST_PASSED;
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
		packet.removeLayer(layerToRemove);

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

PCAPP_TEST(TestTcpReassemblySanity)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv4Address expectedSrcIP(std::string("10.0.0.1"));
	IPv4Address expectedDstIP(std::string("81.218.72.15"));
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 10.0.0.1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 81.218.72.15");


	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestTcpReassemblyRetran)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 21, "Num of data packets isn't 21, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_retransmission_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestTcpReassemblyMissingData)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 17, "Num of data packets isn't 21, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";



	// test flow without SYN packet
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// remove SYN and SYN/ACK packets
	packetStream.erase(packetStream.begin());
	packetStream.erase(packetStream.begin());

	tcpReassemblyTest(packetStream, tcpReassemblyResults, false, true);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "Num of messages from side 1 isn't 2");

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestTcpReassemblyOutOfOrder)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "OOO test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 19, "OOO test: Num of data packets isn't 19, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "OOO test: Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "OOO test: Num of messages from side 1 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "OOO test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "OOO test: Connection ended with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "OOO test: Connection wasn't ended manually");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_out_of_order_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "OOO test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";



	// test out-of-order + missing data
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_tcp_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "OOO + missing data test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 18, "OOO + missing data test: Num of data packets isn't 18, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 2, "OOO + missing data test: Num of messages from side 0 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 2, "OOO + missing data test: Num of messages from side 1 isn't 2");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "OOO + missing data test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "OOO + missing data test: Connection ended with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "OOO + missing data test: Connection wasn't ended manually");

	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_tcp_stream_missing_data_output_ooo.txt"));

	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "OOO + missing data test: Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestTcpReassemblyWithFIN_RST)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData = "";

	// test fin packet in end of connection
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "FIN test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 5, "FIN test: Num of data packets isn't 5, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "FIN test: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "FIN test: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "FIN test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "FIN test: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "FIN test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "FIN test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	// test rst packet in end of connection
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_rst.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "RST test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 2, "RST test: Num of data packets isn't 2, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "RST test: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "RST test: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "RST test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "RST test: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "RST test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_rst_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "RST test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	//test fin packet in end of connection that has also data
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "FIN with data test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 6, "FIN with data test: Num of data packets isn't 6, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "FIN with data test: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "FIN with data test: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "FIN with data test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "FIN with data test: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "FIN with data test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "FIN with data test: Reassembly data different than expected");

	packetStream.clear();
	tcpReassemblyResults.clear();
	expectedReassemblyData = "";

	// test missing data before fin
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// move second packet of server->client message to the end of the message (after FIN)
	RawPacket oooPacketTemp = packetStream[6];
	packetStream.erase(packetStream.begin() + 6);
	packetStream.insert(packetStream.begin() + 12, oooPacketTemp);

	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, false);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Missing data before FIN test: Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 5, "Missing data before FIN test: Num of data packets isn't 5, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "Missing data before FIN test: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "Missing data before FIN test: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Missing data before FIN test: Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "Missing data before FIN test: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "Missing data before FIN test: Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output2.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Missing data before FIN test: Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestTcpReassemblyMalformedPkts)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	std::string expectedReassemblyData = "";

	// test retransmission with new data but payload doesn't really contain all the new data
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_http_stream_fin2.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// take one of the packets and increase the IPv4 total length field
	Packet malPacket(&packetStream.at(8));
	IPv4Layer* ipLayer = malPacket.getLayerOfType<IPv4Layer>();
	PCAPP_ASSERT(ipLayer != NULL, "Cannot find the IPv4 layer of the packet");
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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 6, "Num of data packets isn't 6, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 1, "Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 1, "Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connection wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == true, "Connection didn't end with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == false, "Connection wasn ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_http_stream_fin2_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestTcpReassemblyMultipleConns)
{
	TcpReassemblyMultipleConnStats results;
	std::string errMsg;
	std::string expectedReassemblyData = "";

	TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &results, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

	std::vector<RawPacket> packetStream;
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/three_http_streams.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	RawPacket finPacket1 = packetStream.at(13);
	RawPacket finPacket2 = packetStream.at(15);

	packetStream.erase(packetStream.begin() + 13);
	packetStream.erase(packetStream.begin() + 14);

	for (std::vector<RawPacket>::iterator iter = packetStream.begin(); iter != packetStream.end(); iter++)
	{
		Packet packet(&(*iter));
		tcpReassembly.reassemblePacket(packet);
	}

	PCAPP_ASSERT(results.size() == 3, "Num of connections isn't 3");

	TcpReassemblyMultipleConnStatsIter iter = results.begin();

	PCAPP_ASSERT(iter->second.numOfDataPackets == 2, "Conn #1: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #1: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #1: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #1: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == true, "Conn #1: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == false, "Conn #1: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_1_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #1: Reassembly data different than expected");

	iter++;

	PCAPP_ASSERT(iter->second.numOfDataPackets == 2, "Conn #2: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #2: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #2: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #2: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == true, "Conn #2: Connection didn't end with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == false, "Conn #2: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_2_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #2: Reassembly data different than expected");

	iter++;

	PCAPP_ASSERT(iter->second.numOfDataPackets == 2, "Conn #3: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #3: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #3: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #3: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == false, "Conn #3: Connections ended manually");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/three_http_streams_conn_3_output.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #3: Reassembly data different than expected");


	// test getConnectionInformation and isConnectionOpen

	const std::vector<ConnectionData> managedConnections = tcpReassembly.getConnectionInformation();
	PCAPP_ASSERT(managedConnections.size() == 3, "Size of managed connection list isn't 3");
	std::vector<ConnectionData>::const_iterator connIter = managedConnections.begin();
	PCAPP_ASSERT(tcpReassembly.isConnectionOpen(*connIter) > 0, "Connection #1 is closed");

	connIter++;
	PCAPP_ASSERT(tcpReassembly.isConnectionOpen(*connIter) == 0, "Connection #2 is still open");

	connIter++;
	PCAPP_ASSERT(tcpReassembly.isConnectionOpen(*connIter) == 0, "Connection #3 is still open");

	ConnectionData dummyConn;
	dummyConn.flowKey = 0x12345678;
	PCAPP_ASSERT(tcpReassembly.isConnectionOpen(dummyConn) < 0, "Dummy connection exists");


	// close flow manually and verify it's closed

	tcpReassembly.closeConnection(iter->first);
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended supposedly ended with FIN or RST although ended manually");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections still isn't ended even though ended manually");


	// now send FIN packets of conn 3 and verify they are igonred

	tcpReassembly.reassemblePacket(&finPacket1);
	tcpReassembly.reassemblePacket(&finPacket2);

	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended supposedly ended with FIN or RST after FIN packets sent although ended manually before");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections isn't ended after FIN packets sent even though ended manually before");

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestTcpReassemblyIPv6)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 10, "Num of data packets isn't 10, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 3, "Num of messages from side 0 isn't 3");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 3, "Num of messages from side 1 isn't 3");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP(std::string("2001:618:1:8000::5"));
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 2001:618:1:8000::5");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestTcpReassemblyIPv6MultConns)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;
	std::string expectedReassemblyData = "";

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/four_ipv6_http_streams.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	TcpReassemblyMultipleConnStats tcpReassemblyResults;
	tcpReassemblyTest(packetStream, tcpReassemblyResults, true, true);

	PCAPP_ASSERT(tcpReassemblyResults.size() == 4, "Num of connections isn't 4");

	TcpReassemblyMultipleConnStatsIter iter = tcpReassemblyResults.begin();

	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP1(std::string("2001:618:1:8000::5"));
	IPv6Address expectedDstIP2(std::string("2001:638:902:1:202:b3ff:feee:5dc2"));

	PCAPP_ASSERT(iter->second.numOfDataPackets == 14, "Conn #1: Num of data packets isn't 14, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 3, "Conn #1: Num of messages from side 0 isn't 3");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 3, "Conn #1: Num of messages from side 1 isn't 3");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #1: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #1: Connection ended with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #1: Connections wasn't ended manually");
	PCAPP_ASSERT(iter->second.connData.srcIP != NULL, "Conn #1: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.dstIP != NULL, "Conn #1: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #1: Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #1: Source IP isn't 2001:618:1:8000::5");
	PCAPP_ASSERT(iter->second.connData.srcPort == 35995, "Conn #1: source port isn't 35995");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream4.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #1: Reassembly data different than expected");

	iter++;

	PCAPP_ASSERT(iter->second.numOfDataPackets == 10, "Conn #2: Num of data packets isn't 10, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #2: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #2: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #2: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #2: Connection ended with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #2: Connections wasn't ended manually");
	PCAPP_ASSERT(iter->second.connData.srcIP != NULL, "Conn #2: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.dstIP != NULL, "Conn #2: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #2: Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #2: Source IP isn't 2001:618:1:8000::5");
	PCAPP_ASSERT(iter->second.connData.srcPort == 35999, "Conn #2: source port isn't 35999");

	iter++;

	PCAPP_ASSERT(iter->second.numOfDataPackets == 2, "Conn #3: Num of data packets isn't 2, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 1, "Conn #3: Num of messages from side 0 isn't 1");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 1, "Conn #3: Num of messages from side 1 isn't 1");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #3: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #3: Connection ended with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #3: Connections wasn't ended manually");
	PCAPP_ASSERT(iter->second.connData.srcIP != NULL, "Conn #3: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.dstIP != NULL, "Conn #3: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #3: Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP2), "Conn #3: Source IP isn't 2001:638:902:1:202:b3ff:feee:5dc2");
	PCAPP_ASSERT(iter->second.connData.srcPort == 40426, "Conn #3: source port isn't 40426");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream3.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #3: Reassembly data different than expected");

	iter++;

	PCAPP_ASSERT(iter->second.numOfDataPackets == 13, "Conn #4: Num of data packets isn't 13, it's %d", iter->second.numOfDataPackets);
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[0] == 4, "Conn #4: Num of messages from side 0 isn't 4");
	PCAPP_ASSERT(iter->second.numOfMessagesFromSide[1] == 4, "Conn #4: Num of messages from side 1 isn't 4");
	PCAPP_ASSERT(iter->second.connectionsStarted == true, "Conn #4: Connection wasn't opened");
	PCAPP_ASSERT(iter->second.connectionsEnded == false, "Conn #4: Connection ended with FIN or RST");
	PCAPP_ASSERT(iter->second.connectionsEndedManually == true, "Conn #4: Connections wasn't ended manually");
	PCAPP_ASSERT(iter->second.connData.srcIP != NULL, "Conn #4: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.dstIP != NULL, "Conn #4: Source IP is NULL");
	PCAPP_ASSERT(iter->second.connData.srcIP->equals(&expectedSrcIP), "Conn #4: Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(iter->second.connData.dstIP->equals(&expectedDstIP1), "Conn #4: Source IP isn't 2001:618:1:8000::5");
	PCAPP_ASSERT(iter->second.connData.srcPort == 35997, "Conn #4: source port isn't 35997");
	expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream2.txt"));
	PCAPP_ASSERT(expectedReassemblyData == iter->second.reassembledData, "Conn #4: Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestTcpReassemblyIPv6_OOO)
{
	std::string errMsg;
	std::vector<RawPacket> packetStream;

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/one_ipv6_http_stream.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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

	PCAPP_ASSERT(tcpReassemblyResults.size() == 1, "Num of connections isn't 1");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfDataPackets == 10, "Num of data packets isn't 10, it's %d", tcpReassemblyResults.begin()->second.numOfDataPackets);
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[0] == 3, "Num of messages from side 0 isn't 3");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.numOfMessagesFromSide[1] == 3, "Num of messages from side 1 isn't 3");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsStarted == true, "Connections wasn't opened");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEnded == false, "Connection was ended with FIN or RST");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connectionsEndedManually == true, "Connection wasn't ended manually");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP != NULL, "Source IP is NULL");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP != NULL, "Source IP is NULL");
	IPv6Address expectedSrcIP(std::string("2001:618:400::5199:cc70"));
	IPv6Address expectedDstIP(std::string("2001:618:1:8000::5"));
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.srcIP->equals(&expectedSrcIP), "Source IP isn't 2001:618:400::5199:cc70");
	PCAPP_ASSERT(tcpReassemblyResults.begin()->second.connData.dstIP->equals(&expectedDstIP), "Source IP isn't 2001:618:1:8000::5");

	std::string expectedReassemblyData = readFileIntoString(std::string("PcapExamples/one_ipv6_http_stream.txt"));
	PCAPP_ASSERT(expectedReassemblyData == tcpReassemblyResults.begin()->second.reassembledData, "Reassembly data different than expected");

	PCAPP_TEST_PASSED;
}


void savePacketToFile(RawPacket& packet, std::string fileName)
{
    PcapFileWriterDevice writerDev(fileName.c_str());
    writerDev.open();
    writerDev.writePacket(packet);
    writerDev.close();
}

PCAPP_TEST(TestIPFragmentationSanity)
{
	std::vector<RawPacket> packetStream;
	std::string errMsg;

	// basic IPv4 reassembly test
	// ==========================

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	IPReassembly ipReassembly;
	IPReassembly::ReassemblyStatus status;

	PCAPP_ASSERT(ipReassembly.getMaxCapacity() == PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE, "Max capacity isn't PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE");
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 0, "Capacity before reassembly isn't 0");

	Packet* result = NULL;

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4: First frag status isn't FIRST_FRAGMENT");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv4: Current capacity isn't 1");
		}
		else if (i < (packetStream.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "IPv4: Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4: Frag status isn't FRAGMENT");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv4: Current capacity isn't 1");
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "IPv4: Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv4: Last frag status isn't REASSEMBLED");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 0, "IPv4: Capacity after reassembly isn't 0");
		}
	}

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_reassembled.txt", bufferLength);

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "IPv4: Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv4: Reassembled packet data is different than expected");

	delete result;
	delete [] buffer;


	// basic IPv6 reassembly test
	// ==========================

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1Frags;

	PCAPP_ASSERT(reader.getNextPackets(packet1Frags, 7) == 7, "IPv6: Cannot read 7 frags of packet 1");

	reader.close();

	result = NULL;

	for (size_t i = 0; i < packet1Frags.size(); i++)
	{
		Packet packet(packet1Frags.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6: First frag status isn't FIRST_FRAGMENT");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv6: Current capacity isn't 1");
		}
		else if (i < (packet1Frags.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "IPv6: Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6: Frag status isn't FRAGMENT");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 1, "IPv6: Current capacity isn't 1");
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "IPv6: Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6: Last frag status isn't REASSEMBLED");
			PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 0, "IPv6: Capacity after reassembly isn't 0");
		}
	}

	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", bufferLength);

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "IPv6: Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv6: Reassembled packet data is different than expected");

	delete result;
	delete [] buffer;


	// non-fragment test
	// ==================

	packetStream.clear();
	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/VlanPackets.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	for (size_t i = 0; i < 20; i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PCAPP_ASSERT(result == &packet, "Non-fragment test: didn't get the same non-fragment packet in the result");
		PCAPP_ASSERT(status == IPReassembly::NON_FRAGMENT, "Non-fragment test: status isn't NON_FRAGMENT");
	}


	// non-IP test
	// ==================

	for (size_t i = 20; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);

		PCAPP_ASSERT(result == &packet, "Non-IP test: didn't get the same non-IP packet in the result");
		PCAPP_ASSERT(status == IPReassembly::NON_IP_PACKET, "Non-IP test: status isn't NON_IP_PACKET");
	}

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestIPFragOutOfOrder)
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

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	// swap first and second packet
	std::swap(packetStream[0], packetStream[1]);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i == 0)
		{
			PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "First frag status isn't OUT_OF_ORDER_FRAGMENT");
		}
		else if (i == 1)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Second frag status isn't FIRST_FRAGMENT");
		}
		else if (i < (packetStream.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag status isn't FRAGMENT");
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Second use-case: 6th and 10th fragments are swapped, as well as 3rd and 7th
	// ===========================================================================

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 0)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "First frag status isn't FIRST_FRAGMENT");
		}
		else if (i < (packetStream.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Third use-case: last fragment comes before the end
	// ==================================================

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	//swap 6th and last fragments
	std::swap(packetStream[5], packetStream[10]);

	for (size_t i = 0; i < packetStream.size(); i++)
	{
		Packet packet(&packetStream.at(i));
		result = ipReassembly.processPacket(&packet, status);
		if (i >= 5 && i < (packetStream.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 0)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "First frag status isn't FIRST_FRAGMENT");
		}
		else if (i < 5)
		{
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Fourth use-case: last fragment comes first
	// ==========================================

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else if (i == 1)
		{
			PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Frag#%d status isn't FIRST_FRAGMENT", (int)i);
		}
		else if (i > 1 && i < (packetStream.size()-1))
		{
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag#%d status isn't FRAGMENT, it's %d", (int)i, status);
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();


	// Fifth use-case: fragments come in reverse order
	// ===============================================

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

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
			PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #%d", (int)i);
			PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#%d status isn't OUT_OF_ORDER_FRAGMENT", (int)i);
		}
		else
		{
			PCAPP_ASSERT(result != NULL, "Didn't get reassembled packet on the last fragment");
			PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");
		}
	}

	PCAPP_ASSERT(bufferLength == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Reassembled packet data is different than expected");

	delete result;

	packetStream.clear();

	delete [] buffer;


	// Sixth use-case: IPv6: fragments 1 and 3 are swapped, as well as fragments 6 and 7
	// =================================================================================

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1Frags;

	PCAPP_ASSERT(reader.getNextPackets(packet1Frags, 7) == 7, "IPv6: Cannot read 7 frags of packet 1");

	reader.close();

	result = NULL;

	result = ipReassembly.processPacket(packet1Frags.at(2), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #3");
	PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#3 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(1), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #2");
	PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#2 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(0), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #1");
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "Frag#1 status isn't FIRST_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(3), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #4");
	PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag#4 status isn't FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(4), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #5");
	PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "Frag#5 status isn't FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(6), status);
	PCAPP_ASSERT(result == NULL, "Got reassembled packet too soon on fragment #7");
	PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Frag#7 status isn't OUT_OF_ORDER_FRAGMENT");
	result = ipReassembly.processPacket(packet1Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Last frag status isn't REASSEMBLED");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer2Length);

	// small fix for payload length which is wrong in the original packet
	result->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);

	PCAPP_ASSERT(buffer2Length == result->getRawPacket()->getRawDataLen(), "Reassembled packet len (%d) is different than read packet len (%d)", result->getRawPacket()->getRawDataLen(), buffer2Length);
	PCAPP_ASSERT(memcmp(result->getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Reassembled packet data is different than expected");

	delete result;

	delete [] buffer2;


	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestIPFragPartialData)
{
	std::vector<RawPacket> packetStream;
	std::string errMsg;

	IPReassembly ipReassembly;
	IPReassembly::ReassemblyStatus status;

	// IPv4 partial data
	// ~~~~~~~~~~~~~~~~~

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PcapExamples/frag_http_req_partial.txt", bufferLength);

	PCAPP_ASSERT(tcpReassemblyReadPcapIntoPacketVec("PcapExamples/frag_http_req.pcap", packetStream, errMsg) == true, "Error reading pcap file: %s", errMsg.c_str());

	for (size_t i = 0; i < 6; i++)
	{
		Packet packet(&packetStream.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	IPReassembly::IPv4PacketKey ip4Key(16991, IPv4Address(std::string("172.16.133.54")), IPv4Address(std::string("216.137.33.81")));
	Packet* partialPacket = ipReassembly.getCurrentPacket(ip4Key);

	PCAPP_ASSERT(partialPacket != NULL, "IPv4: Cannot retrieve partial packet");
	PCAPP_ASSERT(bufferLength == partialPacket->getRawPacket()->getRawDataLen(), "IPv4: Partial packet len (%d) is different than read packet len (%d)", partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv4: Partial packet data is different than expected");

	delete partialPacket;
	delete [] buffer;


	// IPv6 partial data
	// ~~~~~~~~~~~~~~~~~

	bufferLength = 0;
	buffer = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1_partial.txt", bufferLength);

	PcapFileReaderDevice reader("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

	RawPacketVector packet1PartialFrags;

	PCAPP_ASSERT(reader.getNextPackets(packet1PartialFrags, 5) == 5, "IPv6: Cannot read 5 first frags of packet 1");

	reader.close();

	for (size_t i = 0; i < 5; i++)
	{
		Packet packet(packet1PartialFrags.at(i));
		ipReassembly.processPacket(&packet, status);
	}

	IPReassembly::IPv6PacketKey ip6Key(0x2c5323, IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), IPv6Address(std::string("ff02::fb")));
	partialPacket = ipReassembly.getCurrentPacket(ip6Key);
	PCAPP_ASSERT(bufferLength == partialPacket->getRawPacket()->getRawDataLen(), "IPv6: Partial packet len (%d) is different than read packet len (%d)", partialPacket->getRawPacket()->getRawDataLen(), bufferLength);
	PCAPP_ASSERT(memcmp(partialPacket->getRawPacket()->getRawData(), buffer, bufferLength) == 0, "IPv6: Partial packet data is different than expected");

	PCAPP_ASSERT(partialPacket != NULL, "IPv6: Cannot retrieve partial packet");

	delete partialPacket;
	delete [] buffer;

	PCAPP_TEST_PASSED;
}

PCAPP_TEST(TestIPFragMultipleFrags)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

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


	PCAPP_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 6");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");

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
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet1 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet1 == NULL, "IPv4 Packet1 first frag - result isn't NULL");
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet2 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet2 == NULL, "IPv4 Packet2 first frag - result isn't NULL");
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet3 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet3 == NULL, "IPv4 Packet3 first frag - result isn't NULL");
	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet4 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 first frag - result isn't NULL");
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet6 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 first frag - result isn't NULL");
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv4 Packet8 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 first frag - result isn't NULL");
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet1 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 first frag - result isn't NULL");
	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet2 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 first frag - result isn't NULL");
	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet3 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip6Packet3 == NULL, "IPv6 Packet3 first frag - result isn't NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::FIRST_FRAGMENT, "IPv6 Packet4 first frag - status isn't FIRST_FRAGMENT");
	PCAPP_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 first frag - result isn't NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity after first fragment isn't 10");


	// read 2nd - 5th frag in each packet

	for (int i = 1; i < 5; i++)
	{
		ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet1 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet1 == NULL, "IPv4 Packet1 frag#%d - result isn't NULL", i);
		ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet2 == NULL, "IPv4 Packet2 frag#%d - result isn't NULL", i);
		ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet3 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet3 == NULL, "IPv4 Packet3 frag#%d - result isn't NULL", i);
		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 frag#%d - result isn't NULL", i);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet6 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 frag#%d - result isn't NULL", i);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet8 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 frag#%d - result isn't NULL", i);
		ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet1 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 frag#%d - result isn't NULL", i);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet3 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet3 == NULL, "IPv6 Packet3 frag#%d - result isn't NULL", i);
		ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 frag#%d - result isn't NULL", i);
	}

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity after 2nd-5th fragment isn't 10");


	// read 6th frag in IPv4 packets 1,2,3

	ip4Packet1 = ipReassembly.processPacket(ip4Packet1Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet1 frag#6 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet1 != NULL, "Packet1 frag#6 - result is NULL");
	ip4Packet2 = ipReassembly.processPacket(ip4Packet2Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet2 frag#6 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet2 != NULL, "Packet2 frag#6 - result is NULL");
	ip4Packet3 = ipReassembly.processPacket(ip4Packet3Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet3 frag#6 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet3 != NULL, "Packet3 frag#6 - result is NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 7, "Capacity after 6th fragment isn't 7");


	// read IPv4 packet5

	ip4Packet5 = ipReassembly.processPacket(ip4Packet5Vec.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet5 - status isn't NON_FRAGMENT");
	PCAPP_ASSERT(ip4Packet5 != NULL, "Packet5 - result is NULL");
	PCAPP_ASSERT(ip4Packet5->getRawPacket() == ip4Packet5Vec.at(0), "Packet5 - result ptr isn't equal to original packet ptr");


	// read 6th - 7th frag in IPv6 packets 1,4

	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet1 frag#6 - status isn't FRAGMENT");
	PCAPP_ASSERT(ip6Packet1 == NULL, "IPv6 Packet1 frag#6 - result isn't NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(5), status);
	PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#6 - status isn't FRAGMENT");
	PCAPP_ASSERT(ip6Packet4 == NULL, "IPv6 Packet4 frag#6 - result isn't NULL");
	ip6Packet1 = ipReassembly.processPacket(ip6Packet1Frags.at(6), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet1 frag#7 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip6Packet1 != NULL, "IPv6 Packet1 frag#7 - result is NULL");
	ip6Packet4 = ipReassembly.processPacket(ip6Packet4Frags.at(6), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet4 frag#7 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip6Packet4 != NULL, "IPv6 Packet4 frag#7 - result is NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 5, "Capacity after 6th fragment isn't 5");


	// read 6th - 9th frag in IPv4 packets 4,6,8 and IPv6 packet 2

	for (int i = 5; i < 9; i++)
	{
		ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet4 == NULL, "IPv4 Packet4 frag#%d - result isn't NULL", i);
		ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet6 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet6 == NULL, "IPv4 Packet6 frag#%d - result isn't NULL", i);
		ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv4 Packet8 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip4Packet8 == NULL, "IPv4 Packet8 frag#%d - result isn't NULL", i);
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
	}


	// read 6th - 9th frag in IPv6 packet 3

	for (int i = 5; i < 8; i++)
	{
		ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet4 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet3 == NULL, "IPv6 Packet4 frag#%d - result isn't NULL", i);
	}

	ip6Packet3 = ipReassembly.processPacket(ip6Packet3Frags.at(8), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet3 frag#9 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip6Packet3 != NULL, "IPv6 Packet3 frag#9 - result is NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 4, "Capacity after IPv6 packet 3 reassembly isn't 4");


	// read IPv4 packet7

	ip4Packet7 = ipReassembly.processPacket(ip4Packet7Vec.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet7 - status isn't NON_FRAGMENT");
	PCAPP_ASSERT(ip4Packet7 != NULL, "Packet7 - result is NULL");
	PCAPP_ASSERT(ip4Packet7->getRawPacket() == ip4Packet7Vec.at(0), "Packet7 - result ptr isn't equal to original packet ptr");


	// read 10th frag in IPv4 packets 4,6,8

	ip4Packet4 = ipReassembly.processPacket(ip4Packet4Frags.at(9), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet4 frag#10 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet4 != NULL, "Packet4 frag#10 - result is NULL");
	ip4Packet6 = ipReassembly.processPacket(ip4Packet6Frags.at(9), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet6 frag#10 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet6 != NULL, "Packet6 frag#10 - result is NULL");
	ip4Packet8 = ipReassembly.processPacket(ip4Packet8Frags.at(9), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "Packet8 frag#10 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip4Packet8 != NULL, "Packet8 frag#10 - result is NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 1, "Capacity after 10th fragment isn't 1");


	// read IPv4 packet 9

	ip4Packet9 = ipReassembly.processPacket(ip4Packet9Vec.at(0), status);
	PCAPP_ASSERT(status == IPReassembly::NON_FRAGMENT, "Packet9 - status isn't NON_FRAGMENT");
	PCAPP_ASSERT(ip4Packet9 != NULL, "Packet9 - result is NULL");
	PCAPP_ASSERT(ip4Packet9->getRawPacket() == ip4Packet9Vec.at(0), "Packet9 - result ptr isn't equal to original packet ptr");


	// read 11th frag in IPv4 packets 4,6 (duplicated last frag)

	PCAPP_ASSERT(ipReassembly.processPacket(ip4Packet4Frags.at(10), status) == NULL, "Packet4 frag#11 - result isn't NULL");
	PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Packet4 frag#11 - status isn't OUT_OF_ORDER_FRAGMENT");
	PCAPP_ASSERT(ipReassembly.processPacket(ip4Packet6Frags.at(10), status) == NULL, "Packet6 frag#11 - result isn't NULL");
	PCAPP_ASSERT(status == IPReassembly::OUT_OF_ORDER_FRAGMENT, "Packet6 frag#11 - status isn't OUT_OF_ORDER_FRAGMENT");


	// read 10th - 13th frag in IPv6 packet 2

	for (int i = 9; i < 12; i++)
	{
		ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(i), status);
		PCAPP_ASSERT(status == IPReassembly::FRAGMENT, "IPv6 Packet2 frag#%d - status isn't FRAGMENT", i+1);
		PCAPP_ASSERT(ip6Packet2 == NULL, "IPv6 Packet2 frag#%d - result isn't NULL", i);
	}

	ip6Packet2 = ipReassembly.processPacket(ip6Packet2Frags.at(12), status);
	PCAPP_ASSERT(status == IPReassembly::REASSEMBLED, "IPv6 Packet2 frag#13 - status isn't REASSEMBLED");
	PCAPP_ASSERT(ip6Packet2 != NULL, "IPv6 Packet2 frag#13 - result is NULL");

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 2, "Capacity after IPv6 packet 3 reassembly isn't 2");


	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet1.txt", buffer1Length);
	PCAPP_ASSERT(buffer1Length == ip4Packet1->getRawPacket()->getRawDataLen(), "IPv4 Packet1 len (%d) is different than read packet len (%d)", ip4Packet1->getRawPacket()->getRawDataLen(), buffer1Length);
	PCAPP_ASSERT(memcmp(ip4Packet1->getRawPacket()->getRawData(), buffer1, buffer1Length) == 0, "IPv4 packet1 data is different than expected");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet4.txt", buffer4Length);
	PCAPP_ASSERT(buffer4Length == ip4Packet4->getRawPacket()->getRawDataLen(), "IPv4 Packet4 len (%d) is different than read packet len (%d)", ip4Packet4->getRawPacket()->getRawDataLen(), buffer4Length);
	PCAPP_ASSERT(memcmp(ip4Packet4->getRawPacket()->getRawData(), buffer4, buffer4Length) == 0, "IPv4 packet4 data is different than expected");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PcapExamples/ip4_fragments_packet6.txt", buffer6Length);
	PCAPP_ASSERT(buffer6Length == ip4Packet6->getRawPacket()->getRawDataLen(), "IPv4 Packet6 len (%d) is different than read packet len (%d)", ip4Packet6->getRawPacket()->getRawDataLen(), buffer6Length);
	PCAPP_ASSERT(memcmp(ip4Packet6->getRawPacket()->getRawData(), buffer6, buffer6Length) == 0, "IPv4 packet6 data is different than expected");

	int buffer61Length = 0;
	uint8_t* buffer61 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet1.txt", buffer61Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet1->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(737);
	PCAPP_ASSERT(buffer61Length == ip6Packet1->getRawPacket()->getRawDataLen(), "IPv6 Packet1 len (%d) is different than read packet len (%d)", ip6Packet1->getRawPacket()->getRawDataLen(), buffer61Length);
	PCAPP_ASSERT(memcmp(ip6Packet1->getRawPacket()->getRawData(), buffer61, buffer61Length) == 0, "IPv6 packet1 data is different than expected");

	int buffer62Length = 0;
	uint8_t* buffer62 = readFileIntoBuffer("PcapExamples/ip6_fragments_packet2.txt", buffer62Length);
	// small fix for payload length which is wrong in the original packet
	ip6Packet2->getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength = htons(1448);
	PCAPP_ASSERT(buffer62Length == ip6Packet2->getRawPacket()->getRawDataLen(), "IPv6 Packet2 len (%d) is different than read packet len (%d)", ip6Packet2->getRawPacket()->getRawDataLen(), buffer62Length);
	PCAPP_ASSERT(memcmp(ip6Packet2->getRawPacket()->getRawData(), buffer62, buffer62Length) == 0, "IPv6 packet2 data is different than expected");


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

	PCAPP_TEST_PASSED;
}


void ipReassemblyOnFragmentsClean(const IPReassembly::PacketKey* key, void* userCookie)
{
	PointerVector<IPReassembly::PacketKey>* packetsRemoved = (PointerVector<IPReassembly::PacketKey>*)userCookie;
	packetsRemoved->pushBack(key->clone());
}

PCAPP_TEST(TestIPFragMapOverflow)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

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

	PCAPP_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 5");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");


	PointerVector<IPReassembly::PacketKey> packetsRemovedFromIPReassemblyEngine;

	IPReassembly ipReassembly(ipReassemblyOnFragmentsClean, &packetsRemovedFromIPReassemblyEngine, 3);

	PCAPP_ASSERT(ipReassembly.getMaxCapacity() == 3, "Max capacity isn't 3");
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 0, "Capacity before reassembly isn't 0");


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

	PCAPP_ASSERT(ipReassembly.getMaxCapacity() == 3, "Max capacity isn't 3");
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 3, "Capacity after reassembly isn't 3");

	PCAPP_ASSERT(packetsRemovedFromIPReassemblyEngine.size() == 5, "Number of packets that have been removed isn't 5, it's %d", (int)packetsRemovedFromIPReassemblyEngine.size());

	IPReassembly::IPv4PacketKey* ip4Key = NULL;
	IPReassembly::IPv6PacketKey* ip6Key = NULL;

	// 1st packet removed should be ip6Packet1Frags
	ip6Key = dynamic_cast<IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(0));
	PCAPP_ASSERT(ip6Key != NULL, "First packet removed isn't IPv6");
	PCAPP_ASSERT(ip6Key->getFragmentID() == 0x2c5323, "First packet removed fragment ID isn't 0x2c5323");
	PCAPP_ASSERT(ip6Key->getSrcIP() == IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), "First packet removed src IP isn't fe80::21f:f3ff:fecd:f617");
	PCAPP_ASSERT(ip6Key->getDstIP() == IPv6Address(std::string("ff02::fb")), "First packet removed dst IP isn't ff02::fb");

	// 2nd packet removed should be ip4Packet2Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(1));
	PCAPP_ASSERT(ip4Key != NULL, "Second packet removed isn't IPv4");
	PCAPP_ASSERT(ip4Key->getIpID() == 0x1ea1, "Second packet removed ID isn't 0x1ea1");
	PCAPP_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Second packet removed src IP isn't 10.118.213.212");
	PCAPP_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Second packet removed dst IP isn't 10.118.213.211");

	// 3rd packet removed should be ip4Packet3Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(2));
	PCAPP_ASSERT(ip4Key != NULL, "Third packet removed isn't IPv4");
	PCAPP_ASSERT(ip4Key->getIpID() == 0x1ea2, "Third packet removed ID isn't 0x1ea2");
	PCAPP_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Third packet removed src IP isn't 10.118.213.212");
	PCAPP_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Third packet removed dst IP isn't 10.118.213.211");

	// 4th packet removed should be ip6Packet2Frags
	ip6Key = dynamic_cast<IPReassembly::IPv6PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(3));
	PCAPP_ASSERT(ip6Key != NULL, "Fourth packet removed isn't IPv6");
	PCAPP_ASSERT(ip6Key->getFragmentID() == 0x98d687d1, "Fourth packet removed fragment ID isn't 0x98d687d1");
	PCAPP_ASSERT(ip6Key->getSrcIP() == IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")), "Fourth packet removed src IP isn't fe80::21f:f3ff:fecd:f617");
	PCAPP_ASSERT(ip6Key->getDstIP() == IPv6Address(std::string("ff02::fb")), "Fourth packet removed dst IP isn't ff02::fb");

	// 5th packet removed should be ip4Packet4Frags
	ip4Key = dynamic_cast<IPReassembly::IPv4PacketKey*>(packetsRemovedFromIPReassemblyEngine.at(4));
	PCAPP_ASSERT(ip4Key != NULL, "Fifth packet removed isn't IPv4");
	PCAPP_ASSERT(ip4Key->getIpID() == 0x1ea3, "Fifth packet removed ID isn't 0x1ea3");
	PCAPP_ASSERT(ip4Key->getSrcIP() == IPv4Address(std::string("10.118.213.212")), "Fifth packet removed src IP isn't 10.118.213.212");
	PCAPP_ASSERT(ip4Key->getDstIP() == IPv4Address(std::string("10.118.213.211")), "Fifth packet removed dst IP isn't 10.118.213.211");

	PCAPP_TEST_PASSED;
}


PCAPP_TEST(TestIPFragRemove)
{
	PcapFileReaderDevice reader("PcapExamples/ip4_fragments.pcap");
	PCAPP_ASSERT(reader.open(), "Cannot open file PcapExamples/ip4_fragments.pcap");

	PcapFileReaderDevice reader2("PcapExamples/ip6_fragments.pcap");
	PCAPP_ASSERT(reader2.open(), "Cannot open file PcapExamples/ip6_fragments.pcap");

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

	PCAPP_ASSERT(reader.getNextPackets(ip4Packet1Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 1");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet2Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 2");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet3Frags, 6) == 6, "Cannot read 6 frags of IPv4 packet 3");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet5Vec, 1) == 1, "Cannot read IPv4 packet 5");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet4Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 4");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 10) == 10, "Cannot read 10 frags of IPv4 packet 5");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet7Vec, 1) == 1, "Cannot read IPv4 packet 7");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet6Frags, 1) == 1, "Cannot read last (11th) frag of IPv4 packet 6");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 8) == 8, "Cannot read 8 frags of IPv4 packet 8");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet9Vec, 1) == 1, "Cannot read IPv4 packet 9");
	PCAPP_ASSERT(reader.getNextPackets(ip4Packet8Frags, 2) == 2, "Cannot read last 2 frags of IPv4 packet 8");

	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet1Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 1");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet2Frags, 13) == 13, "Cannot read 13 frags of IPv6 packet 2");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet3Frags, 9) == 9, "Cannot read 9 frags of IPv6 packet 3");
	PCAPP_ASSERT(reader2.getNextPackets(ip6Packet4Frags, 7) == 7, "Cannot read 7 frags of IPv6 packet 4");

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

	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 10, "Capacity before delete isn't 10");

	IPReassembly::IPv4PacketKey ip4Key;
	ip4Key.setSrcIP(IPv4Address(std::string("10.118.213.212")));
	ip4Key.setDstIP(IPv4Address(std::string("10.118.213.211")));

	ip4Key.setIpID(0x1ea0);
	ipReassembly.removePacket(ip4Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 9, "Capacity after 1st delete isn't 9");

	ip4Key.setIpID(0x1ea5);
	ipReassembly.removePacket(ip4Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 8, "Capacity after 2nd delete isn't 8");

	// IPv4 key doesn't exist
	ip4Key.setIpID(0x1ea9);
	ipReassembly.removePacket(ip4Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 8, "Capacity after delete with non-existing IPv4 packet isn't 8");

	ip4Key.setIpID(0x1ea4);
	ipReassembly.removePacket(ip4Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 7, "Capacity after 3rd delete isn't 7");

	IPReassembly::IPv6PacketKey ip6Key;
	ip6Key.setSrcIP(IPv6Address(std::string("fe80::21f:f3ff:fecd:f617")));
	ip6Key.setDstIP(IPv6Address(std::string("ff02::fb")));

	ip6Key.setFragmentID(0x98d687d1);
	ipReassembly.removePacket(ip6Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after 4th delete isn't 6");

	// IPv6 key doesn't exist
	ip6Key.setFragmentID(0xaaaaaaaa);
	ipReassembly.removePacket(ip6Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after delete with non-existing IPv6 packet isn't 6");

	ip6Key.setFragmentID(0x2c5323);
	ipReassembly.removePacket(ip6Key);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 5, "Capacity after 5th delete isn't 5");

	ipReassembly.processPacket(ip4Packet8Frags.at(0), status);
	PCAPP_ASSERT(ipReassembly.getCurrentCapacity() == 6, "Capacity after delete and 1st add isn't 6");

	PCAPP_TEST_PASSED;
}


static struct option PcapTestOptions[] =
{
	{"debug-mode", no_argument, 0, 'd'},
	{"use-ip",  required_argument, 0, 'i'},
	{"remote-ip", required_argument, 0, 'r'},
	{"remote-port", required_argument, 0, 'p'},
	{"dpdk-port", required_argument, 0, 'k' },
	{"no-networking", no_argument, 0, 'n' },
    {0, 0, 0, 0}
};

void print_usage() 
{
    printf("Usage: Pcap++Test -i ip_to_use | -n [-d] [-r ip_addr] [-p port] [-k dpdk_port]\n\n"
    		"Flags:\n"
    		"-i --use-ip         IP to use for sending and receiving packets\n"
    		"-d --debug-mode     Set log level to DEBUG\n"
    		"-r --remote-ip	     IP of remote machine running rpcapd to test remote capture\n"
    		"-p --remote-port    Port of remote machine running rpcapd to test remote capture\n"
    		"-k --dpdk-port      The DPDK NIC port to test. Required if compiling with DPDK\n"
    		"-n --no-networking  Do not run tests that requires networking\n"
    		);
}

int main(int argc, char* argv[])
{
	start_leak_check();
	PcapTestArgs args;
	args.ipToSendReceivePackets = "";
	args.debugMode = false;
	args.dpdkPort = -1;
	args.runWithNetworking = true;

	int optionIndex = 0;
	char opt = 0;
	while((opt = getopt_long (argc, argv, "di:r:p:k:n", PcapTestOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				args.ipToSendReceivePackets = optarg;
				break;
			case 'd':
				args.debugMode = true;
				break;
			case 'r':
				args.remoteIp = optarg;
				break;
			case 'p':
				args.remotePort = (uint16_t)atoi(optarg);
				break;
			case 'k':
				args.dpdkPort = (int)atoi(optarg);
				break;
			case 'n':
				args.runWithNetworking = false;
				break;
			default:
				print_usage();
				exit(1);
		}
	}

	if(args.runWithNetworking && args.ipToSendReceivePackets == "")
	{
		print_usage();
		exit(1);
	}
#ifdef USE_DPDK
	if (args.dpdkPort == -1)
	{
		printf("When testing with DPDK you must supply the DPDK NIC port to test\n\n");
		print_usage();
		exit(1);
	}
#endif

	if (args.debugMode)
		LoggerPP::getInstance().setAllModlesToLogLevel(LoggerPP::Debug);

	printf("PcapPlusPlus version: %s\n", getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Git info: %s\n", getGitInfo().c_str());
	printf("Using ip: %s\n", args.ipToSendReceivePackets.c_str());
	printf("Debug mode: %s\n", args.debugMode ? "on" : "off");
	printf("Starting tests...\n");

	char errString[1000];
	//LoggerPP::getInstance().setErrorString(errString, 1000);
	args.errString = errString;

	PCAPP_START_RUNNING_TESTS(args.runWithNetworking);

	PCAPP_RUN_TEST(TestIPAddress, args, false);
	PCAPP_RUN_TEST(TestMacAddress, args, false);
	PCAPP_RUN_TEST(TestPcapFileReadWrite, args, false);
	PCAPP_RUN_TEST(TestPcapSllFileReadWrite, args, false);
	PCAPP_RUN_TEST(TestPcapRawIPFileReadWrite, args, false);
	PCAPP_RUN_TEST(TestPcapFileAppend, args, false);
	PCAPP_RUN_TEST(TestPcapNgFileReadWrite, args, false);
	PCAPP_RUN_TEST(TestPcapNgFileReadWriteAdv, args, false);
	PCAPP_RUN_TEST(TestPcapLiveDeviceList, args, false);
	PCAPP_RUN_TEST(TestPcapLiveDeviceListSearch, args, true);
	PCAPP_RUN_TEST(TestPcapLiveDevice, args, true);
	PCAPP_RUN_TEST(TestPcapLiveDeviceNoNetworking, args, false);
	PCAPP_RUN_TEST(TestPcapLiveDeviceStatsMode, args, true);
	PCAPP_RUN_TEST(TestPcapLiveDeviceBlockingMode, args, true);
	PCAPP_RUN_TEST(TestWinPcapLiveDevice, args, true);
	PCAPP_RUN_TEST(TestPcapFilters, args, true);
	PCAPP_RUN_TEST(TestSendPacket, args, true);
	PCAPP_RUN_TEST(TestSendPackets, args, true);
	PCAPP_RUN_TEST(TestRemoteCapture, args, true);
	PCAPP_RUN_TEST(TestHttpRequestParsing, args, false);
	PCAPP_RUN_TEST(TestHttpResponseParsing, args, false);
	PCAPP_RUN_TEST(TestPrintPacketAndLayers, args, false);
	PCAPP_RUN_TEST(TestPfRingDevice, args, true);
	PCAPP_RUN_TEST(TestPfRingDeviceSingleChannel, args, true);
	PCAPP_RUN_TEST(TestPfRingMultiThreadAllCores, args, true);
	PCAPP_RUN_TEST(TestPfRingMultiThreadSomeCores, args, true);
	PCAPP_RUN_TEST(TestPfRingSendPacket, args, true);
	PCAPP_RUN_TEST(TestPfRingSendPackets, args, true);
	PCAPP_RUN_TEST(TestPfRingFilters, args, true);
	PCAPP_RUN_TEST(TestDnsParsing, args, false);
	PCAPP_RUN_TEST(TestDpdkDevice, args, true);
	PCAPP_RUN_TEST(TestDpdkMultiThread, args, true);
	PCAPP_RUN_TEST(TestDpdkDeviceSendPackets, args, true);
	PCAPP_RUN_TEST(TestDpdkMbufRawPacket, args, true);
	PCAPP_RUN_TEST(TestDpdkDeviceWorkerThreads, args, true);
	PCAPP_RUN_TEST(TestGetMacAddress, args, true);
	PCAPP_RUN_TEST(TestTcpReassemblySanity, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyRetran, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyMissingData, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyOutOfOrder, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyWithFIN_RST, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyMalformedPkts, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyMultipleConns, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyIPv6, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyIPv6MultConns, args, false);
	PCAPP_RUN_TEST(TestTcpReassemblyIPv6_OOO, args, false);
	PCAPP_RUN_TEST(TestIPFragmentationSanity, args, false);
	PCAPP_RUN_TEST(TestIPFragOutOfOrder, args, false);
	PCAPP_RUN_TEST(TestIPFragPartialData, args, false);
	PCAPP_RUN_TEST(TestIPFragMultipleFrags, args, false);
	PCAPP_RUN_TEST(TestIPFragMapOverflow, args, false);
	PCAPP_RUN_TEST(TestIPFragRemove, args, false);

	PCAPP_END_RUNNING_TESTS;
}
