#include "../TestDefinition.h"
#include "../Common/PcapFileNamesDef.h"
#include "../Common/GlobalTestArgs.h"
#include "Logger.h"
#include "Packet.h"
#include "RawSocketDevice.h"
#include "PcapFileDevice.h"

extern PcapTestArgs PcapTestGlobalArgs;

PTF_TEST_CASE(TestRawSockets)
{
	pcpp::IPAddress ipAddr = pcpp::IPAddress(PcapTestGlobalArgs.ipToSendReceivePackets);
	pcpp::RawSocketDevice rawSock(ipAddr);

#if defined(_WIN32)
	pcpp::ProtocolType protocol = (ipAddr.getType() == pcpp::IPAddress::IPv4AddressType ? pcpp::IPv4 : pcpp::IPv6);
	bool sendSupported = false;
#elif defined(__linux__)
	pcpp::ProtocolType protocol = pcpp::Ethernet;
	bool sendSupported = true;
#else
	pcpp::ProtocolType protocol = pcpp::Ethernet;
	bool sendSupported = false;
	{
		pcpp::Logger::getInstance().suppressLogs();
		pcpp::RawPacket rawPacket;
		PTF_ASSERT_FALSE(rawSock.open());
		PTF_ASSERT_EQUAL(rawSock.receivePacket(rawPacket, true, 20), pcpp::RawSocketDevice::RecvError, enum);
		PTF_ASSERT_FALSE(rawSock.sendPacket(&rawPacket));
		pcpp::Logger::getInstance().enableLogs();
	}

	PTF_TEST_CASE_PASSED;

#endif

	PTF_ASSERT_TRUE(rawSock.open());

	// receive single packet
	for (int i = 0; i < 4; i++)
	{
		pcpp::RawPacket rawPacket;
		PTF_ASSERT_EQUAL(rawSock.receivePacket(rawPacket, true, 20), pcpp::RawSocketDevice::RecvSuccess, enum);
		pcpp::Packet parsedPacket(&rawPacket);
		PTF_ASSERT_TRUE(parsedPacket.isPacketOfType(protocol));
	}

	// receive multiple packets
	pcpp::RawPacketVector packetVec;
	int failedRecv = 0;
	for (int i = 0; i < 10; i++)
	{
		rawSock.receivePackets(packetVec, 2, failedRecv);
		if (packetVec.size() > 0)
		{
			PTF_PRINT_VERBOSE("Total wait time: " << 2 * i);
			break;
		}
	}

	PTF_ASSERT_GREATER_THAN(packetVec.size(), 0);
	for (pcpp::RawPacketVector::VectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		pcpp::Packet parsedPacket(*iter);
		PTF_ASSERT_TRUE(parsedPacket.isPacketOfType(protocol));
	}

	// receive with timeout
	pcpp::RawSocketDevice::RecvPacketResult res = pcpp::RawSocketDevice::RecvSuccess;
	for (int i = 0; i < 30; i++)
	{
		pcpp::RawPacket rawPacket;
		res = rawSock.receivePacket(rawPacket, true, 1);
		if (res == pcpp::RawSocketDevice::RecvTimeout)
		{
			PTF_PRINT_VERBOSE("Total time until got RecvTimeout: " << i);
			break;
		}
	}
	PTF_NON_CRITICAL_EQUAL(res, pcpp::RawSocketDevice::RecvTimeout, enum);

	// receive non-blocking
	res = pcpp::RawSocketDevice::RecvSuccess;
	for (int i = 0; i < 30; i++)
	{
		pcpp::RawPacket rawPacket;
		res = rawSock.receivePacket(rawPacket, false, -1);
		if (res == pcpp::RawSocketDevice::RecvWouldBlock)
		{
			PTF_PRINT_VERBOSE("Total iterations until got RecvWouldBlock: " << i);
			break;
		}
	}
	PTF_NON_CRITICAL_EQUAL(res, pcpp::RawSocketDevice::RecvWouldBlock, enum);

	// close and reopen sockets, verify can't send and receive while closed
	rawSock.close();
	pcpp::RawPacket tempPacket;
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_EQUAL(rawSock.receivePacket(tempPacket, true, 2), pcpp::RawSocketDevice::RecvError, enum);
	PTF_ASSERT_FALSE(rawSock.sendPacket(packetVec.at(0)));
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(rawSock.open());

	// open another socket on the same interface
	pcpp::RawSocketDevice rawSock2(ipAddr);
	PTF_ASSERT_TRUE(rawSock2.open());

	// receive packet on 2 sockets
	for (int i = 0; i < 3; i++)
	{
		pcpp::RawPacket rawPacket;
		PTF_ASSERT_EQUAL(rawSock.receivePacket(rawPacket, true, 20), pcpp::RawSocketDevice::RecvSuccess, enum);
		pcpp::Packet parsedPacket(&rawPacket);
		PTF_ASSERT_TRUE(parsedPacket.isPacketOfType(protocol));
		pcpp::RawPacket rawPacket2;
		PTF_ASSERT_EQUAL(rawSock2.receivePacket(rawPacket2, true, 20), pcpp::RawSocketDevice::RecvSuccess, enum);
		pcpp::Packet parsedPacket2(&rawPacket2);
		PTF_ASSERT_TRUE(parsedPacket2.isPacketOfType(protocol));
	}

	if (sendSupported)
	{
		pcpp::PcapFileReaderDevice readerDev(EXAMPLE2_PCAP_PATH);
		PTF_ASSERT_TRUE(readerDev.open());
		packetVec.clear();

		// get 100 packets from file
		readerDev.getNextPackets(packetVec, 100);
		pcpp::RawPacketVector::VectorIterator iter = packetVec.begin();

		// send 100 single packets
		while (iter != packetVec.end())
		{
			// parse the packet first to make sure it can be sent, otherwise remove it from the list
			pcpp::Packet parsedPacket(*iter);
			if (!parsedPacket.isPacketOfType(protocol))
			{
				packetVec.erase(iter);
				continue;
			}

			PTF_ASSERT_TRUE(rawSock.sendPacket(*iter));
			PTF_ASSERT_TRUE(rawSock2.sendPacket(*iter));
			iter++;
		}

		// send multiple packets
		PTF_ASSERT_EQUAL(rawSock.sendPackets(packetVec), (int)packetVec.size());
	}
	else
	{
		// test send on unsupported platforms
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_FALSE(rawSock.sendPacket(packetVec.at(0)));
		PTF_ASSERT_FALSE(rawSock.sendPackets(packetVec));
		pcpp::Logger::getInstance().enableLogs();
	}
}  // TestRawSockets
