#include "../TestDefinition.h"
#include "EndianPortable.h"
#include "SystemUtils.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/PcapFileNamesDef.h"
#include "../Common/TestUtils.h"

extern PcapTestArgs PcapTestGlobalArgs;

static int incSleep(const pcpp::RawPacketVector& capturedPackets, size_t expectedPacketCount, int maxTimeToSleep)
{
	int totalSleepTime = 0;
	while (totalSleepTime < maxTimeToSleep)
	{
		if (capturedPackets.size() > expectedPacketCount)
		{
			return totalSleepTime;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));
		totalSleepTime += 1;
	}

	return totalSleepTime;
}

PTF_TEST_CASE(TestPcapFiltersLive)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);

	std::string filterAsString;
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);
	pcpp::RawPacketVector capturedPackets;

	//-----------
	// IP filter
	//-----------
	PTF_PRINT_VERBOSE("Testing IPFilter");
	std::string filterAddrAsString(PcapTestGlobalArgs.ipToSendReceivePackets);
	pcpp::IPFilter ipFilter(filterAddrAsString, pcpp::DST);
	ipFilter.parseToString(filterAsString);
	PTF_ASSERT_TRUE(liveDev->setFilter(ipFilter));
	PTF_ASSERT_TRUE(liveDev->startCapture(capturedPackets));
	PTF_ASSERT_TRUE(sendURLRequest("www.google.com"));
	// let the capture work for couple of seconds
	int totalSleepTime = incSleep(capturedPackets, 2, 7);
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(capturedPackets.size(), 2);

	for (pcpp::RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_EQUAL(ipv4Layer->getDstIPAddress(), ipToSearch);
	}
	capturedPackets.clear();

	//------------
	// Port filter
	//------------
	PTF_PRINT_VERBOSE("Testing PortFilter");
	uint16_t filterPort = 80;
	pcpp::PortFilter portFilter(filterPort, pcpp::SRC);
	portFilter.parseToString(filterAsString);
	PTF_ASSERT_TRUE(liveDev->setFilter(portFilter));
	PTF_ASSERT_TRUE(liveDev->startCapture(capturedPackets));
	PTF_ASSERT_TRUE(sendURLRequest("www.yahoo.com"));
	// let the capture work for couple of seconds
	totalSleepTime = incSleep(capturedPackets, 2, 7);
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(capturedPackets.size(), 2);
	for (pcpp::RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 80);
	}
	capturedPackets.clear();

	//----------------
	// IP & Port filter
	//----------------
	PTF_PRINT_VERBOSE("Testing IP and Port Filter");
	std::vector<pcpp::GeneralFilter*> andFilterFilters;
	andFilterFilters.push_back(&ipFilter);
	andFilterFilters.push_back(&portFilter);
	pcpp::AndFilter andFilter(andFilterFilters);
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_TRUE(liveDev->setFilter(andFilter));
	PTF_ASSERT_TRUE(liveDev->startCapture(capturedPackets));
	PTF_ASSERT_TRUE(sendURLRequest("www.walla.co.il"));
	// let the capture work for couple of seconds
	totalSleepTime = incSleep(capturedPackets, 2, 7);
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(capturedPackets.size(), 2);
	for (pcpp::RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 80);
		PTF_ASSERT_EQUAL(ip4Layer->getDstIPAddress(), ipToSearch);
	}
	capturedPackets.clear();

	//-----------------
	// IP || Port filter
	//-----------------
	PTF_PRINT_VERBOSE("Testing IP or Port Filter");
	std::vector<pcpp::GeneralFilter*> orFilterFilters;
	ipFilter.setDirection(pcpp::SRC);
	orFilterFilters.push_back(&ipFilter);
	orFilterFilters.push_back(&portFilter);
	pcpp::OrFilter orFilter(orFilterFilters);
	orFilter.parseToString(filterAsString);
	PTF_ASSERT_TRUE(liveDev->setFilter(orFilter));
	PTF_ASSERT_TRUE(liveDev->startCapture(capturedPackets));
	PTF_ASSERT_TRUE(sendURLRequest("www.youtube.com"));
	// let the capture work for couple of seconds
	totalSleepTime = incSleep(capturedPackets, 2, 7);
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(capturedPackets.size(), 2);
	for (pcpp::RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (packet.isPacketOfType(pcpp::TCP))
		{
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			bool srcPortMatch = tcpLayer->getSrcPort() == 80;
			bool srcIpMatch = false;
			pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (ip4Layer != nullptr)
			{
				srcIpMatch = ip4Layer->getSrcIPAddress() == ipToSearch;
			}
			PTF_ASSERT_TRUE(srcIpMatch || srcPortMatch);
		}
		else if (packet.isPacketOfType(pcpp::IPv4))
		{
			pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			PTF_ASSERT_EQUAL(ip4Layer->getSrcIPAddress(), ipToSearch);
		}
		// else packet isn't of type IP or TCP
	}
	capturedPackets.clear();

	//----------
	// Not filter
	//----------
	PTF_PRINT_VERBOSE("Testing Not IP Filter");
	ipFilter.setDirection(pcpp::SRC);
	pcpp::NotFilter notFilter(&ipFilter);
	notFilter.parseToString(filterAsString);
	PTF_ASSERT_TRUE(liveDev->setFilter(notFilter));
	PTF_ASSERT_TRUE(liveDev->startCapture(capturedPackets));
	PTF_ASSERT_TRUE(sendURLRequest("www.ebay.com"));
	// let the capture work for couple of seconds
	totalSleepTime = incSleep(capturedPackets, 2, 7);
	PTF_PRINT_VERBOSE("Total sleep time: " << totalSleepTime);
	liveDev->stopCapture();
	PTF_ASSERT_GREATER_OR_EQUAL_THAN(capturedPackets.size(), 2);
	for (pcpp::RawPacketVector::VectorIterator iter = capturedPackets.begin(); iter != capturedPackets.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (packet.isPacketOfType(pcpp::IPv4))
		{
			pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			PTF_ASSERT_NOT_EQUAL(ipv4Layer->getSrcIPAddress(), ipToSearch);
		}
	}
	capturedPackets.clear();

	liveDev->close();

}  // TestPcapFiltersLive

PTF_TEST_CASE(TestPcapFilters_General_BPFStr)
{
	pcpp::RawPacketVector rawPacketVec;
	std::string filterAsString;

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);

	//------------------------------------
	// Test GeneralFilter + BPFStringFilter
	//------------------------------------

	// Try to make an invalid filter
	pcpp::BPFStringFilter badFilter("This is not a valid filter");
	PTF_ASSERT_FALSE(badFilter.verifyFilter());

	// Test stolen from MacAddress test below
	pcpp::MacAddress macAddr("00:13:c3:df:ae:18");
	pcpp::BPFStringFilter bpfStringFilter("ether dst " + macAddr.toString());
	PTF_ASSERT_TRUE(bpfStringFilter.verifyFilter());
	bpfStringFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev.open());
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	int validCounter = 0;

	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		if (bpfStringFilter.matchPacketWithFilter(*iter))
		{
			++validCounter;
			pcpp::Packet packet(*iter);
			pcpp::EthLayer* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
			PTF_ASSERT_EQUAL(ethLayer->getDestMac(), macAddr);
		}
	}

	PTF_ASSERT_EQUAL(validCounter, 5);

	rawPacketVec.clear();
}  // TestPcapFilters_General_BPFStr

PTF_TEST_CASE(TestPcapFilters_MatchStatic)
{
	pcpp::RawPacketVector rawPacketVec;
	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);
	PTF_ASSERT_TRUE(fileReaderDev.open());
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	//	Test empty BPFstring (the "ALL" filter) in combination with a "-" (example wrong filter)
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::BPFStringFilter emptyFilter("");
		PTF_ASSERT_TRUE(emptyFilter.matchPacketWithFilter(*iter));
		pcpp::BPFStringFilter wrongFilter("-");
		PTF_ASSERT_FALSE(wrongFilter.matchPacketWithFilter(*iter));
	}

	rawPacketVec.clear();
}  // TestPcapFilters_MatchStatic

PTF_TEST_CASE(TestPcapFiltersOffline)
{
	pcpp::RawPacketVector rawPacketVec;
	std::string filterAsString;

	pcpp::PcapFileReaderDevice fileReaderDev(EXAMPLE_PCAP_VLAN);
	pcpp::PcapFileReaderDevice fileReaderDev2(EXAMPLE_PCAP_PATH);
	pcpp::PcapFileReaderDevice fileReaderDev3(EXAMPLE_PCAP_GRE);
	pcpp::PcapFileReaderDevice fileReaderDev4(EXAMPLE_PCAP_IGMP);

	//-----------------
	// VLAN filter
	//-----------------

	pcpp::VlanFilter vlanFilter(118);
	vlanFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev.open());
	PTF_ASSERT_TRUE(fileReaderDev.setFilter(vlanFilter));
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 12);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::VLAN));
		pcpp::VlanLayer* vlanLayer = packet.getLayerOfType<pcpp::VlanLayer>();
		PTF_ASSERT_EQUAL(vlanLayer->getVlanID(), 118);
	}

	rawPacketVec.clear();

	//--------------------
	// MacAddress filter
	//--------------------
	pcpp::MacAddress macAddrToFilter("00:13:c3:df:ae:18");
	pcpp::MacAddressFilter macAddrFilter(macAddrToFilter, pcpp::DST);
	macAddrFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev.open());
	PTF_ASSERT_TRUE(fileReaderDev.setFilter(macAddrFilter));
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 5);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		pcpp::EthLayer* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
		PTF_ASSERT_EQUAL(ethLayer->getDestMac(), macAddrToFilter);
	}

	rawPacketVec.clear();

	//--------------------
	// EtherType filter
	//--------------------
	pcpp::EtherTypeFilter ethTypeFiler(PCPP_ETHERTYPE_VLAN);
	ethTypeFiler.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev.open());
	PTF_ASSERT_TRUE(fileReaderDev.setFilter(ethTypeFiler));
	fileReaderDev.getNextPackets(rawPacketVec);
	fileReaderDev.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 24);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::VLAN));
	}

	rawPacketVec.clear();

	//--------------------
	// IPv4 ID filter
	//--------------------
	uint16_t ipID(0x9900);
	pcpp::IPv4IDFilter ipIDFiler(ipID, pcpp::GREATER_THAN);
	ipIDFiler.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(ipIDFiler));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 1423);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_GREATER_THAN(be16toh(ipv4Layer->getIPv4Header()->ipId), ipID);
	}

	rawPacketVec.clear();

	//-------------------------
	// IPv4 Total Length filter
	//-------------------------
	uint16_t totalLength(576);
	pcpp::IPv4TotalLengthFilter ipTotalLengthFiler(totalLength, pcpp::LESS_OR_EQUAL);
	ipTotalLengthFiler.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(ipTotalLengthFiler));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 2066);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_LOWER_OR_EQUAL_THAN(be16toh(ipv4Layer->getIPv4Header()->totalLength), totalLength);
	}

	rawPacketVec.clear();

	//-------------------------
	// TCP window size filter
	//-------------------------
	uint16_t windowSize(8312);
	pcpp::TcpWindowSizeFilter tcpWindowSizeFilter(windowSize, pcpp::NOT_EQUALS);
	tcpWindowSizeFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(tcpWindowSizeFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 4249);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_NOT_EQUAL(be16toh(tcpLayer->getTcpHeader()->windowSize), windowSize);
	}

	rawPacketVec.clear();

	//-------------------------
	// UDP length filter
	//-------------------------
	uint16_t udpLength(46);
	pcpp::UdpLengthFilter udpLengthFilter(udpLength, pcpp::EQUALS);
	udpLengthFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(udpLengthFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 4);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::UDP));
		pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
		PTF_ASSERT_EQUAL(be16toh(udpLayer->getUdpHeader()->length), udpLength);
	}

	rawPacketVec.clear();

	//-------------------------
	// IP filter with mask
	//-------------------------
	pcpp::IPFilter ipFilterWithMask("212.199.202.9", pcpp::SRC, "255.255.255.0");
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip and src net 212.199.202.0/24");

	PTF_ASSERT_RAISES(ipFilterWithMask.setAddr("BogusIPAddressString"), std::invalid_argument,
	                  "Not a valid IP address: BogusIPAddressString");

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(ipFilterWithMask));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 2536);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_TRUE(ipLayer->getSrcIPv4Address().matchNetwork(std::string("212.199.202.9/255.255.255.0")));
	}

	rawPacketVec.clear();

	ipFilterWithMask.clearMask();
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip and src net 212.199.202.9/32");

	ipFilterWithMask = pcpp::IPFilter(pcpp::IPNetwork("212.199.202.9/24"), pcpp::Direction::DST);
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip and dst net 212.199.202.0/24");

	ipFilterWithMask.setDirection(pcpp::Direction::SRC);
	ipFilterWithMask.setLen(24);
	ipFilterWithMask.setAddr("212.199.202.9");
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip and src net 212.199.202.0/24");

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(ipFilterWithMask));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 2536);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_TRUE(ipLayer->getSrcIPv4Address().matchNetwork(std::string("212.199.202.9/255.255.255.0")));
	}
	rawPacketVec.clear();

	ipFilterWithMask.clearLen();
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip and src net 212.199.202.9/32");

	// IPv6 tests

	ipFilterWithMask.setMask("255.255.255.0");
	ipFilterWithMask.setAddr("2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF");
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip6 and src net 2001:d00::/24");
	ipFilterWithMask.clearMask();

	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip6 and src net 2001:db8:3333:4444:cccc:dddd:eeee:ffff/128");

	PTF_ASSERT_RAISES(ipFilterWithMask.setMask("255.255.255.255"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: 255.255.255.255");
	ipFilterWithMask.setMask("ffff:ffff:ffff::");
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip6 and src net 2001:db8:3333::/48");

	ipFilterWithMask.setNetwork(pcpp::IPNetwork("2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF/64"));
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip6 and src net 2001:db8:3333:4444::/64");

	ipFilterWithMask.setLen(48);
	ipFilterWithMask.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "ip6 and src net 2001:db8:3333::/48");

	ipFilterWithMask.setAddr("2001:db8:0:12::1");
	ipFilterWithMask.clearLen();
	ipFilterWithMask.clearMask();
	pcpp::PcapFileReaderDevice fileReaderDev5(EXAMPLE_PCAP_IPV6_PATH);

	PTF_ASSERT_TRUE(fileReaderDev5.open());
	PTF_ASSERT_TRUE(fileReaderDev5.setFilter(ipFilterWithMask));
	fileReaderDev5.getNextPackets(rawPacketVec);
	fileReaderDev5.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 5);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv6));
		pcpp::IPv6Layer* ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();
		// This is essentially matching the host address, but it will have to do for the current sample.
		PTF_ASSERT_TRUE(ipLayer->getSrcIPv6Address().matchNetwork("2001:db8:0:12::1/128"));
	}
	rawPacketVec.clear();
	ipFilterWithMask.setLen(64);

	PTF_ASSERT_TRUE(fileReaderDev5.open());
	PTF_ASSERT_TRUE(fileReaderDev5.setFilter(ipFilterWithMask));
	fileReaderDev5.getNextPackets(rawPacketVec);
	fileReaderDev5.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 10);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv6));
		pcpp::IPv6Layer* ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();
		PTF_ASSERT_TRUE(ipLayer->getSrcIPv6Address().matchNetwork("2001:db8:0:12::/64"));
	}
	rawPacketVec.clear();

	//-------------
	// Port range
	//-------------
	pcpp::PortRangeFilter portRangeFilter(40000, 50000, pcpp::SRC);
	portRangeFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(portRangeFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 1464);

	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP) || packet.isPacketOfType(pcpp::UDP));
		if (packet.isPacketOfType(pcpp::TCP))
		{
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			uint16_t portSrc = tcpLayer->getSrcPort();
			PTF_ASSERT_TRUE(portSrc >= 40000 && portSrc <= 50000);
		}
		else if (packet.isPacketOfType(pcpp::UDP))
		{
			pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
			uint16_t portSrc = udpLayer->getSrcPort();
			PTF_ASSERT_TRUE(portSrc >= 40000 && portSrc <= 50000);
		}
	}
	rawPacketVec.clear();

	//-------------------------
	// TCP flags filter
	//-------------------------
	uint8_t tcpFlagsBitMask(pcpp::TcpFlagsFilter::tcpSyn | pcpp::TcpFlagsFilter::tcpAck);
	pcpp::TcpFlagsFilter tcpFlagsFilter(tcpFlagsBitMask, pcpp::TcpFlagsFilter::MatchAll);
	tcpFlagsFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(tcpFlagsFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 65);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->synFlag, 1);
		PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackFlag, 1);
	}
	rawPacketVec.clear();

	tcpFlagsFilter.setTcpFlagsBitMask(tcpFlagsBitMask, pcpp::TcpFlagsFilter::MatchOneAtLeast);
	tcpFlagsFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(tcpFlagsFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 4489);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
		pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
		PTF_ASSERT_TRUE(tcpLayer->getTcpHeader()->synFlag == 1 || tcpLayer->getTcpHeader()->ackFlag == 1);
	}

	rawPacketVec.clear();

	//------------
	// Proto filter
	//------------

	// ARP proto
	pcpp::ProtoFilter protoFilter(pcpp::ARP);
	protoFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev3.open());
	PTF_ASSERT_TRUE(fileReaderDev3.setFilter(protoFilter));
	fileReaderDev3.getNextPackets(rawPacketVec);
	fileReaderDev3.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 2);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::ARP));
	}
	rawPacketVec.clear();

	// TCP proto
	protoFilter.setProto(pcpp::TCP);
	protoFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev3.open());
	PTF_ASSERT_TRUE(fileReaderDev3.setFilter(protoFilter));
	fileReaderDev3.getNextPackets(rawPacketVec);
	fileReaderDev3.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 9);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::TCP));
	}
	rawPacketVec.clear();

	// GRE proto
	protoFilter.setProto(pcpp::GRE);
	protoFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev3.open());
	PTF_ASSERT_TRUE(fileReaderDev3.setFilter(protoFilter));
	fileReaderDev3.getNextPackets(rawPacketVec);
	fileReaderDev3.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 17);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GRE));
	}
	rawPacketVec.clear();

	// UDP proto
	protoFilter.setProto(pcpp::UDP);
	protoFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev4.open());
	PTF_ASSERT_TRUE(fileReaderDev4.setFilter(protoFilter));
	fileReaderDev4.getNextPackets(rawPacketVec);
	fileReaderDev4.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 38);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::UDP));
	}
	rawPacketVec.clear();

	// IGMP proto
	protoFilter.setProto(pcpp::IGMP);
	protoFilter.parseToString(filterAsString);

	PTF_ASSERT_TRUE(fileReaderDev4.open());
	PTF_ASSERT_TRUE(fileReaderDev4.setFilter(protoFilter));
	fileReaderDev4.getNextPackets(rawPacketVec);
	fileReaderDev4.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 6);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IGMP));
	}
	rawPacketVec.clear();

	//-----------------------
	// And filter - Proto + IP
	//-----------------------

	pcpp::IPFilter ipFilter("10.0.0.6", pcpp::SRC);
	protoFilter.setProto(pcpp::UDP);
	std::vector<pcpp::GeneralFilter*> filterVec;
	filterVec.push_back(&ipFilter);
	filterVec.push_back(&protoFilter);
	pcpp::AndFilter andFilter(filterVec);
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "(ip and src net 10.0.0.6/32) and (udp)");

	andFilter.addFilter(&ipFilter);
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "(ip and src net 10.0.0.6/32) and (udp) and (ip and src net 10.0.0.6/32)");

	andFilter.removeFilter(&ipFilter);
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "(udp) and (ip and src net 10.0.0.6/32)");

	{
		pcpp::OrFilter externalFilter;
		andFilter.removeFilter(&externalFilter);
		PTF_ASSERT_EQUAL(filterAsString, "(udp) and (ip and src net 10.0.0.6/32)");
	}

	andFilter.clearAllFilters();
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "");

	andFilter.setFilters(filterVec);
	andFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "(ip and src net 10.0.0.6/32) and (udp)");

	PTF_ASSERT_TRUE(fileReaderDev2.open());
	PTF_ASSERT_TRUE(fileReaderDev2.setFilter(andFilter));
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 69);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::UDP));
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
		pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_EQUAL(ipv4Layer->getSrcIPAddress().toString(), "10.0.0.6");
	}

	rawPacketVec.clear();

	//------------------------------------------
	// Complex filter - (Proto1 and IP) || Proto2
	//------------------------------------------

	protoFilter.setProto(pcpp::GRE);
	ipFilter.setAddr("20.0.0.1");
	ipFilter.setDirection(pcpp::SRC_OR_DST);

	filterVec.clear();
	filterVec.push_back(&protoFilter);
	filterVec.push_back(&ipFilter);
	andFilter.setFilters(filterVec);

	filterVec.clear();
	pcpp::ProtoFilter protoFilter2(pcpp::ARP);
	filterVec.push_back(&protoFilter2);
	filterVec.push_back(&andFilter);
	pcpp::OrFilter orFilter(filterVec);

	orFilter.parseToString(filterAsString);
	PTF_ASSERT_EQUAL(filterAsString, "(arp) or ((proto 47) and (ip and src or dst net 20.0.0.1/32))");

	PTF_ASSERT_TRUE(fileReaderDev3.open());
	PTF_ASSERT_TRUE(fileReaderDev3.setFilter(orFilter));
	fileReaderDev3.getNextPackets(rawPacketVec);
	fileReaderDev3.close();

	PTF_ASSERT_EQUAL(rawPacketVec.size(), 19);
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (packet.isPacketOfType(pcpp::ARP))
		{
			continue;
		}
		else
		{
			PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GRE));
			PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::IPv4));
			pcpp::IPv4Layer* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			PTF_ASSERT_TRUE(ipv4Layer->getSrcIPAddress().toString() == "20.0.0.1" ||
			                ipv4Layer->getDstIPAddress().toString() == "20.0.0.1");
		}
	}
	rawPacketVec.clear();
}

PTF_TEST_CASE(TestPcapFilters_LinkLayer)
{
	// check if matchPacketWithFilter work properly for packets with different LinkLayerType

	// pcpp::LINKTYPE_DLT_RAW1 layer
	pcpp::PcapFileReaderDevice fileReaderDev1(RAW_IP_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev1.open());
	pcpp::RawPacketVector rawPacketVec;
	fileReaderDev1.getNextPackets(rawPacketVec);
	fileReaderDev1.close();

	int validCounter = 0;
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (pcpp::IPv4Layer* ip4layer = packet.getLayerOfType<pcpp::IPv4Layer>())
		{
			pcpp::BPFStringFilter bpfStringFilter(
			    "host " + ip4layer->getDstIPAddress().toString());  // checking against real filter, not the "" filter
			if (bpfStringFilter.matchPacketWithFilter(*iter))
			{
				if ((*iter)->getLinkLayerType() == pcpp::LINKTYPE_DLT_RAW1)
				{
					++validCounter;
				}
			}
		}
	}
	PTF_ASSERT_EQUAL(validCounter, 50);
	rawPacketVec.clear();

	// pcpp::LINKTYPE_LINUX_SLL layer
	pcpp::PcapFileReaderDevice fileReaderDev2(SLL_PCAP_PATH);
	PTF_ASSERT_TRUE(fileReaderDev2.open());
	fileReaderDev2.getNextPackets(rawPacketVec);
	fileReaderDev2.close();

	validCounter = 0;
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (pcpp::IPv4Layer* ip4layer = packet.getLayerOfType<pcpp::IPv4Layer>())
		{
			pcpp::BPFStringFilter bpfStringFilter(
			    "host " + ip4layer->getDstIPAddress().toString());  // checking against real filter, not the "" filter
			if (bpfStringFilter.matchPacketWithFilter(*iter))
			{
				if ((*iter)->getLinkLayerType() == pcpp::LINKTYPE_LINUX_SLL)
				{
					++validCounter;
				}
			}
		}
	}
	PTF_ASSERT_EQUAL(validCounter, 510);
	rawPacketVec.clear();

	// pcpp::LINKTYPE_ETHERNET layer
	pcpp::PcapNgFileReaderDevice fileReaderDev3(EXAMPLE_PCAPNG_PATH);
	PTF_ASSERT_TRUE(fileReaderDev3.open());
	fileReaderDev3.getNextPackets(rawPacketVec);
	fileReaderDev3.close();

	validCounter = 0;
	for (pcpp::RawPacketVector::VectorIterator iter = rawPacketVec.begin(); iter != rawPacketVec.end(); iter++)
	{
		pcpp::Packet packet(*iter);
		if (pcpp::IPv4Layer* ip4layer = packet.getLayerOfType<pcpp::IPv4Layer>())
		{
			pcpp::BPFStringFilter bpfStringFilter(
			    "host " + ip4layer->getDstIPAddress().toString());  // checking against real filter, not the "" filter
			if (bpfStringFilter.matchPacketWithFilter(*iter))
			{
				if ((*iter)->getLinkLayerType() == pcpp::LINKTYPE_ETHERNET)
				{
					++validCounter;
				}
			}
		}
	}
	PTF_ASSERT_EQUAL(validCounter, 62);
	rawPacketVec.clear();
}  // TestPcapFilters_LinkLayer
