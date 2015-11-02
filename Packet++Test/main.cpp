#include <Logger.h>
#include <Packet.h>
#include <EthLayer.h>
#include <VlanLayer.h>
#include <PayloadLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <ArpLayer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <PPPoELayer.h>
#include <DnsLayer.h>
#include <MplsLayer.h>
#include <IpAddress.h>
#include <fstream>
#include <stdlib.h>
#include <debug_new.h>
#include <iostream>
#include <sstream>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <in.h>
#endif

using namespace std;

#define PACKETPP_TEST(TestName) bool TestName()

#define PACKETPP_ASSERT(exp, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		return false; \
	}

#define PACKETPP_ASSERT_AND_RUN_COMMAND(exp, command, assertFailedFormat, ...) \
	if (!(exp)) \
	{ \
		printf("%-30s: FAILED. assertion failed: " assertFailedFormat "\n", __FUNCTION__, ## __VA_ARGS__); \
		command; \
		return false; \
	}

#define PACKETPP_TEST_PASSED printf("%-30s: PASSED\n", __FUNCTION__); return true

#define PACKETPP_START_RUNNING_TESTS bool allTestsPassed = true
#define PACKETPP_RUN_TEST(TestName) allTestsPassed &= TestName()
#define PACKETPP_END_RUNNING_TESTS \
		if (allTestsPassed) \
			printf("ALL TESTS PASSED!!\n\n\n"); \
		else \
			printf("NOT ALL TESTS PASSED!!\n\n\n");

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


PACKETPP_TEST(EthPacketCreation) {
	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	PayloadLayer payloadLayer(payload, 4, true);

	Packet ethPacket(1);
	PACKETPP_ASSERT(ethPacket.addLayer(&ethLayer), "Adding ethernet layer failed");
	PACKETPP_ASSERT(ethPacket.addLayer(&payloadLayer), "Adding payload layer failed");

	PACKETPP_ASSERT(ethPacket.isPacketOfType(Ethernet), "Packet is not of type Ethernet");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>() != NULL, "Ethernet layer doesn't exist");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>() == &ethLayer, "Ethernet layer doesn't equal to inserted layer");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>()->getDestMac() == dstMac, "Packet dest mac isn't equal to intserted dest mac");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>()->getSourceMac() == srcMac, "Packet src mac isn't equal to intserted src mac");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>()->getEthHeader()->etherType == ntohs(ETHERTYPE_IP), "Packet ether type isn't equal to ETHERTYPE_IP");

	RawPacket* rawPacket = ethPacket.getRawPacket();
	PACKETPP_ASSERT(rawPacket != NULL, "Raw packet is NULL");
	PACKETPP_ASSERT(rawPacket->getRawDataLen() == 18, "Raw packet length expected to be 18 but it's %d", rawPacket->getRawDataLen());

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PACKETPP_ASSERT(memcmp(rawPacket->getRawData(), expectedBuffer, 18) == 0, "Raw packet data is different than expected");
	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(EthAndArpPacketParsing) {
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/ArpResponsePacket.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

//	int* abba = new int[1000];
//	std::cout << abba[500];

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet ethPacket(&rawPacket);
	PACKETPP_ASSERT(ethPacket.isPacketOfType(Ethernet), "Packet is not of type Ethernet");
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>() != NULL, "Ethernet layer doesn't exist");

	MacAddress expectedSrcMac(0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa);
	MacAddress expectedDstMac(0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e);
	EthLayer* ethLayer = ethPacket.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(ethLayer->getDestMac() == expectedDstMac, "Packet dest mac isn't equal to intserted dest mac");
	PACKETPP_ASSERT(ethLayer->getSourceMac() == expectedSrcMac, "Packet src mac isn't equal to intserted src mac");
	PACKETPP_ASSERT(ethLayer->getEthHeader()->etherType == ntohs(ETHERTYPE_ARP), "Packet ether type isn't equal to ETHERTYPE_ARP, it's 0x%x", ethLayer->getEthHeader()->etherType);

	PACKETPP_ASSERT(ethLayer->getNextLayer()->getProtocol() == ARP, "Next layer isn't of type 'ARP'");
	ArpLayer* arpLayer = (ArpLayer*)ethLayer->getNextLayer();
	PACKETPP_ASSERT(arpLayer->getArpHeader()->hardwareType == htons(1), "ARP hardwareType != 1");
	PACKETPP_ASSERT(arpLayer->getArpHeader()->protocolType == htons(ETHERTYPE_IP), "ARP protocolType != ETHERTYPE_IP, it's 0x%4X", ntohs(arpLayer->getArpHeader()->protocolType));
	PACKETPP_ASSERT(arpLayer->getArpHeader()->hardwareSize == 6, "ARP hardwareSize != 6");
	PACKETPP_ASSERT(arpLayer->getArpHeader()->protocolSize == 4, "ARP protocolSize != 4");
	PACKETPP_ASSERT(arpLayer->getArpHeader()->opcode == htons(ARP_REPLY), "ARP opcode != ARP_REPLY");
	PACKETPP_ASSERT(arpLayer->getSenderIpAddr() == IPv4Address(string("10.0.0.138")), "ARP sender IP addr != 10.0.0.138");
	PACKETPP_ASSERT(arpLayer->getTargetMacAddress() == MacAddress("6c:f0:49:b2:de:6e"), "ARP target mac addr != 6c:f0:49:b2:de:6e");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(ArpPacketCreation)
{
	MacAddress srcMac("6c:f0:49:b2:de:6e");
	MacAddress dstMac("ff:ff:ff:ff:ff:ff:");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_ARP);

	ArpLayer arpLayer(ARP_REQUEST, srcMac, srcMac, IPv4Address(string("10.0.0.1")), IPv4Address(string("10.0.0.138")));

	Packet arpRequestPacket(1);
	PACKETPP_ASSERT(arpRequestPacket.addLayer(&ethLayer), "Couldn't add eth layer");
	PACKETPP_ASSERT(arpRequestPacket.addLayer(&arpLayer), "Couldn't add arp layer");
	arpRequestPacket.computeCalculateFields();
	PACKETPP_ASSERT(arpRequestPacket.getRawPacket()->getRawDataLen() == 42, "arp packet size != 42 bytes, Actual: %d", arpRequestPacket.getRawPacket()->getRawDataLen());

	ArpLayer* pArpLayer = arpRequestPacket.getLayerOfType<ArpLayer>();
	PACKETPP_ASSERT(pArpLayer != NULL, "Packet doesn't contain arp layer");

	arphdr* arpHeader = pArpLayer->getArpHeader();
	PACKETPP_ASSERT(arpHeader->hardwareSize == 6, "Arp header: hardwareSize != 6, Actual: %d", arpHeader->hardwareSize);
	PACKETPP_ASSERT(arpHeader->protocolType == htons(ETHERTYPE_IP), "Arp header: protocolType != ETHERTYPE_IP, Actual: %d", arpHeader->protocolType);

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/ArpRequestPacket.dat", bufferLength);
	PACKETPP_ASSERT(buffer != NULL, "cannot read file");
	PACKETPP_ASSERT(bufferLength == arpRequestPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", arpRequestPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(arpRequestPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete [] buffer;
	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(VlanParseAndCreation)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/ArpRequestWithVlan.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);
	Packet arpWithVlan(&rawPacket);
	VlanLayer* pFirstVlanLayer = NULL;
	VlanLayer* pSecondVlanLayer = NULL;
	PACKETPP_ASSERT((pFirstVlanLayer = arpWithVlan.getLayerOfType<VlanLayer>()) != NULL, "Couldn't get first vlan layer from packet");
	vlan_header* vlanHeader = pFirstVlanLayer->getVlanHeader();
	PACKETPP_ASSERT(pFirstVlanLayer->getVlanID() == 100, "first vlan ID != 100, it's 0x%2X", pFirstVlanLayer->getVlanID());
	PACKETPP_ASSERT(vlanHeader->cfi == htons(0), "first vlan CFI != 0");
	PACKETPP_ASSERT(vlanHeader->priority == htons(0), "first vlan priority != 0");
	PACKETPP_ASSERT((pSecondVlanLayer = arpWithVlan.getNextLayerOfType<VlanLayer>(pFirstVlanLayer)) != NULL, "Couldn't get second vlan layer from packet");
	vlanHeader = pSecondVlanLayer->getVlanHeader();
	PACKETPP_ASSERT(pSecondVlanLayer->getVlanID() == 200, "second vlan ID != 200");
	PACKETPP_ASSERT(vlanHeader->cfi == htons(0), "second vlan CFI != 0");
	PACKETPP_ASSERT(vlanHeader->priority == htons(0), "second vlan priority != 0");

	Packet arpWithVlanNew(1);
	MacAddress macSrc("ca:03:0d:b4:00:1c");
	MacAddress macDest("ff:ff:ff:ff:ff:ff");
	EthLayer ethLayer(macSrc, macDest, ETHERTYPE_VLAN);
	VlanLayer firstVlanLayer(100, 0, 0, ETHERTYPE_VLAN);
	VlanLayer secondVlanLayer(200, 0, 0, ETHERTYPE_ARP);
	ArpLayer arpLayer(ARP_REQUEST, macSrc, MacAddress("00:00:00:00:00:00"), IPv4Address(string("192.168.2.200")), IPv4Address(string("192.168.2.254")));
	PACKETPP_ASSERT(arpWithVlanNew.addLayer(&ethLayer), "Couldn't add eth layer");
	PACKETPP_ASSERT(arpWithVlanNew.addLayer(&firstVlanLayer), "Couldn't add first vlan layer");
	PACKETPP_ASSERT(arpWithVlanNew.addLayer(&secondVlanLayer), "Couldn't add second vlan layer");
	PACKETPP_ASSERT(arpWithVlanNew.addLayer(&arpLayer), "Couldn't add second arp layer");

	arpWithVlanNew.computeCalculateFields();

	PACKETPP_ASSERT(bufferLength == arpWithVlanNew.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", arpWithVlanNew.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(arpWithVlanNew.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4PacketCreation)
{
	Packet ip4Packet(1);

	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_IP);
	PACKETPP_ASSERT(ip4Packet.addLayer(&ethLayer), "Adding ethernet layer failed");

	Packet tmpPacket(50);
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(!tmpPacket.addLayer(&ethLayer), "Wrongly succeeded to add the same Ethernet layer into 2 different packets");
	LoggerPP::getInstance().enableErrors();

	RawPacket* rawPacket = ip4Packet.getRawPacket();
	PACKETPP_ASSERT(rawPacket != NULL, "Raw packet is NULL");
	PACKETPP_ASSERT(rawPacket->getRawDataLen() == 14, "Raw packet length expected to be 14 but it's %d", rawPacket->getRawDataLen());


	IPv4Address ipSrc(string("1.1.1.1"));
	IPv4Address ipDst(string("20.20.20.20"));
	IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
	PACKETPP_ASSERT(ip4Packet.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	PayloadLayer payloadLayer(payload, 10, true);
	PACKETPP_ASSERT(ip4Packet.addLayer(&payloadLayer), "Adding payload layer failed");

	ip4Packet.computeCalculateFields();

	PACKETPP_ASSERT(ip4Packet.getLayerOfType<EthLayer>()->getDataLen() == 44, "Eth Layer data len != 44, it's %d", ip4Packet.getLayerOfType<EthLayer>()->getDataLen());
	PACKETPP_ASSERT(ip4Packet.getLayerOfType<IPv4Layer>() != NULL, "Packet doesn't contain IPv4 layer");
	iphdr* ipHeader = ip4Layer.getIPv4Header();
	PACKETPP_ASSERT(ip4Layer.getSrcIpAddress() == ipSrc, "IPv4 Layer src IP isn't equal to inserted src IP");
	PACKETPP_ASSERT(ip4Layer.getDstIpAddress() == ipDst, "IPv4 Layer dst IP isn't equal to inserted dst IP");
	PACKETPP_ASSERT(ipHeader->ipVersion == 4, "IPv4 Layer version != 4, Actual: %d", ipHeader->ipVersion);
	PACKETPP_ASSERT(ipHeader->internetHeaderLength == 5, "IPv4 Layer header length != 5, Actual: %d", ipHeader->internetHeaderLength);
	PACKETPP_ASSERT(ipHeader->totalLength == htons(30), "IPv4 Layer total length != 30");
	PACKETPP_ASSERT(ipHeader->protocol == PACKETPP_IPPROTO_TCP, "IPv4 Layer protocol isn't PACKETPP_IPPROTO_TCP");
	PACKETPP_ASSERT(ipHeader->headerChecksum == htons(0x90b1), "IPv4 Layer header checksum is wrong. Expected: 0x%4X, Actual: 0x%4X", 0x90b1, ipHeader->headerChecksum);

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4PacketParsing)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/IcmpPacket.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet ip4Packet(&rawPacket);
	PACKETPP_ASSERT(ip4Packet.isPacketOfType(Ethernet), "Packet is not of type Ethernet");
	PACKETPP_ASSERT(ip4Packet.getLayerOfType<EthLayer>() != NULL, "Ethernet layer doesn't exist");
	PACKETPP_ASSERT(ip4Packet.isPacketOfType(IPv4), "Packet is not of type IPv4");
	PACKETPP_ASSERT(ip4Packet.getLayerOfType<IPv4Layer>() != NULL, "IPv4 layer doesn't exist");

	EthLayer* ethLayer = ip4Packet.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(ntohs(ethLayer->getEthHeader()->etherType) == ETHERTYPE_IP, "Packet ether type isn't equal to ETHERTYPE_IP");

	IPv4Layer* ipv4Layer = ip4Packet.getLayerOfType<IPv4Layer>();
	IPv4Address ip4addr1(string("10.0.0.4"));
	IPv4Address ip4addr2(string("1.1.1.1"));
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->protocol == 1, "Protocol read from packet isnt ICMP (=1). Protocol is: %d", ipv4Layer->getIPv4Header()->protocol);
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipVersion == 4, "IP version isn't 4. Version is: %d", ipv4Layer->getIPv4Header()->ipVersion);
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipSrc == ip4addr1.toInt(), "incorrect source address");
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipDst == ip4addr2.toInt(), "incorrect dest address");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4UdpChecksum)
{
	for (int i = 1; i<6; i++)
	{
		stringstream strStream;
		strStream << "PacketExamples/UdpPacket4Checksum" << i << ".dat";
		string fileName = strStream.str();
		int bufferLength = 0;
		uint8_t* buffer = readFileIntoBuffer(fileName.c_str(), bufferLength);
		PACKETPP_ASSERT(!(buffer == NULL), "cannot read file '%s'", fileName.c_str());

		timeval time;
		gettimeofday(&time, NULL);
		RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

		Packet udpPacket(&rawPacket);
		UdpLayer* udpLayer = NULL;
		PACKETPP_ASSERT((udpLayer = udpPacket.getLayerOfType<UdpLayer>()) != NULL, "UDP layer doesn't exist");
		uint16_t packetChecksum = udpLayer->getUdpHeader()->headerChecksum;
		udpLayer->computeCalculateFields();
		PACKETPP_ASSERT(udpLayer->getUdpHeader()->headerChecksum == packetChecksum, "Calculated checksum (0x%4X) != original checksum (0x%4X)", udpLayer->getUdpHeader()->headerChecksum, packetChecksum);
	}

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv6UdpPacketParseAndCreate)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/IPv6UdpPacket.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet ip6UdpPacket(&rawPacket);
	PACKETPP_ASSERT(!ip6UdpPacket.isPacketOfType(IPv4), "Packet is of type IPv4 instead IPv6");
	PACKETPP_ASSERT(!ip6UdpPacket.isPacketOfType(TCP), "Packet is of type TCP where it shouldn't");
	IPv6Layer* ipv6Layer = NULL;
	PACKETPP_ASSERT((ipv6Layer = ip6UdpPacket.getLayerOfType<IPv6Layer>()) != NULL, "IPv6 layer doesn't exist");
	PACKETPP_ASSERT(ipv6Layer->getIPv6Header()->nextHeader == 17, "Protocol read from packet isnt UDP (17). Protocol is: %d", ipv6Layer->getIPv6Header()->nextHeader);
	PACKETPP_ASSERT(ipv6Layer->getIPv6Header()->ipVersion == 6, "IP version isn't 6. Version is: %d", ipv6Layer->getIPv6Header()->ipVersion);
	IPv6Address srcIP(string("fe80::4dc7:f593:1f7b:dc11"));
	IPv6Address dstIP(string("ff02::c"));
	PACKETPP_ASSERT(ipv6Layer->getSrcIpAddress() == srcIP, "incorrect source address");
	PACKETPP_ASSERT(ipv6Layer->getDstIpAddress() == dstIP, "incorrect dest address");
	UdpLayer* pUdpLayer = NULL;
	PACKETPP_ASSERT((pUdpLayer = ip6UdpPacket.getLayerOfType<UdpLayer>()) != NULL, "UDP layer doesn't exist");
	PACKETPP_ASSERT(pUdpLayer->getUdpHeader()->portDst == htons(1900), "UDP dest port != 1900");
	PACKETPP_ASSERT(pUdpLayer->getUdpHeader()->portSrc == htons(63628), "UDP dest port != 63628");
	PACKETPP_ASSERT(pUdpLayer->getUdpHeader()->length == htons(154), "UDP dest port != 154");
	PACKETPP_ASSERT(pUdpLayer->getUdpHeader()->headerChecksum == htons(0x5fea), "UDP dest port != 0x5fea");

	Packet ip6UdpPacketNew(1);
	MacAddress macSrc("6c:f0:49:b2:de:6e");
	MacAddress macDest("33:33:00:00:00:0c");
	EthLayer ethLayer(macSrc, macDest, ETHERTYPE_IPV6);

	IPv6Layer ip6Layer(srcIP, dstIP);
	ip6_hdr* ip6Header = ip6Layer.getIPv6Header();
	ip6Header->hopLimit = 1;
	ip6Header->nextHeader = 17;

	UdpLayer udpLayer(63628, 1900);

	Layer* afterIpv6Layer = pUdpLayer->getNextLayer();
	uint8_t payloadData[afterIpv6Layer->getDataLen()];
	afterIpv6Layer->copyData(payloadData);
	PayloadLayer payloadLayer(payloadData, afterIpv6Layer->getDataLen(), true);

	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&ethLayer), "Couldn't add eth layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&ip6Layer), "Couldn't add IPv6 layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&udpLayer), "Couldn't add udp layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&payloadLayer), "Couldn't add payload layer");
	ip6UdpPacketNew.computeCalculateFields();

	PACKETPP_ASSERT(bufferLength == ip6UdpPacketNew.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", ip6UdpPacketNew.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(ip6UdpPacketNew.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(TcpPacketNoOptionsParsing)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketNoOptions.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet tcpPaketNoOptions(&rawPacket);
	PACKETPP_ASSERT(tcpPaketNoOptions.isPacketOfType(IPv4), "Packet isn't of type IPv4");
	PACKETPP_ASSERT(tcpPaketNoOptions.isPacketOfType(TCP), "Packet isn't of type TCP");
	TcpLayer* tcpLayer = NULL;
	PACKETPP_ASSERT((tcpLayer = tcpPaketNoOptions.getLayerOfType<TcpLayer>()) != NULL, "TCP layer is NULL");

	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->portDst == htons(60388), "Dest port != 60388, it's %d", ntohs(tcpLayer->getTcpHeader()->portDst));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->portSrc == htons(80), "Src port != 80, it's %d", ntohs(tcpLayer->getTcpHeader()->portSrc));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->sequenceNumber == htonl(0xbeab364a), "Sequence number != 0xbeab364a, it's 0x%lX", ntohl(tcpLayer->getTcpHeader()->sequenceNumber));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->ackNumber == htonl(0xf9ffb58e), "Ack number != 0xf9ffb58e, it's 0x%lX", ntohl(tcpLayer->getTcpHeader()->ackNumber));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->dataOffset == 5, "Header length != 5 (20 bytes), it's %d", tcpLayer->getTcpHeader()->dataOffset);
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->urgentPointer == 0, "Urgent pointer != 0, it's %d", tcpLayer->getTcpHeader()->urgentPointer);
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->headerChecksum == htons(0x4c03), "Header checksum != 0x4c03, it's 0x%4X", ntohs(tcpLayer->getTcpHeader()->headerChecksum));

	// Flags
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->ackFlag == 1, "ACK Flag != 1");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->pshFlag == 1, "PSH Flag != 1");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->urgFlag == 0, "URG Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->cwrFlag == 0, "CWE Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->synFlag == 0, "SYN Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->finFlag == 0, "FIN Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->rstFlag == 0, "RST Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->eceFlag == 0, "ECE Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->reserved == 0, "Reserved != 0");

	// TCP options
	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 0, "TCP options count isn't 0");
	PACKETPP_ASSERT(tcpLayer->getTcpOptionData(TCPOPT_NOP) == NULL, "TCP option NOP isn't NULL");
	PACKETPP_ASSERT(tcpLayer->getTcpOptionData(TCPOPT_TIMESTAMP) == NULL, "TCP option Timestamp isn't NULL");

	Layer* afterTcpLayer = tcpLayer->getNextLayer();
	PACKETPP_ASSERT(afterTcpLayer != NULL, "Layer after TCP is NULL");
	PACKETPP_ASSERT(afterTcpLayer->getProtocol() == HTTPResponse, "Protocol layer after TCP isn't HTTPResponse");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(TcpPacketWithOptionsParsing)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet tcpPaketWithOptions(&rawPacket);
	PACKETPP_ASSERT(tcpPaketWithOptions.isPacketOfType(IPv4), "Packet isn't of type IPv4");
	PACKETPP_ASSERT(tcpPaketWithOptions.isPacketOfType(TCP), "Packet isn't of type TCP");
	TcpLayer* tcpLayer = NULL;
	PACKETPP_ASSERT((tcpLayer = tcpPaketWithOptions.getLayerOfType<TcpLayer>()) != NULL, "TCP layer is NULL");

	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->portSrc == htons(44147), "Src port != 44147, it's %d", ntohs(tcpLayer->getTcpHeader()->portSrc));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->portDst == htons(80), "Dest port != 80, it's %d", ntohs(tcpLayer->getTcpHeader()->portDst));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->ackFlag == 1, "ACK Flag != 1");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->pshFlag == 1, "PSH Flag != 1");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->synFlag == 0, "SYN Flag != 0");
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->urgentPointer == 0, "Urgent pointer != 0, it's %d", tcpLayer->getTcpHeader()->urgentPointer);

	// TCP options
	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 3, "TCP options count != 3, it's %d", tcpLayer->getTcpOptionsCount());
	TcpOptionData* nopOptionData = NULL;
	TcpOptionData* timestampOptionData = NULL;
	PACKETPP_ASSERT((timestampOptionData = tcpLayer->getTcpOptionData(TCPOPT_TIMESTAMP)) != NULL, "TCP option Timestamp is NULL");
	PACKETPP_ASSERT((nopOptionData = tcpLayer->getTcpOptionData(TCPOPT_NOP)) != NULL, "TCP option NOP is NULL");
	PACKETPP_ASSERT(timestampOptionData->len == 10, "TCP option Timestamp length != 10, it's 0x%X", timestampOptionData->len);
	uint32_t tsValue = 0;
	uint32_t tsEchoReply = 0;
	memcpy(&tsValue, timestampOptionData->value, 4);
	memcpy(&tsEchoReply, timestampOptionData->value+4, 4);
	PACKETPP_ASSERT(tsValue == htonl(195102), "TCP option Timestamp option: timestamp value != 195102, it's %ld", ntohl(tsValue));
	PACKETPP_ASSERT(tsEchoReply == htonl(3555729271), "TCP option Timestamp option: echo reply value != 3555729271, it's %ld", ntohl(tsEchoReply));

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(TcpPacketWithOptionsParsing2)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions3.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet tcpPaketWithOptions(&rawPacket);

	TcpLayer* tcpLayer = NULL;
	PACKETPP_ASSERT((tcpLayer = tcpPaketWithOptions.getLayerOfType<TcpLayer>()) != NULL, "TCP layer is NULL");

	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 5, "TCP options count != 5, it's %d", tcpLayer->getTcpOptionsCount());
	TcpOptionData* mssOptionData = NULL;
	TcpOptionData* sackParmOptionData = NULL;
	TcpOptionData* windowScaleOptionData = NULL;
	PACKETPP_ASSERT((mssOptionData = tcpLayer->getTcpOptionData(TCPOPT_MSS)) != NULL, "TCP option MSS is NULL");
	PACKETPP_ASSERT((sackParmOptionData = tcpLayer->getTcpOptionData(TCPOPT_SACK_PERM)) != NULL, "TCP option SACK perm is NULL");
	PACKETPP_ASSERT((windowScaleOptionData = tcpLayer->getTcpOptionData(TCPOPT_WINDOW)) != NULL, "TCP option window scale is NULL");

	PACKETPP_ASSERT(mssOptionData->len == 4, "TCP option Timestamp length != 4, it's 0x%X", mssOptionData->len);
	PACKETPP_ASSERT(sackParmOptionData->len == 2, "TCP option SACK perm length != 2, it's 0x%X", sackParmOptionData->len);
	PACKETPP_ASSERT(windowScaleOptionData->len == 3, "TCP option window scale length != 3, it's 0x%X", mssOptionData->len);

	uint16_t mssValue = 0;
	memcpy(&mssValue, mssOptionData->value, 2);
	PACKETPP_ASSERT(mssValue == htons(1460), "TCP option MSS option: value != 1460, it's %d", ntohs(mssValue));

	uint8_t windowScale = *windowScaleOptionData->value;
	PACKETPP_ASSERT(windowScale == 4, "TCP option window scale option: value != 4, it's %d", windowScale);

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(TcpPacketCreation)
{
	MacAddress srcMac("30:46:9a:23:fb:fa");
	MacAddress dstMac("08:00:27:19:1c:78");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_IP);
	IPv4Address dstIP(string("10.0.0.6"));
	IPv4Address srcIP(string("212.199.202.9"));
	IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htons(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htons(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	TcpLayer tcpLayer((uint16_t)80, (uint16_t)44160, 3, TCPOPT_NOP, TCPOPT_NOP, TCPOPT_TIMESTAMP);
	tcpLayer.getTcpHeader()->sequenceNumber = htonl(0xb829cb98);
	tcpLayer.getTcpHeader()->ackNumber = htonl(0xe9771586);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htons(20178);
	TcpOptionData* tsOptionData = tcpLayer.getTcpOptionData(TCPOPT_TIMESTAMP);
	uint32_t tsValue = htonl(3555735960);
	memcpy(tsOptionData->value, &tsValue, 4);
	uint8_t payloadData[9] = { 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
	PayloadLayer PayloadLayer(payloadData, 9, true);

	Packet tcpPacket(1);
	tcpPacket.addLayer(&ethLayer);
	tcpPacket.addLayer(&ipLayer);
	tcpPacket.addLayer(&tcpLayer);
	tcpPacket.addLayer(&PayloadLayer);

	uint32_t tsEchoReply = htonl(196757);
	tsOptionData = tcpLayer.getTcpOptionData(TCPOPT_TIMESTAMP);
	memcpy(tsOptionData->value+4, &tsEchoReply, 4);

	tcpPacket.computeCalculateFields();

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

//	printf("\n\n\n");
//	for(int i = 0; i<bufferLength; i++)
//		printf(" 0x%2X  ", buffer[i]);
//	printf("\n\n\n");
//	for(int i = 0; i<bufferLength; i++)
//	{
//		if (tcpPacket.getRawPacket()->getRawData()[i] != buffer[i])
//			printf("*0x%2X* ", tcpPacket.getRawPacket()->getRawData()[i]);
//		else
//			printf(" 0x%2X  ", tcpPacket.getRawPacket()->getRawData()[i]);
//	}
//	printf("\n\n\n");

	PACKETPP_ASSERT(memcmp(tcpPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete [] buffer;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(InsertDataToPacket)
{
	// Creating a packet
	// ~~~~~~~~~~~~~~~~~

	Packet ip4Packet(1);

	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_IP);
	PACKETPP_ASSERT(ip4Packet.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Address ipSrc(string("1.1.1.1"));
	IPv4Address ipDst(string("20.20.20.20"));
	IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
	PACKETPP_ASSERT(ip4Packet.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	PayloadLayer payloadLayer(payload, 10, true);
	PACKETPP_ASSERT(ip4Packet.addLayer(&payloadLayer), "Adding payload layer failed");

	ip4Packet.computeCalculateFields();

//	printf("\n\n\n");
//	for(int i = 0; i<ip4Packet.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", ip4Packet.getRawPacket()->getRawData()[i]);


	// Adding a VLAN layer between Eth and IP
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	VlanLayer vlanLayer(100, 0, 0, ETHERTYPE_IP);

	PACKETPP_ASSERT(ip4Packet.insertLayer(&ethLayer, &vlanLayer) == true, "Couldn't insert VLAN layer after Eth later");

//	printf("\n\n\n");
//	for(int i = 0; i<ip4Packet.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", ip4Packet.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	PACKETPP_ASSERT(ethLayer.getDestMac() == dstMac, "MAC dest after insert is different than MAC dest before insert");
	PACKETPP_ASSERT(ip4Layer.getIPv4Header()->internetHeaderLength == 5, "IP header len != 5");
	PACKETPP_ASSERT(ip4Layer.getDstIpAddress() == ipDst, "IP dst after insert is different than IP dst before insert");
	PACKETPP_ASSERT(ip4Layer.getSrcIpAddress() == ipSrc, "IP src after insert is different than IP src before insert");
	PACKETPP_ASSERT(payloadLayer.getPayload()[3] == 0x04, "Payload after insert is different than payload before insert");


	// Adding another Eth layer at the beginning of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	MacAddress srcMac2("cc:cc:cc:cc:cc:cc");
	MacAddress dstMac2("dd:dd:dd:dd:dd:dd");
	EthLayer ethLayer2(srcMac2, dstMac2, ETHERTYPE_IP);
	PACKETPP_ASSERT(ip4Packet.insertLayer(NULL, &ethLayer2), "Adding 2nd ethernet layer failed");

	PACKETPP_ASSERT(ip4Packet.getFirstLayer() == &ethLayer2, "1st layer in packet isn't ethLayer2");
	PACKETPP_ASSERT(ip4Packet.getFirstLayer()->getNextLayer() == &ethLayer, "2nd layer in packet isn't ethLayer");
	PACKETPP_ASSERT(ip4Packet.getFirstLayer()->getNextLayer()->getNextLayer() == &vlanLayer, "3rd layer in packet isn't vlanLayer");
	PACKETPP_ASSERT(ethLayer.getDestMac() == dstMac, "MAC dest after insert is different than MAC dest before insert");
	PACKETPP_ASSERT(ip4Layer.getIPv4Header()->internetHeaderLength == 5, "IP header len != 5");
	PACKETPP_ASSERT(ip4Layer.getDstIpAddress() == ipDst, "IP dst after insert is different than IP dst before insert");
	PACKETPP_ASSERT(ip4Layer.getSrcIpAddress() == ipSrc, "IP src after insert is different than IP src before insert");
	PACKETPP_ASSERT(payloadLayer.getPayload()[3] == 0x04, "Payload after insert is different than payload before insert");

//	printf("\n\n\n");
//	for(int i = 0; i<ip4Packet.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", ip4Packet.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");


	// Adding a TCP layer at the end of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	TcpLayer tcpLayer((uint16_t)12345, (uint16_t)80, 0);
	PACKETPP_ASSERT(ip4Packet.insertLayer(&payloadLayer, &tcpLayer), "Adding tcp layer at the end of packet failed");


	// Create a new packet and use insertLayer for the first layer in packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	Packet testPacket(1);
	EthLayer ethLayer3(srcMac2, dstMac2, ETHERTYPE_IP);
	testPacket.insertLayer(NULL, &ethLayer3);
	PACKETPP_ASSERT(testPacket.getFirstLayer() == &ethLayer3, "ethLayer3 isn't the first layer in testPacket");
	PACKETPP_ASSERT(testPacket.getFirstLayer()->getNextLayer() == NULL, "ethLayer3 wrongly has a next layer")
	PACKETPP_ASSERT(ethLayer3.getDestMac() == dstMac2, "ethLayer3 MAC dest is different than before inserting to packet");

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(InsertVlanToPacket)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions3.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet tcpPacket(&rawPacket);

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	VlanLayer vlanLayer(4001, 0, 0, ETHERTYPE_IP);
	tcpPacket.insertLayer(tcpPacket.getFirstLayer(), &vlanLayer);

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	PACKETPP_ASSERT(tcpPacket.getRawPacket()->getRawDataLen() == 78, "Size of packet after vlan insert isn't 78, it's %d", tcpPacket.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(tcpPacket.getFirstLayer()->getNextLayer() == &vlanLayer, "VLAN layer isn't the second layer as expected");
	PACKETPP_ASSERT(vlanLayer.getNextLayer() != NULL, "VLAN layer next layer is null");
	PACKETPP_ASSERT(vlanLayer.getNextLayer()->getProtocol() == IPv4, "VLAN layer next layer isn't IPv4");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(RemoveLayerTest)
{
	// parse packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketNoOptions.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet tcpPacket(&rawPacket);

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	// a. Remove layer from the middle
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	IPv4Layer* ipLayer = tcpPacket.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(tcpPacket.removeLayer(ipLayer), "Remove IPv4 layer failed");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(IPv4) == false, "Packet is still of type IPv4");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(Ethernet) == true, "Packet isn't of type Ethernet");
	PACKETPP_ASSERT(tcpPacket.getLayerOfType<IPv4Layer>() == NULL, "Can still retrieve IPv4 layer");
	PACKETPP_ASSERT(tcpPacket.getFirstLayer()->getNextLayer()->getProtocol() == TCP, "Layer next to Ethernet isn't TCP");
	PACKETPP_ASSERT(tcpPacket.getRawPacket()->getRawDataLen() == 271, "Data length != 271, it's %d", tcpPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	// b. Remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PACKETPP_ASSERT(tcpPacket.removeLayer(tcpPacket.getFirstLayer()), "Remove first layer failed");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(IPv4) == false, "Packet is still of type IPv4");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(Ethernet) == false, "Packet is still of type Ethernet");
	PACKETPP_ASSERT(tcpPacket.getFirstLayer()->getProtocol() == TCP, "First layer isn't of type TCP");
	PACKETPP_ASSERT(tcpPacket.getFirstLayer()->getNextLayer()->getNextLayer() == NULL, "More than 2 layers in packet");
	PACKETPP_ASSERT(tcpPacket.getRawPacket()->getRawDataLen() == 257, "Data length != 257, it's %d", tcpPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	// c. Remove last layer
	// ~~~~~~~~~~~~~~~~~~~~
	PACKETPP_ASSERT(tcpPacket.removeLayer(tcpPacket.getLastLayer()), "Remove last layer failed");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(IPv4) == false, "Packet is still of type IPv4");
	PACKETPP_ASSERT(tcpPacket.isPacketOfType(Ethernet) == false, "Packet is still of type Ethernet");
	PACKETPP_ASSERT(tcpPacket.getFirstLayer() == tcpPacket.getLastLayer(), "More than 1 layer still in packet");
	PACKETPP_ASSERT(tcpPacket.getFirstLayer()->getProtocol() == TCP, "TCP layer was accidently removed from packet");
	PACKETPP_ASSERT(tcpPacket.getRawPacket()->getRawDataLen() == 20, "Data length != 20, it's %d", tcpPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<tcpPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", tcpPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	// create packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	Packet testPacket(10);

	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, ETHERTYPE_IP);
	PACKETPP_ASSERT(testPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Address ipSrc(string("1.1.1.1"));
	IPv4Address ipDst(string("20.20.20.20"));
	IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = PACKETPP_IPPROTO_TCP;
	PACKETPP_ASSERT(testPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	PayloadLayer payloadLayer(payload, 10, true);
	PACKETPP_ASSERT(testPacket.addLayer(&payloadLayer), "Adding payload layer failed");

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");

	// a. remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PACKETPP_ASSERT(testPacket.removeLayer(&ethLayer), "Couldn't remove Eth layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer() == &ip4Layer, "IPv4 layer isn't the first layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer()->getNextLayer()->getNextLayer() == NULL, "More than 2 layers remain in packet");
	PACKETPP_ASSERT(testPacket.isPacketOfType(Ethernet) == false, "Packet is wrongly of type Ethernet");
	PACKETPP_ASSERT(testPacket.isPacketOfType(IPv4) == true, "Packet isn't of type IPv4");
	PACKETPP_ASSERT(testPacket.getRawPacket()->getRawDataLen() == 30, "Raw packet length != 30, it's %d", testPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");


	// b. remove last layer
	// ~~~~~~~~~~~~~~~~~~~~

	PACKETPP_ASSERT(testPacket.removeLayer(&payloadLayer), "Couldn't remove Payload layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer() == &ip4Layer, "IPv4 layer isn't the first layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer()->getNextLayer() == NULL, "More than 1 layer remain in packet");
	PACKETPP_ASSERT(testPacket.isPacketOfType(IPv4) == true, "Packet isn't of type IPv4");
	PACKETPP_ASSERT(testPacket.isPacketOfType(Ethernet) == false, "Packet is wrongly of type Ethernet");
	PACKETPP_ASSERT(testPacket.getRawPacket()->getRawDataLen() == 20, "Raw packet length != 20, it's %d", testPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");


	// c. insert a layer
	// ~~~~~~~~~~~~~~~~~

	VlanLayer vlanLayer(4001, 0, 0, ETHERTYPE_IP);
	PACKETPP_ASSERT(testPacket.insertLayer(NULL, &vlanLayer), "Couldn't add VLAN layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer() == &vlanLayer, "VLAN isn't the first layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer()->getNextLayer() == &ip4Layer, "IPv4 isn't the second layer");
	PACKETPP_ASSERT(testPacket.isPacketOfType(VLAN) == true, "Packet isn't of type VLAN");
	PACKETPP_ASSERT(testPacket.getRawPacket()->getRawDataLen() == 24, "Raw packet length != 24, it's %d", testPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");


	// d. remove the remaining layers (packet remains empty!)
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	PACKETPP_ASSERT(testPacket.removeLayer(&ip4Layer), "Couldn't remove IPv4 layer");
	PACKETPP_ASSERT(testPacket.getFirstLayer() == &vlanLayer, "VLAN isn't the first layer");
	PACKETPP_ASSERT(testPacket.isPacketOfType(IPv4) == false, "Packet is wrongly of type IPv4");
	PACKETPP_ASSERT(testPacket.isPacketOfType(VLAN) == true, "Packet isn't of type VLAN");
	PACKETPP_ASSERT(testPacket.getRawPacket()->getRawDataLen() == 4, "Raw packet length != 4, it's %d", testPacket.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(testPacket.removeLayer(&vlanLayer), "Couldn't remove VLAN layer");
	PACKETPP_ASSERT(testPacket.isPacketOfType(VLAN) == false, "Packet is wrongly of type VLAN");
	PACKETPP_ASSERT(testPacket.getRawPacket()->getRawDataLen() == 0, "Raw packet length != 0, it's %d", testPacket.getRawPacket()->getRawDataLen());

//	printf("\n\n\n");
//	for(int i = 0; i<testPacket.getRawPacket()->getRawDataLen(); i++)
//		printf("0x%2X ", testPacket.getRawPacket()->getRawData()[i]);
//	printf("\n\n\n");


	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(HttpRequestLayerParsingTest)
{
	// This is a basic parsing test
	// A much wider test is in Pcap++Test

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpRequests1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet httpPacket(&rawPacket);

	PACKETPP_ASSERT(httpPacket.isPacketOfType(HTTPRequest), "Packet isn't of type HTTPRequest");
	HttpRequestLayer* requestLayer = httpPacket.getLayerOfType<HttpRequestLayer>();
	PACKETPP_ASSERT(requestLayer != NULL, "Couldn't get HttpRequestLayer from packet");

	PACKETPP_ASSERT(requestLayer->getFirstLine()->getMethod() == HttpRequestLayer::HttpGET, "Request method isn't GET");
	PACKETPP_ASSERT(requestLayer->getFirstLine()->getVersion() == OneDotOne, "Request version isn't HTTP/1.1");
	PACKETPP_ASSERT(requestLayer->getFirstLine()->getUri() == "/home/0,7340,L-8,00.html", "Parsed URI is different than expected");

	HttpField* userAgent = requestLayer->getFieldByName(HTTP_USER_AGENT_FIELD);
	PACKETPP_ASSERT(userAgent != NULL, "Couldn't retrieve user-agent field");
	PACKETPP_ASSERT(userAgent->getFieldValue().find("Safari/537.36") != std::string::npos, "User-agent field doesn't contain 'Safari/537.36'");

	PACKETPP_ASSERT(requestLayer->getUrl() == "www.ynet.co.il/home/0,7340,L-8,00.html", "Got wrong URL from layer, url is: '%s'", requestLayer->getUrl().c_str());

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(HttpRequestLayerCreationTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpRequests1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket sampleRawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet sampleHttpPacket(&sampleRawPacket);

	Packet httpPacket(10);

	EthLayer ethLayer(*sampleHttpPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(httpPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Layer ip4Layer;
	ip4Layer = *(sampleHttpPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(httpPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	TcpLayer tcpLayer = *(sampleHttpPacket.getLayerOfType<TcpLayer>());
	PACKETPP_ASSERT(httpPacket.addLayer(&tcpLayer), "Adding TCP layer failed");

	HttpRequestLayer httpLayer(HttpRequestLayer::HttpOPTIONS, "/home/0,7340,L-8,00", OneDotOne);
	PACKETPP_ASSERT(httpLayer.addField(HTTP_ACCEPT_FIELD, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8") != NULL, "Couldn't add ACCEPT field");
	PACKETPP_ASSERT(httpLayer.addField("Dummy-Field", "some value") != NULL, "Couldn't add Dummy-Field field");
	HttpField* hostField = httpLayer.insertField(NULL, HTTP_HOST_FIELD, "www.ynet-ynet.co.il");
	PACKETPP_ASSERT(hostField != NULL, "Couldn't insert HOST field");
	PACKETPP_ASSERT(httpLayer.insertField(hostField, HTTP_CONNECTION_FIELD, "keep-alive") != NULL, "Couldn't add CONNECTION field");
	HttpField* userAgentField = httpLayer.addField(HTTP_USER_AGENT_FIELD, "(Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36");
	httpLayer.getFirstLine()->setUri("bla.php");
	PACKETPP_ASSERT(userAgentField != NULL, "Couldn't add USER-AGENT field");
	PACKETPP_ASSERT(httpLayer.addField(HTTP_ACCEPT_LANGUAGE_FIELD, "en-US,en;q=0.8") != NULL, "Couldn't add ACCEPT-LANGUAGE field");
	PACKETPP_ASSERT(httpLayer.addField("Dummy-Field2", "Dummy Value2") != NULL, "Couldn't add Dummy-Field2");
	PACKETPP_ASSERT(httpLayer.removeField("Dummy-Field") == true, "Couldn't remove Dummy-Field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpLayer.removeField("Kuku") == false, "Wrongly succeeded to delete a field that doesn't exist");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpLayer.addEndOfHeader() != NULL, "Couldn't add end of HTTP header");
	PACKETPP_ASSERT(httpLayer.insertField(userAgentField, HTTP_ACCEPT_ENCODING_FIELD, "gzip,deflate,sdch"), "Couldn't insert ACCEPT-ENCODING field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpLayer.addField("Kuku", "Muku") == NULL, "Wrongly succeeded to add a field after end of header");
	LoggerPP::getInstance().enableErrors();
	hostField->setFieldValue("www.walla.co.il");


	PACKETPP_ASSERT(httpPacket.addLayer(&httpLayer), "Adding HTTP request layer failed");
	hostField->setFieldValue("www.ynet.co.il");
	httpLayer.getFirstLine()->setMethod(HttpRequestLayer::HttpGET);
	httpLayer.getFirstLine()->setUri("/home/0,7340,L-8,00.html");
	PACKETPP_ASSERT(httpLayer.removeField("Dummy-Field2") == true, "Couldn't remove Dummy-Field2");
	userAgentField->setFieldValue("Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36");

	httpPacket.computeCalculateFields();

//	printf("\n\n\n");
//	for(int i = 54; i<bufferLength; i++)
//	{
//		if (buffer[i] == '\r')
//			printf("\\r");
//		else if (buffer[i] == '\n')
//			printf("\\n\n");
//		else
//			printf("%c", buffer[i]);
//	}
//	printf("\n\n\n");
//	for(int i = 54; i<httpPacket.getRawPacket()->getRawDataLen(); i++)
//	{
//		if (httpPacket.getRawPacket()->getRawData()[i] == '\r')
//			printf("\\r");
//		else if (httpPacket.getRawPacket()->getRawData()[i] == '\n')
//			printf("\\n\n");
//		else
//			printf("%c", httpPacket.getRawPacket()->getRawData()[i]);
//	}
//	printf("\n\n\n");

	PACKETPP_ASSERT(bufferLength == httpPacket.getRawPacket()->getRawDataLen(), "Raw packet length (%d) != expected length (%d)", httpPacket.getRawPacket()->getRawDataLen(), bufferLength);

	PACKETPP_ASSERT(memcmp(buffer, httpPacket.getRawPacket()->getRawData(), bufferLength) == 0, "Constructed packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(HttpRequestLayerEditTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpRequests1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet httpRequest(&rawPacket);

	IPv4Layer* ip4Layer = httpRequest.getLayerOfType<IPv4Layer>();
	ip4Layer->getIPv4Header()->ipId = htons(30170);

	TcpLayer* tcpLayer = httpRequest.getLayerOfType<TcpLayer>();
	tcpLayer->getTcpHeader()->portSrc = htons(60383);
	tcpLayer->getTcpHeader()->sequenceNumber = htonl(0x876143cb);
	tcpLayer->getTcpHeader()->ackNumber = htonl(0xa66ed328);
	tcpLayer->getTcpHeader()->windowSize = htons(16660);

	HttpRequestLayer* httpReqLayer = httpRequest.getLayerOfType<HttpRequestLayer>();
	PACKETPP_ASSERT(httpReqLayer->getFirstLine()->setUri("/Common/Api/Video/CmmLightboxPlayerJs/0,14153,061014181713,00.js") == true, "Couldn't change URI");
	HttpField* acceptField = httpReqLayer->getFieldByName(HTTP_ACCEPT_FIELD);
	PACKETPP_ASSERT(acceptField != NULL, "Cannot find ACCEPT field");
	acceptField->setFieldValue("*/*");
	HttpField* userAgentField = httpReqLayer->getFieldByName(HTTP_USER_AGENT_FIELD);
	PACKETPP_ASSERT(userAgentField != NULL, "Cannot find USER-AGENT field");
	httpReqLayer->insertField(userAgentField, HTTP_REFERER_FIELD, "http://www.ynet.co.il/home/0,7340,L-8,00.html");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/TwoHttpRequests2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file");

	PACKETPP_ASSERT(buffer2Length == httpRequest.getRawPacket()->getRawDataLen(), "Raw packet length (%d) != expected length (%d)", httpRequest.getRawPacket()->getRawDataLen(), buffer2Length);

	httpRequest.computeCalculateFields();

	PACKETPP_ASSERT(memcmp(buffer2, httpRequest.getRawPacket()->getRawData(), buffer2Length) == 0, "Constructed packet data is different than expected");

	delete [] buffer2;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(HttpResponseLayerParsingTest)
{
	// This is a basic parsing test
	// A much wider test is in Pcap++Test

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpResponses1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet httpPacket(&rawPacket);

	PACKETPP_ASSERT(httpPacket.isPacketOfType(HTTPResponse), "Packet isn't of type HTTPResponse");
	HttpResponseLayer* responseLayer = httpPacket.getLayerOfType<HttpResponseLayer>();
	PACKETPP_ASSERT(responseLayer != NULL, "Couldn't get HttpResponseLayer from packet");

	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCode() == HttpResponseLayer::Http200OK, "Response status code isn't 200 OK");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getVersion() == OneDotOne, "Response version isn't HTTP/1.1");

	HttpField* contentLengthField = responseLayer->getFieldByName(HTTP_CONTENT_LENGTH_FIELD);
	PACKETPP_ASSERT(contentLengthField != NULL, "Couldn't retrieve content-length field");
	int contentLength = atoi(contentLengthField->getFieldValue().c_str());
	PACKETPP_ASSERT(contentLength == 1616, "Content length != 1616, it's %d", contentLength);

	HttpField* contentTypeField = responseLayer->getFieldByName(HTTP_CONTENT_TYPE_FIELD);
	PACKETPP_ASSERT(contentTypeField != NULL, "Couldn't retrieve content-type field");
	PACKETPP_ASSERT(contentTypeField->getFieldValue() == "application/x-javascript", "Content type isn't 'application/x-javascript'");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(HttpResponseLayerCreationTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpResponses1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket sampleRawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet sampleHttpPacket(&sampleRawPacket);

	Packet httpPacket(100);

	EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(httpPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Layer ip4Layer(*sampleHttpPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(httpPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	TcpLayer tcpLayer(*sampleHttpPacket.getLayerOfType<TcpLayer>());
	PACKETPP_ASSERT(httpPacket.addLayer(&tcpLayer), "Adding TCP layer failed");

	HttpResponseLayer httpResponse(OneDotOne, HttpResponseLayer::Http200OK);
	PACKETPP_ASSERT(httpResponse.addField(HTTP_SERVER_FIELD, "Microsoft-IIS/5.0") != NULL, "Cannot add server field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpResponse.addField(HTTP_SERVER_FIELD, "Microsoft-IIS/6.0") == NULL, "Added the same field twice");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpResponse.addField(HTTP_CONTENT_ENCODING_FIELD, "gzip") != NULL, "Cannot add content-encoding field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName(HTTP_SERVER_FIELD), HTTP_CONTENT_TYPE_FIELD, "application/x-javascript") != NULL, "Cannot insert content-type field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName(HTTP_CONTENT_TYPE_FIELD), "Accept-Ranges", "bytes") != NULL, "Cannot insert accept-ranges field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("Accept-Ranges"), "KuKu", "BlaBla") != NULL, "Cannot insert KuKu field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("kuku"), "Last-Modified", "Wed, 19 Dec 2012 14:06:29 GMT") != NULL, "Cannot insert last-modified field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("last-Modified"), "ETag", "\"3b846daf2ddcd1:e29\"") != NULL, "Cannot insert etag field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("etag"), "Vary", "Accept-Encoding") != NULL, "Cannot insert vary field");
	PACKETPP_ASSERT(httpResponse.setContentLength(1616, HTTP_CONTENT_ENCODING_FIELD) != NULL, "Cannot set content-length");
	PACKETPP_ASSERT(httpResponse.addField("Kuku2", "blibli2") != NULL, "Cannot add Kuku2 field");
	PACKETPP_ASSERT(httpResponse.addField("Cache-Control", "max-age=66137") != NULL, "Cannot add cache-control field");
	PACKETPP_ASSERT(httpResponse.removeField("KUKU") == true, "Couldn't remove kuku field");

	PACKETPP_ASSERT(httpPacket.addLayer(&httpResponse) == true, "Cannot add HTTP response layer");

	PayloadLayer payloadLayer = *sampleHttpPacket.getLayerOfType<PayloadLayer>();
	PACKETPP_ASSERT(httpPacket.addLayer(&payloadLayer) == true, "Cannot add payload layer");

	PACKETPP_ASSERT(httpResponse.addField(HTTP_CONNECTION_FIELD, "keep-alive") != NULL, "Cannot add connection field");
	PACKETPP_ASSERT(httpResponse.addEndOfHeader() != NULL, "Cannot add end of header");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("Cache-Control"), "Expires", "Mon, 20 Oct 2014 13:34:26 GMT") != NULL, "Cannot insert expires field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpResponse.addField("kuku3", "kuka") == NULL, "Added a field after end of header");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("ExpIRes"), "Date", "Sun, 19 Oct 2014 19:12:09 GMT") != NULL, "Cannot insert date field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpResponse.removeField("kuku5") == false, "Managed to remove a field that doesn't exist");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpResponse.removeField("kuku2") == true, "Cannot remove kuku2 field");


	httpPacket.computeCalculateFields();

	PACKETPP_ASSERT(httpResponse.getHeaderLen() == 382, "HTTP header length is different than expected. Expected: %d; Actual: %d", 382, httpResponse.getHeaderLen());

	PACKETPP_ASSERT(memcmp(buffer, httpPacket.getRawPacket()->getRawData(), ethLayer.getHeaderLen()+ip4Layer.getHeaderLen()+tcpLayer.getHeaderLen()+httpResponse.getHeaderLen()) == 0, "Constructed packet data is different than expected");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(HttpResponseLayerEditTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpResponses2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet httpPacket(&rawPacket);

	PACKETPP_ASSERT(httpPacket.isPacketOfType(HTTPResponse), "Packet isn't of type HTTPResponse");
	HttpResponseLayer* responseLayer = httpPacket.getLayerOfType<HttpResponseLayer>();
	PACKETPP_ASSERT(responseLayer != NULL, "Couldn't get HttpResponseLayer from packet");

	PACKETPP_ASSERT(responseLayer->getFirstLine()->isComplete() == true, "Http response not complete");
	responseLayer->getFirstLine()->setVersion(OneDotOne);
	PACKETPP_ASSERT(responseLayer->getFirstLine()->setStatusCode(HttpResponseLayer::Http505HTTPVersionNotSupported) == true, "Couldn't change status code to 505");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCode() == HttpResponseLayer::Http505HTTPVersionNotSupported, "Status code isn't HttpResponseLayer::Http505HTTPVersionNotSupported");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCodeAsInt() == 505, "Status code isn't 505");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCodeString() == "HTTP Version Not Supported", "Status isn't 'HTTP Version Not Supported'");

	PACKETPP_ASSERT(responseLayer->setContentLength(345) != NULL, "Couldn't change content length");

	std::string expectedHttpResponse("HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 345\r\n");

	PACKETPP_ASSERT(memcmp(expectedHttpResponse.c_str(), responseLayer->getData(), expectedHttpResponse.length()) == 0, "Edited HTTP response is different than expected");

	PACKETPP_ASSERT(responseLayer->getFirstLine()->setStatusCode(HttpResponseLayer::Http413RequestEntityTooLarge, "This is a test") == true, "Couldn't change status code to 413");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCodeAsInt() == 413, "Status code isn't 413");
	PACKETPP_ASSERT(responseLayer->getFirstLine()->getStatusCodeString() == "This is a test", "Status isn't 'HTTP Version Not Supported'");

	expectedHttpResponse = "HTTP/1.1 413 This is a test\r\nContent-Length: 345\r\n";
	PACKETPP_ASSERT(memcmp(expectedHttpResponse.c_str(), responseLayer->getData(), expectedHttpResponse.length()) == 0, "Edited HTTP response is different than expected (2)");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(PPPoESessionLayerParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/PPPoESession1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet pppoesPacket(&rawPacket);

	PACKETPP_ASSERT(pppoesPacket.isPacketOfType(PPPoE), "Packet isn't of type PPPoE");
	PACKETPP_ASSERT(pppoesPacket.isPacketOfType(PPPoESession), "Packet isn't of type PPPoESession");
	PPPoESessionLayer* pppoeSessionLayer = pppoesPacket.getLayerOfType<PPPoESessionLayer>();
	PACKETPP_ASSERT(pppoeSessionLayer != NULL, "Couldn't find PPPoESessionLayer, returned NULL");

	PACKETPP_ASSERT(pppoeSessionLayer->getPrevLayer() != NULL, "PPPoESession layer is the first layer");
	PACKETPP_ASSERT(pppoeSessionLayer->getPrevLayer()->getProtocol() == Ethernet, "PPPoESession prev layer isn't Eth");
	PACKETPP_ASSERT(pppoeSessionLayer->getNextLayer() != NULL, "PPPoESession layer is the last layer");
	PACKETPP_ASSERT(pppoeSessionLayer->getNextLayer()->getProtocol() == Unknown, "PPPoESession layer next layer isn't PayloadLayer");

	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->code == PPPoELayer::PPPOE_CODE_SESSION, "PPPoE code isn't PPPOE_CODE_SESSION");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->version == 1, "PPPoE version isn't 1");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->type == 1, "PPPoE type isn't 1");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->sessionId == htons(0x0011), "PPPoE session ID isn't 0x0011");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->payloadLength == htons(20), "PPPoE payload length isn't 20");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPNextProtocol() == PPP_LCP, "PPPoE next protocol isn't LCP");

	PACKETPP_ASSERT(pppoeSessionLayer->toString() == string("PPP-over-Ethernet Session (followed by 'Link Control Protocol')"), "PPPoESession toString failed");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(PPPoESessionLayerCreationTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/PPPoESession2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet samplePacket(&rawPacket);

	Packet pppoesPacket(1);

	EthLayer ethLayer(*samplePacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(pppoesPacket.addLayer(&ethLayer), "Add EthLayer failed");

	PPPoESessionLayer pppoesLayer(1, 1, 0x0011, PPP_IPV6);
	PACKETPP_ASSERT(pppoesPacket.addLayer(&pppoesLayer), "Add PPPoESession layer failed");

	IPv6Layer ipv6Layer(*samplePacket.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(pppoesPacket.addLayer(&ipv6Layer), "Add IPv6Layer failed");

	UdpLayer udpLayer(*samplePacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(pppoesPacket.addLayer(&udpLayer), "Add UdpLayer failed");

	PayloadLayer payloadLayer(*samplePacket.getLayerOfType<PayloadLayer>());
	PACKETPP_ASSERT(pppoesPacket.addLayer(&payloadLayer), "Add PayloadLayer failed");

	pppoesPacket.computeCalculateFields();

	PACKETPP_ASSERT(bufferLength == pppoesPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", pppoesPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(pppoesPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(PPPoEDiscoveryLayerParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/PPPoEDiscovery2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet pppoedPacket(&rawPacket);

	PACKETPP_ASSERT(pppoedPacket.isPacketOfType(PPPoE), "Packet isn't of type PPPoE");
	PACKETPP_ASSERT(pppoedPacket.isPacketOfType(PPPoEDiscovery), "Packet isn't of type PPPoEDiscovery");
	PACKETPP_ASSERT(!pppoedPacket.isPacketOfType(PPPoESession), "Packet is of type PPPoESession");

	PPPoEDiscoveryLayer* pppoeDiscoveryLayer = pppoedPacket.getLayerOfType<PPPoEDiscoveryLayer>();
	PACKETPP_ASSERT(pppoeDiscoveryLayer != NULL, "Couldn't find PPPoEDiscoveryLayer, returned NULL");

	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPrevLayer() != NULL, "PPPoEDiscovery layer is the first layer");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getNextLayer() == NULL, "PPPoEDiscovery layer isn't the last layer");

	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPPPoEHeader()->code == PPPoELayer::PPPOE_CODE_PADS, "PPPoE code isn't PPPOE_CODE_PADS");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPPPoEHeader()->version == 1, "PPPoE version isn't 1");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPPPoEHeader()->type == 1, "PPPoE type isn't 1");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPPPoEHeader()->sessionId == htons(0x0011), "PPPoE session ID isn't 0x0011");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getPPPoEHeader()->payloadLength == htons(40), "PPPoE payload length isn't 40");

	PPPoEDiscoveryLayer::PPPoETag* firstTag = pppoeDiscoveryLayer->getFirstTag();
	PACKETPP_ASSERT(firstTag != NULL, "Couldn't retrieve first tag, NULL returned");
	PACKETPP_ASSERT(firstTag->getType() == PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME, "First tag type isn't PPPOE_TAG_SVC_NAME");
	PACKETPP_ASSERT(firstTag->tagDataLength == 0, "first tag length != 0");

	PPPoEDiscoveryLayer::PPPoETag* secondTag = pppoeDiscoveryLayer->getNextTag(firstTag);
	PACKETPP_ASSERT(secondTag != NULL, "Couldn't retrieve second tag, NULL returned");
	PACKETPP_ASSERT(secondTag->getType() == PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, "Second tag type isn't PPPOE_TAG_HOST_UNIQ");
	PACKETPP_ASSERT(secondTag->tagDataLength == htons(4), "Second tag length != 4");
	PACKETPP_ASSERT(ntohl(secondTag->getTagDataAs<uint32_t>()) == 0x64138518, "Second tag data is wrong");

	PPPoEDiscoveryLayer::PPPoETag* thirdTag = pppoeDiscoveryLayer->getTag(PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME);
	PACKETPP_ASSERT(thirdTag != NULL, "Couldn't retrieve tag PPPOE_TAG_AC_NAME by name, NULL returned");
	PACKETPP_ASSERT(thirdTag == pppoeDiscoveryLayer->getNextTag(secondTag), "getTag and getNextTag returned different results for third tag");
	PACKETPP_ASSERT(thirdTag->getType() == PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, "Third tag type isn't PPPOE_TAG_AC_NAME");
	PACKETPP_ASSERT(thirdTag->tagDataLength == htons(4), "Third tag length != 4");
	PACKETPP_ASSERT(ntohl(thirdTag->getTagDataAs<uint32_t>()) == 0x42524153, "Third tag data is wrong");

	PPPoEDiscoveryLayer::PPPoETag* fourthTag = pppoeDiscoveryLayer->getTag(PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE);
	PACKETPP_ASSERT(fourthTag != NULL, "Couldn't retrieve tag PPPOE_TAG_AC_COOKIE by name, NULL returned");
	PACKETPP_ASSERT(fourthTag == pppoeDiscoveryLayer->getNextTag(thirdTag), "getTag and getNextTag returned different results for fourth tag");
	PACKETPP_ASSERT(fourthTag->getType() == PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, "Fourth tag type isn't PPPOE_TAG_AC_COOKIE");
	PACKETPP_ASSERT(fourthTag->tagDataLength == htons(16), "Fourth tag length != 16");
	PACKETPP_ASSERT(fourthTag->getTagDataAs<uint64_t>() == 0xf284240687050f3dULL, "Fourth tag data is wrong in first 8 bytes");
	PACKETPP_ASSERT(fourthTag->getTagDataAs<uint64_t>(8) == 0x5bbd77fdddb932dfULL, "Fourth tag data is wrong in last 8 bytes");
	PACKETPP_ASSERT(pppoeDiscoveryLayer->getNextTag(fourthTag) == NULL, "Fourth tag should be the last one but it isn't");

	PACKETPP_ASSERT(pppoeDiscoveryLayer->getTagCount() == 4, "Number of tags != 4, it's %d", pppoeDiscoveryLayer->getTagCount());

	PACKETPP_ASSERT(pppoeDiscoveryLayer->toString() == string("PPP-over-Ethernet Discovery (PADS)"), "PPPoEDiscovery toString returned unexpected result");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(PPPoEDiscoveryLayerCreateTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/PPPoEDiscovery1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file PPPoEDiscovery1.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet samplePacket(&rawPacket);

	Packet pppoedPacket(1);

	EthLayer ethLayer(*samplePacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(pppoedPacket.addLayer(&ethLayer), "Add EthLayer failed");

	PPPoEDiscoveryLayer pppoedLayer(1, 1, PPPoELayer::PPPOE_CODE_PADI, 0);

	PACKETPP_ASSERT(pppoedPacket.addLayer(&pppoedLayer), "Add PPPoEDiscovery layer failed");

	PPPoEDiscoveryLayer::PPPoETag* svcNamePtr = pppoedLayer.addTag(PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME, 0, NULL);

	uint32_t hostUniqData = htonl(0x64138518);
	pppoedLayer.addTagAfter(PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, sizeof(uint32_t), (uint8_t*)(&hostUniqData), svcNamePtr);

	pppoedPacket.computeCalculateFields();

	PACKETPP_ASSERT(bufferLength == pppoedPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", pppoedPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(pppoedPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected PPPoEDiscovery1");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/PPPoEDiscovery2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file PPPoEDiscovery2.dat");

	EthLayer* ethLayerPtr = pppoedPacket.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(ethLayerPtr != NULL, "Couldn't retrieve Eth layer");
	ethLayerPtr->setSoureMac(MacAddress("ca:01:0e:88:00:06"));
	ethLayerPtr->setDestMac(MacAddress("cc:05:0e:88:00:00"));

	pppoedLayer.getPPPoEHeader()->code = PPPoELayer::PPPOE_CODE_PADS;
	pppoedLayer.getPPPoEHeader()->sessionId = htons(0x11);

	PPPoEDiscoveryLayer::PPPoETag* acCookieTag = pppoedLayer.addTag(PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, 16, NULL);
	acCookieTag->setTagData<uint64_t>(0xf284240687050f3dULL);
	acCookieTag->setTagData<uint64_t>(0x5bbd77fdddb932dfULL, 8);

	pppoedLayer.addTagAfter(PPPoEDiscoveryLayer::PPPOE_TAG_HURL, sizeof(uint32_t), (uint8_t*)(&hostUniqData), acCookieTag);

	PPPoEDiscoveryLayer::PPPoETag* hostUniqTag = pppoedLayer.getTag(PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ);
	PACKETPP_ASSERT(hostUniqTag != NULL, "Couldn't retrieve tag PPPOE_TAG_HOST_UNIQ");
	PPPoEDiscoveryLayer::PPPoETag* acNameTag = pppoedLayer.addTagAfter(PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 4, NULL, hostUniqTag);
	acNameTag->setTagData<uint32_t>(htonl(0x42524153));

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(pppoedLayer.removeTag(PPPoEDiscoveryLayer::PPPOE_TAG_CREDITS) == false, "Managed to remove a tag that doesn't exist");
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(pppoedLayer.removeTag(PPPoEDiscoveryLayer::PPPOE_TAG_HURL) == true, "Couldn't remove tag PPPOE_TAG_HURL");
	PACKETPP_ASSERT(pppoedLayer.getTag(PPPoEDiscoveryLayer::PPPOE_TAG_HURL) == NULL, "Found a tag that was removed");

	pppoedPacket.computeCalculateFields();

//	printf("\n\n\n");
//	for(int i = 0; i<buffer2Length; i++)
//		printf(" 0x%2X  ", buffer2[i]);
//	printf("\n\n\n");
//	for(int i = 0; i<buffer2Length; i++)
//	{
//		if (pppoedPacket.getRawPacket()->getRawData()[i] != buffer2[i])
//			printf("*0x%2X* ", pppoedPacket.getRawPacket()->getRawData()[i]);
//		else
//			printf(" 0x%2X  ", pppoedPacket.getRawPacket()->getRawData()[i]);
//	}
//	printf("\n\n\n");

	PACKETPP_ASSERT(buffer2Length == pppoedPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", pppoedPacket.getRawPacket()->getRawDataLen(), buffer2Length);
	PACKETPP_ASSERT(memcmp(pppoedPacket.getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Raw packet data is different than expected PPPoEDiscovery2");

	delete [] buffer2;

	PACKETPP_ASSERT(pppoedLayer.removeAllTags() == true, "Couldn't remove all tags");
	pppoedPacket.computeCalculateFields();

	PACKETPP_ASSERT(pppoedLayer.getHeaderLen() == sizeof(pppoe_header), "PPPoED layer after removing all tags doesn't equal sizeof(pppoe_header)");
	PACKETPP_ASSERT(pppoedLayer.getPPPoEHeader()->payloadLength == 0, "PayloadLength after removing all tags isn't 0");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DnsLayerParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/Dns3.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file Dns3.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet dnsPacket(&rawPacket);

	DnsLayer* dnsLayer = dnsPacket.getLayerOfType<DnsLayer>();

	PACKETPP_ASSERT(dnsLayer != NULL, "Couldn't find DnsLayer");
	PACKETPP_ASSERT(dnsLayer->getQueryCount() == 2, "Number of DNS queries != 2");
	PACKETPP_ASSERT(dnsLayer->getAnswerCount() == 0, "Number of DNS answers != 0");
	PACKETPP_ASSERT(dnsLayer->getAuthorityCount() == 2, "Number of DNS authority != 2");
	PACKETPP_ASSERT(dnsLayer->getAdditionalRecordCount() == 1, "Number of DNS additional != 1");
	PACKETPP_ASSERT(ntohs(dnsLayer->getDnsHeader()->transactionID) == 0, "DNS transaction ID != 0");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->queryOrResponse == 0, "Packet isn't a query");

	DnsQuery* firstQuery = dnsLayer->getFirstQuery();
	PACKETPP_ASSERT(firstQuery != NULL, "First query returned NULL");
	PACKETPP_ASSERT(firstQuery->getName() == "Yaels-iPhone.local", "First query name != 'Yaels-iPhone.local'");
	PACKETPP_ASSERT(firstQuery->getDnsType() == DNS_TYPE_ALL, "First query type != DNS_TYPE_ALL, it's %d", firstQuery->getDnsType());
	PACKETPP_ASSERT(firstQuery->getDnsClass() == DNS_CLASS_IN, "First query class != DNS_CLASS_IN");

	DnsQuery* secondQuery = dnsLayer->getNextQuery(firstQuery);
	PACKETPP_ASSERT(secondQuery != NULL, "Second query returned NULL");
	PACKETPP_ASSERT(secondQuery->getName() == "Yaels-iPhone.local", "Second query name != 'Yaels-iPhone.local'");
	PACKETPP_ASSERT(secondQuery->getDnsType() == DNS_TYPE_ALL, "Second query type != DNS_TYPE_ALL");
	PACKETPP_ASSERT(secondQuery->getDnsClass() == DNS_CLASS_IN, "Second query class != DNS_CLASS_IN");
	PACKETPP_ASSERT(dnsLayer->getNextQuery(secondQuery) == NULL, "Unexpected third query in packet");

	DnsQuery* queryByName = dnsLayer->getQuery(string("Yaels-iPhone.local"), true);
	PACKETPP_ASSERT(queryByName != NULL, "Query by name returned NULL");
	PACKETPP_ASSERT(queryByName == firstQuery, "Query by name returned a query different from first query");
	PACKETPP_ASSERT(dnsLayer->getQuery(string("www.seladb.com"), true) == NULL, "Query by wrong name returned a result");

	DnsResource* firstAuthority = dnsLayer->getFirstAuthority();
	PACKETPP_ASSERT(firstAuthority != NULL, "Get first authority returned NULL");
	PACKETPP_ASSERT(firstAuthority->getDnsType() == DNS_TYPE_A, "First authority type isn't A");
	PACKETPP_ASSERT(firstAuthority->getDnsClass() == DNS_CLASS_IN, "First authority class isn't IN");
	PACKETPP_ASSERT(firstAuthority->getTTL() == 120, "First authority TTL != 120");
	PACKETPP_ASSERT(firstAuthority->getName() == "Yaels-iPhone.local", "First authority name isn't 'Yaels-iPhone.local'");
	PACKETPP_ASSERT(firstAuthority->getDataLength() == 4, "First authority data size != 4");
	PACKETPP_ASSERT(firstAuthority->getDataAsString() == "10.0.0.2", "First authority data != 10.0.0.2");
	PACKETPP_ASSERT(firstAuthority->getSize() == 16, "First authority total size != 16");

	DnsResource* secondAuthority = dnsLayer->getNextAuthority(firstAuthority);
	PACKETPP_ASSERT(secondAuthority != NULL, "Get next authority returned NULL");
	PACKETPP_ASSERT(secondAuthority->getDnsType() == DNS_TYPE_AAAA, "Second authority type isn't AAAA");
	PACKETPP_ASSERT(secondAuthority->getDnsClass() == DNS_CLASS_IN, "Second authority class isn't IN");
	PACKETPP_ASSERT(secondAuthority->getTTL() == 120, "Second authority TTL != 120");
	PACKETPP_ASSERT(secondAuthority->getName() == "Yaels-iPhone.local", "Second authority name isn't 'Yaels-iPhone.local'");
	PACKETPP_ASSERT(secondAuthority->getDataLength() == 16, "Second authority data size != 16");
	PACKETPP_ASSERT(secondAuthority->getDataAsString() == "fe80::5a1f:aaff:fe4f:3f9d", "Second authority data != fe80::5a1f:aaff:fe4f:3f9d");
	PACKETPP_ASSERT(secondAuthority->getSize() == 28, "Second authority total size != 28");

	DnsResource* thirdAuthority = dnsLayer->getNextAuthority(secondAuthority);
	PACKETPP_ASSERT(thirdAuthority == NULL, "Found an imaginary third authority");

	PACKETPP_ASSERT(dnsLayer->getAuthority("Yaels-iPhon", false) == firstAuthority, "Get authority by name didn't return the first authority");
	PACKETPP_ASSERT(dnsLayer->getAuthority("www.google.com", false) == NULL, "Found imaginary authority record");

	DnsResource* additionalRecord = dnsLayer->getFirstAdditionalRecord();
	PACKETPP_ASSERT(additionalRecord != NULL, "Couldn't find additional record");
	PACKETPP_ASSERT(additionalRecord->getDnsType() == DNS_TYPE_OPT, "Additional record type isn't OPT");
	PACKETPP_ASSERT(additionalRecord->getDnsClass() == 0x05a0, "Additional record 'class' isn't 0x05a0, it's 0x%X", additionalRecord->getDnsClass());
	PACKETPP_ASSERT(additionalRecord->getTTL() == 0x1194, "Additional record 'TTL' != 0x1194, it's 0x%X", additionalRecord->getTTL());
	PACKETPP_ASSERT(additionalRecord->getName() == "", "Additional record name isn't empty");
	PACKETPP_ASSERT(additionalRecord->getDataLength() == 12, "Second authority data size != 12");
	PACKETPP_ASSERT(additionalRecord->getDataAsString() == "0x0004000800df581faa4f3f9d", "Additional record unexpected data: %s", additionalRecord->getDataAsString().c_str());
	PACKETPP_ASSERT(additionalRecord->getSize() == 23, "Second authority total size != 23");
	PACKETPP_ASSERT(dnsLayer->getNextAdditionalRecord(additionalRecord) == NULL, "Found imaginary additional record");
	PACKETPP_ASSERT(dnsLayer->getAdditionalRecord("", true) == additionalRecord, "Couldn't find additional record by (empty) name");

	PACKETPP_ASSERT(dnsLayer->toString() == "DNS query, ID: 0; queries: 2, answers: 0, authorities: 2, additional record: 1", "Dns3 toString gave the wrong output");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/Dns1.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file Dns1.dat");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet dnsPacket2(&rawPacket2);

	dnsLayer = dnsPacket2.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer != NULL, "Couldn't find DnsLayer");
	PACKETPP_ASSERT(ntohs(dnsLayer->getDnsHeader()->transactionID) == 0x2d6d, "DNS transaction ID != 0x2d6d");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->queryOrResponse == 1, "Packet isn't a response");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->recursionAvailable == 1, "recursionAvailable flag != 1");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->recursionDesired == 1, "recursionDesired flag != 1");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->opcode == 0, "opCode flag != 0");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->authoritativeAnswer == 0, "authoritativeAnswer flag != 0");
	PACKETPP_ASSERT(dnsLayer->getDnsHeader()->checkingDisabled == 0, "checkingDisabled flag != 0");
	firstQuery = dnsLayer->getFirstQuery();
	PACKETPP_ASSERT(firstQuery != NULL, "First query returned NULL for Dns1.dat");
	PACKETPP_ASSERT(firstQuery->getName() == "www.google-analytics.com", "First query name != 'www.google-analytics.com'");
	PACKETPP_ASSERT(firstQuery->getDnsType() == DNS_TYPE_A, "DNS type != DNS_TYPE_A");

	DnsResource* curAnswer = dnsLayer->getFirstAnswer();
	PACKETPP_ASSERT(curAnswer != NULL, "Couldn't find first answer");
	PACKETPP_ASSERT(curAnswer->getDnsType() == DNS_TYPE_CNAME, "First answer type isn't CNAME");
	PACKETPP_ASSERT(curAnswer->getDnsClass() == DNS_CLASS_IN, "First answer class isn't IN");
	PACKETPP_ASSERT(curAnswer->getTTL() == 57008, "First answer TTL != 57008");
	PACKETPP_ASSERT(curAnswer->getName() == "www.google-analytics.com", "First answer name isn't 'www.google-analytics.com'");
	PACKETPP_ASSERT(curAnswer->getDataLength() == 32, "First answer data size != 32");
	PACKETPP_ASSERT(curAnswer->getDataAsString() == "www-google-analytics.l.google.com", "First answer data != 'www-google-analytics.l.google.com'. It's '%s'", curAnswer->getDataAsString().c_str());
	PACKETPP_ASSERT(curAnswer->getSize() == 44, "First authority total size != 44");

	curAnswer = dnsLayer->getNextAnswer(curAnswer);
	int answerCount = 2;
	string addrPrefix = "212.199.219.";
	while (curAnswer != NULL)
	{
		PACKETPP_ASSERT(curAnswer->getDnsType() == DNS_TYPE_A, "Answer #%d type isn't A", answerCount);
		PACKETPP_ASSERT(curAnswer->getDnsClass() == DNS_CLASS_IN, "Answer #%d class isn't IN", answerCount);
		PACKETPP_ASSERT(curAnswer->getTTL() == 117, "Answer #%d TTL != 117", answerCount);
		PACKETPP_ASSERT(curAnswer->getName() == "www-google-analytics.L.google.com", "Answer #%d name isn't 'www-google-analytics.L.google.com'", answerCount);
		PACKETPP_ASSERT(curAnswer->getDataLength() == 4, "Answer #%d data size != 4", answerCount);
		PACKETPP_ASSERT(curAnswer->getDataAsString().substr(0, addrPrefix.size()) == addrPrefix, "Answer #%d data != '212.199.219.X'", answerCount);

		curAnswer = dnsLayer->getNextAnswer(curAnswer);
		answerCount++;
	}

	PACKETPP_ASSERT(answerCount == 18, "Found more/less than 17 answers");

	PACKETPP_ASSERT(dnsLayer->getAnswer("www.google-analytics.com", false) == dnsLayer->getFirstAnswer(), "Couldn't find answer by name 1");
	PACKETPP_ASSERT(dnsLayer->getAnswer("www-google-analytics.L.google.com", true) == dnsLayer->getNextAnswer(dnsLayer->getFirstAnswer()), "Couldn't find answer by name 2");

	PACKETPP_ASSERT(dnsLayer->toString() == "DNS query response, ID: 11629; queries: 1, answers: 17, authorities: 0, additional record: 0", "Dns1 toString gave the wrong output");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/Dns2.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file Dns2.dat");

	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);

	Packet dnsPacket3(&rawPacket3);

	dnsLayer = dnsPacket3.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer != NULL, "Couldn't find DnsLayer");
	queryByName = dnsLayer->getQuery(string("Yaels-iPhone.loca"), false);
	PACKETPP_ASSERT(queryByName != NULL, "Query by name returned NULL for Dns2.dat");
	PACKETPP_ASSERT(queryByName->getDnsClass() == DNS_CLASS_IN_QU, "Query class != DNS_CLASS_IN_QU");

	PACKETPP_ASSERT(dnsLayer->toString() == "DNS query, ID: 0; queries: 2, answers: 0, authorities: 2, additional record: 1", "Dns2 toString gave the wrong output");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DnsLayerQueryCreationTest)
{
	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/DnsEdit2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file DnsEdit2.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket raw2Packet((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet dnsEdit2RefPacket(&raw2Packet);

	Packet dnsEdit2Packet(1);

	EthLayer ethLayer2(*dnsEdit2RefPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(dnsEdit2Packet.addLayer(&ethLayer2), "Add EthLayer failed");

	IPv4Layer ipLayer2(*dnsEdit2RefPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(dnsEdit2Packet.addLayer(&ipLayer2), "Add IPv4Layer failed");

	UdpLayer udpLayer2(*dnsEdit2RefPacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(dnsEdit2Packet.addLayer(&udpLayer2), "Add UdpLayer failed");

	DnsLayer dns2Layer;
	dns2Layer.getDnsHeader()->recursionDesired = true;
	dns2Layer.getDnsHeader()->transactionID = htons(0xb179);
	DnsQuery* newQuery = dns2Layer.addQuery("mail-attachment.googleusercontent.com", DNS_TYPE_A, DNS_CLASS_IN);
	PACKETPP_ASSERT(newQuery != NULL, "Couldn't add query for DnsEdit2");
	PACKETPP_ASSERT(dns2Layer.getQueryCount() == 1, "Query count != 1 after adding a query for DnsEdit2");
	PACKETPP_ASSERT(newQuery->getName() == "mail-attachment.googleusercontent.com", "Name of new query is wrong");

	dnsEdit2Packet.addLayer(&dns2Layer);

	dnsEdit2Packet.computeCalculateFields();

	PACKETPP_ASSERT(buffer2Length == dnsEdit2Packet.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", dnsEdit2Packet.getRawPacket()->getRawDataLen(), buffer2Length);

	PACKETPP_ASSERT(memcmp(dnsEdit2Packet.getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Raw packet data is different than expected DnsEdit2");


	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/DnsEdit1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file DnsEdit1.dat");

	gettimeofday(&time, NULL);
	RawPacket raw1Packet((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet dnsEdit1RefPacket(&raw1Packet);

	Packet dnsEdit1Packet(1);

	EthLayer ethLayer1(*dnsEdit1RefPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(dnsEdit1Packet.addLayer(&ethLayer1), "Add EthLayer failed");

	IPv4Layer ipLayer1(*dnsEdit1RefPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(dnsEdit1Packet.addLayer(&ipLayer1), "Add IPv4Layer failed");

	UdpLayer udpLayer1(*dnsEdit1RefPacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(dnsEdit1Packet.addLayer(&udpLayer1), "Add UdpLayer failed");

	DnsLayer dns1Layer;

	dnsEdit1Packet.addLayer(&dns1Layer);

	newQuery = dns1Layer.addQuery("_apple-mobdev._tcp.local", DNS_TYPE_PTR, DNS_CLASS_IN);
	PACKETPP_ASSERT(newQuery != NULL, "Couldn't add query for DnsEdit1");
	PACKETPP_ASSERT(dns1Layer.getQueryCount() == 1, "Query count != 1 after adding a query for DnsEdit1");

	newQuery = dns1Layer.addQuery(newQuery);
	PACKETPP_ASSERT(newQuery != NULL, "Couldn't add second query for DnsEdit1");
	PACKETPP_ASSERT(dns1Layer.getQueryCount() == 2, "Query count != 2 after adding a second query for DnsEdit1");

	PACKETPP_ASSERT(newQuery->setName("_sleep-proxy._udp.local") == true, "Couldn't set name for DnsEdit1");

	PACKETPP_ASSERT(dns1Layer.addQuery(NULL) == NULL, "adding a null record accidently succeeded");
	PACKETPP_ASSERT(dns1Layer.getQueryCount() == 2, "Query count != 2 after adding a second query and null query for DnsEdit1");

	dnsEdit1Packet.computeCalculateFields();

	PACKETPP_ASSERT(buffer1Length == dnsEdit1Packet.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", dnsEdit1Packet.getRawPacket()->getRawDataLen(), buffer1Length);

	PACKETPP_ASSERT(memcmp(dnsEdit1Packet.getRawPacket()->getRawData(), buffer1, buffer1Length) == 0, "Raw packet data is different than expected DnsEdit1");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DnsLayerResourceCreationTest)
{
	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/DnsEdit4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file DnsEdit4.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket raw4Packet((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet dnsEdit4RefPacket(&raw4Packet);

	Packet dnsEdit4Packet(1);

	EthLayer ethLayer4(*dnsEdit4RefPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(dnsEdit4Packet.addLayer(&ethLayer4), "Add EthLayer failed");

	IPv4Layer ipLayer4(*dnsEdit4RefPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(dnsEdit4Packet.addLayer(&ipLayer4), "Add IPv4Layer failed");

	UdpLayer udpLayer4(*dnsEdit4RefPacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(dnsEdit4Packet.addLayer(&udpLayer4), "Add UdpLayer failed");

	DnsLayer dns4Layer;
	dns4Layer.getDnsHeader()->transactionID = htons(14627);
	dns4Layer.getDnsHeader()->queryOrResponse = 1;
	dns4Layer.getDnsHeader()->recursionDesired = 1;
	dns4Layer.getDnsHeader()->recursionAvailable = 1;

	DnsResource* firstAnswer = dns4Layer.addAnswer("assets.pinterest.com", DNS_TYPE_CNAME, DNS_CLASS_IN, 228, "assets.pinterest.com.cdngc.net");
	PACKETPP_ASSERT(firstAnswer != NULL, "Couldn't add first answer");
	PACKETPP_ASSERT(dns4Layer.getFirstAnswer() == firstAnswer, "Couldn't retrieve first answer from layer");
	PACKETPP_ASSERT(firstAnswer->getDataAsString() == "assets.pinterest.com.cdngc.net", "Couldn't retrieve data for first answer");

	PACKETPP_ASSERT(dnsEdit4Packet.addLayer(&dns4Layer), "Add DnsLayer failed");

	PACKETPP_ASSERT(dnsEdit4Packet.getLayerOfType<DnsLayer>()->getFirstAnswer() == firstAnswer, "Couldn't retrieve first answer from layer after adding layer to packet");

	DnsResource* secondAnswer = dns4Layer.addAnswer("assets.pinterest.com.cdngc.net", DNS_TYPE_A, DNS_CLASS_IN, 3, "151.249.90.217");
	PACKETPP_ASSERT(secondAnswer != NULL, "Couldn't add second answer");
	PACKETPP_ASSERT(secondAnswer->getDataAsString() == "151.249.90.217", "Couldn't retrieve data for second answer");

	DnsQuery* query = dns4Layer.addQuery("assets.pinterest.com", DNS_TYPE_A, DNS_CLASS_IN);
	PACKETPP_ASSERT(query != NULL, "Couldn't add query");

	PACKETPP_ASSERT(dnsEdit4Packet.getLayerOfType<DnsLayer>()->getFirstAnswer() == firstAnswer, "Couldn't retrieve first answer from layer after adding query");
	PACKETPP_ASSERT(dnsEdit4Packet.getLayerOfType<DnsLayer>()->getNextAnswer(firstAnswer) == secondAnswer, "Couldn't retrieve second answer from layer after adding query");

	DnsResource* thirdAnswer = dns4Layer.addAnswer(secondAnswer);
	PACKETPP_ASSERT(thirdAnswer != NULL, "Couldn't add third answer");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(thirdAnswer->setData("256.249.90.238") == false, "Managed to set illegal IPv4 address in third answer");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(thirdAnswer->setData("151.249.90.238") == true, "Couldn't set data for third answer");

	PACKETPP_ASSERT(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", true)->getDataAsString() == "151.249.90.217", "Couldn't retrieve data for second answer after adding third answer");
	PACKETPP_ASSERT(dns4Layer.getNextAnswer(dns4Layer.getAnswer("assets.pinterest.com.cdngc.net", false))->getDataAsString() == "151.249.90.238", "Couldn't retrieve data for third answer after adding third answer");

	dnsEdit4Packet.computeCalculateFields();

	PACKETPP_ASSERT(buffer4Length == dnsEdit4Packet.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", dnsEdit4Packet.getRawPacket()->getRawDataLen(), buffer4Length);

	PACKETPP_ASSERT(memcmp(dnsEdit4Packet.getRawPacket()->getRawData(), buffer4, buffer4Length) == 0, "Raw packet data is different than expected DnsEdit4");



	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/DnsEdit6.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file DnsEdit6.dat");

	gettimeofday(&time, NULL);
	RawPacket raw6Packet((const uint8_t*)buffer6, buffer6Length, time, true);

	Packet dnsEdit6RefPacket(&raw6Packet);

	Packet dnsEdit6Packet(52);

	EthLayer ethLayer6(*dnsEdit6RefPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(dnsEdit6Packet.addLayer(&ethLayer6), "Add EthLayer failed");

	IPv6Layer ipLayer6(*dnsEdit6RefPacket.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(dnsEdit6Packet.addLayer(&ipLayer6), "Add IPv6Layer failed");

	UdpLayer udpLayer6(*dnsEdit6RefPacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(dnsEdit6Packet.addLayer(&udpLayer6), "Add UdpLayer failed");

	DnsLayer dnsLayer6;

	DnsResource* authority = dnsLayer6.addAuthority("Yaels-iPhone.local", DNS_TYPE_A, DNS_CLASS_IN, 120, "10.0.0.2");
	PACKETPP_ASSERT(authority != NULL, "Couldn't add first authority");

	query = dnsLayer6.addQuery(query);
	PACKETPP_ASSERT(query->setName("Yaels-iPhone.local") == true, "Couldn't set name for first query in DnsEdit6");
	query->setDnsClass(DNS_CLASS_CH);
	query->setDnsType(DNS_TYPE_ALL);

	PACKETPP_ASSERT(dnsEdit6Packet.addLayer(&dnsLayer6), "Couldn't set DNS layer for packet DnsEdit6");

	PACKETPP_ASSERT(dnsLayer6.getAuthority("Yaels-iPhone.local", true)->getDataAsString() == "10.0.0.2", "Couldn't retrieve data from first authority");

	authority = dnsLayer6.addAuthority(authority);
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(authority->setData("fe80::5a1f:aaff:fe4f:3f9d") == false, "Managed to set IPv6 data for DNS authority record of type IPv4");
	LoggerPP::getInstance().enableErrors();
	authority->setDnsType(DNS_TYPE_AAAA);
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(authority->setData("fe80::5a1f:aaff.fe4f:3f9d") == false, "Managed to set malformed IPv6 data for DNS authority record");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(authority->setData("fe80::5a1f:aaff:fe4f:3f9d") == true, "Couldn't IPv6 data for DNS authority record");

	query = dnsLayer6.addQuery(query);
	query->setDnsClass(DNS_CLASS_ANY);

	PACKETPP_ASSERT(dnsLayer6.getQueryCount() == 2, "Query count != 2, it's %d", dnsLayer6.getQueryCount());
	PACKETPP_ASSERT(dnsLayer6.getAuthorityCount() == 2, "Authority count != 2");
	PACKETPP_ASSERT(dnsLayer6.getAnswerCount() == 0, "Answers count != 0");
	PACKETPP_ASSERT(dnsLayer6.getAdditionalRecordCount() == 0, "Additional record count != 0");

	DnsResource* additional = dnsLayer6.addAdditionalRecord("", DNS_TYPE_OPT, 0xa005, 0x1194, "0x0004000800df581faa4f3f9d");
	PACKETPP_ASSERT(additional != NULL, "Couldn't add additional record");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(additional->setData("a01234") == false, "Managed to set hex data with no '0x' at the beginning");
	PACKETPP_ASSERT(additional->setData("0xa0123") == false, "Managed to set hex data with odd number of characters");
	PACKETPP_ASSERT(additional->setData("0xa01j34") == false, "Managed to set hex data with illegal hex characters");
	LoggerPP::getInstance().enableErrors();

	dnsEdit6Packet.computeCalculateFields();

	PACKETPP_ASSERT(buffer6Length == dnsEdit6Packet.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", dnsEdit6Packet.getRawPacket()->getRawDataLen(), buffer6Length);

	PACKETPP_ASSERT(memcmp(dnsEdit6Packet.getRawPacket()->getRawData(), buffer6, buffer6Length) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DnsLayerEditTest)
{
	int buffer3Length = 0;
	int buffer5Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/DnsEdit3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file DnsEdit3.dat");
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/DnsEdit5.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file DnsEdit5.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket raw3Packet((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket raw3PacketCopy(raw3Packet);
	RawPacket raw5Packet((const uint8_t*)buffer5, buffer5Length, time, true);

	Packet dnsEdit3(&raw3Packet);
	Packet dnsEdit5(&raw5Packet);

	DnsLayer* dnsLayer3 = dnsEdit3.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer3 != NULL, "Couldn't retrieve DnsLayer for DnsEdit3");

	DnsLayer* dnsLayer5 = dnsEdit5.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer5 != NULL, "Couldn't retrieve DnsLayer for DnsEdit5");

	PACKETPP_ASSERT(dnsLayer3->getFirstQuery()->setName("www.mora.fr") == true, "Couldn't set name for DnsEdit3");
	dnsLayer3->getDnsHeader()->transactionID = htons(35240);
	PACKETPP_ASSERT(dnsLayer3->getHeaderLen() == dnsLayer5->getHeaderLen(), "DNS layers length of DnsEdit3 and DnsEdit5 after edit differ");
	PACKETPP_ASSERT(memcmp(dnsLayer3->getData(), dnsLayer5->getData(), dnsLayer3->getHeaderLen()) == 0, "Raw data for DNS layers of DnsEdit3 and DnsEdit5 differ");

	dnsEdit3 = Packet(&raw3PacketCopy);
	dnsLayer3 = dnsEdit3.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer3 != NULL, "Couldn't retrieve DnsLayer for DnsEdit3");

	dnsLayer5->getDnsHeader()->transactionID = htons(14627);
	PACKETPP_ASSERT(dnsLayer5->getFirstQuery()->setName("assets.pinterest.com") == true, "Couldn't set name for DnsEdit5");
	PACKETPP_ASSERT(dnsLayer3->getHeaderLen() == dnsLayer5->getHeaderLen(), "DNS layers length of DnsEdit3 and DnsEdit5 after edit differ");
	PACKETPP_ASSERT(memcmp(dnsLayer3->getData(), dnsLayer5->getData(), dnsLayer3->getHeaderLen()) == 0, "Raw data for DNS layers of DnsEdit3 and DnsEdit5 differ");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DnsLayerRemoveResourceTest)
{
	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/DnsEdit6.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file DnsEdit6.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket raw6Packet((const uint8_t*)buffer6, buffer6Length, time, true);

	Packet dnsEdit6Packet(&raw6Packet);

	DnsLayer* dnsLayer6 = dnsEdit6Packet.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer6 != NULL, "Couldn't retrieve DnsLayer for DnsEdit6");

	DnsLayer origDnsLayer6(*dnsLayer6);

	DnsQuery* firstQuery = dnsLayer6->getFirstQuery();
	size_t firstQuerySize = firstQuery->getSize();
	DnsQuery* secondQuery = dnsLayer6->getNextQuery(firstQuery);
	PACKETPP_ASSERT(firstQuery != NULL, "Couldn't find first query in DnsEdit6");
	PACKETPP_ASSERT(secondQuery != NULL, "Couldn't find second query in DnsEdit6");
	PACKETPP_ASSERT(dnsLayer6->removeQuery(firstQuery) == true, "Couldn't remove first query from DnsEdit6");

	PACKETPP_ASSERT(dnsLayer6->getFirstQuery() == secondQuery, "Remove query didn't remove the query properly from the resources linked list");
	PACKETPP_ASSERT(dnsLayer6->getFirstQuery()->getDnsType() == DNS_TYPE_ALL, "Remove query didn't properly removed query data from layer");
	PACKETPP_ASSERT(dnsLayer6->getQueryCount() == 1, "Query count after removing the first query != 1");
	PACKETPP_ASSERT(dnsLayer6->getFirstAuthority()->getDataAsString() == "10.0.0.2", "Remove query didn't properly removed query data from layer");
	PACKETPP_ASSERT(dnsLayer6->getFirstAdditionalRecord()->getDnsType() == DNS_TYPE_OPT, "Remove query didn't properly removed query data from layer");

	PACKETPP_ASSERT(dnsLayer6->getHeaderLen() == origDnsLayer6.getHeaderLen()-firstQuerySize, "DNS layer size after removing the first query is wrong");

//	printf("\n\n\n");
//	for(int i = 0; i<dnsLayer6->getHeaderLen(); i++)
//		printf(" 0x%2X  ", (origDnsLayer6.getData()+firstQuerySize)[i]);
//	printf("\n\n\n");
//	for(int i = 0; i<dnsLayer6->getHeaderLen(); i++)
//	{
//		if (dnsLayer6->getData()[i] != (origDnsLayer6.getData()+firstQuerySize)[i])
//			printf("*0x%2X* ", dnsLayer6->getData()[i]);
//		else
//			printf(" 0x%2X  ", dnsLayer6->getData()[i]);
//	}
//	printf("\n\n\n");

	PACKETPP_ASSERT(memcmp(dnsLayer6->getData()+sizeof(dnshdr), origDnsLayer6.getData()+sizeof(dnshdr)+firstQuerySize , dnsLayer6->getHeaderLen()-sizeof(dnshdr)) == 0, "Raw data for DNS layer of DnsEdit6 after removing first query isn't as expected");

	DnsResource* firstAuthority = dnsLayer6->getFirstAuthority();
	DnsResource* secondAuthority = dnsLayer6->getNextAuthority(firstAuthority);
	PACKETPP_ASSERT(secondAuthority != NULL, "Couldn't find second authority in DnsEdit6");
	size_t secondAuthoritySize = secondAuthority->getSize();

	PACKETPP_ASSERT(dnsLayer6->removeAuthority(secondAuthority) == true, "Couldn't remove second authority from DnsEdit6");
	PACKETPP_ASSERT(dnsLayer6->getAuthorityCount() == 1, "Authority count after removing the second authority != 1");
	PACKETPP_ASSERT(dnsLayer6->getFirstAuthority() == firstAuthority, "Cannot find first authority after removing second authority");
	PACKETPP_ASSERT(dnsLayer6->getNextAuthority(firstAuthority) == NULL, "Authority list after removing second authority contains more than 1 element");
	PACKETPP_ASSERT(firstAuthority->getTTL() == 120, "First authority TTL after removing second authority != 120");
	PACKETPP_ASSERT(dnsLayer6->getFirstAdditionalRecord()->getDnsType() == DNS_TYPE_OPT, "Remove query didn't properly removed query data from layer");
	PACKETPP_ASSERT(dnsLayer6->getFirstAdditionalRecord()->getDataLength() == 12, "Remove authority didn't properly removed query data from layer");
	PACKETPP_ASSERT(dnsLayer6->getHeaderLen() == origDnsLayer6.getHeaderLen()-firstQuerySize-secondAuthoritySize, "DNS layer size after removing the second authority is wrong");

	PACKETPP_ASSERT(dnsLayer6->removeQuery("BlaBla", true) == false, "Managed to remove a query which doesn't exist");
	PACKETPP_ASSERT(dnsLayer6->removeAuthority(secondAuthority) == false, "Managed to remove an authority which was already removed");
	PACKETPP_ASSERT(dnsLayer6->removeAdditionalRecord(NULL) == false, "Managed to remove a NULL additional record");

	size_t additionalRecordSize = dnsLayer6->getFirstAdditionalRecord()->getSize();
	PACKETPP_ASSERT(dnsLayer6->removeAdditionalRecord(dnsLayer6->getFirstAdditionalRecord()) == true, "Couldn't remove additional record");
	PACKETPP_ASSERT(dnsLayer6->getAdditionalRecordCount() == 0, "Additional record count after removing the additional record != 0");
	PACKETPP_ASSERT(dnsLayer6->getFirstAdditionalRecord() == NULL, "Getting first additional record after removing all records gave result != NULL");
	PACKETPP_ASSERT(dnsLayer6->getFirstAuthority()->getDataAsString() == "10.0.0.2", "First authority data after removing additional record is different than expected");
	PACKETPP_ASSERT(dnsLayer6->getHeaderLen() == origDnsLayer6.getHeaderLen()-firstQuerySize-secondAuthoritySize-additionalRecordSize, "DNS layer size after removing the additional record is wrong");




	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/DnsEdit4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file DnsEdit4.dat");

	gettimeofday(&time, NULL);
	RawPacket raw4Packet((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet dnsEdit4Packet(&raw4Packet);

	DnsLayer* dnsLayer4 = dnsEdit4Packet.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(dnsLayer4 != NULL, "Couldn't retrieve DnsLayer for DnsEdit4");

	DnsLayer origDnsLayer4(*dnsLayer4);

	firstQuerySize = dnsLayer4->getFirstQuery()->getSize();
	PACKETPP_ASSERT(dnsLayer4->removeQuery("pinter", false) == true, "Couldn't remove query in DnsEdit4");
	PACKETPP_ASSERT(dnsLayer4->getQueryCount() == 0, "Query count after removing the only query > 0");
	PACKETPP_ASSERT(dnsLayer4->getHeaderLen() == origDnsLayer4.getHeaderLen()-firstQuerySize, "DNS layer size after removing the first query is wrong");

	DnsResource* firstAnswer = dnsLayer4->getFirstAnswer();
	PACKETPP_ASSERT(firstAnswer != NULL, "Couldn't find first answer");
	size_t firstAnswerSize = firstAnswer->getSize();
	PACKETPP_ASSERT(dnsLayer4->getFirstAnswer()->getDataAsString() == "assets.pinterest.com.cdngc.net", "First answer data after removing first query is wrong");

	DnsResource* secondAnswer = dnsLayer4->getNextAnswer(firstAnswer);
	PACKETPP_ASSERT(secondAnswer != NULL, "Couldn't find second answer");
	size_t secondAnswerSize = secondAnswer->getSize();

	DnsResource* thirdAnswer = dnsLayer4->getNextAnswer(secondAnswer);
	PACKETPP_ASSERT(thirdAnswer != NULL, "Couldn't find third answer");

	PACKETPP_ASSERT(dnsLayer4->removeAnswer("assets.pinterest.com.cdngc.net", true) == true, "Couldn't remove second answer by name");
	PACKETPP_ASSERT(dnsLayer4->getAnswerCount() == 2, "Answer count after removing the second answer != 2");
	PACKETPP_ASSERT(dnsLayer4->getFirstAnswer() == firstAnswer, "First answer after removing the second answer isn't as expected");
	PACKETPP_ASSERT(dnsLayer4->getNextAnswer(dnsLayer4->getFirstAnswer()) == thirdAnswer, "Second answer after removing the second answer isn't as expected");
	PACKETPP_ASSERT(dnsLayer4->getHeaderLen() == origDnsLayer4.getHeaderLen()-firstQuerySize-secondAnswerSize, "DNS layer size after removing the second answer is wrong");

	PACKETPP_ASSERT(dnsLayer4->removeAnswer(firstAnswer) == true, "Couldn't remove first answer");
	PACKETPP_ASSERT(dnsLayer4->getAnswerCount() == 1, "Answer count after removing the first answer != 1");
	PACKETPP_ASSERT(dnsLayer4->getFirstAnswer() == thirdAnswer, "First answer after removing the first answer isn't as expected");
	PACKETPP_ASSERT(dnsLayer4->getFirstAnswer()->getDataAsString() == "151.249.90.238", "Third answer data isn't as expected");
	PACKETPP_ASSERT(dnsLayer4->getHeaderLen() == origDnsLayer4.getHeaderLen()-firstQuerySize-secondAnswerSize-firstAnswerSize, "DNS layer size after removing the first answer is wrong");

	PACKETPP_ASSERT(dnsLayer4->removeAnswer(thirdAnswer) == true, "Couldn't remove third answer");
	PACKETPP_ASSERT(dnsLayer4->removeAdditionalRecord("blabla", false) == false, "Managed to remove an additional record that doesn't exist");
	PACKETPP_ASSERT(dnsLayer4->getHeaderLen() == sizeof(dnshdr), "After removing all resources, header size is expected to be sizeof(dnshdr), but this is not the case");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(MplsLayerTest)
{
	int buffer1Length = 0;
	int buffer2Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/MplsPackets1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file MplsPackets1.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/MplsPackets2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file MplsPackets2.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet mplsPacket1(&rawPacket1);
	Packet mplsPacket2(&rawPacket2);

	MplsLayer* mplsLayer = mplsPacket1.getLayerOfType<MplsLayer>();
	PACKETPP_ASSERT(mplsLayer != NULL, "Couldn't find MPLS layer for MplsPackets1.dat");

	PACKETPP_ASSERT(mplsLayer->getTTL() == 126, "TTL != 126 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->isBottomOfStack() == true, "Bottom of stack != true for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getExperimentalUseValue() == 0, "expermentalUse != 0 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getMplsLabel() == 16000, "label != 16000 for MplsPackets1.dat");

	PACKETPP_ASSERT(mplsLayer->getNextLayer() != NULL, "Layer after MPLS is NULL");
	PACKETPP_ASSERT(mplsLayer->getNextLayer()->getProtocol() == IPv4, "Layer after MPLS isn't IPv4");

	mplsLayer = mplsPacket2.getLayerOfType<MplsLayer>();
	PACKETPP_ASSERT(mplsLayer != NULL, "Couldn't find MPLS layer for MplsPackets2.dat");

	PACKETPP_ASSERT(mplsLayer->getTTL() == 254, "TTL != 254 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->isBottomOfStack() == false, "Bottom of stack != false for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getExperimentalUseValue() == 0, "expermentalUse != 0 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getMplsLabel() == 18, "label != 18 for MplsPackets1.dat");

	mplsLayer = mplsPacket2.getNextLayerOfType<MplsLayer>(mplsLayer);
	PACKETPP_ASSERT(mplsLayer != NULL, "Couldn't find second MPLS layer for MplsPackets2.dat");

	PACKETPP_ASSERT(mplsLayer->getTTL() == 255, "TTL != 255 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->isBottomOfStack() == true, "Bottom of stack != true for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getExperimentalUseValue() == 0, "expermentalUse != 0 for MplsPackets1.dat");
	PACKETPP_ASSERT(mplsLayer->getMplsLabel() == 16, "label != 16 for MplsPackets1.dat");

	PACKETPP_ASSERT(mplsLayer->getNextLayer() != NULL, "Layer after MPLS is NULL");
	PACKETPP_ASSERT(mplsLayer->getNextLayer()->getProtocol() == Unknown, "Layer after MPLS isn't general payload");

	mplsLayer->setBottomOfStack(true);
	PACKETPP_ASSERT(mplsLayer->setExperimentalUseValue(6) == true, "Couldn't set a legal exp value");
	mplsLayer->setTTL(111);
	PACKETPP_ASSERT(mplsLayer->setMplsLabel(100000), "Couldn't set a legal label value");
	uint8_t expectedResult[4] = { 0x18, 0x6A, 0x0d, 0x6f };
	PACKETPP_ASSERT(memcmp(mplsLayer->getData(), expectedResult , 4) == 0, "MPLS data is wrong, got 0x%X 0x%X 0x%X 0x%X",
			mplsLayer->getData()[0], mplsLayer->getData()[1], mplsLayer->getData()[2], mplsLayer->getData()[3]);
	PACKETPP_ASSERT(mplsLayer->getTTL() == 111, "Read the set TTL gave different result");
	PACKETPP_ASSERT(mplsLayer->getMplsLabel() == 100000, "Read the set MPLS labek gave different result");
	PACKETPP_ASSERT(mplsLayer->getExperimentalUseValue() == 6, "Read the set exp value gave different result");
	PACKETPP_ASSERT(mplsLayer->isBottomOfStack() == true, "Read the set bottom-of-stack value gave different result");

	MplsLayer mplsLayer2(0xdff0f, 20, 7, false);
	uint8_t expectedResult2[4] = { 0xdf, 0xf0, 0xfe, 0x14 };
	PACKETPP_ASSERT(memcmp(mplsLayer2.getData(), expectedResult2 , 4) == 0, "MPLS data2 is wrong, got 0x%X 0x%X 0x%X 0x%X",
			mplsLayer2.getData()[0], mplsLayer2.getData()[1], mplsLayer2.getData()[2], mplsLayer2.getData()[3]);

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(mplsLayer->setExperimentalUseValue(600) == false, "Managed to set an out-of-range exp value");
	PACKETPP_ASSERT(mplsLayer->setMplsLabel(0xFFFFFF) == false, "Managed to set an out-of-range MPLS label value");
	LoggerPP::getInstance().enableErrors();


	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(CopyLayerAndPacketTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TwoHttpResponses1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket sampleRawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet sampleHttpPacket(&sampleRawPacket);

	//RawPacket copy c'tor / assignment operator test
	//-----------------------------------------------
	RawPacket copyRawPacket;
	copyRawPacket = sampleRawPacket;
	PACKETPP_ASSERT(copyRawPacket.getRawDataLen() == sampleRawPacket.getRawDataLen(), "Original and copy RawPacket data length differs");
	PACKETPP_ASSERT(copyRawPacket.getRawData() != sampleRawPacket.getRawData(), "Original and copy RawPacket data pointers are the same");
	PACKETPP_ASSERT(memcmp(copyRawPacket.getRawData(), sampleRawPacket.getRawData(), sampleRawPacket.getRawDataLen()) == 0, "Original and copy RawPacket data differs");

	//EthLayer copy c'tor test
	//------------------------
	EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayload() != ethLayer.getLayerPayload(),
			"EthLayer copy c'tor didn't actually copy the data, payload data pointer of original and copied layers are equal");
	PACKETPP_ASSERT(memcmp(sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayload(), ethLayer.getLayerPayload(), sampleHttpPacket.getLayerOfType<EthLayer>()->getLayerPayloadSize()) == 0,
			"EthLayer copy c'tor didn't copy data properly, original and copied payload data isn't equal");


	//TcpLayer copy c'tor test
	//------------------------
	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file");

	RawPacket sampleRawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet sampleTcpPacketWithOptions(&sampleRawPacket2);
	TcpLayer tcpLayer = *sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>();
	PACKETPP_ASSERT(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getData() != tcpLayer.getData(),
			"TcpLayer copy c'tor didn't actually copy the data, data pointer of original and copied layers are equal");
	PACKETPP_ASSERT(memcmp(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getData(), tcpLayer.getData(), sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getDataLen()) == 0,
			"TcpLayer copy c'tor didn't copy data properly, original and copied data isn't equal");
	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionsCount(),
			"TcpLayer copy and original TCP options count is not equal");
	PACKETPP_ASSERT(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionData(TCPOPT_TIMESTAMP) != tcpLayer.getTcpOptionData(TCPOPT_TIMESTAMP),
			"TcpLayer copy and original TCP Timestamp option pointer is the same");
	PACKETPP_ASSERT(memcmp(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionData(TCPOPT_TIMESTAMP), tcpLayer.getTcpOptionData(TCPOPT_TIMESTAMP), TCPOLEN_TIMESTAMP) == 0,
			"TcpLayer copy and original TCP Timestamp option data differs");


	//HttpLayer copy c'tor test
	//--------------------------

	HttpResponseLayer* sampleHttpLayer = sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
	HttpResponseLayer httpResLayer = *sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine() != httpResLayer.getFirstLine(), "HttpResponseLayer copy c'tor didn't actually copy first line, pointers are the same");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getStatusCode() == httpResLayer.getFirstLine()->getStatusCode(), "HttpResponseLayer copy c'tor: status codes differ between original and copy");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getSize() == httpResLayer.getFirstLine()->getSize(), "HttpResponseLayer copy c'tor: sizes differ between original and copy");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getVersion() == httpResLayer.getFirstLine()->getVersion(), "HttpResponseLayer copy c'tor: versions differ between original and copy");

	HttpField* curFieldInSample = sampleHttpLayer->getFirstField();
	HttpField* curFieldInCopy = httpResLayer.getFirstField();
	while (curFieldInSample != NULL && curFieldInCopy != NULL)
	{
		PACKETPP_ASSERT(curFieldInCopy != curFieldInSample, "HttpRequestLayer copy c'tor didn't actually copy the field '%s'", curFieldInSample->getFieldName().c_str());
		PACKETPP_ASSERT(curFieldInSample->getFieldName() == curFieldInCopy->getFieldName(),
				"HttpResponseLayer copy c'tor: different field names between original and copy. Original: '%s', Copy: '%s'",
				curFieldInSample->getFieldName().c_str(), curFieldInCopy->getFieldName().c_str());
		PACKETPP_ASSERT(curFieldInSample->getFieldValue() == curFieldInCopy->getFieldValue(),
				"HttpResponseLayer copy c'tor: different field value between original and copy. Original: '%s', Copy: '%s'",
				curFieldInSample->getFieldValue().c_str(), curFieldInCopy->getFieldValue().c_str());
		PACKETPP_ASSERT(curFieldInSample->getFieldSize() == curFieldInCopy->getFieldSize(),
				"HttpResponseLayer copy c'tor: different field size between original and copy. Original: '%d', Copy: '%d'",
				curFieldInSample->getFieldSize(), curFieldInCopy->getFieldSize());

		curFieldInSample = sampleHttpLayer->getNextField(curFieldInSample);
		curFieldInCopy = sampleHttpLayer->getNextField(curFieldInCopy);
	}

	PACKETPP_ASSERT(curFieldInSample == NULL, "HttpResponseLayer copy c'tor: number of fields differs between original and copy");
	PACKETPP_ASSERT(curFieldInCopy == NULL, "HttpResponseLayer copy c'tor: number of fields differs between original and copy");


	//Packet copy c'tor test
	//----------------------

	Packet samplePacketCopy(sampleHttpPacket);
	PACKETPP_ASSERT(samplePacketCopy.getFirstLayer() != sampleHttpPacket.getFirstLayer(), "Packet copy c'tor didn't actually copy first layer");
	PACKETPP_ASSERT(samplePacketCopy.getLastLayer() != sampleHttpPacket.getLastLayer(), "Packet copy c'tor didn't actually last layer");
	PACKETPP_ASSERT(samplePacketCopy.getRawPacket() != sampleHttpPacket.getRawPacket(), "Packet copy c'tor didn't actually copy raw packet");
	PACKETPP_ASSERT(samplePacketCopy.getRawPacket()->getRawDataLen() == sampleHttpPacket.getRawPacket()->getRawDataLen(),
			"Packet copy c'tor: raw packet length differs");
	PACKETPP_ASSERT(memcmp(samplePacketCopy.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawDataLen()) == 0,
			"Packet copy c'tor: raw packet data differs");
	PACKETPP_ASSERT(samplePacketCopy.isPacketOfType(Ethernet) == true, "Packet copy isn't of type ethernet");
	PACKETPP_ASSERT(samplePacketCopy.isPacketOfType(IPv4) == true, "Packet copy isn't of type IPv4");
	PACKETPP_ASSERT(samplePacketCopy.isPacketOfType(TCP) == true, "Packet copy isn't of type TCP");
	PACKETPP_ASSERT(samplePacketCopy.isPacketOfType(HTTPResponse) == true, "Packet copy isn't of type HTTP response");
	Layer* curSamplePacketLayer = sampleHttpPacket.getFirstLayer();
	Layer* curPacketCopyLayer = samplePacketCopy.getFirstLayer();
	while (curSamplePacketLayer != NULL && curPacketCopyLayer != NULL)
	{
		PACKETPP_ASSERT(curSamplePacketLayer->getProtocol() == curPacketCopyLayer->getProtocol(), "Packet copy c'tor: layer protocol is different");
		PACKETPP_ASSERT(curSamplePacketLayer->getHeaderLen() == curPacketCopyLayer->getHeaderLen(), "Packet copy c'tor: layer header len is different");
		PACKETPP_ASSERT(curSamplePacketLayer->getLayerPayloadSize() == curPacketCopyLayer->getLayerPayloadSize(), "Packet copy c'tor: layer payload size is different");
		PACKETPP_ASSERT(curSamplePacketLayer->getDataLen() == curPacketCopyLayer->getDataLen(), "Packet copy c'tor: data len is different");
		PACKETPP_ASSERT(memcmp(curSamplePacketLayer->getData(), curPacketCopyLayer->getData(), curSamplePacketLayer->getDataLen()) == 0, "Packet copy c'tor: layer data differs");
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}

	PACKETPP_ASSERT(curSamplePacketLayer == NULL, "Packet copy c'tor: number of layers differs between original and copy");
	PACKETPP_ASSERT(curPacketCopyLayer == NULL, "Packet copy c'tor: number of layers differs between original and copy");


	//DnsLayer copy c'tor and operator= test
	//--------------------------------------
	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/Dns2.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file Dns2.dat");

	RawPacket sampleRawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);

	Packet sampleDnsPacket(&sampleRawPacket3);

	DnsLayer* origDnsLayer = sampleDnsPacket.getLayerOfType<DnsLayer>();
	PACKETPP_ASSERT(origDnsLayer != NULL, "Couldn't find DNS layer in file");
	DnsLayer copyDnsLayer(*origDnsLayer);
	PACKETPP_ASSERT(copyDnsLayer.getQueryCount() == origDnsLayer->getQueryCount(), "Query count differs");
	PACKETPP_ASSERT(copyDnsLayer.getFirstQuery()->getName() == origDnsLayer->getFirstQuery()->getName(), "Name for first query differs");
	PACKETPP_ASSERT(copyDnsLayer.getFirstQuery()->getDnsType() == origDnsLayer->getFirstQuery()->getDnsType(), "DNS type for first query differs");

	PACKETPP_ASSERT(copyDnsLayer.getAuthorityCount() == origDnsLayer->getAuthorityCount(), "Authority count differs");
	PACKETPP_ASSERT(copyDnsLayer.getAuthority("Yaels-iPhone.local", true)->getDataAsString() == origDnsLayer->getAuthority("Yaels-iPhone.local", true)->getDataAsString(), "Authority data differs");

	PACKETPP_ASSERT(copyDnsLayer.getAdditionalRecord("", true)->getDataAsString() == origDnsLayer->getAdditionalRecord("", true)->getDataAsString(), "Additional data differs");

	copyDnsLayer.addQuery("bla", DNS_TYPE_A, DNS_CLASS_ANY);
	copyDnsLayer.addAnswer("bla", DNS_TYPE_A, DNS_CLASS_ANY, 123, "1.1.1.1");

	copyDnsLayer = *origDnsLayer;

	PACKETPP_ASSERT(copyDnsLayer.getQueryCount() == origDnsLayer->getQueryCount(), "Query count differs");
	PACKETPP_ASSERT(copyDnsLayer.getFirstQuery()->getName() == origDnsLayer->getFirstQuery()->getName(), "Name for first query differs");
	PACKETPP_ASSERT(copyDnsLayer.getFirstQuery()->getDnsType() == origDnsLayer->getFirstQuery()->getDnsType(), "DNS type for first query differs");

	PACKETPP_ASSERT(copyDnsLayer.getAuthorityCount() == origDnsLayer->getAuthorityCount(), "Authority count differs");
	PACKETPP_ASSERT(copyDnsLayer.getAuthority(".local", false)->getDataAsString() == origDnsLayer->getAuthority("iPhone.local", false)->getDataAsString(), "Authority data differs");

	PACKETPP_ASSERT(copyDnsLayer.getAnswerCount() == origDnsLayer->getAnswerCount(), "Answer count differs");

	PACKETPP_ASSERT(copyDnsLayer.getAdditionalRecord("", true)->getDataAsString() == origDnsLayer->getAdditionalRecord("", true)->getDataAsString(), "Additional data differs");



	PACKETPP_TEST_PASSED;
}


int main(int argc, char* argv[]) {
	start_leak_check();

	PACKETPP_START_RUNNING_TESTS;

	PACKETPP_RUN_TEST(EthPacketCreation);
	PACKETPP_RUN_TEST(EthAndArpPacketParsing);
	PACKETPP_RUN_TEST(ArpPacketCreation);
	PACKETPP_RUN_TEST(VlanParseAndCreation);
	PACKETPP_RUN_TEST(Ipv4PacketCreation);
	PACKETPP_RUN_TEST(Ipv4PacketParsing);
	PACKETPP_RUN_TEST(Ipv4UdpChecksum);
	PACKETPP_RUN_TEST(Ipv6UdpPacketParseAndCreate);
	PACKETPP_RUN_TEST(TcpPacketNoOptionsParsing);
	PACKETPP_RUN_TEST(TcpPacketWithOptionsParsing);
	PACKETPP_RUN_TEST(TcpPacketWithOptionsParsing2);
	PACKETPP_RUN_TEST(TcpPacketCreation);
	PACKETPP_RUN_TEST(InsertDataToPacket);
	PACKETPP_RUN_TEST(InsertVlanToPacket);
	PACKETPP_RUN_TEST(RemoveLayerTest);
	PACKETPP_RUN_TEST(HttpRequestLayerParsingTest);
	PACKETPP_RUN_TEST(HttpRequestLayerCreationTest);
	PACKETPP_RUN_TEST(HttpRequestLayerEditTest);
	PACKETPP_RUN_TEST(HttpResponseLayerParsingTest);
	PACKETPP_RUN_TEST(HttpResponseLayerCreationTest);
	PACKETPP_RUN_TEST(HttpResponseLayerEditTest);
	PACKETPP_RUN_TEST(PPPoESessionLayerParsingTest);
	PACKETPP_RUN_TEST(PPPoESessionLayerCreationTest);
	PACKETPP_RUN_TEST(PPPoEDiscoveryLayerParsingTest);
	PACKETPP_RUN_TEST(PPPoEDiscoveryLayerCreateTest);
	PACKETPP_RUN_TEST(DnsLayerParsingTest);
	PACKETPP_RUN_TEST(DnsLayerQueryCreationTest);
	PACKETPP_RUN_TEST(DnsLayerResourceCreationTest);
	PACKETPP_RUN_TEST(DnsLayerEditTest);
	PACKETPP_RUN_TEST(DnsLayerRemoveResourceTest);
	PACKETPP_RUN_TEST(MplsLayerTest);
	PACKETPP_RUN_TEST(CopyLayerAndPacketTest);

	PACKETPP_END_RUNNING_TESTS;
}
