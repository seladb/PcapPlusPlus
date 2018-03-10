#include <Logger.h>
#include <PcapPlusPlusVersion.h>
#include <Packet.h>
#include <EthLayer.h>
#include <SllLayer.h>
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
#include <IcmpLayer.h>
#include <GreLayer.h>
#include <SSLLayer.h>
#include <DhcpLayer.h>
#include <NullLoopbackLayer.h>
#include <IgmpLayer.h>
#include <VxlanLayer.h>
#include <SipLayer.h>
#include <SdpLayer.h>
#include <PacketTrailerLayer.h>
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
#ifdef _MSC_VER
#include <SystemUtils.h>
#endif

// For debug purpose only
//#include <pcap.h>

using namespace std;
using namespace pcpp;
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
		{ \
			printf("ALL TESTS PASSED!!\n\n\n"); \
			return 0; \
		} \
		else \
		{ \
			printf("NOT ALL TESTS PASSED!!\n\n\n"); \
			return 1; \
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

// For debug purpose only
//void createPcapFile(Packet& packet, std::string fileName)
//{
//    pcap_t *pcap;
//    pcap = pcap_open_dead(1, 65565);
//
//    pcap_dumper_t *d;
//    /* open output file */
//    d = pcap_dump_open(pcap, fileName.c_str());
//    if (d == NULL)
//    {
//        pcap_perror(pcap, "pcap_dump_fopen");
//        return;
//    }
//
//    /* prepare for writing */
//    struct pcap_pkthdr hdr;
//    hdr.ts.tv_sec = 0;  /* sec */
//    hdr.ts.tv_usec = 0; /* ms */
//    hdr.caplen = hdr.len = packet.getRawPacket()->getRawDataLen();
//    /* write single IP packet */
//    pcap_dump((u_char *)d, &hdr, packet.getRawPacketReadOnly()->getRawData());
//
//    /* finish up */
//    pcap_dump_close(d);
//    return;
//}


PACKETPP_TEST(EthPacketCreation) {
	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

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
	PACKETPP_ASSERT(ethPacket.getLayerOfType<EthLayer>()->getEthHeader()->etherType == ntohs(PCPP_ETHERTYPE_IP), "Packet ether type isn't equal to PCPP_ETHERTYPE_IP");

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
	PACKETPP_ASSERT(ethLayer->getEthHeader()->etherType == ntohs(PCPP_ETHERTYPE_ARP), "Packet ether type isn't equal to PCPP_ETHERTYPE_ARP, it's 0x%x", ethLayer->getEthHeader()->etherType);

	PACKETPP_ASSERT(ethLayer->getNextLayer()->getProtocol() == ARP, "Next layer isn't of type 'ARP'");
	ArpLayer* arpLayer = (ArpLayer*)ethLayer->getNextLayer();
	PACKETPP_ASSERT(arpLayer->getArpHeader()->hardwareType == htons(1), "ARP hardwareType != 1");
	PACKETPP_ASSERT(arpLayer->getArpHeader()->protocolType == htons(PCPP_ETHERTYPE_IP), "ARP protocolType != PCPP_ETHERTYPE_IP, it's 0x%4X", ntohs(arpLayer->getArpHeader()->protocolType));
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
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP);

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
	PACKETPP_ASSERT(arpHeader->protocolType == htons(PCPP_ETHERTYPE_IP), "Arp header: protocolType != PCPP_ETHERTYPE_IP, Actual: %d", arpHeader->protocolType);

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
	PACKETPP_ASSERT(pFirstVlanLayer->getVlanID() == 100, "first vlan ID != 100, it's 0x%2X", pFirstVlanLayer->getVlanID());
	PACKETPP_ASSERT(pFirstVlanLayer->getCFI() == 1, "first vlan CFI != 1");
	PACKETPP_ASSERT(pFirstVlanLayer->getPriority() == 5, "first vlan priority != 5");
	PACKETPP_ASSERT((pSecondVlanLayer = arpWithVlan.getNextLayerOfType<VlanLayer>(pFirstVlanLayer)) != NULL, "Couldn't get second vlan layer from packet");
	PACKETPP_ASSERT(pSecondVlanLayer->getVlanID() == 200, "second vlan ID != 200");
	PACKETPP_ASSERT(pSecondVlanLayer->getCFI() == 0, "second vlan CFI != 0");
	PACKETPP_ASSERT(pSecondVlanLayer->getPriority() == 2, "second vlan priority != 2");

	Packet arpWithVlanNew(1);
	MacAddress macSrc("ca:03:0d:b4:00:1c");
	MacAddress macDest("ff:ff:ff:ff:ff:ff");
	EthLayer ethLayer(macSrc, macDest, PCPP_ETHERTYPE_VLAN);
	VlanLayer firstVlanLayer(100, 1, 5, PCPP_ETHERTYPE_VLAN);
	VlanLayer secondVlanLayer(200, 0, 2, PCPP_ETHERTYPE_ARP);
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
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
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

	PACKETPP_ASSERT(ip4Packet.getLayerOfType<EthLayer>()->getDataLen() == 44, "Eth Layer data len != 44, it's %d", (int)ip4Packet.getLayerOfType<EthLayer>()->getDataLen());
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
	PACKETPP_ASSERT(ntohs(ethLayer->getEthHeader()->etherType) == PCPP_ETHERTYPE_IP, "Packet ether type isn't equal to PCPP_ETHERTYPE_IP");

	IPv4Layer* ipv4Layer = ip4Packet.getLayerOfType<IPv4Layer>();
	IPv4Address ip4addr1(string("10.0.0.4"));
	IPv4Address ip4addr2(string("1.1.1.1"));
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->protocol == 1, "Protocol read from packet isnt ICMP (=1). Protocol is: %d", ipv4Layer->getIPv4Header()->protocol);
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipVersion == 4, "IP version isn't 4. Version is: %d", ipv4Layer->getIPv4Header()->ipVersion);
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipSrc == ip4addr1.toInt(), "incorrect source address");
	PACKETPP_ASSERT(ipv4Layer->getIPv4Header()->ipDst == ip4addr2.toInt(), "incorrect dest address");
	PACKETPP_ASSERT(ipv4Layer->getFirstOptionData() == NULL, "Managed to get the first IPv4 option although packet doesn't contain any options");
	PACKETPP_ASSERT(ipv4Layer->getOptionData(IPV4OPT_CommercialSecurity) == NULL, "Managed to get an IPv4 option by type although packet doesn't contain any options");
	PACKETPP_ASSERT(ipv4Layer->getOptionsCount() == 0, "IPv4 option count isn't 0");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4FragmentationTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IPv4Frag1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IPv4Frag1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IPv4Frag2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IPv4Frag2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IPv4Frag3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IPv4Frag3.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);

	Packet frag1(&rawPacket1);
	Packet frag2(&rawPacket2);
	Packet frag3(&rawPacket3);

	IPv4Layer* ipLayer = frag1.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find Frag1 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->isFragment() == true, "Frag1 is mistakenly not a fragment");
	PACKETPP_ASSERT(ipLayer->isFirstFragment() == true, "Frag1 is mistakenly not a first fragment");
	PACKETPP_ASSERT(ipLayer->isLastFragment() == false, "Frag1 is mistakenly a last fragment");
	PACKETPP_ASSERT(ipLayer->getFragmentOffset() == 0, "Frag1 fragment offset != 0");
	PACKETPP_ASSERT((ipLayer->getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) != 0, "Frag1 mistakenly doesn't contain the 'more fragments' flag");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == pcpp::GenericPayolad, "Frag1 next protocol is not generic payload");


	ipLayer = frag2.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find Frag2 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->isFragment() == true, "Frag2 is mistakenly not a fragment");
	PACKETPP_ASSERT(ipLayer->isFirstFragment() == false, "Frag2 is mistakenly a first fragment");
	PACKETPP_ASSERT(ipLayer->isLastFragment() == false, "Frag2 is mistakenly a last fragment");
	PACKETPP_ASSERT(ipLayer->getFragmentOffset() == 1480, "Frag2 fragment offset != 1480");
	PACKETPP_ASSERT((ipLayer->getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) != 0, "Frag2 mistakenly doesn't contain the 'more fragments' flag");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == pcpp::GenericPayolad, "Frag2 next protocol is not generic payload");

	ipLayer = frag3.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find Frag3 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->isFragment() == true, "Frag3 is mistakenly not a fragment");
	PACKETPP_ASSERT(ipLayer->isFirstFragment() == false, "Frag3 is mistakenly a first fragment");
	PACKETPP_ASSERT(ipLayer->isLastFragment() == true, "Frag3 is mistakenly not a last fragment");
	PACKETPP_ASSERT(ipLayer->getFragmentOffset() == 2960, "Frag3 fragment offset != 2960");
	PACKETPP_ASSERT(ipLayer->getFragmentFlags() == 0, "Frag3 mistakenly contains flags, 0x%X", ipLayer->getFragmentFlags());
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == pcpp::GenericPayolad, "Frag3 next protocol is not generic payload");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4OptionsParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IPv4Option1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IPv4Option1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IPv4Option2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IPv4Option2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IPv4Option3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IPv4Option3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IPv4Option4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IPv4Option4.dat");

	int buffer5Length = 0;
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/IPv4Option5.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file IPv4Option5.dat");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/IPv4Option6.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file IPv4Option6.dat");

	int buffer7Length = 0;
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/IPv4Option7.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file IPv4Option7.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);
	RawPacket rawPacket6((const uint8_t*)buffer6, buffer6Length, time, true);
	RawPacket rawPacket7((const uint8_t*)buffer7, buffer7Length, time, true);

	Packet ipOpt1(&rawPacket1);
	Packet ipOpt2(&rawPacket2);
	Packet ipOpt3(&rawPacket3);
	Packet ipOpt4(&rawPacket4);
	Packet ipOpt5(&rawPacket5);
	Packet ipOpt6(&rawPacket6);
	Packet ipOpt7(&rawPacket7);

	IPv4Layer* ipLayer = ipOpt1.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt1 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 44, "ipOpt1 header length isn't 44 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 3, "ipOpt1 option count isn't 3");
	IPv4OptionData* opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt1 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_CommercialSecurity, "ipOpt1 first option isn't commercial-security");
	PACKETPP_ASSERT(opt->getDataSize() == 20, "ipOpt1 first option data size isn't 20");
	PACKETPP_ASSERT(opt->getTotalSize() == 22, "ipOpt1 first option total size isn't 22");
	PACKETPP_ASSERT(opt->getValueAs<uint32_t>() == htonl(2), "ipOpt1 first int value isn't 2");
	PACKETPP_ASSERT(opt->getValueAs<uint8_t>(4) == 2, "ipOpt1 value in offset 4 isn't 2");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt != NULL, "ipOpt1 second option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_EndOfOtionsList, "ipOpt1 second option isn't end-of-option-list");
	PACKETPP_ASSERT(opt->getType() == 0, "ipOpt1 second option isn't end-of-option-list");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt != NULL, "ipOpt1 third option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_EndOfOtionsList, "ipOpt1 second option isn't end-of-option-list");
	PACKETPP_ASSERT(opt->getType() == 0, "ipOpt1 second option isn't end-of-option-list");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt1 fourth option isn't NULL");
	opt = ipLayer->getOptionData(IPV4OPT_EndOfOtionsList);
	PACKETPP_ASSERT(opt != NULL, "ipOpt1 couldn't retrieve option by type");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_EndOfOtionsList, "ipOpt1 type if retrieved option isn't end-of-option-list");
	PACKETPP_ASSERT(ipLayer->getOptionData(IPV4OPT_Timestamp) == NULL, "ipOpt1 Managed to reprieve timestamp option although doens't exist in the packet");

	ipLayer = ipOpt2.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt2 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 60, "ipOpt2 header length isn't 60 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 1, "ipOpt2 option count isn't 1");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt2 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_Timestamp, "ipOpt2 first option isn't timestamp");
	PACKETPP_ASSERT(opt->getDataSize() == 38, "ipOpt2 first option data size isn't 38");
	PACKETPP_ASSERT(opt->getTotalSize() == 40, "ipOpt2 first option total size isn't 40");
	IPv4TimestampOptionValue tsValue = opt->getTimestampOptionValue();
	PACKETPP_ASSERT(tsValue.type == IPv4TimestampOptionValue::TimestampOnly, "ipOpt2 ts type isn't TimestampOnly");
	PACKETPP_ASSERT(tsValue.timestamps.size() == 1, "ipOpt2 ts value contains more than 1 ts");
	PACKETPP_ASSERT(tsValue.ipAddresses.size() == 0, "ipOpt2 ts value contains more than 0 IPs");
	PACKETPP_ASSERT(tsValue.timestamps.at(0) == htonl(82524601), "ipOpt2 ts value first ts isn't 82524601");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt2 second option isn't NULL");

	ipLayer = ipOpt3.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt3 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 24, "ipOpt3 header length isn't 24 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 1, "ipOpt3 option count isn't 1");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt3 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_RouterAlert, "ipOpt3 first option isn't router-alert");
	PACKETPP_ASSERT(opt->getDataSize() == 2, "ipOpt3 first option data size isn't 2");
	PACKETPP_ASSERT(opt->getTotalSize() == 4, "ipOpt3 first option total size isn't 4");
	PACKETPP_ASSERT(opt->getValueAs<uint16_t>() == 0, "ipOpt3 value isn't 0");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt3 second option isn't NULL");

	ipLayer = ipOpt4.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt4 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 60, "ipOpt4 header length isn't 60 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 2, "ipOpt4 option count isn't 2");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt4 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_RecordRoute, "ipOpt4 first option isn't record-route");
	PACKETPP_ASSERT(opt->getDataSize() == 37, "ipOpt4 first option data size isn't 37");
	PACKETPP_ASSERT(opt->getTotalSize() == 39, "ipOpt4 first option total size isn't 39");
	std::vector<IPv4Address> ipAddrs = opt->getValueAsIpList();
	PACKETPP_ASSERT(ipAddrs.size() == 3, "ipOpt4 number of IP addresses isn't 3");
	PACKETPP_ASSERT(ipAddrs.at(0) == IPv4Address(std::string("1.2.3.4")), "ipOpt4 first IP addr isn't 1.2.3.4");
	PACKETPP_ASSERT(ipAddrs.at(1) == IPv4Address(std::string("10.0.0.138")), "ipOpt4 second IP addr isn't 10.0.0.138");
	PACKETPP_ASSERT(ipAddrs.at(2) == IPv4Address(std::string("10.0.0.138")), "ipOpt4 third IP addr isn't 10.0.0.138");
	IPv4OptionData* opt2 = ipLayer->getOptionData(IPV4OPT_RecordRoute);
	PACKETPP_ASSERT(opt2 != NULL, "ipOpt4 couldn't retrieve option by type");
	PACKETPP_ASSERT(opt2 == opt, "ipOpt4 option retrieved by type and by getFirstOptionData aren't the same pointer");

	ipLayer = ipOpt5.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt5 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 56, "ipOpt5 header length isn't 56 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 1, "ipOpt5 option count isn't 1");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt5 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_Timestamp, "ipOpt5 first option isn't timestamp");
	PACKETPP_ASSERT(opt->getDataSize() == 34, "ipOpt5 first option data size isn't 34");
	PACKETPP_ASSERT(opt->getTotalSize() == 36, "ipOpt5 first option total size isn't 36");
	tsValue = opt->getTimestampOptionValue();
	PACKETPP_ASSERT(tsValue.type == IPv4TimestampOptionValue::TimestampAndIP, "ipOpt5 ts type isn't TimestampAndIP");
	PACKETPP_ASSERT(tsValue.timestamps.size() == 3, "ipOpt5 ts value doesn't contain 3 ts");
	PACKETPP_ASSERT(tsValue.ipAddresses.size() == 3, "ipOpt5 ts value deosn't contain 3 IPs");
	PACKETPP_ASSERT(tsValue.timestamps.at(0) == htonl(70037668), "ipOpt5 ts value first ts isn't 70037668");
	PACKETPP_ASSERT(tsValue.timestamps.at(2) == htonl(77233718), "ipOpt5 ts value third ts isn't 77233718");
	PACKETPP_ASSERT(tsValue.ipAddresses.at(0) == IPv4Address(std::string("10.0.0.6")), "ipOpt5 ts value first IP isn't 10.0.0.6");
	PACKETPP_ASSERT(tsValue.ipAddresses.at(1) == IPv4Address(std::string("10.0.0.138")), "ipOpt5 ts value second IP isn't 10.0.0.138");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt5 second option isn't NULL");

	ipLayer = ipOpt6.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt6 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 28, "ipOpt6 header length isn't 28 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 2, "ipOpt6 option count isn't 2");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt6 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_NOP, "ipOpt6 first option isn't nop");
	PACKETPP_ASSERT(opt->getDataSize() == 0, "ipOpt6 first option data size isn't 0");
	PACKETPP_ASSERT(opt->getTotalSize() == 1, "ipOpt6 first option total size isn't 1");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt != NULL, "ipOpt6 second option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_StrictSourceRoute, "ipOpt6 second option isn't strict-source-route");
	PACKETPP_ASSERT(opt->getDataSize() == 5, "ipOpt6 second option data size isn't 5");
	PACKETPP_ASSERT(opt->getTotalSize() == 7, "ipOpt6 second option total size isn't 7");
	ipAddrs = opt->getValueAsIpList();
	PACKETPP_ASSERT(ipAddrs.size() == 0, "ipOpt6 number of IP addresses isn't 0");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt6 third option isn't NULL");

	ipLayer = ipOpt7.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer != NULL, "Coudln't find ipOpt7 IPv4 layer");
	PACKETPP_ASSERT(ipLayer->getHeaderLen() == 28, "ipOpt7 header length isn't 28 Bytes");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 2, "ipOpt7 option count isn't 2");
	opt = ipLayer->getFirstOptionData();
	PACKETPP_ASSERT(opt != NULL, "ipOpt7 first option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_NOP, "ipOpt7 first option isn't nop");
	PACKETPP_ASSERT(opt->getDataSize() == 0, "ipOpt7 first option data size isn't 0");
	PACKETPP_ASSERT(opt->getTotalSize() == 1, "ipOpt7 first option total size isn't 1");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt != NULL, "ipOpt7 second option is NULL");
	PACKETPP_ASSERT(opt->getType() == IPV4OPT_LooseSourceRoute, "ipOpt7 second option isn't loose-source-route");
	PACKETPP_ASSERT(opt->getDataSize() == 5, "ipOpt7 second option data size isn't 5");
	PACKETPP_ASSERT(opt->getTotalSize() == 7, "ipOpt7 second option total size isn't 7");
	ipAddrs = opt->getValueAsIpList();
	PACKETPP_ASSERT(ipAddrs.size() == 0, "ipOpt7 number of IP addresses isn't 0");
	opt2 = ipLayer->getOptionData(IPV4OPT_LooseSourceRoute);
	PACKETPP_ASSERT(opt2 != NULL, "ipOpt7 couldn't retrieve option by type");
	PACKETPP_ASSERT(opt2 == opt, "ipOpt7 option retrieved by type and by getNextOptionData aren't the same pointer");
	opt = ipLayer->getNextOptionData(opt);
	PACKETPP_ASSERT(opt == NULL, "ipOpt7 third option isn't NULL");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv4OptionsEditTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IPv4-NoOptions1.dat");
	int buffer11Length = 0;
	uint8_t* buffer11 = readFileIntoBuffer("PacketExamples/IPv4Option1.dat", buffer11Length);
	PACKETPP_ASSERT(!(buffer11 == NULL), "cannot read file IPv4Option1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IPv4-NoOptions2.dat");
	int buffer22Length = 0;
	uint8_t* buffer22 = readFileIntoBuffer("PacketExamples/IPv4Option2.dat", buffer22Length);
	PACKETPP_ASSERT(!(buffer22 == NULL), "cannot read file IPv4Option2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IPv4-NoOptions3.dat");
	int buffer33Length = 0;
	uint8_t* buffer33 = readFileIntoBuffer("PacketExamples/IPv4Option3.dat", buffer33Length);
	PACKETPP_ASSERT(!(buffer33 == NULL), "cannot read file IPv4Option3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IPv4-NoOptions4.dat");
	int buffer44Length = 0;
	uint8_t* buffer44 = readFileIntoBuffer("PacketExamples/IPv4Option4.dat", buffer44Length);
	PACKETPP_ASSERT(!(buffer44 == NULL), "cannot read file IPv4Option4.dat");

	int buffer5Length = 0;
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions5.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file IPv4-NoOptions5.dat");
	int buffer55Length = 0;
	uint8_t* buffer55 = readFileIntoBuffer("PacketExamples/IPv4Option5.dat", buffer55Length);
	PACKETPP_ASSERT(!(buffer55 == NULL), "cannot read file IPv4Option5.dat");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions6.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file IPv4-NoOptions6.dat");
	int buffer66Length = 0;
	uint8_t* buffer66 = readFileIntoBuffer("PacketExamples/IPv4Option6.dat", buffer66Length);
	PACKETPP_ASSERT(!(buffer66 == NULL), "cannot read file IPv4Option6.dat");

	int buffer7Length = 0;
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/IPv4-NoOptions7.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file IPv4-NoOptions7.dat");
	int buffer77Length = 0;
	uint8_t* buffer77 = readFileIntoBuffer("PacketExamples/IPv4Option7.dat", buffer77Length);
	PACKETPP_ASSERT(!(buffer77 == NULL), "cannot read file IPv4Option7.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);
	RawPacket rawPacket6((const uint8_t*)buffer6, buffer6Length, time, true);
	RawPacket rawPacket7((const uint8_t*)buffer7, buffer7Length, time, true);

	Packet ipOpt1(&rawPacket1);
	Packet ipOpt2(&rawPacket2);
	Packet ipOpt3(&rawPacket3);
	Packet ipOpt4(&rawPacket4);
	Packet ipOpt5(&rawPacket5);
	Packet ipOpt6(&rawPacket6);
	Packet ipOpt7(&rawPacket7);

	IPv4Layer* ipLayer = ipOpt1.getLayerOfType<IPv4Layer>();
	uint8_t commSecOptionData[] = { 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0xef };
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_CommercialSecurity, 20, commSecOptionData) != NULL, "Cannot add commercial security option to packet 1");
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_EndOfOtionsList, 0, NULL) != NULL, "Cannot add end-of-opt-list option to packet 1");
	PACKETPP_ASSERT(ipLayer->addOptionAfter(IPV4OPT_EndOfOtionsList, 0, NULL, IPV4OPT_CommercialSecurity) != NULL, "Cannot add 2nd end-of-opt-list option to packet 1");
	ipOpt1.computeCalculateFields();


	PACKETPP_ASSERT(buffer11Length == ipOpt1.getRawPacket()->getRawDataLen(), "ipOpt1 len (%d) is different than read packet len (%d)", ipOpt1.getRawPacket()->getRawDataLen(), buffer11Length);
	PACKETPP_ASSERT(memcmp(ipOpt1.getRawPacket()->getRawData(), buffer11, ipOpt1.getRawPacket()->getRawDataLen()) == 0, "ipOpt1: Raw packet data is different than expected");

	ipLayer = ipOpt2.getLayerOfType<IPv4Layer>();
	IPv4TimestampOptionValue tsOption;
	tsOption.type = IPv4TimestampOptionValue::TimestampOnly;
	tsOption.timestamps.push_back(82524601);
	for (int i = 0; i < 8; i++)
		tsOption.timestamps.push_back(0);
	PACKETPP_ASSERT(ipLayer->addTimestampOption(tsOption) != NULL, "Cannot add timestamp option to packet 2");
	ipOpt2.computeCalculateFields();
	PACKETPP_ASSERT(buffer22Length == ipOpt2.getRawPacket()->getRawDataLen(), "ipOpt2 len (%d) is different than read packet len (%d)", ipOpt2.getRawPacket()->getRawDataLen(), buffer22Length);
	PACKETPP_ASSERT(memcmp(ipOpt2.getRawPacket()->getRawData(), buffer22, ipOpt2.getRawPacket()->getRawDataLen()) == 0, "ipOpt2: Raw packet data is different than expected");


	ipLayer = ipOpt3.getLayerOfType<IPv4Layer>();
	uint16_t routerAlerVal = 0;
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_RouterAlert, sizeof(uint16_t), (uint8_t*)&routerAlerVal) != NULL, "Cannot add router alert option to packet 3");
	ipOpt3.computeCalculateFields();
	PACKETPP_ASSERT(buffer33Length == ipOpt3.getRawPacket()->getRawDataLen(), "ipOpt3 len (%d) is different than read packet len (%d)", ipOpt3.getRawPacket()->getRawDataLen(), buffer33Length);
	PACKETPP_ASSERT(memcmp(ipOpt3.getRawPacket()->getRawData(), buffer33, ipOpt3.getRawPacket()->getRawDataLen()) == 0, "ipOpt3: Raw packet data is different than expected");


	ipLayer = ipOpt4.getLayerOfType<IPv4Layer>();
	std::vector<IPv4Address> ipListValue;
	ipListValue.push_back(IPv4Address(std::string("1.2.3.4")));
	ipListValue.push_back(IPv4Address(std::string("10.0.0.138")));
	ipListValue.push_back(IPv4Address(std::string("10.0.0.138")));
	for (int i = 0; i < 6; i++)
		ipListValue.push_back(IPv4Address::Zero);
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_RecordRoute, ipListValue) != NULL, "Cannot add record route option to packet 4");
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_EndOfOtionsList, 0, NULL) != NULL, "Cannot add end-of-opt-list option to packet 4");
	ipOpt4.computeCalculateFields();
	PACKETPP_ASSERT(buffer44Length == ipOpt4.getRawPacket()->getRawDataLen(), "ipOpt4 len (%d) is different than read packet len (%d)", ipOpt4.getRawPacket()->getRawDataLen(), buffer44Length);
	PACKETPP_ASSERT(memcmp(ipOpt4.getRawPacket()->getRawData(), buffer44, ipOpt4.getRawPacket()->getRawDataLen()) == 0, "ipOpt4: Raw packet data is different than expected");


	ipLayer = ipOpt5.getLayerOfType<IPv4Layer>();
	tsOption.clear();
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(ipLayer->addTimestampOption(tsOption) == NULL, "Managed to add an empty timestamp value");
	LoggerPP::getInstance().enableErrors();
	tsOption.type = IPv4TimestampOptionValue::TimestampAndIP;
	tsOption.ipAddresses.push_back(IPv4Address(std::string("10.0.0.6")));
	tsOption.ipAddresses.push_back(IPv4Address(std::string("10.0.0.138")));
	tsOption.ipAddresses.push_back(IPv4Address(std::string("10.0.0.138")));
	tsOption.ipAddresses.push_back(IPv4Address::Zero);
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(ipLayer->addTimestampOption(tsOption) == NULL, "Managed to set timestamp option value with non-equal number of timestamps and IPs");
	LoggerPP::getInstance().enableErrors();
	tsOption.timestamps.push_back(70037668);
	tsOption.timestamps.push_back(77233718);
	tsOption.timestamps.push_back(77233718);
	tsOption.timestamps.push_back(0);
	IPv4OptionData* optData = ipLayer->addTimestampOption(tsOption);
	PACKETPP_ASSERT(optData != NULL, "Cannot add timestamp option to packet 5");
	PACKETPP_ASSERT(optData->getType() == IPV4OPT_Timestamp, "Packet 5: timestamp option doesn't have type IPV4OPT_Timestamp");
	PACKETPP_ASSERT(optData->getTotalSize() == 36, "Packet 5: timestamp option length isn't 36");
	tsOption.clear();
	tsOption = optData->getTimestampOptionValue();
	PACKETPP_ASSERT(tsOption.type == IPv4TimestampOptionValue::TimestampAndIP, "Packet 5: timestamp data type isn't TimestampAndIP");
	PACKETPP_ASSERT(tsOption.timestamps.size() == 3, "Packet 5: number of timestamps isn't 3");
	PACKETPP_ASSERT(tsOption.timestamps.at(1) == htonl(77233718), "Packet 5: timestamps[1] isn't 77233718");
	PACKETPP_ASSERT(tsOption.ipAddresses.size() == 3, "Packet 5: number of IP addresses isn't 3");
	PACKETPP_ASSERT(tsOption.ipAddresses.at(2) == IPv4Address(std::string("10.0.0.138")), "Packet 5: IP[2] isn't 10.0.0.138");
	ipOpt5.computeCalculateFields();
	PACKETPP_ASSERT(buffer55Length == ipOpt5.getRawPacket()->getRawDataLen(), "ipOpt5 len (%d) is different than read packet len (%d)", ipOpt5.getRawPacket()->getRawDataLen(), buffer55Length);
	PACKETPP_ASSERT(memcmp(ipOpt5.getRawPacket()->getRawData(), buffer55, ipOpt5.getRawPacket()->getRawDataLen()) == 0, "ipOpt5: Raw packet data is different than expected");


	ipLayer = ipOpt6.getLayerOfType<IPv4Layer>();
	ipListValue.clear();
	ipListValue.push_back(IPv4Address::Zero);
	optData = ipLayer->addOption(IPV4OPT_StrictSourceRoute, ipListValue);
	PACKETPP_ASSERT(optData != NULL, "Cannot add strict source route option to packet 6");
	PACKETPP_ASSERT(optData->getType() == IPV4OPT_StrictSourceRoute, "Packet 6: strict source route option doesn't have type IPV4OPT_StrictSourceRoute");
	PACKETPP_ASSERT(optData->getTotalSize() == 7, "Packet 6: strict source route length isn't 7");
	ipListValue = optData->getValueAsIpList();
	PACKETPP_ASSERT(ipListValue.size() == 0, "Packet 6: strict source route IP list value length isn't 0");
	optData = ipLayer->addOptionAfter(IPV4OPT_NOP, 0, NULL);
	PACKETPP_ASSERT(optData != NULL, "Cannot add NOP option to packet 6");
	PACKETPP_ASSERT(optData->getType() == IPV4OPT_NOP, "Packet 6: NOP option doesn't have type NOP");
	PACKETPP_ASSERT(optData->getTotalSize() == 1, "Packet 6: NOP option length isn't 1");
	ipOpt6.computeCalculateFields();
	PACKETPP_ASSERT(buffer66Length == ipOpt6.getRawPacket()->getRawDataLen(), "ipOpt6 len (%d) is different than read packet len (%d)", ipOpt6.getRawPacket()->getRawDataLen(), buffer66Length);
	PACKETPP_ASSERT(memcmp(ipOpt6.getRawPacket()->getRawData(), buffer66, ipOpt6.getRawPacket()->getRawDataLen()) == 0, "ipOpt6: Raw packet data is different than expected");


	ipLayer = ipOpt7.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_NOP, 0, NULL) != NULL, "Cannot add NOP option to packet 7");
	ipListValue.clear();
	ipListValue.push_back(IPv4Address::Zero);
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_LooseSourceRoute, ipListValue) != NULL, "Cannot add loose source route option to packet 7");
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(buffer77Length == ipOpt7.getRawPacket()->getRawDataLen(), "ipOpt7 len (%d) is different than read packet len (%d)", ipOpt7.getRawPacket()->getRawDataLen(), buffer77Length);
	PACKETPP_ASSERT(memcmp(ipOpt7.getRawPacket()->getRawData(), buffer77, ipOpt7.getRawPacket()->getRawDataLen()) == 0, "ipOpt7: Raw packet data is different than expected");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 2, "Packet 7 option count after adding loose source route isn't 2, it's %d", (int)ipLayer->getOptionsCount());

	tsOption.clear();
	tsOption.type = IPv4TimestampOptionValue::TimestampAndIP;
	tsOption.ipAddresses.push_back(IPv4Address(std::string("10.0.0.6")));
	tsOption.ipAddresses.push_back(IPv4Address::Zero);
	tsOption.timestamps.push_back(70037668);
	tsOption.timestamps.push_back(70037669);
	PACKETPP_ASSERT(ipLayer->addTimestampOptionAfter(tsOption, IPV4OPT_NOP) != NULL, "Cannot add timestamp option to packet 7");
	PACKETPP_ASSERT(ipLayer->addOptionAfter(IPV4OPT_RouterAlert, sizeof(uint16_t), (uint8_t*)&routerAlerVal) != NULL, "Cannot add router alert option to packet 7");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 4, "Packet 7 option count after adding router alert option isn't 4");
	ipOpt7.computeCalculateFields();
	tsOption.clear();
	tsOption.type = IPv4TimestampOptionValue::TimestampOnly;
	tsOption.timestamps.push_back(70037670);
	PACKETPP_ASSERT(ipLayer->addTimestampOption(tsOption) != NULL, "Cannot add 2nd timestamp option to packet 7");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 5, "Packet 7 option count after adding 2nd timestamp option isn't 5");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(ipLayer->addOption(IPV4OPT_RouterAlert, sizeof(uint16_t), (uint8_t*)&routerAlerVal) == NULL, "Managed to add an option to packet 7 although max option size exceeded");
	LoggerPP::getInstance().enableErrors();
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 5, "Packet 7 option count after adding all options isn't 5");


	PACKETPP_ASSERT(ipLayer->removeOption(IPV4OPT_Timestamp) == true, "Cannot remove timestamp option");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 4, "Packet 7 option count after removing 1st timestamp option isn't 4");
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(ipLayer->removeOption(IPV4OPT_RouterAlert) == true, "Cannot remove router alert option");
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(ipLayer->removeOption(IPV4OPT_Timestamp) == true, "Cannot remove 2nd timestamp option");
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 2, "Packet 7 option count after removing 2nd timestamp option isn't 2");
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(buffer77Length == ipOpt7.getRawPacket()->getRawDataLen(), "ipOpt7 len (%d) is different than read packet len (%d)", ipOpt7.getRawPacket()->getRawDataLen(), buffer77Length);
	PACKETPP_ASSERT(memcmp(ipOpt7.getRawPacket()->getRawData(), buffer77, ipOpt7.getRawPacket()->getRawDataLen()) == 0, "ipOpt7: Raw packet data is different than expected");

	PACKETPP_ASSERT(ipLayer->removeAllOptions() == true, "Cannot remove all remaining options");
	ipOpt7.computeCalculateFields();
	PACKETPP_ASSERT(ipOpt7.getRawPacketReadOnly()->getRawDataLen() == 42, "Packet 7 length after removing all options isn't 42");
	ipLayer = ipOpt7.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ipLayer->getOptionsCount() == 0, "Packet 7 option count after removing all options isn't 0");

	delete [] buffer11;
	delete [] buffer22;
	delete [] buffer33;
	delete [] buffer44;
	delete [] buffer55;
	delete [] buffer66;
	delete [] buffer77;

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
	EthLayer ethLayer(MacAddress("6c:f0:49:b2:de:6e"), MacAddress ("33:33:00:00:00:0c"));

	IPv6Layer ip6Layer(srcIP, dstIP);
	ip6_hdr* ip6Header = ip6Layer.getIPv6Header();
	ip6Header->hopLimit = 1;
	ip6Header->nextHeader = 17;

	UdpLayer udpLayer(63628, 1900);

	Layer* afterIpv6Layer = pUdpLayer->getNextLayer();
	uint8_t* payloadData = new uint8_t[afterIpv6Layer->getDataLen()];
	afterIpv6Layer->copyData(payloadData);
	PayloadLayer payloadLayer(payloadData, afterIpv6Layer->getDataLen(), true);

	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&ethLayer), "Couldn't add eth layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&ip6Layer), "Couldn't add IPv6 layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&udpLayer), "Couldn't add udp layer");
	PACKETPP_ASSERT(ip6UdpPacketNew.addLayer(&payloadLayer), "Couldn't add payload layer");
	ip6UdpPacketNew.computeCalculateFields();

	PACKETPP_ASSERT(bufferLength == ip6UdpPacketNew.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", ip6UdpPacketNew.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(ip6UdpPacketNew.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete[] payloadData;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv6FragmentationTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IPv6Frag1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IPv6Frag1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IPv6Frag2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IPv6Frag2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IPv6Frag3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IPv6Frag3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IPv6Frag4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IPv6Frag4.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet frag1(&rawPacket1);
	Packet frag2(&rawPacket2);
	Packet frag3(&rawPacket3);
	Packet frag4(&rawPacket4);

	IPv6Layer* ipv6Layer = frag1.getLayerOfType<IPv6Layer>();
	IPv6FragmentationHeader* fragHeader = ipv6Layer->getExtensionOfType<IPv6FragmentationHeader>();
	PACKETPP_ASSERT(fragHeader->getExtensionType() == IPv6Extension::IPv6Fragmentation, "Frag1 extension type isn't IPv6Fragmentation");
	PACKETPP_ASSERT(fragHeader != NULL, "Frag1 - can't retrieve frag header");
	PACKETPP_ASSERT(fragHeader->isFirstFragment() == true, "Frag1 isn't first fragment");
	PACKETPP_ASSERT(fragHeader->isLastFragment() == false, "Frag1 is marked as last fragment");
	PACKETPP_ASSERT(fragHeader->getFragmentOffset() == 0, "Frag1 offset isn't 0");
	PACKETPP_ASSERT(ntohl(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag1 frag id isn't as expected");
	PACKETPP_ASSERT(fragHeader->getFragHeader()->nextHeader == PACKETPP_IPPROTO_UDP, "Frag1 next header isn't UDP, it's %d", fragHeader->getFragHeader()->nextHeader);

	ipv6Layer = frag2.getLayerOfType<IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<IPv6FragmentationHeader>();
	PACKETPP_ASSERT(fragHeader->getExtensionType() == IPv6Extension::IPv6Fragmentation, "Frag2 extension type isn't IPv6Fragmentation");
	PACKETPP_ASSERT(fragHeader != NULL, "Frag2 - can't retrieve frag header");
	PACKETPP_ASSERT(fragHeader->isFirstFragment() == false, "Frag2 is marked as first fragment");
	PACKETPP_ASSERT(fragHeader->isLastFragment() == false, "Frag2 is marked as last fragment");
	PACKETPP_ASSERT(fragHeader->getFragmentOffset() == 1448, "Frag2 offset isn't 1448");
	PACKETPP_ASSERT(ntohl(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag2 frag id isn't as expected");
	PACKETPP_ASSERT(fragHeader->getFragHeader()->nextHeader == PACKETPP_IPPROTO_UDP, "Frag2 next header isn't UDP");

	ipv6Layer = frag3.getLayerOfType<IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<IPv6FragmentationHeader>();
	PACKETPP_ASSERT(fragHeader->getExtensionType() == IPv6Extension::IPv6Fragmentation, "Frag3 extension type isn't IPv6Fragmentation");
	PACKETPP_ASSERT(fragHeader != NULL, "Frag3 - can't retrieve frag header");
	PACKETPP_ASSERT(fragHeader->isFirstFragment() == false, "Frag3 is marked as first fragment");
	PACKETPP_ASSERT(fragHeader->isLastFragment() == false, "Frag3 is marked as last fragment");
	PACKETPP_ASSERT(fragHeader->getFragmentOffset() == 2896, "Frag3 offset isn't 2896");
	PACKETPP_ASSERT(ntohl(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag3 frag id isn't as expected");
	PACKETPP_ASSERT(fragHeader->getFragHeader()->nextHeader == PACKETPP_IPPROTO_UDP, "Frag3 next header isn't UDP");

	ipv6Layer = frag4.getLayerOfType<IPv6Layer>();
	PACKETPP_ASSERT(ipv6Layer->getHeaderLen() == 48, "Frag4 IPv6 layer len isn't 48");
	fragHeader = ipv6Layer->getExtensionOfType<IPv6FragmentationHeader>();
	PACKETPP_ASSERT(fragHeader->getExtensionType() == IPv6Extension::IPv6Fragmentation, "Frag4 extension type isn't IPv6Fragmentation");
	PACKETPP_ASSERT(fragHeader != NULL, "Frag4 - can't retrieve frag header");
	PACKETPP_ASSERT(fragHeader->isFirstFragment() == false, "Frag4 is marked as first fragment");
	PACKETPP_ASSERT(fragHeader->isLastFragment() == true, "Frag4 isn't last fragment");
	PACKETPP_ASSERT(fragHeader->getFragmentOffset() == 4344, "Frag4 offset isn't 4344");
	PACKETPP_ASSERT(ntohl(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag4 frag id isn't as expected");
	PACKETPP_ASSERT(fragHeader->getFragHeader()->nextHeader == PACKETPP_IPPROTO_UDP, "Frag4 next header isn't UDP");

	EthLayer newEthLayer(*frag1.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer(*frag1.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer.removeAllExtensions();
	PACKETPP_ASSERT(newIPv6Layer.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	PayloadLayer newPayloadLayer(*frag4.getLayerOfType<PayloadLayer>());

	Packet newFrag;
	newFrag.addLayer(&newEthLayer);
	newFrag.addLayer(&newIPv6Layer);
	newFrag.addLayer(&newPayloadLayer);

	IPv6FragmentationHeader newFragHeader(0xf88eb466, 4344, true);
	newIPv6Layer.addExtension<IPv6FragmentationHeader>(newFragHeader);
	PACKETPP_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with new frag extension isn't 48");

	newFrag.computeCalculateFields();

	PACKETPP_ASSERT(frag4.getRawPacket()->getRawDataLen() == newFrag.getRawPacket()->getRawDataLen(), "Generated fragment len (%d) is different than frag4 len (%d)", newFrag.getRawPacket()->getRawDataLen(), frag4.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(frag4.getRawPacket()->getRawData(), newFrag.getRawPacket()->getRawData(), frag4.getRawPacket()->getRawDataLen()) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Ipv6ExtensionsTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/ipv6_options_destination.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file ipv6_options_destination.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/ipv6_options_hop_by_hop.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file ipv6_options_hop_by_hop.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/ipv6_options_routing1.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file ipv6_options_routing1.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/ipv6_options_routing2.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file ipv6_options_routing2.dat");

	int buffer5Length = 0;
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/ipv6_options_ah.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5== NULL), "cannot read file ipv6_options_ah.dat");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/ipv6_options_multi.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6== NULL), "cannot read file ipv6_options_multi.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);
	RawPacket rawPacket6((const uint8_t*)buffer6, buffer6Length, time, true);

	Packet ipv6Dest(&rawPacket1);
	Packet ipv6HopByHop(&rawPacket2);
	Packet ipv6Routing1(&rawPacket3);
	Packet ipv6Routing2(&rawPacket4);
	Packet ipv6AuthHdr(&rawPacket5);
	Packet ipv6MultipleOptions(&rawPacket6);


	// parsing of Destionation extension
	IPv6TLVOptionHeader::TLVOption* option = NULL;
	IPv6Layer* ipv6Layer = ipv6Dest.getLayerOfType<IPv6Layer>();
	PACKETPP_ASSERT(ipv6Layer->getExtensionCount() == 1, "Dest ext packet1: num of extensions isn't 1");
	IPv6HopByHopHeader* hopByHopExt = ipv6Layer->getExtensionOfType<IPv6HopByHopHeader>();
	IPv6DestinationHeader* destExt = ipv6Layer->getExtensionOfType<IPv6DestinationHeader>();
	PACKETPP_ASSERT(hopByHopExt == NULL, "Dest ext packet: Found Hop-By-Hop extension although it doesn't exist");
	PACKETPP_ASSERT(destExt != NULL, "Dest ext packet: Cannot find dest extension");
	PACKETPP_ASSERT(destExt->getExtensionType() == IPv6Extension::IPv6Destination, "Dest ext packet: Dest ext type isn't IPv6Extension::IPv6Destination");
	PACKETPP_ASSERT(destExt->getOptionCount() == 2, "Dest ext packet: Number of options isn't 2");
	option = destExt->getFirstOption();
	PACKETPP_ASSERT(option != NULL, "Dest ext packet: First option is null");
	PACKETPP_ASSERT(option->optionType == 11, "Dest ext packet: First option type isn't 11");
	PACKETPP_ASSERT(option->getTotalSize() == 3, "Dest ext packet: First option total size isn't 3");
	PACKETPP_ASSERT(option->getDataSize() == 1, "Dest ext packet: First option data size isn't 1");
	PACKETPP_ASSERT(option->getValueAs<uint8_t>() == 9, "Dest ext packet: First option data isn't 9");
	option = destExt->getNextOption(option);
	PACKETPP_ASSERT(option != NULL, "Dest ext packet: Second option is null");
	PACKETPP_ASSERT(option->optionType == 1, "Dest ext packet: Second option type isn't 1");
	PACKETPP_ASSERT(option->getTotalSize() == 3, "Dest ext packet: Second option total size isn't 3");
	PACKETPP_ASSERT(option->getDataSize() == 1, "Dest ext packet: Second option data size isn't 1");
	PACKETPP_ASSERT(option->getValueAs<uint8_t>() == 0, "Dest ext packet: Second option data isn't 0");
	option = destExt->getNextOption(option);
	PACKETPP_ASSERT(option == NULL, "Dest ext packet: Found third option");
	option = destExt->getOption(11);
	PACKETPP_ASSERT(option != NULL, "Dest ext packet: Cannot find option with type 11");
	PACKETPP_ASSERT(option->getTotalSize() == 3, "Dest ext packet: Option with type 11 total size isn't 3");
	PACKETPP_ASSERT(destExt->getOption(12) == NULL, "Dest ext packet: Found option with type 12");
	PACKETPP_ASSERT(destExt->getOption(0) == NULL, "Dest ext packet: Found option with type 0");


	// parsing of Hop-By-Hop extension
	ipv6Layer = ipv6HopByHop.getLayerOfType<IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<IPv6HopByHopHeader>();
	destExt = ipv6Layer->getExtensionOfType<IPv6DestinationHeader>();
	PACKETPP_ASSERT(destExt == NULL, "Hop-By-Hop ext packet: Found dest extension although it doesn't exist");
	PACKETPP_ASSERT(hopByHopExt != NULL, "Hop-By-Hop ext packet: Cannot find Hop-By-Hop extension");
	PACKETPP_ASSERT(hopByHopExt->getExtensionType() == IPv6Extension::IPv6HopByHop, "Hop-By-Hop ext packet: Hop-By-Hop ext type isn't IPv6Extension::IPv6HopByHop");
	PACKETPP_ASSERT(hopByHopExt->getOptionCount() == 2, "Hop-By-Hop ext packet: Number of options isn't 2");
	PACKETPP_ASSERT(hopByHopExt->getOption(3) == NULL, "Hop-By-Hop ext packet: Found option with type 3");
	PACKETPP_ASSERT(hopByHopExt->getOption(0) == NULL, "Hop-By-Hop ext packet: Found option with type 0");
	option = hopByHopExt->getFirstOption();
	PACKETPP_ASSERT(option->optionType == 5, "Hop-By-Hop ext packet: First option type isn't 5");
	PACKETPP_ASSERT(option->getTotalSize() == 4, "Hop-By-Hop ext packet: First option total size isn't 4");
	PACKETPP_ASSERT(option->getDataSize() == 2, "Hop-By-Hop ext packet: First option data size isn't 2");
	PACKETPP_ASSERT(option->getValueAs<uint16_t>() == (uint16_t)0, "Hop-By-Hop ext packet: First option data isn't 0");
	option = hopByHopExt->getNextOption(option);
	PACKETPP_ASSERT(option != NULL, "Hop-By-Hop ext packet: Second option is null");
	PACKETPP_ASSERT(option->optionType == 1, "Hop-By-Hop ext packet: Second option type isn't 1");
	PACKETPP_ASSERT(option->getTotalSize() == 2, "Hop-By-Hop ext packet: Second option total size isn't 2");
	PACKETPP_ASSERT(option->getDataSize() == 0, "Hop-By-Hop ext packet: Second option data size isn't 0");
	PACKETPP_ASSERT(option->getValueAs<uint8_t>() == 0, "Hop-By-Hop ext packet: Second option data isn't 0");
	option = hopByHopExt->getNextOption(option);
	PACKETPP_ASSERT(option == NULL, "Hop-By-Hop ext packet: Found third option");


	// parsing of routing extension #1
	ipv6Layer = ipv6Routing1.getLayerOfType<IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<IPv6HopByHopHeader>();
	PACKETPP_ASSERT(ipv6Layer->getExtensionCount() == 1, "Routing ext packet1: num of extensions isn't 1");
	IPv6RoutingHeader* routingExt = ipv6Layer->getExtensionOfType<IPv6RoutingHeader>();
	PACKETPP_ASSERT(destExt == NULL, "Routing ext packet1: Found dest extension although it doesn't exist");
	PACKETPP_ASSERT(routingExt != NULL, "Routing ext packet1: Cannot find routing extension");
	PACKETPP_ASSERT(routingExt->getExtensionType() == IPv6Extension::IPv6Routing, "Routing ext packet1: routing ext isn't of type IPv6Extension::IPv6Routing");
	PACKETPP_ASSERT(routingExt->getRoutingHeader()->routingType == 0, "Routing ext packet1: routing type isn't 0");
	PACKETPP_ASSERT(routingExt->getRoutingHeader()->segmentsLeft == 2, "Routing ext packet1: segments left isn't 2");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataLength() == 36, "Routing ext packet1: additional data len isn't 36");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(4) == IPv6Address(std::string("2200::210:2:0:0:4")), "Routing ext packet1: IPv6 address is wrong");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(20) == IPv6Address(std::string("2200::240:2:0:0:4")), "Routing ext packet1: second IPv6 address is wrong");


	// parsing of routing extension #2
	ipv6Layer = ipv6Routing2.getLayerOfType<IPv6Layer>();
	routingExt = ipv6Layer->getExtensionOfType<IPv6RoutingHeader>();
	PACKETPP_ASSERT(routingExt != NULL, "Routing ext packet2: Cannot find routing extension");
	PACKETPP_ASSERT(routingExt->getExtensionType() == IPv6Extension::IPv6Routing, "Routing ext packet2: routing ext isn't of type IPv6Extension::IPv6Routing");
	PACKETPP_ASSERT(routingExt->getRoutingHeader()->routingType == 0, "Routing ext packet2: routing type isn't 0");
	PACKETPP_ASSERT(routingExt->getRoutingHeader()->segmentsLeft == 1, "Routing ext packet2: segments left isn't 1");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataLength() == 20, "Routing ext packet2: additional data len isn't 20");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(4) == IPv6Address(std::string("2200::210:2:0:0:4")), "Routing ext packet2: IPv6 address is wrong");
	PACKETPP_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(20) == IPv6Address::Zero, "Routing ext packet2: additional data out-of-bounds but isn't returned as zero IPv6 address");


	// parsing of authentication header extension
	ipv6Layer = ipv6AuthHdr.getLayerOfType<IPv6Layer>();
	IPv6AuthenticationHeader* authHdrExt = ipv6Layer->getExtensionOfType<IPv6AuthenticationHeader>();
	PACKETPP_ASSERT(authHdrExt != NULL, "AH ext packet: Cannot find AH extension");
	PACKETPP_ASSERT(authHdrExt->getExtensionType() == IPv6Extension::IPv6AuthenticationHdr, "AH ext packet: AH ext isn't of type IPv6Extension::IPv6AuthenticationHdr");
	PACKETPP_ASSERT(authHdrExt->getAuthHeader()->securityParametersIndex == htonl(0x100), "AH ext packet: SPI isn't 0x100");
	PACKETPP_ASSERT(authHdrExt->getAuthHeader()->sequenceNumber == htonl(32), "AH ext packet: sequence isn't 32");
	PACKETPP_ASSERT(authHdrExt->getIntegrityCheckValueLength() == 12, "AH ext packet: ICV len isn't 12");
	uint8_t expectedICV[12] = { 0x35, 0x48, 0x21, 0x48, 0xb2, 0x43, 0x5a, 0x23, 0xdc, 0xdd, 0x55, 0x36 };
	PACKETPP_ASSERT(memcmp(expectedICV, authHdrExt->getIntegrityCheckValue(), authHdrExt->getIntegrityCheckValueLength()) == 0, "AH ext packet: ICV value isn't as expected");


	// parsing of multiple options in one IPv6 layer
	ipv6Layer = ipv6MultipleOptions.getLayerOfType<IPv6Layer>();
	PACKETPP_ASSERT(ipv6Layer->getExtensionCount() == 4, "Multiple ext packet: Num of extensions isn't 4");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6AuthenticationHeader>() != NULL, "Multiple ext packet: Cannot find AH extension");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6AuthenticationHeader>()->getAuthHeader()->securityParametersIndex = ntohl(0x100),
			"Multiple ext packet: AH ext SPI isn't 0x100");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6DestinationHeader>() != NULL, "Multiple ext packet: Cannot find Dest extension");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6DestinationHeader>()->getFirstOption()->optionType == 11,
			"Multiple ext packet: Dest ext first option type isn't 11");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6HopByHopHeader>() != NULL, "Multiple ext packet: Cannot find Hop-By-Hop extension");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6HopByHopHeader>()->getFirstOption()->optionType == 5,
			"Multiple ext packet: Hop-By-Hop ext first option type isn't 5");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6RoutingHeader>() != NULL, "Multiple ext packet: Cannot find Routing extension");
	PACKETPP_ASSERT(ipv6Layer->getExtensionOfType<IPv6RoutingHeader>()->getRoutingHeader()->routingType == 0,
			"Multiple ext packet: Routing ext - routing type isn't 0");


	// creation of Destionation extension
	EthLayer newEthLayer(*ipv6Dest.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer(*ipv6Dest.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer.removeAllExtensions();
	PACKETPP_ASSERT(newIPv6Layer.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	std::vector<IPv6TLVOptionHeader::TLVOptionBuilder> destExtOptions;
	destExtOptions.push_back(IPv6TLVOptionHeader::TLVOptionBuilder(11, (uint8_t)9));
	destExtOptions.push_back(IPv6TLVOptionHeader::TLVOptionBuilder(1, (uint8_t)0));
	IPv6DestinationHeader newDestExtHeader(destExtOptions);
	newIPv6Layer.addExtension<IPv6DestinationHeader>(newDestExtHeader);

	UdpLayer newUdpLayer(*ipv6Dest.getLayerOfType<UdpLayer>());
	PayloadLayer newPayloadLayer(*ipv6Dest.getLayerOfType<PayloadLayer>());

	Packet newPacket;
	newPacket.addLayer(&newEthLayer);
	newPacket.addLayer(&newIPv6Layer);
	newPacket.addLayer(&newUdpLayer);
	newPacket.addLayer(&newPayloadLayer);
	newPacket.computeCalculateFields();

	PACKETPP_ASSERT(ipv6Dest.getRawPacket()->getRawDataLen() == newPacket.getRawPacket()->getRawDataLen(), "IPv6 Dest ext: Generated packet len (%d) is different than original packet len (%d)", newPacket.getRawPacket()->getRawDataLen(), ipv6Dest.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(ipv6Dest.getRawPacket()->getRawData(), newPacket.getRawPacket()->getRawData(), ipv6Dest.getRawPacket()->getRawDataLen()) == 0, "IPv6 Dest ext: Raw packet data is different than expected");


	// creation of hop-by-hop extension
	EthLayer newEthLayer2(*ipv6HopByHop.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer2(*ipv6HopByHop.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(newIPv6Layer2.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer2.removeAllExtensions();
	PACKETPP_ASSERT(newIPv6Layer2.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	std::vector<IPv6TLVOptionHeader::TLVOptionBuilder> hopByHopExtOptions;
	hopByHopExtOptions.push_back(IPv6TLVOptionHeader::TLVOptionBuilder(5, (uint16_t)0));
	hopByHopExtOptions.push_back(IPv6TLVOptionHeader::TLVOptionBuilder(1, 0, NULL));
	IPv6HopByHopHeader newHopByHopHeader(hopByHopExtOptions);
	newIPv6Layer2.addExtension<IPv6HopByHopHeader>(newHopByHopHeader);

	PayloadLayer newPayloadLayer2(*ipv6HopByHop.getLayerOfType<PayloadLayer>());

	Packet newPacket2;
	newPacket2.addLayer(&newEthLayer2);
	newPacket2.addLayer(&newIPv6Layer2);
	newPacket2.addLayer(&newPayloadLayer2);
	newPacket2.computeCalculateFields();

	PACKETPP_ASSERT(ipv6HopByHop.getRawPacket()->getRawDataLen() == newPacket2.getRawPacket()->getRawDataLen(), "IPv6 hop-by-hop ext: Generated packet len (%d) is different than original packet len (%d)", newPacket2.getRawPacket()->getRawDataLen(), ipv6HopByHop.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(ipv6HopByHop.getRawPacket()->getRawData(), newPacket2.getRawPacket()->getRawData(), ipv6HopByHop.getRawPacket()->getRawDataLen()) == 0, "IPv6 hop-by-hop ext: Raw packet data is different than expected");


	// creation of routing extension
	EthLayer newEthLayer3(*ipv6Routing2.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer3(*ipv6Routing2.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(newIPv6Layer3.getHeaderLen() == 64, "New IPv6 layer len with old extensions isn't 64");
	newIPv6Layer3.removeAllExtensions();
	PACKETPP_ASSERT(newIPv6Layer3.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	uint8_t* routingAdditionalData = new uint8_t[20];
	memset(routingAdditionalData, 0, 20);
	IPv6Address ip6Addr(std::string("2200::210:2:0:0:4"));
	ip6Addr.copyTo(routingAdditionalData + 4);
	IPv6RoutingHeader newRoutingHeader(0, 1, routingAdditionalData, 20);
	newIPv6Layer3.addExtension<IPv6RoutingHeader>(newRoutingHeader);
	delete [] routingAdditionalData;

	UdpLayer newUdpLayer3(*ipv6Routing2.getLayerOfType<UdpLayer>());

	Packet newPacket3;
	newPacket3.addLayer(&newEthLayer3);
	newPacket3.addLayer(&newIPv6Layer3);
	newPacket3.addLayer(&newUdpLayer3);

	PACKETPP_ASSERT(ipv6Routing2.getRawPacket()->getRawDataLen() == newPacket3.getRawPacket()->getRawDataLen(), "IPv6 routing ext: Generated packet len (%d) is different than original packet len (%d)", newPacket3.getRawPacket()->getRawDataLen(), ipv6Routing2.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(ipv6Routing2.getRawPacket()->getRawData(), newPacket3.getRawPacket()->getRawData(), ipv6Routing2.getRawPacket()->getRawDataLen()) == 0, "IPv6 routing ext: Raw packet data is different than expected");


	// creation of AH extension
	EthLayer newEthLayer4(*ipv6AuthHdr.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer4(*ipv6AuthHdr.getLayerOfType<IPv6Layer>());
	PACKETPP_ASSERT(newIPv6Layer4.getHeaderLen() == 64, "New IPv6 layer len with old extensions isn't 64");
	newIPv6Layer4.removeAllExtensions();
	PACKETPP_ASSERT(newIPv6Layer4.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	IPv6AuthenticationHeader newAHExtension(0x100, 32, expectedICV, 12);
	newIPv6Layer4.addExtension<IPv6AuthenticationHeader>(newAHExtension);

	PayloadLayer newPayloadLayer4(*ipv6AuthHdr.getLayerOfType<PayloadLayer>());

	Packet newPacket4;
	newPacket4.addLayer(&newEthLayer4);
	newPacket4.addLayer(&newIPv6Layer4);
	newPacket4.addLayer(&newPayloadLayer4);
	newPacket4.computeCalculateFields();

	PACKETPP_ASSERT(ipv6AuthHdr.getRawPacket()->getRawDataLen() == newPacket4.getRawPacket()->getRawDataLen(), "IPv6 AH ext: Generated packet len (%d) is different than original packet len (%d)", newPacket4.getRawPacket()->getRawDataLen(), ipv6AuthHdr.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(ipv6AuthHdr.getRawPacket()->getRawData(), newPacket4.getRawPacket()->getRawData(), ipv6AuthHdr.getRawPacket()->getRawDataLen()) == 0, "IPv6 AH ext: Raw packet data is different than expected");


	// creation of packet with several extensions
	EthLayer newEthLayer5(*ipv6AuthHdr.getLayerOfType<EthLayer>());

	IPv6Layer newIPv6Layer5(*ipv6AuthHdr.getLayerOfType<IPv6Layer>());
	newIPv6Layer5.removeAllExtensions();

	newIPv6Layer5.addExtension<IPv6HopByHopHeader>(newHopByHopHeader);
	newIPv6Layer5.addExtension<IPv6DestinationHeader>(newDestExtHeader);
	newIPv6Layer5.addExtension<IPv6RoutingHeader>(newRoutingHeader);
	newIPv6Layer5.addExtension<IPv6AuthenticationHeader>(newAHExtension);

	PayloadLayer newPayloadLayer5(*ipv6AuthHdr.getLayerOfType<PayloadLayer>());

	Packet newPacket5;
	newPacket5.addLayer(&newEthLayer5);
	newPacket5.addLayer(&newIPv6Layer5);
	newPacket5.addLayer(&newPayloadLayer5);
	newPacket5.computeCalculateFields();

	PACKETPP_ASSERT(ipv6MultipleOptions.getRawPacket()->getRawDataLen() == newPacket5.getRawPacket()->getRawDataLen(), "IPv6 multiple ext: Generated packet len (%d) is different than original packet len (%d)", newPacket5.getRawPacket()->getRawDataLen(), ipv6MultipleOptions.getRawPacket()->getRawDataLen());
	PACKETPP_ASSERT(memcmp(ipv6MultipleOptions.getRawPacket()->getRawData(), newPacket5.getRawPacket()->getRawData(), ipv6MultipleOptions.getRawPacket()->getRawDataLen()) == 0, "IPv6 multiple ext: Raw packet data is different than expected");


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
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->sequenceNumber == htonl(0xbeab364a), "Sequence number != 0xbeab364a, it's 0x%X", (int)ntohl(tcpLayer->getTcpHeader()->sequenceNumber));
	PACKETPP_ASSERT(tcpLayer->getTcpHeader()->ackNumber == htonl(0xf9ffb58e), "Ack number != 0xf9ffb58e, it's 0x%X", (int)ntohl(tcpLayer->getTcpHeader()->ackNumber));
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
	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 0, "TCP options count isn't 0, it's %d", (int)tcpLayer->getTcpOptionsCount());
	PACKETPP_ASSERT(tcpLayer->getTcpOptionData(PCPP_TCPOPT_NOP) == NULL, "TCP option NOP isn't NULL");
	PACKETPP_ASSERT(tcpLayer->getTcpOptionData(PCPP_TCPOPT_TIMESTAMP) == NULL, "TCP option Timestamp isn't NULL");

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
	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 3, "TCP options count != 3, it's %d", (int)tcpLayer->getTcpOptionsCount());
	TcpOptionData* nopOptionData = NULL;
	TcpOptionData* timestampOptionData = NULL;
	PACKETPP_ASSERT((timestampOptionData = tcpLayer->getTcpOptionData(PCPP_TCPOPT_TIMESTAMP)) != NULL, "TCP option Timestamp is NULL");
	PACKETPP_ASSERT((nopOptionData = tcpLayer->getTcpOptionData(PCPP_TCPOPT_NOP)) != NULL, "TCP option NOP is NULL");
	PACKETPP_ASSERT(timestampOptionData->len == 10, "TCP option Timestamp length != 10, it's 0x%X", timestampOptionData->len);
	uint32_t tsValue = 0;
	uint32_t tsEchoReply = 0;
	memcpy(&tsValue, timestampOptionData->value, 4);
	memcpy(&tsEchoReply, timestampOptionData->value+4, 4);
	PACKETPP_ASSERT(tsValue == htonl(195102), "TCP option Timestamp option: timestamp value != 195102, it's %d", (int)ntohl(tsValue));
	PACKETPP_ASSERT(tsEchoReply == htonl(3555729271UL), "TCP option Timestamp option: echo reply value != 3555729271, it's %d", (int)ntohl(tsEchoReply));

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

	PACKETPP_ASSERT(tcpLayer->getTcpOptionsCount() == 5, "TCP options count != 5, it's %d", (int)tcpLayer->getTcpOptionsCount());
	TcpOptionData* mssOptionData = NULL;
	TcpOptionData* sackParmOptionData = NULL;
	TcpOptionData* windowScaleOptionData = NULL;
	PACKETPP_ASSERT((mssOptionData = tcpLayer->getTcpOptionData(TCPOPT_MSS)) != NULL, "TCP option MSS is NULL");
	PACKETPP_ASSERT((sackParmOptionData = tcpLayer->getTcpOptionData(TCPOPT_SACK_PERM)) != NULL, "TCP option SACK perm is NULL");
	PACKETPP_ASSERT((windowScaleOptionData = tcpLayer->getTcpOptionData(PCPP_TCPOPT_WINDOW)) != NULL, "TCP option window scale is NULL");

	PACKETPP_ASSERT(mssOptionData->getType() == TCPOPT_MSS, "MSS option isn't of type TCPOPT_MSS");
	PACKETPP_ASSERT(sackParmOptionData->getType() == TCPOPT_SACK_PERM, "Sack perm option isn't of type TCPOPT_SACK_PERM");
	PACKETPP_ASSERT(windowScaleOptionData->getType() == PCPP_TCPOPT_WINDOW, "Window scale option isn't of type PCPP_TCPOPT_WINDOW");

	PACKETPP_ASSERT(mssOptionData->len == 4, "TCP option Timestamp length != 4, it's 0x%X", mssOptionData->len);
	PACKETPP_ASSERT(sackParmOptionData->len == 2, "TCP option SACK perm length != 2, it's 0x%X", sackParmOptionData->len);
	PACKETPP_ASSERT(windowScaleOptionData->len == 3, "TCP option window scale length != 3, it's 0x%X", mssOptionData->len);

	PACKETPP_ASSERT(mssOptionData->getValueAs<uint16_t>() == htons(1460), "TCP option MSS option: value != 1460, it's %d", ntohs(mssOptionData->getValueAs<uint16_t>()));
	PACKETPP_ASSERT(windowScaleOptionData->getValueAs<uint8_t>() == 4, "TCP option window scale option: value != 4, it's %d", windowScaleOptionData->getValueAs<uint8_t>());
	PACKETPP_ASSERT(sackParmOptionData->getValueAs<uint32_t>() == 0, "TCP option sack perm option: value != 0, it's %d", sackParmOptionData->getValueAs<uint32_t>());
	PACKETPP_ASSERT(mssOptionData->getValueAs<uint32_t>() == 0, "Wrongly fetched MSS value as uint32_t");
	PACKETPP_ASSERT(mssOptionData->getValueAs<uint16_t>(1) == 0, "Wrongly fetched MSS value as uint16_t from offset 1");

	TcpOptionData* curOpt = tcpLayer->getFirstTcpOptionData();
	PACKETPP_ASSERT(curOpt != NULL && curOpt->getType() == TCPOPT_MSS, "First option isn't of type TCPOPT_MSS");
	curOpt = tcpLayer->getNextTcpOptionData(curOpt);
	PACKETPP_ASSERT(curOpt != NULL && curOpt->getType() == TCPOPT_SACK_PERM, "Second option isn't of type TCPOPT_SACK_PERM");
	curOpt = tcpLayer->getNextTcpOptionData(curOpt);
	PACKETPP_ASSERT(curOpt != NULL && curOpt->getType() == PCPP_TCPOPT_TIMESTAMP, "Third option isn't of type PCPP_TCPOPT_TIMESTAMP");
	curOpt = tcpLayer->getNextTcpOptionData(curOpt);
	PACKETPP_ASSERT(curOpt != NULL && curOpt->getType() == PCPP_TCPOPT_NOP, "Fourth option isn't of type PCPP_TCPOPT_NOP");
	curOpt = tcpLayer->getNextTcpOptionData(curOpt);
	PACKETPP_ASSERT(curOpt != NULL && curOpt->getType() == PCPP_TCPOPT_WINDOW, "Fifth option isn't of type PCPP_TCPOPT_WINDOW");
	curOpt = tcpLayer->getNextTcpOptionData(curOpt);
	PACKETPP_ASSERT(curOpt == NULL, "There is sixth TCP option");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(TcpPacketCreation)
{
	MacAddress srcMac("30:46:9a:23:fb:fa");
	MacAddress dstMac("08:00:27:19:1c:78");
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	IPv4Address dstIP(string("10.0.0.6"));
	IPv4Address srcIP(string("212.199.202.9"));
	IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htons(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htons(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	TcpLayer tcpLayer((uint16_t)80, (uint16_t)44160);
	tcpLayer.getTcpHeader()->sequenceNumber = htonl(0xb829cb98);
	tcpLayer.getTcpHeader()->ackNumber = htonl(0xe9771586);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htons(20178);
	PACKETPP_ASSERT(tcpLayer.addTcpOption(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL) != NULL, "Couldn't add 1st NOP option");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 24, "Header len isn't 24 after 1st NOP addition")
	PACKETPP_ASSERT(tcpLayer.addTcpOption(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL) != NULL, "Couldn't add 2nd NOP option");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 24, "Header len isn't 24 after 2nd NOP addition")
	TcpOptionData* tsOption = tcpLayer.addTcpOption(PCPP_TCPOPT_TIMESTAMP, PCPP_TCPOLEN_TIMESTAMP, NULL);
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 32, "Header len isn't 32 after timestamp addition")

	PACKETPP_ASSERT(tsOption != NULL, "Couldn't add timestamp option");
	tsOption->setValue<uint32_t>(htonl(3555735960UL));

	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 3, "TCP option count isn't 3");

	uint8_t payloadData[9] = { 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
	PayloadLayer PayloadLayer(payloadData, 9, true);

	Packet tcpPacket(1);
	tcpPacket.addLayer(&ethLayer);
	tcpPacket.addLayer(&ipLayer);
	tcpPacket.addLayer(&tcpLayer);
	tcpPacket.addLayer(&PayloadLayer);

	uint32_t tsEchoReply = htonl(196757);
	TcpOptionData* tsOptionData = tcpLayer.getTcpOptionData(PCPP_TCPOPT_TIMESTAMP);
	PACKETPP_ASSERT(tsOptionData != NULL, "Couldn't get timestamp option");
	tsOptionData->setValue<uint32_t>(tsEchoReply, 4);

	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 3, "TCP option count (2nd check) isn't 3");

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

PACKETPP_TEST(TcpPacketCreation2)
{
	MacAddress srcMac("08:00:27:19:1c:78");
	MacAddress dstMac("30:46:9a:23:fb:fa");
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	IPv4Address dstIP(string("23.44.242.127"));
	IPv4Address srcIP(string("10.0.0.6"));
	IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htons(1556);
	ipLayer.getIPv4Header()->fragmentOffset = 0x40;
	ipLayer.getIPv4Header()->timeToLive = 64;
	TcpLayer tcpLayer((uint16_t)60225, (uint16_t)80);
	tcpLayer.getTcpHeader()->sequenceNumber = htonl(0x2d3904e0);
	tcpLayer.getTcpHeader()->ackNumber = 0;
	tcpLayer.getTcpHeader()->synFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htons(14600);

	TcpOptionData* nopOption = tcpLayer.addTcpOption(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL);
	PACKETPP_ASSERT(nopOption != NULL, "Couldn't add NOP option");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 24, "Header len isn't 24 after NOP addition");

	uint16_t mssValue = htons(1460);
	TcpOptionData* mssOption = tcpLayer.addTcpOptionAfter(TCPOPT_MSS, PCPP_TCPOLEN_MSS, (uint8_t*)&mssValue, NULL);
	PACKETPP_ASSERT(mssOption != NULL, "Couldn't add MSS option");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 28, "Header len isn't 28 after MSS addition")

	TcpOptionData* tsOption = tcpLayer.addTcpOptionAfter(PCPP_TCPOPT_TIMESTAMP, PCPP_TCPOLEN_TIMESTAMP, NULL, mssOption);
	PACKETPP_ASSERT(tsOption != NULL, "Couldn't add timestamp option");
	tsOption->setValue<uint32_t>(htonl(197364));
	tsOption->setValue<uint32_t>(0, 4);
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 36, "Header len isn't 36 after timestamp addition")

	TcpOptionData* winScaleOption = tcpLayer.addTcpOption(PCPP_TCPOPT_WINDOW, PCPP_TCPOLEN_WINDOW, NULL);
	PACKETPP_ASSERT(winScaleOption != NULL, "Couldn't add Window Scale option");
	winScaleOption->setValue<uint8_t>(4);
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 40, "Header len isn't 40 after Window scale addition");

	mssOption = tcpLayer.getTcpOptionData(TCPOPT_MSS);
	PACKETPP_ASSERT(tcpLayer.addTcpOptionAfter(TCPOPT_SACK_PERM, PCPP_TCPOLEN_SACK_PERM, NULL, mssOption) != NULL, "Couldn't add SACK PERM option");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 40, "Header len isn't 28 after SACK PERM addition")

	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 5, "TCP option count isn't 5");

	Packet tcpPacket(1);
	tcpPacket.addLayer(&ethLayer);
	tcpPacket.addLayer(&ipLayer);
	tcpPacket.addLayer(&tcpLayer);

	tcpPacket.computeCalculateFields();

	tcpLayer.getTcpHeader()->headerChecksum = 0xe013;

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/TcpPacketWithOptions3.dat", bufferLength);
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


	mssOption = tcpLayer.getTcpOptionData(TCPOPT_MSS);
	int tcpQsValue = htonl(9999);
	PACKETPP_ASSERT(tcpLayer.addTcpOptionAfter(TCPOPT_QS, PCPP_TCPOLEN_QS, (uint8_t*)&tcpQsValue, mssOption) != NULL, "Cannot add QS option");
	int tcpSnackValue = htonl(1000);
	PACKETPP_ASSERT(tcpLayer.addTcpOption(TCPOPT_SNACK, PCPP_TCPOLEN_SNACK, (uint8_t*)&tcpSnackValue) != NULL, "Cannot add SNACK option");
	tsOption = tcpLayer.getTcpOptionData(PCPP_TCPOPT_TIMESTAMP);
	PACKETPP_ASSERT(tcpLayer.addTcpOptionAfter(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL, tsOption) != NULL, "Cannot add 2nd NOP option");

	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 8, "TCP option count isn't 8");

	PACKETPP_ASSERT(tcpLayer.removeTcpOption(TCPOPT_QS) == true, "Cannot remove QS option");
	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 7, "TCP option count isn't 7");
	PACKETPP_ASSERT(tcpLayer.removeTcpOption(TCPOPT_SNACK) == true, "Cannot remove SNACK option");
	PACKETPP_ASSERT(tcpLayer.removeTcpOption(PCPP_TCPOPT_NOP) == true, "Cannot remove NOP option");
	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 5, "TCP option count isn't 5 again");

	PACKETPP_ASSERT(memcmp(tcpPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete [] buffer;

	PACKETPP_ASSERT(tcpLayer.removeAllTcpOptions() == true, "Couldn't remove all TCP options");
	PACKETPP_ASSERT(tcpLayer.getTcpOptionsCount() == 0, "TCP option count isn't zero after removing all of them");
	PACKETPP_ASSERT(tcpLayer.getFirstTcpOptionData() == NULL, "Found TCP option after removing all of them");
	PACKETPP_ASSERT(tcpLayer.getHeaderLen() == 20, "Header len isn't 20 after removing all TCP options");
	PACKETPP_ASSERT(tcpLayer.getTcpOptionData(PCPP_TCPOPT_TIMESTAMP) == NULL, "Found TS option after removing all of TCP options");

	PACKETPP_ASSERT(tcpLayer.addTcpOption(TCPOPT_SNACK, PCPP_TCPOLEN_SNACK, (uint8_t*)&tcpSnackValue) != NULL, "Cannot add SNACK option again");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(InsertDataToPacket)
{
	// Creating a packet
	// ~~~~~~~~~~~~~~~~~

	Packet ip4Packet(1);

	MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
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

	VlanLayer vlanLayer(100, 0, 0, PCPP_ETHERTYPE_IP);

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
	EthLayer ethLayer2(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
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

	TcpLayer tcpLayer((uint16_t)12345, (uint16_t)80);
	PACKETPP_ASSERT(ip4Packet.insertLayer(&payloadLayer, &tcpLayer), "Adding tcp layer at the end of packet failed");


	// Create a new packet and use insertLayer for the first layer in packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	Packet testPacket(1);
	EthLayer ethLayer3(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
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

	VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
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
	EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
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

	VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
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

	HeaderField* userAgent = requestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
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
	PACKETPP_ASSERT(httpLayer.addField(PCPP_HTTP_ACCEPT_FIELD, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8") != NULL, "Couldn't add ACCEPT field");
	PACKETPP_ASSERT(httpLayer.addField("Dummy-Field", "some value") != NULL, "Couldn't add Dummy-Field field");
	HeaderField* hostField = httpLayer.insertField(NULL, PCPP_HTTP_HOST_FIELD, "www.ynet-ynet.co.il");
	PACKETPP_ASSERT(hostField != NULL, "Couldn't insert HOST field");
	PACKETPP_ASSERT(httpLayer.insertField(hostField, PCPP_HTTP_CONNECTION_FIELD, "keep-alive") != NULL, "Couldn't add CONNECTION field");
	HeaderField* userAgentField = httpLayer.addField(PCPP_HTTP_USER_AGENT_FIELD, "(Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36");
	httpLayer.getFirstLine()->setUri("bla.php");
	PACKETPP_ASSERT(userAgentField != NULL, "Couldn't add USER-AGENT field");
	PACKETPP_ASSERT(httpLayer.addField(PCPP_HTTP_ACCEPT_LANGUAGE_FIELD, "en-US,en;q=0.8") != NULL, "Couldn't add ACCEPT-LANGUAGE field");
	PACKETPP_ASSERT(httpLayer.addField("Dummy-Field2", "Dummy Value2") != NULL, "Couldn't add Dummy-Field2");
	PACKETPP_ASSERT(httpLayer.removeField("Dummy-Field") == true, "Couldn't remove Dummy-Field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpLayer.removeField("Kuku") == false, "Wrongly succeeded to delete a field that doesn't exist");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpLayer.addEndOfHeader() != NULL, "Couldn't add end of HTTP header");
	PACKETPP_ASSERT(httpLayer.insertField(userAgentField, PCPP_HTTP_ACCEPT_ENCODING_FIELD, "gzip,deflate,sdch"), "Couldn't insert ACCEPT-ENCODING field");
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
	HeaderField* acceptField = httpReqLayer->getFieldByName(PCPP_HTTP_ACCEPT_FIELD);
	PACKETPP_ASSERT(acceptField != NULL, "Cannot find ACCEPT field");
	acceptField->setFieldValue("*/*");
	HeaderField* userAgentField = httpReqLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
	PACKETPP_ASSERT(userAgentField != NULL, "Cannot find USER-AGENT field");
	httpReqLayer->insertField(userAgentField, PCPP_HTTP_REFERER_FIELD, "http://www.ynet.co.il/home/0,7340,L-8,00.html");

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

	HeaderField* contentLengthField = responseLayer->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
	PACKETPP_ASSERT(contentLengthField != NULL, "Couldn't retrieve content-length field");
	int contentLength = atoi(contentLengthField->getFieldValue().c_str());
	PACKETPP_ASSERT(contentLength == 1616, "Content length != 1616, it's %d", contentLength);

	HeaderField* contentTypeField = responseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
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
	PACKETPP_ASSERT(httpResponse.addField(PCPP_HTTP_SERVER_FIELD, "Microsoft-IIS/5.0") != NULL, "Cannot add server field");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(httpResponse.addField(PCPP_HTTP_SERVER_FIELD, "Microsoft-IIS/6.0") == NULL, "Added the same field twice");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(httpResponse.addField(PCPP_HTTP_CONTENT_ENCODING_FIELD, "gzip") != NULL, "Cannot add content-encoding field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName(PCPP_HTTP_SERVER_FIELD), PCPP_HTTP_CONTENT_TYPE_FIELD, "application/x-javascript") != NULL, "Cannot insert content-type field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD), "Accept-Ranges", "bytes") != NULL, "Cannot insert accept-ranges field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("Accept-Ranges"), "KuKu", "BlaBla") != NULL, "Cannot insert KuKu field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("kuku"), "Last-Modified", "Wed, 19 Dec 2012 14:06:29 GMT") != NULL, "Cannot insert last-modified field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("last-Modified"), "ETag", "\"3b846daf2ddcd1:e29\"") != NULL, "Cannot insert etag field");
	PACKETPP_ASSERT(httpResponse.insertField(httpResponse.getFieldByName("etag"), "Vary", "Accept-Encoding") != NULL, "Cannot insert vary field");
	PACKETPP_ASSERT(httpResponse.setContentLength(1616, PCPP_HTTP_CONTENT_ENCODING_FIELD) != NULL, "Cannot set content-length");
	PACKETPP_ASSERT(httpResponse.addField("Kuku2", "blibli2") != NULL, "Cannot add Kuku2 field");
	PACKETPP_ASSERT(httpResponse.addField("Cache-Control", "max-age=66137") != NULL, "Cannot add cache-control field");
	PACKETPP_ASSERT(httpResponse.removeField("KUKU") == true, "Couldn't remove kuku field");

	PACKETPP_ASSERT(httpPacket.addLayer(&httpResponse) == true, "Cannot add HTTP response layer");

	PayloadLayer payloadLayer = *sampleHttpPacket.getLayerOfType<PayloadLayer>();
	PACKETPP_ASSERT(httpPacket.addLayer(&payloadLayer) == true, "Cannot add payload layer");

	PACKETPP_ASSERT(httpResponse.addField(PCPP_HTTP_CONNECTION_FIELD, "keep-alive") != NULL, "Cannot add connection field");
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

	PACKETPP_ASSERT(httpResponse.getHeaderLen() == 382, "HTTP header length is different than expected. Expected: %d; Actual: %d", 382, (int)httpResponse.getHeaderLen());

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
	PACKETPP_ASSERT(pppoeSessionLayer->getNextLayer()->getProtocol() == pcpp::GenericPayolad, "PPPoESession layer next layer isn't PayloadLayer");

	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->code == PPPoELayer::PPPOE_CODE_SESSION, "PPPoE code isn't PPPOE_CODE_SESSION");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->version == 1, "PPPoE version isn't 1");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->type == 1, "PPPoE type isn't 1");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->sessionId == htons(0x0011), "PPPoE session ID isn't 0x0011");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPoEHeader()->payloadLength == htons(20), "PPPoE payload length isn't 20");
	PACKETPP_ASSERT(pppoeSessionLayer->getPPPNextProtocol() == PCPP_PPP_LCP, "PPPoE next protocol isn't LCP");

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

	PPPoESessionLayer pppoesLayer(1, 1, 0x0011, PCPP_PPP_IPV6);
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
	ethLayerPtr->setSourceMac(MacAddress("ca:01:0e:88:00:06"));
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

	PACKETPP_ASSERT(dnsLayer6.getQueryCount() == 2, "Query count != 2, it's %d", (int)dnsLayer6.getQueryCount());
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
	PACKETPP_ASSERT(mplsLayer->getNextLayer()->getProtocol() == pcpp::GenericPayolad, "Layer after MPLS isn't general payload");

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
	PACKETPP_ASSERT(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionData(PCPP_TCPOPT_TIMESTAMP) != tcpLayer.getTcpOptionData(PCPP_TCPOPT_TIMESTAMP),
			"TcpLayer copy and original TCP Timestamp option pointer is the same");
	PACKETPP_ASSERT(memcmp(sampleTcpPacketWithOptions.getLayerOfType<TcpLayer>()->getTcpOptionData(PCPP_TCPOPT_TIMESTAMP), tcpLayer.getTcpOptionData(PCPP_TCPOPT_TIMESTAMP), PCPP_TCPOLEN_TIMESTAMP) == 0,
			"TcpLayer copy and original TCP Timestamp option data differs");


	//HttpLayer copy c'tor test
	//--------------------------

	HttpResponseLayer* sampleHttpLayer = sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
	HttpResponseLayer httpResLayer = *sampleHttpPacket.getLayerOfType<HttpResponseLayer>();
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine() != httpResLayer.getFirstLine(), "HttpResponseLayer copy c'tor didn't actually copy first line, pointers are the same");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getStatusCode() == httpResLayer.getFirstLine()->getStatusCode(), "HttpResponseLayer copy c'tor: status codes differ between original and copy");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getSize() == httpResLayer.getFirstLine()->getSize(), "HttpResponseLayer copy c'tor: sizes differ between original and copy");
	PACKETPP_ASSERT(sampleHttpLayer->getFirstLine()->getVersion() == httpResLayer.getFirstLine()->getVersion(), "HttpResponseLayer copy c'tor: versions differ between original and copy");

	HeaderField* curFieldInSample = sampleHttpLayer->getFirstField();
	HeaderField* curFieldInCopy = httpResLayer.getFirstField();
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
				(int)curFieldInSample->getFieldSize(), (int)curFieldInCopy->getFieldSize());

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

PACKETPP_TEST(IcmpParsingTest)
{
	IcmpLayer* icmpLayer = NULL;
	int buffer1Length = 0;
	int buffer2Length = 0;
	int buffer3Length = 0;
	int buffer4Length = 0;
	int buffer5Length = 0;
	int buffer6Length = 0;
	int buffer7Length = 0;
	int buffer8Length = 0;
	int buffer9Length = 0;
	int buffer10Length = 0;
	int buffer11Length = 0;
	int buffer12Length = 0;
	int buffer13Length = 0;
	int buffer14Length = 0;
	int buffer15Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IcmpEchoRequest.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IcmpEchoRequest.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IcmpEchoReply.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IcmpEchoReply.dat");
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IcmpTimestampRequest.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IcmpTimestampRequest.dat");
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IcmpTimestampReply.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IcmpTimestampReply.dat");
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/IcmpRedirect.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file IcmpRedirect.dat");
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/IcmpRouterAdv1.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file IcmpRouterAdv1.dat");
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/IcmpRouterAdv2.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file IcmpRouterAdv2.dat");
	uint8_t* buffer8 = readFileIntoBuffer("PacketExamples/IcmpRouterSol.dat", buffer8Length);
	PACKETPP_ASSERT(!(buffer8 == NULL), "cannot read file IcmpRouterSol.dat");
	uint8_t* buffer9 = readFileIntoBuffer("PacketExamples/IcmpTimeExceededUdp.dat", buffer9Length);
	PACKETPP_ASSERT(!(buffer9 == NULL), "cannot read file IcmpTimeExceededUdp.dat");
	uint8_t* buffer10 = readFileIntoBuffer("PacketExamples/IcmpDestUnreachableUdp.dat", buffer10Length);
	PACKETPP_ASSERT(!(buffer10 == NULL), "cannot read file IcmpDestUnreachableUdp.dat");
	uint8_t* buffer11 = readFileIntoBuffer("PacketExamples/IcmpTimeExceededEcho.dat", buffer11Length);
	PACKETPP_ASSERT(!(buffer11 == NULL), "cannot read file IcmpTimeExceededEcho.dat");
	uint8_t* buffer12 = readFileIntoBuffer("PacketExamples/IcmpDestUnreachableEcho.dat", buffer12Length);
	PACKETPP_ASSERT(!(buffer12 == NULL), "cannot read file IcmpDestUnreachableEcho.dat");
	uint8_t* buffer13 = readFileIntoBuffer("PacketExamples/IcmpSourceQuench.dat", buffer13Length);
	PACKETPP_ASSERT(!(buffer13 == NULL), "cannot read file IcmpSourceQuench.dat");
	uint8_t* buffer14 = readFileIntoBuffer("PacketExamples/IcmpAddrMaskReq.dat", buffer14Length);
	PACKETPP_ASSERT(!(buffer14 == NULL), "cannot read file IcmpAddrMaskReq.dat");
	uint8_t* buffer15 = readFileIntoBuffer("PacketExamples/IcmpAddrMaskRep.dat", buffer15Length);
	PACKETPP_ASSERT(!(buffer15 == NULL), "cannot read file IcmpAddrMaskRep.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);
	RawPacket rawPacket6((const uint8_t*)buffer6, buffer6Length, time, true);
	RawPacket rawPacket7((const uint8_t*)buffer7, buffer7Length, time, true);
	RawPacket rawPacket8((const uint8_t*)buffer8, buffer8Length, time, true);
	RawPacket rawPacket9((const uint8_t*)buffer9, buffer9Length, time, true);
	RawPacket rawPacket10((const uint8_t*)buffer10, buffer10Length, time, true);
	RawPacket rawPacket11((const uint8_t*)buffer11, buffer11Length, time, true);
	RawPacket rawPacket12((const uint8_t*)buffer12, buffer12Length, time, true);
	RawPacket rawPacket13((const uint8_t*)buffer13, buffer13Length, time, true);
	RawPacket rawPacket14((const uint8_t*)buffer14, buffer14Length, time, true);
	RawPacket rawPacket15((const uint8_t*)buffer15, buffer15Length, time, true);


	Packet icmpEchoRequest(&rawPacket1);
	Packet icmpEchoReply(&rawPacket2);
	Packet icmpTimestampReq(&rawPacket3);
	Packet icmpTimestampReply(&rawPacket4);
	Packet icmpRedirect(&rawPacket5);
	Packet icmpRouterAdv1(&rawPacket6);
	Packet icmpRouterAdv2(&rawPacket7);
	Packet icmpRouterSol(&rawPacket8);
	Packet icmpTimeExceededUdp(&rawPacket9);
	Packet icmpDestUnreachableUdp(&rawPacket10);
	Packet icmpTimeExceededEcho(&rawPacket11);
	Packet icmpDestUnreachableEcho(&rawPacket12);
	Packet icmpSourceQuench(&rawPacket13);
	Packet icmpAddrMaskReq(&rawPacket14);
	Packet icmpAddrMaskRep(&rawPacket15);


	PACKETPP_ASSERT(icmpEchoRequest.isPacketOfType(ICMP) == true, "ICMP echo request isn't of type ICMP");
	PACKETPP_ASSERT(icmpEchoReply.isPacketOfType(ICMP) == true, "ICMP echo reply isn't of type ICMP");
	PACKETPP_ASSERT(icmpTimestampReq.isPacketOfType(ICMP) == true, "ICMP ts request isn't of type ICMP");
	PACKETPP_ASSERT(icmpTimestampReply.isPacketOfType(ICMP) == true, "ICMP ts reply isn't of type ICMP");
	PACKETPP_ASSERT(icmpRedirect.isPacketOfType(ICMP) == true, "ICMP redirect isn't of type ICMP");
	PACKETPP_ASSERT(icmpRouterAdv1.isPacketOfType(ICMP) == true, "ICMP router adv1 isn't of type ICMP");
	PACKETPP_ASSERT(icmpRouterAdv2.isPacketOfType(ICMP) == true, "ICMP router adv2 isn't of type ICMP");
	PACKETPP_ASSERT(icmpRouterSol.isPacketOfType(ICMP) == true, "ICMP router sol isn't of type ICMP");
	PACKETPP_ASSERT(icmpTimeExceededUdp.isPacketOfType(ICMP) == true, "ICMP time exceeded isn't of type ICMP");
	PACKETPP_ASSERT(icmpDestUnreachableUdp.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");
	PACKETPP_ASSERT(icmpTimeExceededEcho.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");
	PACKETPP_ASSERT(icmpDestUnreachableEcho.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");
	PACKETPP_ASSERT(icmpSourceQuench.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");
	PACKETPP_ASSERT(icmpAddrMaskReq.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");
	PACKETPP_ASSERT(icmpAddrMaskRep.isPacketOfType(ICMP) == true, "ICMP dest unreachable isn't of type ICMP");


	// Echo request
	icmpLayer = icmpEchoRequest.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP echo request layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ECHO_REQUEST) == true, "ICMP echo request isn't of type ICMP_ECHO_REQUEST");
	PACKETPP_ASSERT(icmpLayer->getEchoReplyData() == NULL, "Echo reply data isn't NULL for echo request");
	icmp_echo_request* reqData = icmpLayer->getEchoRequestData();
	PACKETPP_ASSERT(reqData != NULL, "Echo request data is NULL");
	PACKETPP_ASSERT(reqData->header->code == 0, "Echo request code isn't 0");
	PACKETPP_ASSERT(reqData->header->checksum == 0xb3bb, "Echo request checksum isn't 0xb3bb");
	PACKETPP_ASSERT(reqData->header->id == 0x3bd7, "Echo request id isn't 0x3bd7");
	PACKETPP_ASSERT(reqData->header->sequence == 0, "Echo request sequence isn't 0");
	PACKETPP_ASSERT(reqData->header->timestamp == 0xE45104007DD6A751ULL, "Echo request timestamp is wrong");
	PACKETPP_ASSERT(reqData->dataLength == 48, "Echo request data length isn't 48");
	PACKETPP_ASSERT(reqData->data[5] == 0x0d && reqData->data[43] == 0x33, "Echo request data is wrong");

	// Echo reply
	icmpLayer = icmpEchoReply.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP echo reply layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ECHO_REPLY) == true, "ICMP echo reply isn't of type ICMP_ECHO_REPLY");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() == NULL, "Echo request data isn't NULL for echo reply");
	icmp_echo_reply* repData = icmpLayer->getEchoReplyData();
	PACKETPP_ASSERT(repData != NULL, "Echo reply data is NULL");
	PACKETPP_ASSERT(repData->header->checksum == 0xb3c3, "Echo reply checksum isn't 0xb3c3");
	PACKETPP_ASSERT(repData->dataLength == 48, "Echo reply data length isn't 48");
	PACKETPP_ASSERT(repData->data[5] == 0x0d && reqData->data[43] == 0x33, "Echo reply data is wrong");

	// Timestamp request
	icmpLayer = icmpTimestampReq.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP ts request layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_TIMESTAMP_REQUEST) == true, "ICMP ts request isn't of type ICMP_TIMESTAMP_REQUEST");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() == NULL, "Echo request data isn't NULL for ts request");
	icmp_timestamp_request* tsReqData = icmpLayer->getTimestampRequestData();
	PACKETPP_ASSERT(tsReqData != NULL, "ts request data is NULL");
	PACKETPP_ASSERT(tsReqData->code == 0, "ts req code isn't 0");
	PACKETPP_ASSERT(tsReqData->originateTimestamp == 0x6324f600, "ts req originate ts is wrong, it's 0x%X", tsReqData->originateTimestamp);
	PACKETPP_ASSERT(tsReqData->transmitTimestamp == 0, "ts req transmit ts isn't 0");

	// Timestamp reply
	icmpLayer = icmpTimestampReply.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP ts reply layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_TIMESTAMP_REPLY) == true, "ICMP ts reply isn't of type ICMP_TIMESTAMP_REPLY");
	PACKETPP_ASSERT(icmpLayer->getSourceQuenchdata() == NULL, "Source quench data isn't NULL for ts reply");
	icmp_timestamp_reply* tsRepData = icmpLayer->getTimestampReplyData();
	PACKETPP_ASSERT(tsRepData != NULL, "ts reply data is NULL");
	PACKETPP_ASSERT(tsRepData->checksum == 0x19e3, "ts rep wrong checksum");
	PACKETPP_ASSERT(tsRepData->receiveTimestamp == 0x00f62d62, "ts rep data wrong receive ts");
	PACKETPP_ASSERT(tsRepData->transmitTimestamp == 0x00f62d62, "ts rep data wrong transmit ts");

	// Address mask request
	icmpLayer = icmpAddrMaskReq.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP mask request layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ADDRESS_MASK_REQUEST) == true, "ICMP mask request isn't of type ICMP_ADDRESS_MASK_REQUEST");
	PACKETPP_ASSERT(icmpLayer->getRouterAdvertisementData() == NULL, "Router adv data isn't NULL for mask request");
	icmp_address_mask_request* maskReqData = icmpLayer->getAddressMaskRequestData();
	PACKETPP_ASSERT(maskReqData != NULL, "mask request data is NULL");
	PACKETPP_ASSERT(maskReqData->id == 0x0cb0, "mask request id is wrong");
	PACKETPP_ASSERT(maskReqData->sequence == 0x6, "mask request sequence is wrong");
	PACKETPP_ASSERT(maskReqData->addressMask == 0, "mask request mask is wrong");

	// Address mask reply
	icmpLayer = icmpAddrMaskRep.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP mask reply layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ADDRESS_MASK_REPLY) == true, "ICMP mask reply isn't of type ICMP_ADDRESS_MASK_REPLY");
	PACKETPP_ASSERT(icmpLayer->getSourceQuenchdata() == NULL, "Source quench data isn't NULL for mask reply");
	PACKETPP_ASSERT(icmpLayer->getAddressMaskRequestData() == NULL, "Mask request data isn't NULL for mask reply");
	icmp_address_mask_reply* maskRepData = icmpLayer->getAddressMaskReplyData();
	PACKETPP_ASSERT(maskRepData != NULL, "mask reply data is NULL");
	PACKETPP_ASSERT(maskRepData->id == 0x0cb2, "mask reply id is wrong");
	PACKETPP_ASSERT(maskRepData->type == (uint8_t)ICMP_ADDRESS_MASK_REPLY, "mask reply type is wrong");
	PACKETPP_ASSERT(maskRepData->addressMask == 0, "mask request mask is wrong");

	// Router solicitation
	icmpLayer = icmpRouterSol.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP router solicitation layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ROUTER_SOL) == true, "ICMP router solicitation isn't of type ICMP_ROUTER_SOL");
	PACKETPP_ASSERT(icmpLayer->getSourceQuenchdata() == NULL, "Source quench data isn't NULL for router solicitation");
	PACKETPP_ASSERT(icmpLayer->getAddressMaskRequestData() == NULL, "Mask request data isn't NULL for router solicitation");
	icmp_router_solicitation* solData = icmpLayer->getRouterSolicitationData();
	PACKETPP_ASSERT(solData != NULL, "Router solicitation data is NULL");
	PACKETPP_ASSERT(solData->checksum == 0xfff5, "Router soliciation checksum is wrong");

	// Destination unreachable
	icmpLayer = icmpDestUnreachableUdp.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP dest unreachable (udp) layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_DEST_UNREACHABLE) == true, "ICMP dest unreachable (udp) isn't of type ICMP_DEST_UNREACHABLE");
	icmp_destination_unreachable* destUnreachData = icmpLayer->getDestUnreachableData();
	PACKETPP_ASSERT(destUnreachData != NULL, "dest unreachable (udp) data is NULL");
	PACKETPP_ASSERT(destUnreachData->nextHopMTU == 0, "dest unreachable (udp) next hop mtu isn't 0");
	PACKETPP_ASSERT(destUnreachData->code == IcmpPortUnreachable, "dest unreachable (udp) code isn't IcmpPortUnreachable");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "dest unreachable (udp) next layer is null or not IPv4");
	IPv4Layer* ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer->getSrcIpAddress() == IPv4Address(std::string("10.0.1.2")), "dest unreachable (udp) IP source isn't 10.0.1.12");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == UDP, "dest unreachable (udp) next layer is not UDP");

	icmpLayer = icmpDestUnreachableEcho.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP dest unreachable (echo) layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_DEST_UNREACHABLE) == true, "ICMP dest unreachable (echo) isn't of type ICMP_DEST_UNREACHABLE");
	destUnreachData = icmpLayer->getDestUnreachableData();
	PACKETPP_ASSERT(destUnreachData != NULL, "dest unreachable (echo) data is NULL");
	PACKETPP_ASSERT(destUnreachData->nextHopMTU == 0, "dest unreachable (echo) next hop mtu isn't 0");
	PACKETPP_ASSERT(destUnreachData->code == IcmpHostUnreachable, "dest unreachable (echo) code isn't IcmpHostUnreachable");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "dest unreachable (echo) next layer is null or not IPv4");
	ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer->getDstIpAddress() == IPv4Address(std::string("10.0.0.111")), "dest unreachable (udp) IP dest isn't 10.0.0.111");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == ICMP, "dest unreachable (echo) next layer is not ICMP");

	// Time exceeded
	icmpLayer = icmpTimeExceededUdp.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP time exceeded (udp) layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_TIME_EXCEEDED) == true, "ICMP time exceeded (udp) isn't of type ICMP_TIME_EXCEEDED");
	icmp_time_exceeded* timeExData = icmpLayer->getTimeExceededData();
	PACKETPP_ASSERT(timeExData != NULL, "ICMP time exceeded (udp) data is NULL");
	PACKETPP_ASSERT(timeExData->checksum == 0x2dac, "ICMP time exceeded (udp) checksum is wrong");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "ICMP time exceeded (udp) next layer is null or not IPv4");
	ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == UDP, "ICMP time exceeded (udp) next layer is not UDP");

	icmpLayer = icmpTimeExceededEcho.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP time exceeded (echo) layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_TIME_EXCEEDED) == true, "ICMP time exceeded (echo) isn't of type ICMP_TIME_EXCEEDED");
	timeExData = icmpLayer->getTimeExceededData();
	PACKETPP_ASSERT(timeExData != NULL, "ICMP time exceeded (echo) data is NULL");
	PACKETPP_ASSERT(timeExData->code == 0, "ICMP time exceeded (echo) code != 0");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "ICMP time exceeded (echo) next layer is null or not IPv4");
	ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == ICMP, "ICMP time exceeded (echo) next layer is not ICMP");
	icmpLayer = (IcmpLayer*)ipLayer->getNextLayer();
	PACKETPP_ASSERT(icmpLayer->getMessageType() == ICMP_ECHO_REQUEST, "ICMP time exceeded (echo) inner ICMP message isn't of type ICMP_ECHO_REQUEST");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() != NULL && icmpLayer->getEchoRequestData()->header->id == 0x670c, "ICMP time exceeded (echo) inner ICMP message id is wrong");

	// Redirect
	icmpLayer = icmpRedirect.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP redirect layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_REDIRECT) == true, "ICMP redirect isn't of type ICMP_REDIRECT");
	icmp_redirect* redirectData = icmpLayer->getRedirectData();
	PACKETPP_ASSERT(redirectData != NULL, "ICMP redirect data is NULL");
	PACKETPP_ASSERT(icmpLayer->getEchoReplyData() == NULL && icmpLayer->getInfoRequestData() == NULL && icmpLayer->getParamProblemData() == NULL, "ICMP redirect other message types not null");
	PACKETPP_ASSERT(IPv4Address(redirectData->gatewayAddress).toString() == "10.2.99.98", "ICMP redirect gw addr != 10.2.99.98");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "ICMP redirect next layer is null or not IPv4");
	ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer != NULL && ipLayer->getSrcIpAddress().toString() == "10.2.10.2", "ICMP redirect inner IP layer source IP != 10.2.10.2");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == ICMP, "ICMP redirect next layer is not ICMP");
	icmpLayer = (IcmpLayer*)ipLayer->getNextLayer();
	PACKETPP_ASSERT(icmpLayer->getMessageType() == ICMP_ECHO_REQUEST, "ICMP redirect inner ICMP message isn't of type ICMP_ECHO_REQUEST");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData()->header->id == 0x2, "ICMP redirect inner ICMP message id != 2");

	// Router advertisement
	icmpLayer = icmpRouterAdv1.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP router adv1 layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ROUTER_ADV) == true, "ICMP router adv1 isn't of type ICMP_ROUTER_ADV");
	icmp_router_advertisement* routerAdvData = icmpLayer->getRouterAdvertisementData();
	PACKETPP_ASSERT(routerAdvData != NULL, "ICMP router adv1 data is NULL");
	PACKETPP_ASSERT(routerAdvData->header->advertisementCount == 1, "ICMP router adv1 count != 1");
	PACKETPP_ASSERT(routerAdvData->header->lifetime == htons(200), "ICMP router adv1 lifetime != 200");
	PACKETPP_ASSERT(routerAdvData->getRouterAddress(1) == NULL && routerAdvData->getRouterAddress(100) == NULL, "ICMP router adv1 managed to get addr in indices > 0");
	icmp_router_address_structure* routerAddr = routerAdvData->getRouterAddress(0);
	PACKETPP_ASSERT(routerAddr != NULL, "ICMP router adv1 router addr #0 is null");
	PACKETPP_ASSERT(IPv4Address(routerAddr->routerAddress) == IPv4Address(std::string("192.168.144.2")), "ICMP router adv1 router addr #0 != 192.168.144.2");
	PACKETPP_ASSERT(routerAddr->preferenceLevel == 0x80, "ICMP router adv1 router addr #0 preference level != 0x80");

	icmpLayer = icmpRouterAdv2.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Couldn't retrieve ICMP router adv2 layer");
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ROUTER_ADV) == true, "ICMP router adv2 isn't of type ICMP_ROUTER_ADV");
	routerAdvData = icmpLayer->getRouterAdvertisementData();
	PACKETPP_ASSERT(routerAdvData != NULL, "ICMP router adv2 data is NULL");
	PACKETPP_ASSERT(routerAdvData->header->advertisementCount == 1, "ICMP router adv2 count != 1");
	PACKETPP_ASSERT(routerAdvData->header->addressEntrySize == 2, "ICMP router adv2 entry size != 2");
	PACKETPP_ASSERT(routerAdvData->getRouterAddress(1) == NULL && routerAdvData->getRouterAddress(20) == NULL, "ICMP router adv2 managed to get addr in indices > 0");
	routerAddr = routerAdvData->getRouterAddress(0);
	PACKETPP_ASSERT(routerAddr != NULL, "ICMP router adv1 router addr #0 is null");
	PACKETPP_ASSERT(IPv4Address(routerAddr->routerAddress) == IPv4Address(std::string("14.80.84.66")), "ICMP router adv2 router addr #0 != 14.80.84.66");
	PACKETPP_ASSERT(routerAddr->preferenceLevel == 0, "ICMP router adv2 router addr #0 preference level != 0");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(IcmpCreationTest)
{
	int buffer1Length = 0;
	int buffer2Length = 0;
	int buffer3Length = 0;
	int buffer4Length = 0;
	int buffer5Length = 0;
	int buffer6Length = 0;
	int buffer7Length = 0;
	int buffer8Length = 0;
	int buffer9Length = 0;
	int buffer10Length = 0;
	int buffer11Length = 0;
	int buffer12Length = 0;
	int buffer13Length = 0;
	int buffer14Length = 0;
	int buffer15Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IcmpEchoRequest.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IcmpEchoRequest.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IcmpEchoReply.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IcmpEchoReply.dat");
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IcmpTimestampRequest.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IcmpTimestampRequest.dat");
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IcmpTimestampReply.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IcmpTimestampReply.dat");
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/IcmpRedirect.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file IcmpRedirect.dat");
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/IcmpRouterAdv1.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file IcmpRouterAdv1.dat");
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/IcmpRouterAdv2.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file IcmpRouterAdv2.dat");
	uint8_t* buffer8 = readFileIntoBuffer("PacketExamples/IcmpRouterSol.dat", buffer8Length);
	PACKETPP_ASSERT(!(buffer8 == NULL), "cannot read file IcmpRouterSol.dat");
	uint8_t* buffer9 = readFileIntoBuffer("PacketExamples/IcmpTimeExceededUdp.dat", buffer9Length);
	PACKETPP_ASSERT(!(buffer9 == NULL), "cannot read file IcmpTimeExceededUdp.dat");
	uint8_t* buffer10 = readFileIntoBuffer("PacketExamples/IcmpDestUnreachableUdp.dat", buffer10Length);
	PACKETPP_ASSERT(!(buffer10 == NULL), "cannot read file IcmpDestUnreachableUdp.dat");
	uint8_t* buffer11 = readFileIntoBuffer("PacketExamples/IcmpTimeExceededEcho.dat", buffer11Length);
	PACKETPP_ASSERT(!(buffer11 == NULL), "cannot read file IcmpTimeExceededEcho.dat");
	uint8_t* buffer12 = readFileIntoBuffer("PacketExamples/IcmpDestUnreachableEcho.dat", buffer12Length);
	PACKETPP_ASSERT(!(buffer12 == NULL), "cannot read file IcmpDestUnreachableEcho.dat");
	uint8_t* buffer13 = readFileIntoBuffer("PacketExamples/IcmpSourceQuench.dat", buffer13Length);
	PACKETPP_ASSERT(!(buffer13 == NULL), "cannot read file IcmpSourceQuench.dat");
	uint8_t* buffer14 = readFileIntoBuffer("PacketExamples/IcmpAddrMaskReq.dat", buffer14Length);
	PACKETPP_ASSERT(!(buffer14 == NULL), "cannot read file IcmpAddrMaskReq.dat");
	uint8_t* buffer15 = readFileIntoBuffer("PacketExamples/IcmpAddrMaskRep.dat", buffer15Length);
	PACKETPP_ASSERT(!(buffer15 == NULL), "cannot read file IcmpAddrMaskRep.dat");

	EthLayer ethLayer(MacAddress("11:22:33:44:55:66"), MacAddress("66:55:44:33:22:11"));

	IPv4Layer ipLayer(IPv4Address(std::string("1.1.1.1")), IPv4Address(std::string("2.2.2.2")));


	uint8_t data[48] = { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
			0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };

	// Echo request creation
	Packet echoRequestPacket(1);
	IcmpLayer echoReqLayer;
	PACKETPP_ASSERT(echoReqLayer.setEchoRequestData(0xd73b, 0, 0xe45104007dd6a751ULL, data, 48) != NULL, "Couldn't set echo request data");
	echoRequestPacket.addLayer(&ethLayer);
	echoRequestPacket.addLayer(&ipLayer);
	echoRequestPacket.addLayer(&echoReqLayer);
	echoRequestPacket.computeCalculateFields();
	PACKETPP_ASSERT(echoRequestPacket.getRawPacket()->getRawDataLen() == buffer1Length, "Echo request data len is different than expected");
	PACKETPP_ASSERT(memcmp(echoRequestPacket.getRawPacket()->getRawData()+34, buffer1+34, buffer1Length-34) == 0, "Echo request raw data is different than expected");

	// Echo reply creation
	EthLayer ethLayer2(ethLayer);
	IPv4Layer ipLayer2(ipLayer);
	IcmpLayer echoRepLayer;
	Packet echoReplyPacket(10);
	echoReplyPacket.addLayer(&ethLayer2);
	echoReplyPacket.addLayer(&ipLayer2);
	echoReplyPacket.addLayer(&echoRepLayer);
	PACKETPP_ASSERT(echoRepLayer.setEchoReplyData(0xd73b, 0, 0xe45104007dd6a751ULL, data, 48) != NULL, "Couldn't set echo reply data");
	echoReplyPacket.computeCalculateFields();
	PACKETPP_ASSERT(echoReplyPacket.getRawPacket()->getRawDataLen() == buffer2Length, "Echo reply data len is different than expected");
	PACKETPP_ASSERT(memcmp(echoReplyPacket.getRawPacket()->getRawData()+34, buffer2+34, buffer2Length-34) == 0, "Echo reply raw data is different than expected");

	// Time exceeded creation
	EthLayer ethLayer3(ethLayer);
	IPv4Layer ipLayer3(ipLayer);
	IcmpLayer timeExceededLayer;
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(timeExceededLayer.setTimeExceededData(1, NULL, NULL) == NULL, "Managed to set time exceeded data on a layer not attached to a packet");
	LoggerPP::getInstance().enableErrors();
	Packet timeExceededPacket(10);
	timeExceededPacket.addLayer(&ethLayer3);
	timeExceededPacket.addLayer(&ipLayer3);
	timeExceededPacket.addLayer(&timeExceededLayer);
	IPv4Layer ipLayerForTimeExceeded(IPv4Address(std::string("10.0.0.6")), IPv4Address(std::string("8.8.8.8")));
	ipLayerForTimeExceeded.getIPv4Header()->fragmentOffset = 0x40;
	ipLayerForTimeExceeded.getIPv4Header()->timeToLive = 1;
	ipLayerForTimeExceeded.getIPv4Header()->ipId = ntohs(2846);
	IcmpLayer icmpLayerForTimeExceeded;
	icmpLayerForTimeExceeded.setEchoRequestData(3175, 1, 0x00058bbd569f3d49ULL, data, 48);
	PACKETPP_ASSERT(timeExceededLayer.setTimeExceededData(0, &ipLayerForTimeExceeded, &icmpLayerForTimeExceeded) != NULL, "Failed to set time exceeded data");
	timeExceededPacket.computeCalculateFields();
	PACKETPP_ASSERT(timeExceededPacket.getRawPacket()->getRawDataLen() == buffer11Length, "Time exceeded data len is different than expected");
	PACKETPP_ASSERT(memcmp(timeExceededPacket.getRawPacket()->getRawData()+34, buffer11+34, buffer11Length-34) == 0, "Time exceeded raw data is different than expected");

	// Dest unreachable creation
	EthLayer ethLayer4(ethLayer);
	IPv4Layer ipLayer4(ipLayer);
	IcmpLayer destUnreachableLayer;
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(destUnreachableLayer.setDestUnreachableData(IcmpHostUnreachable, 0, NULL, NULL) == NULL, "Managed to set dest unreachable data on a layer not attached to a packet");
	LoggerPP::getInstance().enableErrors();
	Packet destUnreachablePacket(10);
	destUnreachablePacket.addLayer(&ethLayer4);
	destUnreachablePacket.addLayer(&ipLayer4);
	destUnreachablePacket.addLayer(&destUnreachableLayer);
	IPv4Layer ipLayerForDestUnreachable(IPv4Address(std::string("10.0.1.2")), IPv4Address(std::string("172.16.0.2")));
	ipLayerForDestUnreachable.getIPv4Header()->timeToLive = 1;
	ipLayerForDestUnreachable.getIPv4Header()->ipId = ntohs(230);
	UdpLayer udpLayerForDestUnreachable(49182, 33446);
	PACKETPP_ASSERT(destUnreachableLayer.setDestUnreachableData(IcmpPortUnreachable, 0, &ipLayerForDestUnreachable, &udpLayerForDestUnreachable) != NULL, "Failed to set dest unreachable data");
	destUnreachablePacket.computeCalculateFields();
	PACKETPP_ASSERT(destUnreachablePacket.getRawPacket()->getRawDataLen() == buffer10Length, "Dest unreachable data len is different than expected");
	PACKETPP_ASSERT(memcmp(destUnreachablePacket.getRawPacket()->getRawData()+34, buffer10+34, buffer10Length-34) == 0, "Dest unreachable raw data is different than expected");

	// Timestamp reply
	EthLayer ethLayer5(ethLayer);
	IPv4Layer ipLayer5(ipLayer);
	IcmpLayer timestampReplyLayer;
	Packet timestampReplyPacket(20);
	timestampReplyPacket.addLayer(&ethLayer5);
	timestampReplyPacket.addLayer(&ipLayer5);
	timeval orig = { 16131, 171000 };
	timeval recv = { 16133, 474000 };
	timeval tran = { 16133, 474000 };
	PACKETPP_ASSERT(timestampReplyLayer.setTimestampReplyData(14640, 0, orig, recv, tran) != NULL, "Couldn't set timestamp reply data");
	timestampReplyPacket.addLayer(&timestampReplyLayer);
	timestampReplyPacket.computeCalculateFields();
	PACKETPP_ASSERT(timestampReplyPacket.getRawPacket()->getRawDataLen() == buffer4Length-6, "Timestamp reply data len is different than expected");

	// Address mask request
	EthLayer ethLayer6(ethLayer);
	IPv4Layer ipLayer6(ipLayer);
	IcmpLayer addressMaskRequestLayer;
	Packet addressMaskRequestPacket(30);
	addressMaskRequestPacket.addLayer(&ethLayer6);
	addressMaskRequestPacket.addLayer(&ipLayer6);
	PACKETPP_ASSERT(addressMaskRequestLayer.setAddressMaskRequestData(45068, 1536, IPv4Address::Zero) != NULL, "Couldn't set address mask request data");
	addressMaskRequestPacket.addLayer(&addressMaskRequestLayer);
	addressMaskRequestPacket.computeCalculateFields();
	PACKETPP_ASSERT(addressMaskRequestPacket.getRawPacket()->getRawDataLen() == buffer14Length-14, "Address mask request data len is different than expected");
	PACKETPP_ASSERT(memcmp(addressMaskRequestPacket.getRawPacket()->getRawData()+34, buffer14+34, buffer14Length-34-14) == 0, "Address mask request raw data is different than expected");

	// Redirect creation
	EthLayer ethLayer7(ethLayer);
	IPv4Layer ipLayer7(ipLayer);
	IcmpLayer redirectLayer;
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(redirectLayer.setDestUnreachableData(IcmpHostUnreachable, 0, NULL, NULL) == NULL, "Managed to set redirect data on a layer not attached to a packet");
	LoggerPP::getInstance().enableErrors();
	Packet redirectPacket(13);
	redirectPacket.addLayer(&ethLayer7);
	redirectPacket.addLayer(&ipLayer7);
	redirectPacket.addLayer(&redirectLayer);
	IPv4Layer ipLayerForRedirect(IPv4Address(std::string("10.2.10.2")), IPv4Address(std::string("10.3.71.7")));
	ipLayerForRedirect.getIPv4Header()->ipId = ntohs(14848);
	ipLayerForRedirect.getIPv4Header()->timeToLive = 31;
	IcmpLayer icmpLayerForRedirect;
	icmpLayerForRedirect.setEchoRequestData(512, 12544, 0, NULL, 0);
	PACKETPP_ASSERT(redirectLayer.setRedirectData(1, IPv4Address(std::string("10.2.99.98")), &ipLayerForRedirect, &icmpLayerForRedirect) != NULL, "Failed to set redirect data");
	redirectPacket.computeCalculateFields();
	PACKETPP_ASSERT(redirectPacket.getRawPacket()->getRawDataLen() == buffer5Length+8, "Redirect data len is different than expected");

	// Router advertisement creation
	EthLayer ethLayer8(ethLayer);
	IPv4Layer ipLayer8(ipLayer);
	IcmpLayer routerAdvLayer;
	Packet routerAdvPacket(23);
	routerAdvPacket.addLayer(&ethLayer8);
	routerAdvPacket.addLayer(&ipLayer8);
	routerAdvPacket.addLayer(&routerAdvLayer);
	icmp_router_address_structure addr1;
	addr1.setRouterAddress(IPv4Address(std::string("192.168.144.2")), (uint32_t)0x08000000);
	icmp_router_address_structure addr2;
	addr2.setRouterAddress(IPv4Address(std::string("1.1.1.1")), (uint32_t)1000);
	icmp_router_address_structure addr3;
	addr3.setRouterAddress(IPv4Address(std::string("10.0.0.138")), (uint32_t)30000);
	std::vector<icmp_router_address_structure> routerAddresses;
	routerAddresses.push_back(addr1);
	routerAddresses.push_back(addr2);
	routerAddresses.push_back(addr3);
	PACKETPP_ASSERT(routerAdvLayer.setRouterAdvertisementData(16, 200, routerAddresses) != NULL, "Failed to set router adv data");
	routerAdvPacket.computeCalculateFields();
	PACKETPP_ASSERT(routerAdvLayer.getHeaderLen() == 32, "Router adv header len != 32");
	PACKETPP_ASSERT(routerAdvPacket.getRawPacket()->getRawDataLen() == buffer6Length-18, "Router adv len is different than expected");


	delete [] buffer1;
	delete [] buffer2;
	delete [] buffer3;
	delete [] buffer4;
	delete [] buffer5;
	delete [] buffer6;
	delete [] buffer7;
	delete [] buffer8;
	delete [] buffer9;
	delete [] buffer10;
	delete [] buffer11;
	delete [] buffer12;
	delete [] buffer13;
	delete [] buffer14;
	delete [] buffer15;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(IcmpEditTest)
{
	int buffer1Length = 0;
	int buffer2Length = 0;
	int buffer3Length = 0;
	int buffer4Length = 0;
	int buffer5Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IcmpRouterAdv1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IcmpRouterAdv1.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IcmpEchoRequest.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IcmpEchoRequest.dat");
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/IcmpEchoReply.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file IcmpEchoReply.dat");
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/IcmpTimeExceededUdp.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file IcmpTimeExceededUdp.dat");
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/IcmpDestUnreachableEcho.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file IcmpDestUnreachableEcho.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);

	// convert router adv to echo request

	Packet icmpRouterAdv1(&rawPacket1);

	IcmpLayer* icmpLayer = icmpRouterAdv1.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Cannot extract ICMP layer from router adv1");

	uint8_t data[48] = { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
			0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };

	PACKETPP_ASSERT(icmpLayer->getRouterAdvertisementData() != NULL, "Couldn't extract router adv data");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() == NULL, "Managed to extract echo request data although packet is router adv");
	icmp_echo_request* echoReq = icmpLayer->setEchoRequestData(55099, 0, 0xe45104007dd6a751ULL, data, 48);
	PACKETPP_ASSERT(echoReq != NULL, "Couldn't convert router adv to echo request");
	PACKETPP_ASSERT(icmpLayer->getHeaderLen() == 64, "Echo request length != 64");
	PACKETPP_ASSERT(echoReq->header->id == htons(55099), "Echo request id != 55099");
	PACKETPP_ASSERT(echoReq->dataLength == 48, "Echo request data len != 48");
	icmpRouterAdv1.computeCalculateFields();
	PACKETPP_ASSERT(icmpLayer->getRouterAdvertisementData() == NULL, "Managed to extract router adv data although packet converted to echo request");
	PACKETPP_ASSERT(memcmp(icmpRouterAdv1.getRawPacket()->getRawData()+34, buffer2+34, buffer2Length-34) == 0, "Echo request raw data is different than expected");


	// convert echo request to echo reply

	icmp_echo_reply* echoReply = icmpLayer->setEchoReplyData(55099, 0, 0xe45104007dd6a751ULL, data, 48);
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() == NULL, "Managed to extract echo request data although packet converted to echo reply");
	icmpRouterAdv1.computeCalculateFields();
	PACKETPP_ASSERT(echoReply->header->checksum == htons(0xc3b3), "Wrong checksum for echo reply");
	PACKETPP_ASSERT(memcmp(icmpRouterAdv1.getRawPacket()->getRawData()+34, buffer3+34, buffer3Length-34) == 0, "Echo reply raw data is different than expected");


	// convert time exceeded to echo request

	Packet icmpTimeExceededUdp(&rawPacket4);

	icmpLayer = icmpTimeExceededUdp.getLayerOfType<IcmpLayer>();
	PACKETPP_ASSERT(icmpLayer != NULL, "Cannot extract ICMP layer from time exceeded udp");
	PACKETPP_ASSERT(icmpLayer->getTimeExceededData() != NULL, "Couldn't extract time exceeded data");
	PACKETPP_ASSERT(icmpLayer->getEchoRequestData() == NULL, "Managed to extract echo request data although packet is time exceeded");
	echoReq = icmpLayer->setEchoRequestData(55090, 0, 0xe45104007dd6a751ULL, data, 48);
	PACKETPP_ASSERT(echoReq != NULL, "Couldn't convert time exceeded to echo request");
	PACKETPP_ASSERT(icmpLayer->getHeaderLen() == 64, "Echo request length != 64");
	PACKETPP_ASSERT(echoReq->header->id == htons(55090), "Echo request id != 55090");
	echoReq->header->id = htons(55099);
	PACKETPP_ASSERT(echoReq->header->id == htons(55099), "Echo request id != 55099");
	PACKETPP_ASSERT(echoReq->dataLength == 48, "Echo request data len != 48");
	icmpTimeExceededUdp.computeCalculateFields();
	PACKETPP_ASSERT(memcmp(icmpTimeExceededUdp.getRawPacket()->getRawData()+34, buffer2+34, buffer2Length-34) == 0, "Echo request raw data is different than expected");


	// convert echo request to dest unreachable

	IPv4Layer ipLayerForDestUnreachable(IPv4Address(std::string("10.0.0.7")), IPv4Address(std::string("10.0.0.111")));
	ipLayerForDestUnreachable.getIPv4Header()->fragmentOffset = 0x0040;
	ipLayerForDestUnreachable.getIPv4Header()->timeToLive = 64;
	ipLayerForDestUnreachable.getIPv4Header()->ipId = ntohs(10203);
	IcmpLayer icmpLayerForDestUnreachable;
	icmpLayerForDestUnreachable.setEchoRequestData(3189, 4, 0x000809f2569f3e41ULL, data, 48);
	icmp_destination_unreachable* destUnreachable = icmpLayer->setDestUnreachableData(IcmpHostUnreachable, 0, &ipLayerForDestUnreachable, &icmpLayerForDestUnreachable);
	PACKETPP_ASSERT(destUnreachable != NULL, "Couldn't convert echo request to dest unreachable");
	PACKETPP_ASSERT(icmpLayer->getHeaderLen() == 8, "Echo request length != 8");
	PACKETPP_ASSERT(destUnreachable->code == (uint8_t)IcmpHostUnreachable, "Dest unreachable code != IcmpHostUnreachable");
	PACKETPP_ASSERT(icmpLayer->getNextLayer() != NULL && icmpLayer->getNextLayer()->getProtocol() == IPv4, "Dest unreachable doesn't have a next IP layer or it's not IPv4");
	IPv4Layer* ipLayer = (IPv4Layer*)icmpLayer->getNextLayer();
	PACKETPP_ASSERT(ipLayer->getDstIpAddress() == IPv4Address(std::string("10.0.0.111")), "Dest unreachable IP header dest addr != 10.0.0.111");
	PACKETPP_ASSERT(ipLayer->getNextLayer() != NULL && ipLayer->getNextLayer()->getProtocol() == ICMP, "Dest unreachable doesn't have a next ICMP layer or it's not ICMP");
	icmpLayer = (IcmpLayer*)ipLayer->getNextLayer();
	PACKETPP_ASSERT(icmpLayer->isMessageOfType(ICMP_ECHO_REQUEST) == true, "Dest unreachable ICMP layer isn't of type echo request");
	echoReq = icmpLayer->getEchoRequestData();
	PACKETPP_ASSERT(echoReq != NULL, "Coulnd't extract echo request data from dest unreachable ICMP layer");
	PACKETPP_ASSERT(echoReq->header->sequence == htons(4), "Dest unreachable ICMP layer sequence != 4");
	icmpTimeExceededUdp.computeCalculateFields();
	PACKETPP_ASSERT(memcmp(icmpTimeExceededUdp.getRawPacket()->getRawData()+34, buffer5+34, buffer5Length-34) == 0, "Dest unreachable raw data is different than expected");

	delete [] buffer2;
	delete [] buffer3;
	delete [] buffer5;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(GreParsingTest)
{
	GREv0Layer* grev0Layer = NULL;
	GREv1Layer* grev1Layer = NULL;
	int buffer1Length = 0;
	int buffer2Length = 0;
	int buffer3Length = 0;
	int buffer4Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/GREv0_1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file GREv0_1.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/GREv0_2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file GREv0_2.dat");
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/GREv1_1.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file GREv1_1.dat");
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/GREv1_2.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file GREv1_2.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet grev0Packet1(&rawPacket1);
	Packet grev0Packet2(&rawPacket2);
	Packet grev1Packet1(&rawPacket3);
	Packet grev1Packet2(&rawPacket4);

	uint16_t value16 = 0;
	uint32_t value32 = 0;

	// GREv0 packet 1
	PACKETPP_ASSERT(grev0Packet1.isPacketOfType(GRE) && grev0Packet1.isPacketOfType(GREv0), "GREv0 Packet 1 isn't of type GREv0");
	grev0Layer = grev0Packet1.getLayerOfType<GREv0Layer>();
	PACKETPP_ASSERT(grev0Layer != NULL, "Couldn't retrieve GREv0 layer for GREv0 Packet 1");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 8, "GREv0 Packet 1 header len isn't 8");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 1, "GREv0 Packet 1 checksum bit not set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->routingBit == 0, "GREv0 Packet 1 routing bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->ackSequenceNumBit == 0, "GREv0 Packet 1 ack bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 Packet 1 seq bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->recursionControl == 0, "GREv0 Packet 1 recursion isn't 0");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->flags == 0, "GREv0 Packet 1 flags isn't 0");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->protocol == htons(PCPP_ETHERTYPE_IP), "GREv0 Packet 1 protocol isn't IPv4");
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16) == true, "GREv0 Packet 1 couldn't retrieve checksum");
	PACKETPP_ASSERT(value16 == 30719, "GREv0 Packet 1 checksum isn't 30719");
	value16 = 40000;
	value32 = 40000;
	PACKETPP_ASSERT(grev0Layer->getOffset(value16) == false, "GREv0 Packet 1 offset is valid");
	PACKETPP_ASSERT(value16 == 40000, "GREv0 Packet 1 value isn't 40000");
	PACKETPP_ASSERT(grev0Layer->getKey(value32) == false, "GREv0 Packet 1 key is valid");
	PACKETPP_ASSERT(value32 == 40000, "GREv0 Packet 1 value isn't 40000");
	PACKETPP_ASSERT(grev0Layer->getSequenceNumber(value32) == false, "GREv0 Packet 1 seq is valid");
	PACKETPP_ASSERT(value32 == 40000, "GREv0 Packet 1 value isn't 40000");
	PACKETPP_ASSERT(grev0Layer->getNextLayer() != NULL && grev0Layer->getNextLayer()->getProtocol() == IPv4, "GREv0 Packet 1 next protocol isn't IPv4");
	grev0Layer = NULL;

	// GREv0 packet 2
	PACKETPP_ASSERT(grev0Packet2.isPacketOfType(GRE) && grev0Packet2.isPacketOfType(GREv0), "GREv0 Packet 2 isn't of type GREv0");
	grev0Layer = grev0Packet2.getLayerOfType<GREv0Layer>();
	PACKETPP_ASSERT(grev0Layer != NULL, "Couldn't retrieve GREv0 layer for GREv0 Packet 2");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 4, "GREv0 Packet 2 header len isn't 4");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 0, "GREv0 Packet 2 checksum bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 Packet 2 seq bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->recursionControl == 0, "GREv0 Packet 2 recursion isn't 0");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->protocol == htons(PCPP_ETHERTYPE_IP), "GREv0 Packet 2 protocol isn't IPv4");
	value16 = 40000;
	value32 = 40000;
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16) == false, "GREv0 Packet 2 checksum valid");
	PACKETPP_ASSERT(value16 == 40000, "GREv0 Packet 2 value isn't 40000");
	PACKETPP_ASSERT(grev0Layer->getKey(value32) == false, "GREv0 Packet 2 key is valid");
	PACKETPP_ASSERT(value32 == 40000, "GREv0 Packet 1 value isn't 40000");
	PACKETPP_ASSERT(grev0Layer->getNextLayer() != NULL && grev0Layer->getNextLayer()->getProtocol() == IPv4, "GREv0 Packet 2 next protocol isn't IPv4");
	grev0Layer = grev0Packet2.getNextLayerOfType<GREv0Layer>(grev0Layer);
	PACKETPP_ASSERT(grev0Layer != NULL, "Couldn't retrieve second GREv0 layer for GREv0 Packet 2");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 4, "GREv0 Packet 2 2nd GRE header len isn't 4");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 0, "GREv0 Packet 2 2nd GRE checksum bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 Packet 2 2nd GRE seq bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->recursionControl == 0, "GREv0 Packet 2 2nd GRE recursion isn't 0");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->protocol == htons(PCPP_ETHERTYPE_IP), "GREv0 Packet 2 2nd GRE protocol isn't IPv4");
	PACKETPP_ASSERT(grev0Layer->getNextLayer() != NULL && grev0Layer->getNextLayer()->getProtocol() == IPv4, "GREv0 Packet 2 2nd GRE next protocol isn't IPv4");
	grev0Layer = NULL;

	// GREv1 packet 1
	PACKETPP_ASSERT(grev1Packet1.isPacketOfType(GRE) && grev1Packet1.isPacketOfType(GREv1), "GREv1 Packet 1 isn't of type GREv1");
	grev1Layer = grev1Packet1.getLayerOfType<GREv1Layer>();
	PACKETPP_ASSERT(grev1Layer != NULL, "Couldn't retrieve GREv1 layer for GREv1 Packet 1");
	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 12, "GREv1 Packet 1 header len isn't 12");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->checksumBit == 0, "GREv1 Packet 1 checksum bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->sequenceNumBit == 0, "GREv1 Packet 1 seq bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->keyBit == 1, "GREv1 Packet 1 key bit not set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->ackSequenceNumBit == 1, "GREv1 Packet 1 ack bit not set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->callID == htons(6), "GREv1 Packet 1 call id isn't 6");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->payloadLength == 0, "GREv1 Packet 1 payload length isn't 0");
	value16 = 40000;
	value32 = 40000;
	PACKETPP_ASSERT(grev1Layer->getSequenceNumber(value32) == false, "GREv1 Packet 1 seq is valid");
	PACKETPP_ASSERT(value32 == 40000, "GREv1 Packet 1 value isn't 40000");
	PACKETPP_ASSERT(grev1Layer->getAcknowledgmentNum(value32) == true, "GREv1 Packet 1 couldn't retrieve ack");
	PACKETPP_ASSERT(value32 == 26, "GREv1 Packet 1 ack value isn't 26");
	PACKETPP_ASSERT(grev1Layer->getNextLayer() == NULL, "GREv1 Packet 1 next protocol isn't null");
	grev1Layer = NULL;

	// GREv1 packet 2
	PACKETPP_ASSERT(grev1Packet2.isPacketOfType(GRE) && grev1Packet2.isPacketOfType(GREv1), "GREv1 Packet 2 isn't of type GREv1");
	PACKETPP_ASSERT(grev1Packet2.isPacketOfType(PPP_PPTP), "GREv1 Packet 2 isn't of type PPP_PPTP");
	grev1Layer = grev1Packet2.getLayerOfType<GREv1Layer>();
	PACKETPP_ASSERT(grev1Layer != NULL, "Couldn't retrieve GREv1 layer for GREv1 Packet 2");
	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 12, "GREv1 Packet 2 header len isn't 12");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->checksumBit == 0, "GREv1 Packet 2 checksum bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->routingBit == 0, "GREv1 Packet 2 routing bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->sequenceNumBit == 1, "GREv1 Packet 2 seq bit not set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->keyBit == 1, "GREv1 Packet 1 key bit not set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->ackSequenceNumBit == 0, "GREv1 Packet 1 ack bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->callID == htons(17), "GREv1 Packet 1 call id isn't 17");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->payloadLength == htons(178), "GREv1 Packet 1 payload length isn't 178");
	value16 = 40000;
	value32 = 40000;
	PACKETPP_ASSERT(grev1Layer->getAcknowledgmentNum(value32) == false, "GREv1 Packet 2 ack valid");
	PACKETPP_ASSERT(value32 == 40000, "GREv1 Packet 2 value isn't 40000");
	PACKETPP_ASSERT(grev1Layer->getSequenceNumber(value32) == true, "GREv1 Packet 2 couldn't retrieve seq num");
	PACKETPP_ASSERT(value32 == 539320, "GREv1 Packet 2 seq value isn't 539320");
	PACKETPP_ASSERT(grev1Layer->getNextLayer() != NULL && grev1Layer->getNextLayer()->getProtocol() == PPP_PPTP, "GREv1 Packet 2 next protocol isn't PPP_PPTP");
	PPP_PPTPLayer* pppLayer = grev1Packet2.getLayerOfType<PPP_PPTPLayer>();
	PACKETPP_ASSERT(pppLayer != NULL, "Couldn't retrieve PPP layer for GREv1 Packet 2");
	PACKETPP_ASSERT(pppLayer->getHeaderLen() == 4, "GREv1 Packet 2 PPP layer header len isn't 4");
	PACKETPP_ASSERT(pppLayer ==  grev1Layer->getNextLayer(), "GREv1 Packet 2 PPP layer from packet isn't equal to PPP layer after GRE");
	PACKETPP_ASSERT(pppLayer->getPPP_PPTPHeader()->address == 0xff, "GREv1 Packet 2 PPP layer address != 0xff");
	PACKETPP_ASSERT(pppLayer->getPPP_PPTPHeader()->control == 3, "GREv1 Packet 2 PPP layer control != 3");
	PACKETPP_ASSERT(pppLayer->getPPP_PPTPHeader()->protocol == htons(PCPP_PPP_IP), "GREv1 Packet 2 PPP layer protocol isn't PPP_IP");
	PACKETPP_ASSERT(pppLayer->getNextLayer() != NULL && pppLayer->getNextLayer()->getProtocol() == IPv4, "GREv1 Packet 2 PPP layer next protocol isn't IPv4");
	grev1Layer = NULL;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(GreCreationTest)
{
	int buffer1Length = 0;
	int buffer2Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/GREv1_3.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file GREv1_3.dat");
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/GREv0_3.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file GREv0_3.dat");


	// GREv1 packet creation

	EthLayer ethLayer(MacAddress("00:90:4b:1f:a4:f7"), MacAddress("00:0d:ed:7b:48:f4"));
	IPv4Layer ipLayer(IPv4Address(std::string("192.168.2.65")), IPv4Address(std::string("192.168.2.254")));
	ipLayer.getIPv4Header()->ipId = htons(1660);
	ipLayer.getIPv4Header()->timeToLive = 128;

	GREv1Layer grev1Layer(6);

	PPP_PPTPLayer pppLayer(0xff, 3);
	pppLayer.getPPP_PPTPHeader()->protocol = htons(PCPP_PPP_CCP);

	uint8_t data[4] = { 0x06, 0x04, 0x00, 0x04 };
	PayloadLayer payloadLayer(data, 4, true);

	Packet grev1Packet(1);
	grev1Packet.addLayer(&ethLayer);
	grev1Packet.addLayer(&ipLayer);
	grev1Packet.addLayer(&grev1Layer);
	grev1Packet.addLayer(&pppLayer);
	grev1Packet.addLayer(&payloadLayer);

	PACKETPP_ASSERT(grev1Layer.setAcknowledgmentNum(17), "Couldn't set ack num");
	PACKETPP_ASSERT(grev1Layer.setSequenceNumber(34), "Couldn't set seq num");

	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev1Packet.getRawPacket()->getRawDataLen() == buffer1Length, "GREv1 packet raw data length is different than expected");
	PACKETPP_ASSERT(memcmp(grev1Packet.getRawPacket()->getRawData(), buffer1, buffer1Length) == 0, "GREv1 packet raw data is different than expected");


	// GREv0 packet creation

	EthLayer ethLayer2(MacAddress("00:01:01:00:00:01"), MacAddress("00:01:01:00:00:02"));
	IPv4Layer ipLayer2(IPv4Address(std::string("127.0.0.1")), IPv4Address(std::string("127.0.0.1")));
	ipLayer2.getIPv4Header()->ipId = htons(1);
	ipLayer2.getIPv4Header()->timeToLive = 64;
	IPv4Layer ipLayer3(IPv4Address(std::string("127.0.0.1")), IPv4Address(std::string("127.0.0.1")));
	ipLayer3.getIPv4Header()->ipId = htons(46845);
	ipLayer3.getIPv4Header()->timeToLive = 64;

	GREv0Layer grev0Layer1;
	PACKETPP_ASSERT(grev0Layer1.setChecksum(1), "Couldn't set checksum");

	GREv0Layer grev0Layer2;

	Packet grev0Packet(12);
	grev0Packet.addLayer(&ethLayer2);
	grev0Packet.addLayer(&ipLayer2);
	grev0Packet.addLayer(&grev0Layer1);
	grev0Packet.addLayer(&ipLayer3);
	grev0Packet.addLayer(&grev0Layer2);
	grev0Packet.computeCalculateFields();


	PACKETPP_ASSERT(grev0Packet.getRawPacket()->getRawDataLen() == buffer2Length, "GREv0 packet raw data length is different than expected");
	PACKETPP_ASSERT(memcmp(grev0Packet.getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "GREv0 packet raw data is different than expected");


	delete [] buffer1;
	delete [] buffer2;

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(GreEditTest)
{
	// GREv0 packet edit

	int buffer1Length = 0;

	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/GREv0_3.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file GREv0_3.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet grev0Packet(&rawPacket1);

	PACKETPP_ASSERT(grev0Packet.isPacketOfType(GRE) && grev0Packet.isPacketOfType(GREv0), "GREv0 Packet isn't of type GREv0");
	GREv0Layer* grev0Layer = grev0Packet.getLayerOfType<GREv0Layer>();
	PACKETPP_ASSERT(grev0Layer != NULL, "GREv0 layer is null");
	PACKETPP_ASSERT(grev0Layer->setSequenceNumber(1234), "Couldn't set seq num");
	PACKETPP_ASSERT(grev0Layer->setKey(2341), "Couldn't set offset");
	grev0Packet.computeCalculateFields();


	uint16_t value16 = 0;
	uint32_t value32 = 0;
	grev0Layer = grev0Packet.getLayerOfType<GREv0Layer>();
	PACKETPP_ASSERT(grev0Layer != NULL, "GREv0 layer after editing is null");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 1, "GREv0 layer checksum bit not set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 1, "GREv0 layer seq bit not set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->keyBit == 1, "GREv0 layer key bit not set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->strictSourceRouteBit == 0, "GREv0 layer strict bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->routingBit == 0, "GREv0 layer routing bit set");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 16, "GREv0 layer after editing wrong header len");
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16), "GREv0 layer after editing checksum not set");
	PACKETPP_ASSERT(value16 == 14856, "GREv0 layer after editing wrong checksum");
	PACKETPP_ASSERT(grev0Layer->getSequenceNumber(value32), "GREv0 layer after editing seq not set");
	PACKETPP_ASSERT(value32 == 1234, "GREv0 layer after editing wrong seq");
	PACKETPP_ASSERT(grev0Layer->getKey(value32), "GREv0 layer after editing key not set");
	PACKETPP_ASSERT(value32 == 2341, "GREv0 layer after editing wrong key");
	PACKETPP_ASSERT(!grev0Layer->getOffset(value16), "GREv0 layer after editing offset set");
	grev0Layer->getGreHeader()->routingBit = 1;
	PACKETPP_ASSERT(grev0Layer->getOffset(value16), "GREv0 layer after editing offset not set");
	PACKETPP_ASSERT(value16 == 0, "GREv0 layer after editing wrong offset");
	grev0Layer->getGreHeader()->routingBit = 0;

	PACKETPP_ASSERT(grev0Layer->setSequenceNumber(5678), "Couldn't set seq num");
	grev0Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev0Layer->getSequenceNumber(value32), "GREv0 layer after editing seq not set");
	PACKETPP_ASSERT(value32 == 5678, "GREv0 layer after editing wrong seq");
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16), "GREv0 layer after editing checksum not set");
	PACKETPP_ASSERT(value16 == 10412, "GREv0 layer after editing wrong checksum");
	PACKETPP_ASSERT(grev0Layer->getKey(value32), "GREv0 layer after editing key not set");
	PACKETPP_ASSERT(value32 == 2341, "GREv0 layer after editing wrong key");

	PACKETPP_ASSERT(grev0Layer->unsetSequenceNumber(), "Couldn't unset seq num");
	grev0Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 layer after seq unset seq bit still set");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 12, "GREv0 layer after seq unset wrong header len");
	PACKETPP_ASSERT(!grev0Layer->getSequenceNumber(value32), "GREv0 layer after seq unset seq still valid");
	PACKETPP_ASSERT(grev0Layer->getKey(value32), "GREv0 layer after seq unset key not set");
	PACKETPP_ASSERT(value32 == 2341, "GREv0 layer after seq unset wrong key");
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16), "GREv0 layer after seq unset checksum not set");
	PACKETPP_ASSERT(value16 == 20186, "GREv0 layer after seq unset wrong checksum");

	PACKETPP_ASSERT(grev0Layer->unsetChecksum(), "Couldn't unset checksum");
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(!grev0Layer->unsetSequenceNumber(), "Managed to unset seq num although already unset");
	LoggerPP::getInstance().enableErrors();
	grev0Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 0, "GREv0 layer after checksum unset checksum bit still set");
	PACKETPP_ASSERT(!grev0Layer->getChecksum(value16), "GREv0 layer after checksum unset checksum still valid");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 layer after checksum unset seq bit set");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 8, "GREv0 layer after checksum unset wrong header len");
	PACKETPP_ASSERT(!grev0Layer->getSequenceNumber(value32), "GREv0 layer after checksum unset seq valid");
	PACKETPP_ASSERT(grev0Layer->getKey(value32), "GREv0 layer after checksum unset key not set");
	PACKETPP_ASSERT(value32 == 2341, "GREv0 layer after checksum unset wrong key");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(!grev0Layer->unsetChecksum(), "Managed to unset checksum although already unset");
	PACKETPP_ASSERT(!grev0Layer->unsetSequenceNumber(), "Managed to unset seq num although already unset");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(grev0Layer->unsetKey(), "Couldn't unset key");
	grev0Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev0Layer->getGreHeader()->keyBit == 0, "GREv0 layer after key unset key bit still set");
	PACKETPP_ASSERT(!grev0Layer->getKey(value32), "GREv0 layer after key unset key still valid");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 4, "GREv0 layer after key unset wrong header len");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 0, "GREv0 layer after key unset checksum bit set");
	PACKETPP_ASSERT(!grev0Layer->getChecksum(value16), "GREv0 layer after key unset checksum valid");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 layer after key unset seq bit set");

	PACKETPP_ASSERT(grev0Layer->setChecksum(0), "Couldn't re-add checksum");
	grev0Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev0Layer->getGreHeader()->checksumBit == 1, "GREv0 layer after re-add checksum checksum bit unset");
	PACKETPP_ASSERT(grev0Layer->getHeaderLen() == 8, "GREv0 layer after re-add checksum wrong header len");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->keyBit == 0, "GREv0 layer after re-add checksum key bit set");
	PACKETPP_ASSERT(grev0Layer->getGreHeader()->sequenceNumBit == 0, "GREv0 layer after re-add checksum seq bit set");
	PACKETPP_ASSERT(grev0Layer->getChecksum(value16), "GREv0 layer after re-add checksum checksum not valid");
	PACKETPP_ASSERT(value16 == 30719, "GREv0 layer after re-add checksum wrong checksum");


	// GREv1 packet edit

	int buffer2Length = 0;

	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/GREv1_2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file GREv1_2.dat");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet grev1Packet(&rawPacket2);

	value16 = 0;
	value32 = 0;
	GREv1Layer* grev1Layer = grev1Packet.getLayerOfType<GREv1Layer>();
	PACKETPP_ASSERT(grev1Layer->setAcknowledgmentNum(56789), "GREv1 layer couldn't add ack num");
	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 16, "GREv1 layer after set ack wrong header len");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->ackSequenceNumBit == 1, "GREv1 layer after set ack ack bit still unset");
	PACKETPP_ASSERT(grev1Layer->getAcknowledgmentNum(value32), "GREv1 layer after set ack ack is not valid");
	PACKETPP_ASSERT(value32 == 56789, "GREv1 layer after set ack wrong ack");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->keyBit == 1, "GREv1 layer after set ack key bit unset");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->checksumBit == 0, "GREv1 layer after set ack checksun bit set");
	PACKETPP_ASSERT(grev1Layer->getSequenceNumber(value32), "GREv1 layer after set ack seq num is not valid");
	PACKETPP_ASSERT(value32 == 539320, "GREv1 layer after set ack wrong seq num");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->callID == htons(17), "GREv1 layer after set ack wrong call id");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->payloadLength == htons(178), "GREv1 layer after set ack wrong payload length");

	PACKETPP_ASSERT(grev1Layer->setSequenceNumber(12345), "GREv1 layer couldn't set seq num");
	grev1Layer->getGreHeader()->callID = htons(123);
	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 16, "GREv1 layer after set seq num wrong header len");
	PACKETPP_ASSERT(grev1Layer->getSequenceNumber(value32), "GREv1 layer after set seq num seq num is not valid");
	PACKETPP_ASSERT(value32 == 12345, "GREv1 layer after set seq num wrong seq num");
	PACKETPP_ASSERT(grev1Layer->getAcknowledgmentNum(value32), "GREv1 layer after set seq num ack is not valid");
	PACKETPP_ASSERT(value32 == 56789, "GREv1 layer after set seq num wrong ack");

	PACKETPP_ASSERT(grev1Layer->unsetSequenceNumber(), "GREv1 layer couldn't unset seq num");
	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 12, "GREv1 layer after unset seq num wrong header len");
	PACKETPP_ASSERT(!grev1Layer->getSequenceNumber(value32), "GREv1 layer after unset seq num seq num still valid");
	PACKETPP_ASSERT(grev1Layer->getAcknowledgmentNum(value32), "GREv1 layer after unset seq num ack is not valid");
	PACKETPP_ASSERT(value32 == 56789, "GREv1 layer after unset seq num wrong ack");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->callID == htons(123), "GREv1 layer after unset seq num wrong call id");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->payloadLength == htons(178), "GREv1 layer after unset seq num wrong payload length");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(!grev0Layer->unsetSequenceNumber(), "GREv1 layer managed to unset seq num although already unset");
	LoggerPP::getInstance().enableErrors();
	PACKETPP_ASSERT(grev1Layer->unsetAcknowledgmentNum(), "GREv1 layer couldn't unset ack num");
	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(grev1Layer->getHeaderLen() == 8, "GREv1 layer after unset ack num wrong header len");
	PACKETPP_ASSERT(!grev1Layer->getAcknowledgmentNum(value32), "GREv1 layer after unset ack num ack is still valid");
	PACKETPP_ASSERT(!grev1Layer->getSequenceNumber(value32), "GREv1 layer after unset ack num seq num valid");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->ackSequenceNumBit == 0, "GREv1 layer after unset ack num bit still set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->sequenceNumBit == 0, "GREv1 layer after unset ack num seq bit set");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->keyBit == 1, "GREv1 layer after unset ack num key bit unset");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->callID == htons(123), "GREv1 layer after unset ack num wrong call id");
	PACKETPP_ASSERT(grev1Layer->getGreHeader()->payloadLength == htons(178), "GREv1 layer after unset ack num wrong payload length");

	PACKETPP_ASSERT(grev1Layer->getNextLayer() != NULL && grev1Layer->getNextLayer()->getProtocol() == PPP_PPTP, "GREv1 layer next protocol isn't PPP");
	PPP_PPTPLayer* pppLayer = dynamic_cast<PPP_PPTPLayer*>(grev1Layer->getNextLayer());
	PACKETPP_ASSERT(pppLayer != NULL, "GREv1 PPP layer is null");
	pppLayer->getPPP_PPTPHeader()->control = 255;

	Layer* curLayer = pppLayer->getNextLayer();
	while (curLayer != NULL)
	{
		Layer* temp = curLayer->getNextLayer();
		grev1Packet.removeLayer(curLayer);
		curLayer = temp;
	}

	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(pppLayer->getPPP_PPTPHeader()->protocol == 0, "PPP protocol isn't 0 after removing top layers");

	IPv6Layer ipv6Layer(IPv6Address(std::string("2402:f000:1:8e01::5555")), IPv6Address(std::string("2607:fcd0:100:2300::b108:2a6b")));
	PACKETPP_ASSERT(grev1Packet.addLayer(&ipv6Layer), "Couldn't add IPv6 layer to GREv1 packet");
	grev1Packet.computeCalculateFields();

	PACKETPP_ASSERT(pppLayer->getNextLayer() != NULL && pppLayer->getNextLayer()->getProtocol() == IPv6, "PPP next layer isnt' IPv6");
	PACKETPP_ASSERT(pppLayer->getPPP_PPTPHeader()->protocol == htons(PCPP_PPP_IPV6), "PPP layer protocol isn't IPv6");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SSLClientHelloParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-ClientHello1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet clientHelloPacket(&rawPacket);

	PACKETPP_ASSERT(clientHelloPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = clientHelloPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract handshake layer");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Number of messages in client-hello layer != 1");
	SSLClientHelloMessage* clientHelloMessage = handshakeLayer->getHandshakeMessageOfType<SSLClientHelloMessage>();
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessageAt(0) == clientHelloMessage, "handshake message at index 0 isn't client-hello message");
	PACKETPP_ASSERT(clientHelloMessage != NULL, "Client-hello layer is NULL");
	PACKETPP_ASSERT(handshakeLayer->getRecordType() == SSL_HANDSHAKE, "Record layer isn't of type handshake");
	PACKETPP_ASSERT(handshakeLayer->getRecordVersion() == TLS1_0, "Record version isn't TLSv1.0");
	PACKETPP_ASSERT(clientHelloMessage->getHandshakeType() == SSL_CLIENT_HELLO, "Handshake type isn't client-hello");
	PACKETPP_ASSERT(clientHelloMessage->getHandshakeVersion() == TLS1_2, "Handshake version isn't TLSv1.2");
	uint8_t* random = clientHelloMessage->getClientHelloHeader()->random;
	PACKETPP_ASSERT(random[0] == 0x3e && random[8] == 0x78 && random[27] == 0xe5, "Random value not as expected");
	PACKETPP_ASSERT(clientHelloMessage->getSessionIDLength() == 0 && clientHelloMessage->getSessionID() == NULL, "Session ID values not as expected");
	PACKETPP_ASSERT(clientHelloMessage->getCipherSuiteCount() == 11, "Cipher suite count != 11, it's %d", clientHelloMessage->getCipherSuiteCount());

	uint16_t cipherSuiteIDs[11] = { 0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a };
	std::string cipherSuiteNames[11] = {
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA"
			};
	SSLKeyExchangeAlgorithm cipherSuiteKey[11] = {
			SSL_KEYX_ECDHE,
			SSL_KEYX_ECDHE,
			SSL_KEYX_ECDHE,
			SSL_KEYX_ECDHE,
			SSL_KEYX_ECDHE,
			SSL_KEYX_ECDHE,
			SSL_KEYX_DHE,
			SSL_KEYX_DHE,
			SSL_KEYX_RSA,
			SSL_KEYX_RSA,
			SSL_KEYX_RSA
	};

	SSLAuthenticationAlgorithm cipherSuiteAuth[11] = {
			SSL_AUTH_ECDSA,
			SSL_AUTH_RSA,
			SSL_AUTH_ECDSA,
			SSL_AUTH_ECDSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA,
			SSL_AUTH_RSA
	};

	SSLSymetricEncryptionAlgorithm cipherSuiteSym[11] = {
			SSL_SYM_AES_128_GCM,
			SSL_SYM_AES_128_GCM,
			SSL_SYM_AES_256_CBC,
			SSL_SYM_AES_128_CBC,
			SSL_SYM_AES_128_CBC,
			SSL_SYM_AES_256_CBC,
			SSL_SYM_AES_128_CBC,
			SSL_SYM_AES_256_CBC,
			SSL_SYM_AES_128_CBC,
			SSL_SYM_AES_256_CBC,
			SSL_SYM_3DES_EDE_CBC
	};

	SSLHashingAlgorithm cipherSuiteHash[11] = {
			SSL_HASH_SHA256,
			SSL_HASH_SHA256,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA,
			SSL_HASH_SHA
	};

	for (int i = 0; i < clientHelloMessage->getCipherSuiteCount(); i++)
	{
		SSLCipherSuite* curCipherSuite = clientHelloMessage->getCipherSuite(i);
		PACKETPP_ASSERT(curCipherSuite != NULL, "Cipher suite at index %d is NULL", i);
		PACKETPP_ASSERT(curCipherSuite->asString() == cipherSuiteNames[i], "Cipher suite name at index %d is incorrect", i);
		PACKETPP_ASSERT(curCipherSuite->getID() == cipherSuiteIDs[i], "Cipher suite ID at index %d is incorrect", i);
		PACKETPP_ASSERT(curCipherSuite->getKeyExchangeAlg() == cipherSuiteKey[i], "Cipher suite key alg at index %d is incorrect", i);
		PACKETPP_ASSERT(curCipherSuite->getAuthAlg() == cipherSuiteAuth[i], "Cipher suite auth alg at index %d is incorrect", i);
		PACKETPP_ASSERT(curCipherSuite->getSymKeyAlg() == cipherSuiteSym[i], "Cipher suite sym alg at index %d is incorrect", i);
		PACKETPP_ASSERT(curCipherSuite->getMACAlg() == cipherSuiteHash[i], "Cipher suite MAC alg at index %d is incorrect", i);
	}

	PACKETPP_ASSERT(clientHelloMessage->getCompressionMethodsValue() == 0, "Compression value isn't 0, it's 0x%X", clientHelloMessage->getCompressionMethodsValue());
	PACKETPP_ASSERT(handshakeLayer->getHeaderLen() == 188, "Header len isn't as expected");

	int extCount = clientHelloMessage->getExtensionCount();
	PACKETPP_ASSERT(extCount == 9, "Num of extensions != 9, it's %d", clientHelloMessage->getExtensionCount());
	PACKETPP_ASSERT(clientHelloMessage->getExtensionsLenth() == 116, "Extensions length != 116");

	SSLExtension* ext = clientHelloMessage->getExtension(0);
	PACKETPP_ASSERT(ext->getType() == SSL_EXT_SERVER_NAME, "First extension isn't server name");
	SSLServerNameIndicationExtension* serverNameExt = clientHelloMessage->getExtensionOfType<SSLServerNameIndicationExtension>();
	PACKETPP_ASSERT(serverNameExt != NULL, "Couldn't find SNI ext");
	PACKETPP_ASSERT(serverNameExt->getHostName() == "www.google.com", "SNI value isn't as expected");

	SSLExtensionType extTypes[9] = { SSL_EXT_SERVER_NAME, SSL_EXT_RENEGOTIATION_INFO, SSL_EXT_ELLIPTIC_CURVES, SSL_EXT_EC_POINT_FORMATS,
			SSL_EXT_SESSIONTICKET_TLS, SSL_EXT_Unknown, SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, SSL_EXT_STATUS_REQUEST,
			SSL_EXT_SIGNATURE_ALGORITHMS };

	uint16_t extLength[9] = { 19, 1, 8, 2, 0, 0, 23, 5, 22 };

	for (int i = 0; i < extCount; i++)
	{
		SSLExtension* curExt = clientHelloMessage->getExtension(i);
		PACKETPP_ASSERT(curExt->getType() == extTypes[i], "SSL ext no. %d is not of the correct type", i);
		PACKETPP_ASSERT(curExt->getLength() == extLength[i], "SSL ext no. %d is not of the correct length", i);
		PACKETPP_ASSERT(clientHelloMessage->getExtensionOfType(extTypes[i]) == curExt, "SSL ext no. %d: fetching the extension by type failed", i);
	}

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SSLAppDataParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-MultipleAppData.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet appDataPacket(&rawPacket);

	PACKETPP_ASSERT(appDataPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLApplicationDataLayer* appDataLayer = appDataPacket.getLayerOfType<SSLApplicationDataLayer>();
	PACKETPP_ASSERT(appDataLayer != NULL, "Couldn't extract first app data layer");

	PACKETPP_ASSERT(appDataLayer->getRecordVersion() == TLS1_2, "Record TLS version isn't SSLv1.2");
	PACKETPP_ASSERT(appDataLayer->getRecordType() == SSL_APPLICATION_DATA, "Record type isn't app data");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedDataLen() == 880, "Encrypted data len isn't 880");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[0] == 0, "1st byte of encrypted data != 0");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[16] == 0xd9, "16th byte of encrypted data != 0xd9");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[77] == 0x19, "77th byte of encrypted data != 0x19");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[869] == 0xbc, "869th byte of encrypted data != 0xbc");

	PACKETPP_ASSERT(appDataLayer->getNextLayer() != NULL && appDataLayer->getNextLayer()->getProtocol() == SSL, "2nd app data layer is null or not SSL");
	appDataLayer = dynamic_cast<SSLApplicationDataLayer*>(appDataLayer->getNextLayer());
	PACKETPP_ASSERT(appDataLayer != NULL, "Couldn't extract second app data layer");

	PACKETPP_ASSERT(appDataLayer->getRecordVersion() == TLS1_2, "Second record TLS version isn't SSLv1.2");
	PACKETPP_ASSERT(appDataLayer->getRecordType() == SSL_APPLICATION_DATA, "Second record type isn't app data");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedDataLen() == 41, "Encrypted data len isn't 41");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[0] == 0, "1st byte of encrypted data != 0");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[19] == 0x7d, "20th byte of encrypted data != 0x7d");
	PACKETPP_ASSERT(appDataLayer->getEncrpytedData()[40] == 0xec, "41th byte of encrypted data != 0xec");

	PACKETPP_ASSERT(appDataLayer->getNextLayer() == NULL, "We have extra layer that shouldn't exist")

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SSLAlertParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/SSL-AlertClear.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/SSL-AlertEnc.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet clearAlertPacket(&rawPacket1);
	Packet encAlertPacket(&rawPacket2);

	PACKETPP_ASSERT(clearAlertPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLAlertLayer* clearAlertLayer = clearAlertPacket.getLayerOfType<SSLAlertLayer>();
	PACKETPP_ASSERT(clearAlertLayer != NULL, "Couldn't extract alert layer");
	PACKETPP_ASSERT(clearAlertLayer->getRecordVersion() == TLS1_0, "Record TLS version isn't SSLv1.0");
	PACKETPP_ASSERT(clearAlertLayer->getRecordType() == SSL_ALERT, "Record type isn't ssl alert");
	PACKETPP_ASSERT(clearAlertLayer->getAlertLevel() == SSL_ALERT_LEVEL_FATAL, "Alert level isn't fatal");
	PACKETPP_ASSERT(clearAlertLayer->getAlertDescription() == SSL_ALERT_PROTOCOL_VERSION, "Alert desc isn't protocol version");
	PACKETPP_ASSERT(clearAlertLayer->getRecordLayer()->length == ntohs(2), "Record length isn't 2");
	PACKETPP_ASSERT(clearAlertLayer->getNextLayer() == NULL, "Alert layer isn't the last layer");

	PACKETPP_ASSERT(encAlertPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLAlertLayer* encAlertLayer = encAlertPacket.getLayerOfType<SSLAlertLayer>();
	PACKETPP_ASSERT(encAlertLayer != NULL, "Couldn't extract alert layer");
	PACKETPP_ASSERT(encAlertLayer->getRecordVersion() == TLS1_2, "Record TLS version isn't SSLv1.2");
	PACKETPP_ASSERT(encAlertLayer->getRecordType() == SSL_ALERT, "Record type isn't ssl alert");
	PACKETPP_ASSERT(encAlertLayer->getAlertLevel() == SSL_ALERT_LEVEL_ENCRYPTED, "Alert level isn't encrypted");
	PACKETPP_ASSERT(encAlertLayer->getAlertDescription() == SSL_ALERT_ENCRYPRED, "Alert desc isn't encrypted");
	PACKETPP_ASSERT(encAlertLayer->getRecordLayer()->length == ntohs(26), "Record length isn't 26");
	PACKETPP_ASSERT(encAlertLayer->getHeaderLen() == 31, "Header length isn't 31");

	PACKETPP_TEST_PASSED;
}

/**
 * Testing: server-hello, change-cipher-spec, hello-request
 */
PACKETPP_TEST(SSLMultipleRecordParsingTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-MultipleRecords1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet multipleRecordsPacket(&rawPacket);

	PACKETPP_ASSERT(multipleRecordsPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Num of messages in server-hello record != 1, %d", (int)handshakeLayer->getHandshakeMessagesCount());
	SSLServerHelloMessage* serverHelloMessage = handshakeLayer->getHandshakeMessageOfType<SSLServerHelloMessage>();
	PACKETPP_ASSERT(serverHelloMessage != NULL, "Couldn't extract server-hello message");
	PACKETPP_ASSERT(serverHelloMessage->getSessionIDLength() == 32, "Server-hello session-id length != 32");
	PACKETPP_ASSERT(serverHelloMessage->getSessionID()[0] == 0xbf, "Server-hello 1st byte of session-id isn't 0xbf");
	PACKETPP_ASSERT(serverHelloMessage->getSessionID()[31] == 0x44, "Server-hello last byte of session-id isn't 0x44");
	PACKETPP_ASSERT(serverHelloMessage->getCipherSuite()->asString() == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "Got the wrong cipher suite");
	PACKETPP_ASSERT(serverHelloMessage->getCipherSuite()->getSymKeyAlg() == SSL_SYM_AES_128_GCM, "Cipher suite - wrong sym key");
	PACKETPP_ASSERT(serverHelloMessage->getExtensionsLenth() == 20, "Extension length != 20");
	PACKETPP_ASSERT(serverHelloMessage->getExtensionCount() == 3, "Num of extensions != 3");
	uint16_t extensionsLength[3] = { 1, 5, 2 };
	uint16_t totalExtensionsLength[3] = { 5, 9, 6 };
	SSLExtensionType extensionTypes[3] = { SSL_EXT_RENEGOTIATION_INFO, SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, SSL_EXT_EC_POINT_FORMATS };
	uint8_t extensionDataFirstByte[3] = { 0, 0, 1 };
	for (int i = 0; i < 3; i++)
	{
		SSLExtension* curExt = serverHelloMessage->getExtension(i);
		PACKETPP_ASSERT(curExt->getLength() == extensionsLength[i], "Extension #%d - wrong length", i);
		PACKETPP_ASSERT(curExt->getTotalLength() == totalExtensionsLength[i], "Extension #%d - wrong total length", i);
		PACKETPP_ASSERT(curExt->getType() == extensionTypes[i], "Extension #%d - wrong type", i);
		PACKETPP_ASSERT(curExt->getData()[0] == extensionDataFirstByte[i], "Extension #%d - wrong first byte", i);
	}

	SSLChangeCipherSpecLayer* ccsLayer = multipleRecordsPacket.getLayerOfType<SSLChangeCipherSpecLayer>();
	PACKETPP_ASSERT(ccsLayer != NULL, "Couldn't change-cipher-spec layer");
	PACKETPP_ASSERT(ccsLayer->getRecordVersion() == TLS1_2, "Record TLS version isn't SSLv1.2");
	PACKETPP_ASSERT(ccsLayer->getRecordType() == SSL_CHANGE_CIPHER_SPEC, "Record type isn't change-cipher-spec");
	PACKETPP_ASSERT(ccsLayer->getHeaderLen() == 6, "Record len isn't 6");

	handshakeLayer = multipleRecordsPacket.getNextLayerOfType<SSLHandshakeLayer>(handshakeLayer);
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract third handshake layer");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 3, "Num of messages in hello-request record != 3, it's %d", (int)handshakeLayer->getHandshakeMessagesCount());
	SSLHelloRequestMessage* helloRequest = handshakeLayer->getHandshakeMessageOfType<SSLHelloRequestMessage>();
	PACKETPP_ASSERT(helloRequest != NULL, "Couldn't retrieve first hello-request");
	PACKETPP_ASSERT(helloRequest->getHandshakeType() == SSL_HELLO_REQUEST, "Hello-request message isn't of type hello-request");
	PACKETPP_ASSERT(helloRequest->getMessageLength() == 4, "Hello-request isn't of size 4");
	SSLHelloRequestMessage* helloRequest2 = handshakeLayer->getNextHandshakeMessageOfType<SSLHelloRequestMessage>(helloRequest);
	PACKETPP_ASSERT(helloRequest2 != NULL, "Couldn't retrieve second hello-request");
	PACKETPP_ASSERT(helloRequest2 != helloRequest, "Wrong search - both hello-request messages are the same pointer");
	PACKETPP_ASSERT(helloRequest2->getHandshakeType() == SSL_HELLO_REQUEST, "Second hello-request message isn't of type hello-request");
	PACKETPP_ASSERT(helloRequest2->getMessageLength() == 4, "Second hello-request isn't of size 4");
	helloRequest2 = handshakeLayer->getNextHandshakeMessageOfType<SSLHelloRequestMessage>(helloRequest2);
	PACKETPP_ASSERT(helloRequest2 == NULL, "Found 3rd hello-request message");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessageAt(2) != NULL, "Couldn't find the 3rd handshake message");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessageAt(2)->getHandshakeType() == SSL_HANDSHAKE_UNKNOWN, "3rd handshake message isn't of type unknown");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessageAt(2)->getMessageLength() == 32, "Unknown handshake message isn't of length 32, it's %d", (int)(handshakeLayer->getHandshakeMessageAt(2)->getMessageLength()));

	PACKETPP_TEST_PASSED;
}

/**
 * Testing: client-key-exchange
 */
PACKETPP_TEST(SSLMultipleRecordParsing2Test)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-MultipleRecords2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet multipleRecordsPacket(&rawPacket);

	PACKETPP_ASSERT(multipleRecordsPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");

	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Num of messages in client-key-exchange record != 1");
	SSLClientKeyExchangeMessage* clientKeyExMsg = handshakeLayer->getHandshakeMessageOfType<SSLClientKeyExchangeMessage>();
	PACKETPP_ASSERT(clientKeyExMsg != NULL, "Couldn't find client-key-exchange message");
	PACKETPP_ASSERT(clientKeyExMsg->getHandshakeType() == SSL_CLIENT_KEY_EXCHANGE, "Client-key-exchange message isn't of the right type");
	PACKETPP_ASSERT(clientKeyExMsg->getMessageLength() == 70, "Client-key-exchange message isn't of the right length");
	PACKETPP_ASSERT(clientKeyExMsg->getClientKeyExchangeParamsLength() == 66, "Client-key-exchange params len != 66");
	PACKETPP_ASSERT(clientKeyExMsg->getClientKeyExchangeParams()[0] == 0x41, "Server-key-exchange params - 1st byte != 0x41");
	PACKETPP_ASSERT(clientKeyExMsg->getClientKeyExchangeParams()[10] == 0xf2, "Server-key-exchange params - 11th byte != 0xf2");
	PACKETPP_ASSERT(clientKeyExMsg->getClientKeyExchangeParams()[65] == 0xdc, "Server-key-exchange params - 66th byte != 0xdc");

	PACKETPP_TEST_PASSED;
}

/**
 * Testing - certificate, certificate-request
 */
PACKETPP_TEST(SSLMultipleRecordParsing3Test)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-MultipleRecords3.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet multipleRecordsPacket(&rawPacket);

	PACKETPP_ASSERT(multipleRecordsPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");

	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 5, "Couldn't find 5 handshake messages");

	SSLCertificateMessage* certMsg = handshakeLayer->getHandshakeMessageOfType<SSLCertificateMessage>();
	PACKETPP_ASSERT(certMsg != NULL, "Couldn't find certificate message");
	PACKETPP_ASSERT(certMsg->getHandshakeType() == SSL_CERTIFICATE, "Message type isn't SSL_CERTIFICATE");
	PACKETPP_ASSERT(certMsg->getMessageLength() == 4966, "Cert message doesn't have the right length");
	PACKETPP_ASSERT(certMsg->getNumOfCertificates() == 3, "Couldn't find 3 certificate messages, found %d messages", certMsg->getNumOfCertificates());
	PACKETPP_ASSERT(certMsg->getCertificate(1000) == NULL, "Managed to fetch cert that doesn't exits");

	SSLx509Certificate* cert = certMsg->getCertificate(0);
	PACKETPP_ASSERT(cert != NULL, "Couldn't retrieve cert #0");
	PACKETPP_ASSERT(cert->allDataExists() == true, "Cert #0 - not all data exists");
	PACKETPP_ASSERT(cert->getDataLength() == 1509, "Cert#0 length isn't 1509");
	std::string certBuffer(cert->getData(), cert->getData()+cert->getDataLength());
	std::size_t pos = certBuffer.find("LDAP Intermediate CA");
	PACKETPP_ASSERT(pos != std::string::npos, "Cert#0 - couldn't find common name");
	pos = certBuffer.find("Internal Development CA");
	PACKETPP_ASSERT(pos == std::string::npos, "Found non-relevant common name");
	cert = certMsg->getCertificate(1);
	PACKETPP_ASSERT(cert != NULL, "Couldn't retrieve cert #1");
	PACKETPP_ASSERT(cert->allDataExists() == true, "Cert #1 - not all data exists");
	PACKETPP_ASSERT(cert->getDataLength() == 1728, "Cert#1 length isn't 1728");
	certBuffer = std::string(cert->getData(), cert->getData()+cert->getDataLength());
	pos = certBuffer.find("Internal Development CA");
	PACKETPP_ASSERT(pos != std::string::npos, "Cert#1 - couldn't find common name");
	cert = certMsg->getCertificate(2);
	PACKETPP_ASSERT(cert != NULL, "Couldn't retrieve cert #2");
	PACKETPP_ASSERT(cert->allDataExists() == true, "Cert #2 - not all data exists");
	PACKETPP_ASSERT(cert->getDataLength() == 1713, "Cert#2 length isn't 1713");
	certBuffer = std::string(cert->getData(), cert->getData()+cert->getDataLength());
	pos = certBuffer.find("Internal Development CA");
	PACKETPP_ASSERT(pos != std::string::npos, "Cert#2 - couldn't find common name");

	SSLCertificateRequestMessage* certReqMsg = handshakeLayer->getHandshakeMessageOfType<SSLCertificateRequestMessage>();
	PACKETPP_ASSERT(certReqMsg->isMessageComplete() == true, "Cert req message identifies as incomplete");
	PACKETPP_ASSERT(certReqMsg->getHandshakeType() == SSL_CERTIFICATE_REQUEST, "Cert req message isn't of type SSL_CERTIFICATE_REQUEST");
	PACKETPP_ASSERT(certReqMsg->getCertificateTypes().size() == 2, "Number of types in cert req message != 2");
	PACKETPP_ASSERT(certReqMsg->getCertificateTypes().at(0) == SSL_CCT_RSA_SIGN, "First type in cert req message isn't SSL_CCT_RSA_SIGN");
	PACKETPP_ASSERT(certReqMsg->getCertificateTypes().at(1) == SSL_CCT_DSS_SIGN, "Second type in cert req message isn't SSL_CCT_DSS_SIGN");
	PACKETPP_ASSERT(certReqMsg->getCertificateAuthorityLength() == 110, "Cert auth len isn't 110");
	PACKETPP_ASSERT(certReqMsg->getCertificateAuthorityData()[0] == 0x0, "Cert auth data in index 0 isn't 0x0");
	PACKETPP_ASSERT(certReqMsg->getCertificateAuthorityData()[1] == 0x6c, "Cert auth data in index 1 isn't 0x6c");
	PACKETPP_ASSERT(certReqMsg->getCertificateAuthorityData()[14] == 0x2, "Cert auth data in index 14 isn't 0x2");
	PACKETPP_ASSERT(certReqMsg->getCertificateAuthorityData()[47] == 0x13, "Cert auth data in index 47 isn't 0x13");

	PACKETPP_TEST_PASSED;
}

/**
 * Testing: server-key-exchange, server-hello-done
 */
PACKETPP_TEST(SSLMultipleRecordParsing4Test)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-MultipleRecords4.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet multipleRecordsPacket(&rawPacket);

	PACKETPP_ASSERT(multipleRecordsPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = multipleRecordsPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");

	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Num of messages in server-key-exchange record != 1");
	SSLServerKeyExchangeMessage* serverKeyExMsg = handshakeLayer->getHandshakeMessageOfType<SSLServerKeyExchangeMessage>();
	PACKETPP_ASSERT(serverKeyExMsg != NULL, "Couldn't find server-key-exchange message");
	PACKETPP_ASSERT(serverKeyExMsg->getHandshakeType() == SSL_SERVER_KEY_EXCHANGE, "Server-key-exchange message isn't of the right type");
	PACKETPP_ASSERT(serverKeyExMsg->getMessageLength() == 333, "Server-key-exchange message isn't of the right length");
	PACKETPP_ASSERT(serverKeyExMsg->getServerKeyExchangeParamsLength() == 329, "Server-key-exchange params len != 329");
	PACKETPP_ASSERT(serverKeyExMsg->getServerKeyExchangeParams()[0] == 0x03, "Server-key-exchange params - 1st byte != 0x03");
	PACKETPP_ASSERT(serverKeyExMsg->getServerKeyExchangeParams()[10] == 0x7a, "Server-key-exchange params - 11th byte != 0x7a");
	PACKETPP_ASSERT(serverKeyExMsg->getServerKeyExchangeParams()[328] == 0x33, "Server-key-exchange params - 328th byte != 0x33");

	handshakeLayer = multipleRecordsPacket.getNextLayerOfType<SSLHandshakeLayer>(handshakeLayer);
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract second handshake layer");
	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Num of messages in server-hello-done record != 1");
	SSLServerHelloDoneMessage* serverHelloDoneMsg = handshakeLayer->getHandshakeMessageOfType<SSLServerHelloDoneMessage>();
	PACKETPP_ASSERT(serverHelloDoneMsg != NULL, "Couldn't find server-hello-done message");
	PACKETPP_ASSERT(serverHelloDoneMsg->getHandshakeType() == SSL_SERVER_DONE, "Server-hello-done message isn't of the right type");
	PACKETPP_ASSERT(serverHelloDoneMsg->getMessageLength() == 4, "Server-hello-done message length != 4");
	PACKETPP_ASSERT(serverHelloDoneMsg == handshakeLayer->getHandshakeMessageAt(0), "Server-hello-done message isn't equal to msg at 0");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SSLPartialCertificateParseTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/SSL-PartialCertificate1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet partialCertPacket(&rawPacket1);

	PACKETPP_ASSERT(partialCertPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = partialCertPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");
	handshakeLayer = partialCertPacket.getNextLayerOfType<SSLHandshakeLayer>(handshakeLayer);
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract second handshake layer");
	SSLCertificateMessage* certMsg = handshakeLayer->getHandshakeMessageOfType<SSLCertificateMessage>();
	PACKETPP_ASSERT(certMsg != NULL, "Couldn't extract certificate message");
	PACKETPP_ASSERT(certMsg->isMessageComplete() == false, "Cert msg falsely complete");
	PACKETPP_ASSERT(certMsg->getNumOfCertificates() == 1, "Found more than 1 cert");
	SSLx509Certificate* cert = certMsg->getCertificate(0);
	PACKETPP_ASSERT(cert->allDataExists() == false, "Cert falsely complete");
	PACKETPP_ASSERT(cert->getDataLength() == 1266, "Wrong cert length");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/SSL-PartialCertificate2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet partialCertPacket2(&rawPacket2);

	PACKETPP_ASSERT(partialCertPacket2.isPacketOfType(SSL) == true, "Packet2 isn't of type SSL");
	handshakeLayer = partialCertPacket2.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");
	handshakeLayer = partialCertPacket2.getNextLayerOfType<SSLHandshakeLayer>(handshakeLayer);
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract second handshake layer");
	certMsg = handshakeLayer->getHandshakeMessageOfType<SSLCertificateMessage>();
	PACKETPP_ASSERT(certMsg != NULL, "Couldn't extract certificate message");
	PACKETPP_ASSERT(certMsg->isMessageComplete() == false, "Cert msg falsely complete");
	PACKETPP_ASSERT(certMsg->getNumOfCertificates() == 1, "Found more than 1 cert");
	cert = certMsg->getCertificate(0);
	PACKETPP_ASSERT(cert->allDataExists() == false, "Cert falsely complete");
	PACKETPP_ASSERT(cert->getDataLength() == 1268, "Wrong cert length");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SSLNewSessionTicketParseTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SSL-NewSessionTicket.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet sslPacket(&rawPacket);

	PACKETPP_ASSERT(sslPacket.isPacketOfType(SSL) == true, "Packet isn't of type SSL");
	SSLHandshakeLayer* handshakeLayer = sslPacket.getLayerOfType<SSLHandshakeLayer>();
	PACKETPP_ASSERT(handshakeLayer != NULL, "Couldn't extract first handshake layer");

	PACKETPP_ASSERT(handshakeLayer->getHandshakeMessagesCount() == 1, "Hanshake layer contains more than 1 message");
	SSLNewSessionTicketMessage* newSessionTicketMsg = handshakeLayer->getHandshakeMessageOfType<SSLNewSessionTicketMessage>();
	PACKETPP_ASSERT(newSessionTicketMsg != NULL, "Couldn't extract new-session-ticket message");
	PACKETPP_ASSERT(newSessionTicketMsg->isMessageComplete() == true, "New session ticket message falsely incomplete");
	PACKETPP_ASSERT(newSessionTicketMsg->getHandshakeType() == SSL_NEW_SESSION_TICKET, "New session ticket message type isn't SSL_NEW_SESSION_TICKET");
	PACKETPP_ASSERT(newSessionTicketMsg->getSessionTicketDataLength() == 214, "New session ticket data len isn't 218");
	PACKETPP_ASSERT(newSessionTicketMsg->getSessionTicketData()[0] == 0, "New session ticket data - byte#0 isn't 0x0");
	PACKETPP_ASSERT(newSessionTicketMsg->getSessionTicketData()[16] == 0xf9, "New session ticket data - byte#17 isn't 0xf9");
	PACKETPP_ASSERT(newSessionTicketMsg->getSessionTicketData()[213] == 0x75, "New session ticket data - byte#213 isn't 0x7f");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SllPacketParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/SllPacket.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true, LINKTYPE_LINUX_SLL);

	Packet sllPacket(&rawPacket1);
	PACKETPP_ASSERT(sllPacket.isPacketOfType(SLL) == true, "Packet isn't of type SLL");
	PACKETPP_ASSERT(sllPacket.getFirstLayer()->getProtocol() == SLL, "First layer isn't of type SLL");
	SllLayer* sllLayer = sllPacket.getLayerOfType<SllLayer>();
	PACKETPP_ASSERT(sllLayer->getNextLayer() != NULL, "Next layer is NULL");
	PACKETPP_ASSERT(sllLayer->getNextLayer()->getProtocol() == IPv6, "Next layer isn't IPv6");
	PACKETPP_ASSERT(sllPacket.isPacketOfType(HTTP) == true, "Packet isn't of type HTTP");
	PACKETPP_ASSERT(sllLayer != NULL, "Couldn't find SllLayer");
	PACKETPP_ASSERT(sllLayer == sllPacket.getFirstLayer(), "SLL isn't the first layer");
	PACKETPP_ASSERT(sllLayer->getSllHeader()->packet_type == 0, "Packet type isn't 0");
	PACKETPP_ASSERT(sllLayer->getSllHeader()->ARPHRD_type == htons(1), "ARPHRD_type isn't 1");
	PACKETPP_ASSERT(sllLayer->getSllHeader()->link_layer_addr_len == htons(6), "link_layer_addr_len isn't 6");
	MacAddress macAddrFromPacket(sllLayer->getSllHeader()->link_layer_addr);
	MacAddress macAddrRef("00:12:44:1e:74:00");
	PACKETPP_ASSERT(macAddrRef == macAddrFromPacket, "MAC address isn't correct, %s", macAddrFromPacket.toString().c_str());
	PACKETPP_ASSERT(sllLayer->getSllHeader()->protocol_type == htons(PCPP_ETHERTYPE_IPV6), "Next protocol isn't IPv4");
	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SllPacketCreationTest)
{
	SllLayer sllLayer(4, 1);
	sllLayer.setMacAddressAsLinkLayer(MacAddress("00:30:48:dd:00:53"));
	sllLayer.getSllHeader()->link_layer_addr[6] = 0xf6;
	sllLayer.getSllHeader()->link_layer_addr[7] = 0x7f;

	IPv4Layer ipLayer(IPv4Address(std::string("130.217.250.13")), IPv4Address(std::string("130.217.250.128")));
	ipLayer.getIPv4Header()->fragmentOffset = 0x40;
	ipLayer.getIPv4Header()->ipId = htons(63242);
	ipLayer.getIPv4Header()->timeToLive = 64;

	TcpLayer tcpLayer((uint16_t)55013, (uint16_t)6000);
	tcpLayer.getTcpHeader()->sequenceNumber = htonl(0x92f2ad86);
	tcpLayer.getTcpHeader()->ackNumber = htonl(0x7633e977);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htons(4098);
	PACKETPP_ASSERT(tcpLayer.addTcpOption(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL) != NULL, "Cannot add 1st NOP option");
	PACKETPP_ASSERT(tcpLayer.addTcpOption(PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, NULL) != NULL, "Cannot add 2nd NOP option");
	TcpOptionData* tsOption = tcpLayer.addTcpOption(PCPP_TCPOPT_TIMESTAMP, PCPP_TCPOLEN_TIMESTAMP, NULL);
	PACKETPP_ASSERT(tsOption != NULL, "Couldn't set timestamp TCP option");
	tsOption->setValue<uint32_t>(htonl(0x0402383b));
	tsOption->setValue<uint32_t>(htonl(0x03ff37f5), 4);

	Packet sllPacket(1);
	sllPacket.addLayer(&sllLayer);
	sllPacket.addLayer(&ipLayer);
	sllPacket.addLayer(&tcpLayer);

	sllPacket.computeCalculateFields();

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/SllPacket2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	PACKETPP_ASSERT(bufferLength == sllPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", sllPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(sllPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete [] buffer;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DhcpParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/Dhcp1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file Dhcp1.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet dhcpPacket(&rawPacket1);
	PACKETPP_ASSERT(dhcpPacket.isPacketOfType(DHCP) == true, "Packet isn't of type DHCP");
	DhcpLayer* dhcpLayer = dhcpPacket.getLayerOfType<DhcpLayer>();
	PACKETPP_ASSERT(dhcpLayer != NULL, "Couldn't extract DHCP layer");

	PACKETPP_ASSERT(dhcpLayer->getOpCode() == DHCP_BOOTREPLY, "Op code isn't boot reply");
	PACKETPP_ASSERT(dhcpLayer->getDhcpHeader()->secondsElapsed == ntohs(10), "Seconds elapsed isn't 10");
	PACKETPP_ASSERT(dhcpLayer->getDhcpHeader()->hops == 1, "hops isn't 1");
	PACKETPP_ASSERT(dhcpLayer->getDhcpHeader()->transactionID == ntohl(0x7771cf85), "hops isn't 0x7771cf85, it's 0x%x", dhcpLayer->getDhcpHeader()->transactionID);
	PACKETPP_ASSERT(dhcpLayer->getClientIpAddress() == IPv4Address::Zero, "Client IP address isn't 0.0.0.0");
	PACKETPP_ASSERT(dhcpLayer->getYourIpAddress() == IPv4Address(string("10.10.8.235")), "Your IP address isn't 10.10.8.235");
	PACKETPP_ASSERT(dhcpLayer->getServerIpAddress() == IPv4Address(string("172.22.178.234")), "Server IP address isn't 172.22.178.234");
	PACKETPP_ASSERT(dhcpLayer->getGatewayIpAddress() == IPv4Address(string("10.10.8.240")), "Gateway IP address isn't 10.10.8.240");
	PACKETPP_ASSERT(dhcpLayer->getClientHardwareAddress() == MacAddress(string("00:0e:86:11:c0:75")), "Client hardware address isn't 00:0e:86:11:c0:75");

	PACKETPP_ASSERT(dhcpLayer->getOptionsCount() == 12, "Option count is wrong, expected 12 and got %d", (int)dhcpLayer->getOptionsCount());
	DhcpOptionData* opt = dhcpLayer->getFirstOptionData();
	DhcpOptionTypes optTypeArr[] = {
			DHCPOPT_DHCP_MESSAGE_TYPE,
			DHCPOPT_SUBNET_MASK,
			DHCPOPT_DHCP_SERVER_IDENTIFIER,
			DHCPOPT_DHCP_LEASE_TIME,
			DHCPOPT_ROUTERS,
			DHCPOPT_DOMAIN_NAME_SERVERS,
			DHCPOPT_TFTP_SERVER_NAME,
			DHCPOPT_SIP_SERVERS,
			DHCPOPT_DHCP_CLIENT_IDENTIFIER,
			DHCPOPT_AUTHENTICATION,
			DHCPOPT_DHCP_AGENT_OPTIONS,
			DHCPOPT_END
	};

	uint8_t optLenArr[] = { 1, 4, 4, 4, 4, 8, 14, 5, 16, 31, 22, 0 };

	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PACKETPP_ASSERT(opt != NULL, "First opt is null");
		PACKETPP_ASSERT(opt->getType() == optTypeArr[i], "Option #%d type isn't %d, it's %d", (int)i, optTypeArr[i], opt->getType());
		PACKETPP_ASSERT(opt->getLength() == optLenArr[i], "Option #%d length isn't %d, it's %d", (int)i, optLenArr[i], opt->getLength());
		opt = dhcpLayer->getNextOptionData(opt);
	}

	PACKETPP_ASSERT(opt == NULL, "Last option isn't NULL");

	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PACKETPP_ASSERT(dhcpLayer->getOptionData(optTypeArr[i]) != NULL, "Cannot get option of type %d", optTypeArr[i]);
	}

	PACKETPP_ASSERT(dhcpLayer->getOptionData(DHCPOPT_SUBNET_MASK)->getValueAsIpAddr() == IPv4Address(std::string("255.255.255.0")), "Subnet mask isn't 255.255.255.0");
	PACKETPP_ASSERT(dhcpLayer->getOptionData(DHCPOPT_DHCP_SERVER_IDENTIFIER)->getValueAsIpAddr() == IPv4Address(std::string("172.22.178.234")), "Server id isn't 172.22.178.234");
	PACKETPP_ASSERT(dhcpLayer->getOptionData(DHCPOPT_DHCP_LEASE_TIME)->getValueAs<uint32_t>() == htonl(43200), "Lease time isn't 43200");
	PACKETPP_ASSERT(dhcpLayer->getOptionData(DHCPOPT_TFTP_SERVER_NAME)->getValueAsString() == "172.22.178.234", "TFTP server isn't 172.22.178.234");

	PACKETPP_ASSERT(dhcpLayer->getMesageType() == DHCP_OFFER, "Message type isn't DHCP_OFFER");



	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/Dhcp2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file Dhcp2.dat");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet dhcpPacket2(&rawPacket2);

	dhcpLayer = dhcpPacket2.getLayerOfType<DhcpLayer>();
	PACKETPP_ASSERT(dhcpLayer != NULL, "Couldn't extract DHCP layer for packet 2");

	PACKETPP_ASSERT(dhcpLayer->getOpCode() == DHCP_BOOTREQUEST, "Op code isn't boot request");
	PACKETPP_ASSERT(dhcpLayer->getDhcpHeader()->hops == 0, "hops isn't 0");
	PACKETPP_ASSERT(dhcpLayer->getClientIpAddress() == IPv4Address::Zero, "Client IP address isn't 0.0.0.0");
	PACKETPP_ASSERT(dhcpLayer->getYourIpAddress() == IPv4Address::Zero, "Your IP address isn't 0.0.0.0");
	PACKETPP_ASSERT(dhcpLayer->getServerIpAddress() == IPv4Address::Zero, "Server IP address isn't 0.0.0.0");
	PACKETPP_ASSERT(dhcpLayer->getGatewayIpAddress() == IPv4Address::Zero, "Gateway IP address isn't 0.0.0.0");
	PACKETPP_ASSERT(dhcpLayer->getClientHardwareAddress() == MacAddress(string("00:00:6c:82:dc:4e")), "Client hardware address isn't 00:00:6c:82:dc:4e");

	PACKETPP_ASSERT(dhcpLayer->getOptionsCount() == 9, "Option count is wrong, expected 9 and got %d", (int)dhcpLayer->getOptionsCount());
	opt = dhcpLayer->getFirstOptionData();
	DhcpOptionTypes optTypeArr2[] = {
			DHCPOPT_DHCP_MESSAGE_TYPE,
			DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
			DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
			DHCPOPT_DHCP_LEASE_TIME,
			DHCPOPT_DHCP_OPTION_OVERLOAD,
			DHCPOPT_DHCP_MESSAGE,
			DHCPOPT_PAD,
			DHCPOPT_DHCP_CLIENT_IDENTIFIER,
			DHCPOPT_END
	};

	uint8_t optLenArr2[] = { 1, 2, 4, 4, 1, 7, 0, 7, 0 };

	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PACKETPP_ASSERT(opt != NULL, "First opt is null");
		PACKETPP_ASSERT(opt->getType() == optTypeArr2[i], "Option #%d type isn't %d, it's %d", (int)i, optTypeArr2[i], opt->getType());
		PACKETPP_ASSERT(opt->getLength() == optLenArr2[i], "Option #%d length isn't %d, it's %d", (int)i, optLenArr2[i], opt->getLength());
		opt = dhcpLayer->getNextOptionData(opt);
	}

	PACKETPP_ASSERT(opt == NULL, "Last option isn't NULL");

	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PACKETPP_ASSERT(dhcpLayer->getOptionData(optTypeArr2[i]) != NULL, "Cannot get option of type %d", optTypeArr2[i]);
	}

	PACKETPP_ASSERT(dhcpLayer->getMesageType() == DHCP_DISCOVER, "Message type isn't DHCP_DISCOVER");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DhcpCreationTest)
{
	EthLayer ethLayer(MacAddress("00:13:72:25:fa:cd"), MacAddress("00:e0:b1:49:39:02"));

	IPv4Address srcIp(std::string("172.22.178.234"));
	IPv4Address dstIp(std::string("10.10.8.240"));
	IPv4Layer ipLayer(srcIp, dstIp);
	ipLayer.getIPv4Header()->ipId = htons(20370);
	ipLayer.getIPv4Header()->timeToLive = 128;

	UdpLayer udpLayer((uint16_t)67, (uint16_t)67);

	MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
	DhcpLayer dhcpLayer(DHCP_OFFER, clientMac);
	dhcpLayer.getDhcpHeader()->hops = 1;
	dhcpLayer.getDhcpHeader()->transactionID = htonl(0x7771cf85);
	dhcpLayer.getDhcpHeader()->secondsElapsed = htons(10);
	IPv4Address yourIP(std::string("10.10.8.235"));
	IPv4Address serverIP(std::string("172.22.178.234"));
	IPv4Address gatewayIP(std::string("10.10.8.240"));
	dhcpLayer.setYourIpAddress(yourIP);
	dhcpLayer.setServerIpAddress(serverIP);
	dhcpLayer.setGatewayIpAddress(gatewayIP);

	DhcpOptionData* subnetMaskOpt = dhcpLayer.addOption(DHCPOPT_SUBNET_MASK, 4, NULL);
	PACKETPP_ASSERT(subnetMaskOpt != NULL, "Couldn't add subnet mask option");
	IPv4Address subnetMask(std::string("255.255.255.0"));
	subnetMaskOpt->setValueIpAddr(subnetMask);

	uint8_t sipServersData[] = { 0x01, 0xac, 0x16, 0xb2, 0xea };
	DhcpOptionData* sipServersOpt = dhcpLayer.addOption(DHCPOPT_SIP_SERVERS, 5, sipServersData);
	PACKETPP_ASSERT(sipServersOpt != NULL, "Couldn't add SIP servers option");

	uint8_t agentData[] = { 0x01, 0x14, 0x20, 0x50, 0x4f, 0x4e, 0x20, 0x31, 0x2f, 0x31, 0x2f, 0x30, 0x37, 0x2f, 0x30, 0x31, 0x3a, 0x31, 0x2e, 0x30, 0x2e, 0x31 };
	DhcpOptionData* agentOpt = dhcpLayer.addOption(DHCPOPT_DHCP_AGENT_OPTIONS, 22, agentData);
	PACKETPP_ASSERT(agentOpt != NULL, "Couldn't add agent option");

	DhcpOptionData* clientIdOpt = dhcpLayer.addOptionAfter(DHCPOPT_DHCP_CLIENT_IDENTIFIER, 16, NULL, DHCPOPT_SIP_SERVERS);
	PACKETPP_ASSERT(clientIdOpt != NULL, "Couldn't add client ID option");
	clientIdOpt->setValue<uint8_t>(0);
	clientIdOpt->setValueString("nathan1clientid", 1);

	uint8_t authOptData[] = { 0x01, 0x01, 0x00, 0xc8, 0x78, 0xc4, 0x52, 0x56, 0x40, 0x20, 0x81, 0x31, 0x32, 0x33, 0x34, 0x8f, 0xe0, 0xcc, 0xe2, 0xee, 0x85, 0x96,
			0xab, 0xb2, 0x58, 0x17, 0xc4, 0x80, 0xb2, 0xfd, 0x30};
	DhcpOptionData* authOpt = dhcpLayer.addOptionAfter(DHCPOPT_AUTHENTICATION, 31, authOptData, DHCPOPT_DHCP_CLIENT_IDENTIFIER);
	PACKETPP_ASSERT(authOpt != NULL, "Couldn't add authentication option");

	DhcpOptionData* dhcpServerIdOpt = dhcpLayer.addOptionAfter(DHCPOPT_DHCP_SERVER_IDENTIFIER, 4, NULL, DHCPOPT_SUBNET_MASK);
	PACKETPP_ASSERT(dhcpServerIdOpt != NULL, "Couldn't add DHCP server ID option");
	IPv4Address dhcpServerIdIP = IPv4Address(std::string("172.22.178.234"));
	dhcpServerIdOpt->setValueIpAddr(dhcpServerIdIP);


	Packet newPacket(6);
	newPacket.addLayer(&ethLayer);
	newPacket.addLayer(&ipLayer);
	newPacket.addLayer(&udpLayer);
	newPacket.addLayer(&dhcpLayer);

	DhcpOptionData* routerOpt = dhcpLayer.addOptionAfter(DHCPOPT_ROUTERS, 4, NULL, DHCPOPT_DHCP_SERVER_IDENTIFIER);
	PACKETPP_ASSERT(routerOpt != NULL, "Couldn't add routers option");
	IPv4Address routerIP = IPv4Address(std::string("10.10.8.254"));
	routerOpt->setValueIpAddr(routerIP);

	DhcpOptionData* tftpServerOpt = dhcpLayer.addOptionAfter(DHCPOPT_TFTP_SERVER_NAME, 14, NULL, DHCPOPT_ROUTERS);
	PACKETPP_ASSERT(tftpServerOpt != NULL, "Couldn't add TFTP server name option");
	tftpServerOpt->setValueString("172.22.178.234");

	DhcpOptionData* dnsOpt = dhcpLayer.addOptionAfter(DHCPOPT_DOMAIN_NAME_SERVERS, 8, NULL, DHCPOPT_ROUTERS);
	PACKETPP_ASSERT(dnsOpt != NULL, "Couldn't add DNS option");
	IPv4Address dns1IP = IPv4Address(std::string("143.209.4.1"));
	IPv4Address dns2IP = IPv4Address(std::string("143.209.5.1"));
	dnsOpt->setValueIpAddr(dns1IP);
	dnsOpt->setValueIpAddr(dns2IP, 4);

	DhcpOptionData* leaseOpt = dhcpLayer.addOptionAfter(DHCPOPT_DHCP_LEASE_TIME, 4, NULL, DHCPOPT_DHCP_SERVER_IDENTIFIER);
	PACKETPP_ASSERT(leaseOpt != NULL, "Couldn't add lease option");
	leaseOpt->setValue<uint32_t>(htonl(43200));

	newPacket.computeCalculateFields();

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/Dhcp1.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file");

	PACKETPP_ASSERT(bufferLength == newPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", newPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(newPacket.getRawPacket()->getRawData(), buffer, bufferLength) == 0, "Raw packet data is different than expected");

	delete [] buffer;

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(DhcpEditTest)
{
	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/Dhcp4.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file Dhcp4.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet dhcpPacket(&rawPacket);

	DhcpLayer* dhcpLayer = dhcpPacket.getLayerOfType<DhcpLayer>();

	PACKETPP_ASSERT(dhcpLayer->removeOption(DHCPOPT_TFTP_SERVER_NAME) == true, "Couldn't remove DHCPOPT_TFTP_SERVER_NAME");

	PACKETPP_ASSERT(dhcpLayer->removeOption(DHCPOPT_TFTP_SERVER_NAME) == false, "Managed to remove DHCPOPT_TFTP_SERVER_NAME twice");

	PACKETPP_ASSERT(dhcpLayer->removeOption(DHCPOPT_IRC_SERVER) == false, "Managed to remove non-existing DHCPOPT_IRC_SERVER");

	PACKETPP_ASSERT(dhcpLayer->removeOption(DHCPOPT_DHCP_MAX_MESSAGE_SIZE) == true, "Couldn't remove DHCPOPT_DHCP_MAX_MESSAGE_SIZE");

	DhcpOptionData* opt = dhcpLayer->getOptionData(DHCPOPT_SUBNET_MASK);
	IPv4Address newSubnet(std::string("255.255.255.0"));
	opt->setValueIpAddr(newSubnet);

	PACKETPP_ASSERT(dhcpLayer->setMesageType(DHCP_ACK) == true, "Couldn't change message type");

	opt = dhcpLayer->addOptionAfter(DHCPOPT_ROUTERS, 4, NULL, DHCPOPT_SUBNET_MASK);
	PACKETPP_ASSERT(opt != NULL, "Couldn't add DHCPOPT_ROUTERS option");
	IPv4Address newRouter(std::string("192.168.2.1"));
	opt->setValueIpAddr(newRouter);

	opt = dhcpLayer->addOptionAfter(DHCPOPT_DHCP_SERVER_IDENTIFIER, 4, NULL, DHCPOPT_DHCP_MESSAGE_TYPE);
	PACKETPP_ASSERT(opt != NULL, "Couldn't add DHCPOPT_DHCP_SERVER_IDENTIFIER option");
	opt->setValueIpAddr(newRouter);

	dhcpPacket.computeCalculateFields();

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/Dhcp3.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file Dhcp3.dat");

	PACKETPP_ASSERT(buffer2Length == dhcpPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", dhcpPacket.getRawPacket()->getRawDataLen(), buffer2Length);
	PACKETPP_ASSERT(memcmp(dhcpPacket.getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Raw packet data is different than expected");

	delete [] buffer2;

	PACKETPP_ASSERT(dhcpLayer->removeAllOptions() == true, "Couldn't remove all options");

	PACKETPP_ASSERT(dhcpLayer->getOptionsCount() == 0, "Option count isn't 0 after removing all options");

	PACKETPP_ASSERT(dhcpLayer->getDataLen() == sizeof(dhcp_header), "DHCP layer data isn't sizeof(dhcp_header) after removing all options");

	PACKETPP_ASSERT(dhcpLayer->getMesageType() == DHCP_UNKNOWN_MSG_TYPE, "Managed to get message type after all options removed");

	PACKETPP_ASSERT(dhcpLayer->addOption(DHCPOPT_END, 0, NULL) != NULL, "Couldn't set DHCPOPT_END");

	PACKETPP_ASSERT(dhcpLayer->setMesageType(DHCP_UNKNOWN_MSG_TYPE) == false, "Managed to set message type to DHCP_UNKNOWN_MSG_TYPE");

	PACKETPP_ASSERT(dhcpLayer->setMesageType(DHCP_DISCOVER) == true, "Couldn't set message type to DHCP_DISCOVER");

	PACKETPP_ASSERT(dhcpLayer->getOptionsCount() == 2, "Option count isn't 2 after re-adding 2 options");

	PACKETPP_ASSERT(dhcpLayer->getDataLen() == sizeof(dhcp_header)+4, "DHCP layer data isn't sizeof(dhcp_header)+4 after re-adding 2 options");

	PACKETPP_ASSERT(dhcpLayer->getMesageType() == DHCP_DISCOVER, "Message type isn't DHCP_DISCOVER after re-adding options");

	dhcpPacket.computeCalculateFields();

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(NullLoopbackTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/NullLoopback1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file NullLoopback1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/NullLoopback2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file NullLoopback2.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true, LINKTYPE_NULL);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true, LINKTYPE_NULL);

	Packet nullPacket1(&rawPacket1);
	Packet nullPacket2(&rawPacket2);

	NullLoopbackLayer* nullLoopbackLayer;
	Layer* nextLayer;

	PACKETPP_ASSERT(nullPacket1.isPacketOfType(NULL_LOOPBACK) == true, "nullPacket1 isn't of type Null/Loopback");
	nullLoopbackLayer = nullPacket1.getLayerOfType<NullLoopbackLayer>();
	PACKETPP_ASSERT(nullLoopbackLayer != NULL, "Couldn't get null/loopback layer for nullPacket1");
	nextLayer = nullLoopbackLayer->getNextLayer();
	PACKETPP_ASSERT(nextLayer != NULL, "Couldn't get IPv6 layer");
	PACKETPP_ASSERT(nextLayer->getProtocol() == IPv6, "Next layer isn't of type IPv6");
	PACKETPP_ASSERT(nullLoopbackLayer->getFamily() == PCPP_BSD_AF_INET6_DARWIN, "nullPacket1: family isn't PCPP_BSD_AF_INET6_DARWIN");

	PACKETPP_ASSERT(nullPacket2.isPacketOfType(NULL_LOOPBACK) == true, "nullPacket2 isn't of type Null/Loopback");
	nullLoopbackLayer = nullPacket2.getLayerOfType<NullLoopbackLayer>();
	PACKETPP_ASSERT(nullLoopbackLayer != NULL, "Couldn't get null/loopback layer for nullPacket2");
	nextLayer = nullLoopbackLayer->getNextLayer();
	PACKETPP_ASSERT(nextLayer != NULL, "Couldn't get IPv4 layer");
	PACKETPP_ASSERT(nextLayer->getProtocol() == IPv4, "Next layer isn't of type IPv4");
	PACKETPP_ASSERT(((IPv4Layer*)nextLayer)->getSrcIpAddress() == IPv4Address(std::string("172.16.1.117")), "IPv4 src IP isn't 172.16.1.117");
	PACKETPP_ASSERT(nullLoopbackLayer->getFamily() == PCPP_BSD_AF_INET, "nullPacket1: family isn't PCPP_BSD_AF_INET");

	Packet newNullPacket(1);
	NullLoopbackLayer newNullLoopbackLayer(PCPP_BSD_AF_INET);
	IPv4Layer newIp4Layer(IPv4Address(std::string("172.16.1.117")), IPv4Address(std::string("172.16.1.255")));
	newIp4Layer.getIPv4Header()->ipId = htons(49513);
	newIp4Layer.getIPv4Header()->timeToLive = 64;

	UdpLayer newUdpLayer(55369, 8612);

	uint8_t payload[] = { 0x42, 0x4a, 0x4e, 0x42, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PayloadLayer newPayloadLayer(payload, 16, false);

	PACKETPP_ASSERT(newNullPacket.addLayer(&newNullLoopbackLayer) == true, "Couldn't add null/loopback layer");
	PACKETPP_ASSERT(newNullPacket.addLayer(&newIp4Layer) == true, "Couldn't add IPv4 layer");
	PACKETPP_ASSERT(newNullPacket.addLayer(&newUdpLayer) == true, "Couldn't add UDP layer");
	PACKETPP_ASSERT(newNullPacket.addLayer(&newPayloadLayer) == true, "Couldn't add payload layer");

	newNullPacket.computeCalculateFields();

	PACKETPP_ASSERT(buffer2Length == newNullPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", newNullPacket.getRawPacket()->getRawDataLen(), buffer2Length);
	PACKETPP_ASSERT(memcmp(newNullPacket.getRawPacket()->getRawData(), buffer2, buffer2Length) == 0, "Raw packet data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(IgmpParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IGMPv1_1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IGMPv1_1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IGMPv2_1.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IGMPv2_1.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet igmpv1Packet(&rawPacket1);
	Packet igmpv2Packet(&rawPacket2);

	PACKETPP_ASSERT(igmpv1Packet.isPacketOfType(IGMPv1) == true, "igmpv1Packet isn't of type IGMPv1");
	PACKETPP_ASSERT(igmpv1Packet.isPacketOfType(IGMP) == true, "igmpv1Packet isn't of type IGMP");
	PACKETPP_ASSERT(igmpv1Packet.isPacketOfType(IGMPv2) == false, "igmpv1Packet is of type IGMPv2");
	IgmpV1Layer* igmpv1Layer = igmpv1Packet.getLayerOfType<IgmpV1Layer>();
	PACKETPP_ASSERT(igmpv1Layer != NULL, "Couldn't get IGMPv1 layer for igmpv1Packet");

	PACKETPP_ASSERT(igmpv1Layer->getType() == IgmpType_MembershipQuery, "IGMPv1 type isn't membership query");
	PACKETPP_ASSERT(igmpv1Layer->getGroupAddress() == IPv4Address::Zero, "IGMPv1 group address isn't zero");
	PACKETPP_ASSERT(igmpv1Layer->toString() == "IGMPv1 Layer, Membership Query message", "IGMPv1 to string failed");

	PACKETPP_ASSERT(igmpv2Packet.isPacketOfType(IGMPv2) == true, "igmpv2Packet isn't of type IGMPv2");
	PACKETPP_ASSERT(igmpv2Packet.isPacketOfType(IGMP) == true, "igmpv2Packet isn't of type IGMP");
	PACKETPP_ASSERT(igmpv2Packet.isPacketOfType(IGMPv1) == false, "igmpv2Packet is of type IGMPv1");
	IgmpV2Layer* igmpv2Layer = igmpv2Packet.getLayerOfType<IgmpV2Layer>();
	PACKETPP_ASSERT(igmpv2Layer != NULL, "Couldn't get IGMPv2 layer for igmpv2Packet");

	PACKETPP_ASSERT(igmpv2Layer->getType() == IgmpType_MembershipReportV2, "IGMPv2 type isn't membership report");
	PACKETPP_ASSERT(igmpv2Layer->getGroupAddress() == IPv4Address(std::string("239.255.255.250")), "IGMPv2 group address isn't 239.255.255.250");
	PACKETPP_ASSERT(igmpv2Layer->toString() == "IGMPv2 Layer, Membership Report message", "IGMPv2 to string failed");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(IgmpCreateAndEditTest)
{
	MacAddress srcMac1(std::string("5c:d9:98:f9:1c:18"));
	MacAddress dstMac1(std::string("01:00:5e:00:00:01"));
	MacAddress srcMac2(std::string("00:15:58:dc:a8:4d"));
	MacAddress dstMac2(std::string("01:00:5e:7f:ff:fa"));
	EthLayer ethLayer1(srcMac1, dstMac1);
	EthLayer ethLayer2(srcMac2, dstMac2);

	IPv4Address srcIp1(std::string("10.0.200.151"));
	IPv4Address dstIp1(std::string("224.0.0.1"));
	IPv4Address srcIp2(std::string("10.60.2.7"));
	IPv4Address dstIp2(std::string("239.255.255.250"));
	IPv4Layer ipLayer1(srcIp1, dstIp1);
	IPv4Layer ipLayer2(srcIp2, dstIp2);

	ipLayer1.getIPv4Header()->ipId = htons(2);
	ipLayer1.getIPv4Header()->timeToLive = 1;
	ipLayer2.getIPv4Header()->ipId = htons(3655);
	ipLayer2.getIPv4Header()->timeToLive = 1;

	IgmpV1Layer igmpV1Layer(IgmpType_MembershipQuery);
	IgmpV2Layer igmpV2Layer(IgmpType_MembershipReportV2, IPv4Address(std::string("239.255.255.250")));

	Packet igmpv1Packet(1);
	igmpv1Packet.addLayer(&ethLayer1);
	igmpv1Packet.addLayer(&ipLayer1);
	igmpv1Packet.addLayer(&igmpV1Layer);
	igmpv1Packet.computeCalculateFields();
	ipLayer1.getIPv4Header()->headerChecksum = 0x3d72;

	Packet igmpv2Packet(1);
	igmpv2Packet.addLayer(&ethLayer2);
	igmpv2Packet.addLayer(&ipLayer2);
	igmpv2Packet.addLayer(&igmpV2Layer);
	igmpv2Packet.computeCalculateFields();
	ipLayer2.getIPv4Header()->headerChecksum = 0x541a;

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/IGMPv1_1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file IGMPv1_1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IGMPv2_1.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IGMPv2_1.dat");

	PACKETPP_ASSERT(buffer1Length-14 == igmpv1Packet.getRawPacket()->getRawDataLen(), "IGMPv1: Generated packet len (%d) is different than read packet len (%d)", igmpv1Packet.getRawPacket()->getRawDataLen(), buffer1Length);
	PACKETPP_ASSERT(memcmp(igmpv1Packet.getRawPacket()->getRawData(), buffer1, igmpv1Packet.getRawPacket()->getRawDataLen()) == 0, "IGMPv1: Raw packet data is different than expected");

	PACKETPP_ASSERT(buffer2Length-14 == igmpv2Packet.getRawPacket()->getRawDataLen(), "IGMPv2: Generated packet len (%d) is different than read packet len (%d)", igmpv2Packet.getRawPacket()->getRawDataLen(), buffer2Length);
	PACKETPP_ASSERT(memcmp(igmpv2Packet.getRawPacket()->getRawData(), buffer2, igmpv2Packet.getRawPacket()->getRawDataLen()) == 0, "IGMPv2: Raw packet data is different than expected");

	IgmpV1Layer* igmpLayer = igmpv1Packet.getLayerOfType<IgmpV1Layer>();
	igmpLayer->setType(IgmpType_MembershipReportV2);
	igmpLayer->setGroupAddress(IPv4Address(std::string("239.255.255.250")));
	igmpv1Packet.computeCalculateFields();

	PACKETPP_ASSERT(memcmp(igmpLayer->getData(), igmpV2Layer.getData(), igmpLayer->getHeaderLen()) == 0, "IGMPv1 edit: Raw data is different than expected");

	delete [] buffer1;
	delete [] buffer2;
	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Igmpv3ParsingTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/igmpv3_query.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file igmpv3_query.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/igmpv3_report.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file igmpv3_report.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet igmpv3QueryPacket(&rawPacket1);
	Packet igmpv3ReportPacket(&rawPacket2);

	PACKETPP_ASSERT(igmpv3QueryPacket.isPacketOfType(IGMPv3) == true, "igmpv3QueryPacket isn't of type IGMPv3");
	PACKETPP_ASSERT(igmpv3QueryPacket.isPacketOfType(IGMP) == true, "igmpv3QueryPacket isn't of type IGMP");
	PACKETPP_ASSERT(igmpv3QueryPacket.isPacketOfType(IGMPv2) == false, "igmpv3QueryPacket is of type IGMPv2");
	IgmpV3QueryLayer* igmpv3QueryLayer = igmpv3QueryPacket.getLayerOfType<IgmpV3QueryLayer>();
	PACKETPP_ASSERT(igmpv3QueryLayer != NULL, "Couldn't get IGMPv3 query layer for igmpv3QueryPacket");
	PACKETPP_ASSERT(igmpv3QueryLayer->getGroupAddress().toString() == "224.0.0.9", "Group address isn't 224.0.0.9");
	PACKETPP_ASSERT(igmpv3QueryLayer->getIgmpV3QueryHeader()->s_qrv == 0x0f, "s_qrv isn't 0x0f");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressCount() == 1, "Number of records isn't 1");
	PACKETPP_ASSERT(igmpv3QueryLayer->getHeaderLen() == 16, "query header len isn't 16");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(0).toString() == "192.168.20.222", "Source address at index 0 isn't 192.168.20.222");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(1).toString() == "0.0.0.0", "Source address at index 1 isn't zero");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(100).toString() == "0.0.0.0", "Source address at index 100 isn't zero");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(-1).toString() == "0.0.0.0", "Source address at index -1 isn't zero");
	PACKETPP_ASSERT(igmpv3QueryLayer->toString() == "IGMPv3 Layer, Membership Query message", "Query to string failed");

	igmpv3QueryLayer->getIgmpV3QueryHeader()->numOfSources = htons(100);

	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressCount() == 100, "Number of records after change isn't 100");
	PACKETPP_ASSERT(igmpv3QueryLayer->getHeaderLen() == 16, "query header len after change isn't 16");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(0).toString() == "192.168.20.222", "Source address at index 0 after change isn't 192.168.20.222");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(1).toString() == "0.0.0.0", "Source address at index 1 after change isn't zero");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(50).toString() == "0.0.0.0", "Source address at index 50 after change isn't zero");
	PACKETPP_ASSERT(igmpv3QueryLayer->getSourceAddressAtIndex(-1).toString() == "0.0.0.0", "Source address at index -1 after change isn't zero");


	PACKETPP_ASSERT(igmpv3ReportPacket.isPacketOfType(IGMPv3) == true, "igmpv3ReportPacket isn't of type IGMPv3");
	PACKETPP_ASSERT(igmpv3ReportPacket.isPacketOfType(IGMP) == true, "igmpv3ReportPacket isn't of type IGMP");
	PACKETPP_ASSERT(igmpv3ReportPacket.isPacketOfType(IGMPv1) == false, "igmpv3ReportPacket is of type IGMPv1");
	IgmpV3ReportLayer* igmpv3ReportLayer = igmpv3ReportPacket.getLayerOfType<IgmpV3ReportLayer>();
	PACKETPP_ASSERT(igmpv3ReportLayer != NULL, "Couldn't get IGMPv3 report layer for igmpv3ReportPacket");
	PACKETPP_ASSERT(igmpv3ReportLayer->getGroupRecordCount() == 1, "Number of records isn't 1");
	PACKETPP_ASSERT(igmpv3ReportLayer->getHeaderLen() == 20, "report header len isn't 20");
	igmpv3_group_record* curGroup = igmpv3ReportLayer->getFirstGroupRecord();
	PACKETPP_ASSERT(curGroup != NULL, "First record is null");
	PACKETPP_ASSERT(curGroup->recordType == 1, "First group type isn't 1");
	PACKETPP_ASSERT(curGroup->getMulticastAddress().toString() == "224.0.0.9", "Multicast address in first group isn't 224.0.0.9");
	PACKETPP_ASSERT(curGroup->getSourceAdressCount() == 1, "Num of source addresses in first group 1 isn't 1");
	PACKETPP_ASSERT(curGroup->getRecordLen() == 12, "First group len isn't 12");
	PACKETPP_ASSERT(curGroup->getSoruceAddressAtIndex(0).toString() == "192.168.20.222", "First address in first group isn't 192.168.20.222");
	PACKETPP_ASSERT(curGroup->getSoruceAddressAtIndex(-1).toString() == "0.0.0.0", "Address in index -1 in first group isn't 0.0.0.0");
	PACKETPP_ASSERT(curGroup->getSoruceAddressAtIndex(1).toString() == "0.0.0.0", "Address in index 1 in first group isn't 0.0.0.0");
	PACKETPP_ASSERT(curGroup->getSoruceAddressAtIndex(100).toString() == "0.0.0.0", "Address in index 100 in first group isn't 0.0.0.0");
	curGroup = igmpv3ReportLayer->getNextGroupRecord(curGroup);
	PACKETPP_ASSERT(curGroup == NULL, "Second record is not null");
	PACKETPP_ASSERT(igmpv3ReportLayer->toString() == "IGMPv3 Layer, Membership Report message", "Report to string failed");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Igmpv3QueryCreateAndEditTest)
{
	EthLayer ethLayer(MacAddress("00:01:01:00:00:01"), MacAddress("01:00:5e:00:00:09"));

	IPv4Address srcIp(std::string("127.0.0.1"));
	IPv4Address dstIp(std::string("224.0.0.9"));
	IPv4Layer ipLayer(srcIp, dstIp);

	ipLayer.getIPv4Header()->ipId = htons(36760);
	ipLayer.getIPv4Header()->timeToLive = 1;

	IPv4Address multicastAddr(std::string("224.0.0.11"));
	IgmpV3QueryLayer igmpV3QueryLayer(multicastAddr, 1, 0x0f);

	IPv4Address srcAddr1(std::string("192.168.20.222"));
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddress(srcAddr1) == true, "Couldn't add src addr 1");

	Packet igmpv3QueryPacket(33);
	igmpv3QueryPacket.addLayer(&ethLayer);
	igmpv3QueryPacket.addLayer(&ipLayer);
	igmpv3QueryPacket.addLayer(&igmpV3QueryLayer);

	IPv4Address srcAddr2(std::string("1.2.3.4"));
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddress(srcAddr2) == true, "Couldn't add src addr 2");

	IPv4Address srcAddr3(std::string("10.20.30.40"));
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr3, 0) == true, "Couldn't add src addr 3");

	IPv4Address srcAddr4(std::string("100.200.255.255"));

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, -1) == false, "Managed to add src addr at index -1");
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 4) == false, "Managed to add src addr at index 4");
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htons(100);
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 4) == false, "Managed to add src addr at index 4 2");
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htons(3);
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 2) == true, "Couldn't add src addr 4");

	IPv4Address srcAddr5(std::string("11.22.33.44"));
	PACKETPP_ASSERT(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr5, 4) == true, "Couldn't add src addr 5");

	igmpv3QueryPacket.computeCalculateFields();

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/igmpv3_query2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file igmpv3_query2.dat");

	PACKETPP_ASSERT(bufferLength == igmpv3QueryPacket.getRawPacket()->getRawDataLen(), "IGMPv3 query: Generated packet len (%d) is different than read packet len (%d)", igmpv3QueryPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(igmpv3QueryPacket.getRawPacket()->getRawData(), buffer, igmpv3QueryPacket.getRawPacket()->getRawDataLen()) == 0, "IGMPv3 query: Raw packet data is different than expected");

	delete[] buffer;

	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(4) == true, "Couldn't remove src addr at index 4");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(4) == false, "Managed to remove non-existing index 4");
	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(-1) == false, "Managed to remove non-existing index 4");
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htons(100);
	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(4) == false, "Managed to remove non-existing index 4 2");
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htons(4);
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(0) == true, "Couldn't remove src addr at index 0");
	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(1) == true, "Couldn't remove src addr at index 1");
	PACKETPP_ASSERT(igmpV3QueryLayer.removeSourceAddressAtIndex(1) == true, "Couldn't remove 2nd src addr at index 1");

	igmpV3QueryLayer.setGroupAddress(IPv4Address(std::string("224.0.0.9")));

	igmpv3QueryPacket.computeCalculateFields();

	ipLayer.getIPv4Header()->headerChecksum = 0x2d36;

	buffer = readFileIntoBuffer("PacketExamples/igmpv3_query.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file igmpv3_query.dat");

	PACKETPP_ASSERT(bufferLength == igmpv3QueryPacket.getRawPacket()->getRawDataLen(), "IGMPv3 query: Generated packet len (%d) is different than read packet len (%d)", igmpv3QueryPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(igmpv3QueryPacket.getRawPacket()->getRawData(), buffer, igmpv3QueryPacket.getRawPacket()->getRawDataLen()) == 0, "IGMPv3 query: Raw packet data after edit is different than expected");

	delete[] buffer;

	PACKETPP_ASSERT(igmpV3QueryLayer.removeAllSourceAddresses() == true, "Couldn't remove all source addresses");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(Igmpv3ReportCreateAndEditTest)
{
	EthLayer ethLayer(MacAddress("00:01:01:00:00:02"), MacAddress("01:00:5e:00:00:16"));

	IPv4Address srcIp(std::string("127.0.0.1"));
	IPv4Address dstIp(std::string("224.0.0.22"));
	IPv4Layer ipLayer(srcIp, dstIp);

	ipLayer.getIPv4Header()->ipId = htons(3941);
	ipLayer.getIPv4Header()->timeToLive = 1;

	IgmpV3ReportLayer igmpV3ReportLayer;

	std::vector<IPv4Address> srcAddrVec1;
	srcAddrVec1.push_back(IPv4Address(std::string("192.168.20.222")));
	igmpv3_group_record* groupRec = igmpV3ReportLayer.addGroupRecord(1, IPv4Address(std::string("224.0.0.9")), srcAddrVec1);
	PACKETPP_ASSERT(groupRec != NULL, "Group record is null for 1st group");
	PACKETPP_ASSERT(groupRec->getSoruceAddressAtIndex(0) == IPv4Address(std::string("192.168.20.222")), "Source addr in index 0 of 1st group isn't 192.168.20.222");

	std::vector<IPv4Address> srcAddrVec2;
	srcAddrVec2.push_back(IPv4Address(std::string("1.2.3.4")));
	srcAddrVec2.push_back(IPv4Address(std::string("11.22.33.44")));
	srcAddrVec2.push_back(IPv4Address(std::string("111.222.33.44")));
	groupRec = igmpV3ReportLayer.addGroupRecord(2, IPv4Address(std::string("4.3.2.1")), srcAddrVec2);
	PACKETPP_ASSERT(groupRec != NULL, "Group record is null for 2nd group");
	PACKETPP_ASSERT(groupRec->getSourceAdressCount() == 3, "Source addr count of 2nd group isn't 3");

	std::vector<IPv4Address> srcAddrVec3;
	srcAddrVec3.push_back(IPv4Address(std::string("12.34.56.78")));
	srcAddrVec3.push_back(IPv4Address(std::string("88.77.66.55")));
	srcAddrVec3.push_back(IPv4Address(std::string("44.33.22.11")));
	srcAddrVec3.push_back(IPv4Address(std::string("255.255.255.255")));
	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(3, IPv4Address(std::string("1.1.1.1")), srcAddrVec3, 0);
	PACKETPP_ASSERT(groupRec != NULL, "Group record is null for 3rd group");
	PACKETPP_ASSERT(groupRec->getRecordLen() == 24, "Group record len of 3rd group isn't 24");

	std::vector<IPv4Address> srcAddrVec4;
	srcAddrVec4.push_back(IPv4Address(std::string("13.24.57.68")));
	srcAddrVec4.push_back(IPv4Address(std::string("31.42.75.86")));

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(igmpV3ReportLayer.addGroupRecordAtIndex(4, IPv4Address(std::string("1.3.5.7")), srcAddrVec4, -1) == NULL, "Managed to add group record at index -1");
	PACKETPP_ASSERT(igmpV3ReportLayer.addGroupRecordAtIndex(4, IPv4Address(std::string("1.3.5.7")), srcAddrVec4, 4) == NULL, "Managed to add group record at index 4");
	PACKETPP_ASSERT(igmpV3ReportLayer.addGroupRecordAtIndex(4, IPv4Address(std::string("1.3.5.7")), srcAddrVec4, 100) == NULL, "Managed to add group record at index 100");
	LoggerPP::getInstance().enableErrors();

	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(4, IPv4Address(std::string("1.3.5.7")), srcAddrVec4, 1);
	PACKETPP_ASSERT(groupRec != NULL, "Group record is null for 4th group");
	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(5, IPv4Address(std::string("2.4.6.8")), srcAddrVec4, 4);
	PACKETPP_ASSERT(groupRec != NULL, "Group record is null for 5th group");


	Packet igmpv3ReportPacket;
	igmpv3ReportPacket.addLayer(&ethLayer);
	igmpv3ReportPacket.addLayer(&ipLayer);
	igmpv3ReportPacket.addLayer(&igmpV3ReportLayer);

	igmpv3ReportPacket.computeCalculateFields();

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/igmpv3_report2.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file igmpv3_report2.dat");

	PACKETPP_ASSERT(bufferLength == igmpv3ReportPacket.getRawPacket()->getRawDataLen(), "IGMPv3 report: Generated packet len (%d) is different than read packet len (%d)", igmpv3ReportPacket.getRawPacket()->getRawDataLen(), bufferLength);
	PACKETPP_ASSERT(memcmp(igmpv3ReportPacket.getRawPacket()->getRawData(), buffer, igmpv3ReportPacket.getRawPacket()->getRawDataLen()) == 0, "IGMPv3 report: Raw packet data is different than expected");

	delete[] buffer;


	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(4) == true, "Couldn't remove group record at index 4");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(4) == false, "Managed to remove group record at index 4 which is out of bounds");
	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(-1) == false, "Managed to remove group record at index -1 which is out of bounds");
	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(100) == false, "Managed to remove group record at index 100 which is out of bounds");
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(0) == true, "Couldn't remove group record at index 0");
	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(2) == true, "Couldn't remove group record at index 2");
	PACKETPP_ASSERT(igmpV3ReportLayer.removeGroupRecordAtIndex(0) == true, "Couldn't remove second group record at index 0");

	buffer = readFileIntoBuffer("PacketExamples/igmpv3_report.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file igmpv3_report.dat");

	PACKETPP_ASSERT(bufferLength == igmpv3ReportPacket.getRawPacket()->getRawDataLen(), "IGMPv3 report edit: Generated packet len (%d) is different than read packet len (%d)", igmpv3ReportPacket.getRawPacket()->getRawDataLen(), bufferLength);

	igmpv3ReportPacket.computeCalculateFields();
	ipLayer.getIPv4Header()->headerChecksum = 0x4fb6;

	PACKETPP_ASSERT(memcmp(igmpv3ReportPacket.getRawPacket()->getRawData(), buffer, igmpv3ReportPacket.getRawPacket()->getRawDataLen()) == 0, "IGMPv3 report edit: Raw packet data after edit is different than expected");

	delete[] buffer;

	PACKETPP_ASSERT(igmpV3ReportLayer.removeAllGroupRecords() == true, "Couldn't remove all group records");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(ParsePartialPacketTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/SSL-ClientHello1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file SSL-ClientHello1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/IGMPv1_1.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file IGMPv1_1.dat.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/TwoHttpRequests1.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file TwoHttpRequests1.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/PPPoESession2.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file PPPoESession2.dat");

	int buffer5Length = 0;
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/TwoHttpRequests2.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file TwoHttpRequests2.dat");

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/IcmpTimestampRequest.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file IcmpTimestampRequest.dat");

	int buffer7Length = 0;
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/GREv0_2.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file GREv0_2.dat");


	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);
	RawPacket rawPacket6((const uint8_t*)buffer6, buffer6Length, time, true);
	RawPacket rawPacket7((const uint8_t*)buffer7, buffer7Length, time, true);

	Packet sslPacket(&rawPacket1, TCP);
	Packet igmpPacket(&rawPacket2, IP);
	Packet httpPacket(&rawPacket3, OsiModelTransportLayer);
	Packet pppoePacket(&rawPacket4, OsiModelDataLinkLayer);
	Packet httpPacket2(&rawPacket5, OsiModelPresentationLayer);
	Packet icmpPacket(&rawPacket6, OsiModelNetworkLayer);
	Packet grePacket(&rawPacket7, GRE);

	PACKETPP_ASSERT(sslPacket.isPacketOfType(IPv4) == true, "ssl packet isn't of type IPv4");
	PACKETPP_ASSERT(sslPacket.isPacketOfType(TCP) == true, "ssl packet isn't of type TCP");
	PACKETPP_ASSERT(sslPacket.isPacketOfType(SSL) == false, "ssl packet is of type SSL");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for ssl packet");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<IPv4Layer>() != NULL, "couldn't fetch IPv4 layer for ssl packet");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<TcpLayer>() != NULL, "couldn't fetch TCP layer for ssl packet");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<TcpLayer>()->getNextLayer() == NULL, "layer after TCP layer isn't NULL for ssl packet");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<SSLHandshakeLayer>() == NULL, "managed to fetch SSL layer for ssl packet");
	PACKETPP_ASSERT(sslPacket.getLayerOfType<PayloadLayer>() == NULL, "managed to fetch generic payload layer for ssl packet");

	PACKETPP_ASSERT(igmpPacket.isPacketOfType(IPv4) == true, "igmp packet isn't of type IPv4");
	PACKETPP_ASSERT(igmpPacket.isPacketOfType(Ethernet) == true, "igmp packet isn't of type Ethernet");
	PACKETPP_ASSERT(igmpPacket.isPacketOfType(IGMP) == false, "igmp packet is of type IGMP");
	PACKETPP_ASSERT(igmpPacket.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for igmp packet");
	PACKETPP_ASSERT(igmpPacket.getLayerOfType<IPv4Layer>() != NULL, "couldn't fetch IPv4 layer for igmp packet");
	PACKETPP_ASSERT(igmpPacket.getLayerOfType<IgmpV1Layer>() == NULL, "managed to fetch IGMPv1 layer for igmp packet");
	PACKETPP_ASSERT(igmpPacket.getLayerOfType<PayloadLayer>() == NULL, "managed to fetch generic payload layer for igmp packet");

	PACKETPP_ASSERT(httpPacket.isPacketOfType(IPv4) == true, "http packet isn't of type IPv4");
	PACKETPP_ASSERT(httpPacket.isPacketOfType(Ethernet) == true, "http packet isn't of type Ethernet");
	PACKETPP_ASSERT(httpPacket.isPacketOfType(TCP) == true, "http packet isn't of type TCP");
	PACKETPP_ASSERT(httpPacket.isPacketOfType(HTTP) == false, "http packet is of type HTTP");
	PACKETPP_ASSERT(httpPacket.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for http packet");
	PACKETPP_ASSERT(httpPacket.getLayerOfType<IPv4Layer>() != NULL, "couldn't fetch IPv4 layer for http packet");
	PACKETPP_ASSERT(httpPacket.getLayerOfType<TcpLayer>() != NULL, "couldn't fetch TCP layer for http packet");
	PACKETPP_ASSERT(httpPacket.getLayerOfType<HttpRequestLayer>() == NULL, "managed to fetch HTTP request layer for http packet");
	PACKETPP_ASSERT(httpPacket.getLayerOfType<PayloadLayer>() == NULL, "managed to fetch generic payload layer for http packet");

	PACKETPP_ASSERT(pppoePacket.isPacketOfType(Ethernet) == true, "pppoe packet isn't of type Ethernet");
	PACKETPP_ASSERT(pppoePacket.isPacketOfType(PPPoESession) == true, "pppoe packet isn't of type PPPoE");
	PACKETPP_ASSERT(pppoePacket.isPacketOfType(IPv6) == false, "pppoe packet is of type IPv6");
	PACKETPP_ASSERT(pppoePacket.isPacketOfType(UDP) == false, "pppoe packet is of type UDP");
	PACKETPP_ASSERT(pppoePacket.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for pppoe packet");
	PACKETPP_ASSERT(pppoePacket.getLayerOfType<PPPoESessionLayer>() != NULL, "couldn't fetch PPPoE session layer for pppoe packet");
	PACKETPP_ASSERT(pppoePacket.getLayerOfType<IPv6Layer>() == NULL, "managed to fetch IPv6 layer for pppoe packet");

	PACKETPP_ASSERT(httpPacket2.isPacketOfType(IPv4) == true, "http2 packet isn't of type IPv4");
	PACKETPP_ASSERT(httpPacket2.isPacketOfType(Ethernet) == true, "http2 packet isn't of type Ethernet");
	PACKETPP_ASSERT(httpPacket2.isPacketOfType(TCP) == true, "http2 packet isn't of type TCP");
	PACKETPP_ASSERT(httpPacket2.isPacketOfType(HTTP) == false, "http2 packet is of type HTTP");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<IPv4Layer>() != NULL, "couldn't fetch IPv4 layer for http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<TcpLayer>() != NULL, "couldn't fetch TCP layer for http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<TcpLayer>()->getNextLayer() == NULL, "Next layer for TCP isn't NULL in http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLastLayer()->getProtocol() == TCP, "TCP isn't the last layer for http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<HttpRequestLayer>() == NULL, "managed to fetch HTTP request layer for http2 packet");
	PACKETPP_ASSERT(httpPacket2.getLayerOfType<PayloadLayer>() == NULL, "managed to fetch generic payload layer for http2 packet");

	PACKETPP_ASSERT(icmpPacket.isPacketOfType(IPv4) == true, "icmp packet isn't of type IPv4");
	PACKETPP_ASSERT(icmpPacket.isPacketOfType(Ethernet) == true, "icmp packet isn't of type Ethernet");
	PACKETPP_ASSERT(icmpPacket.isPacketOfType(ICMP) == true, "icmp packet isn't of type ICMP");
	PACKETPP_ASSERT(icmpPacket.getLayerOfType<EthLayer>() != NULL, "couldn't fetch Eth layer for icmp packet");
	PACKETPP_ASSERT(icmpPacket.getLayerOfType<IPv4Layer>() != NULL, "couldn't fetch IPv4 layer for icmp packet");
	PACKETPP_ASSERT(icmpPacket.getLayerOfType<IcmpLayer>() != NULL, "couldn't fetch ICMP layer for icmp packet");

	PACKETPP_ASSERT(grePacket.isPacketOfType(Ethernet) == true, "gre packet isn't of type Ethernet");
	PACKETPP_ASSERT(grePacket.isPacketOfType(IPv4) == true, "gre packet isn't of type IPv4");
	PACKETPP_ASSERT(grePacket.isPacketOfType(GREv0) == true, "gre packet isn't of type GREv0");
	PACKETPP_ASSERT(grePacket.isPacketOfType(UDP) == false, "gre packet is of type UDP");
	Layer* curLayer = grePacket.getFirstLayer();
	PACKETPP_ASSERT(curLayer != NULL && curLayer->getProtocol() == Ethernet, "gre first layer isn't Ethernet");
	curLayer = curLayer->getNextLayer();
	PACKETPP_ASSERT(curLayer != NULL && curLayer->getProtocol() == IPv4, "gre second layer isn't IPv4");
	curLayer = curLayer->getNextLayer();
	PACKETPP_ASSERT(curLayer != NULL && curLayer->getProtocol() == GREv0, "gre third layer isn't GRE");
	curLayer = curLayer->getNextLayer();
	PACKETPP_ASSERT(curLayer == NULL, "found fourth layer for gre packet");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(VxlanParsingAndCreationTest)
{
	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/Vxlan1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file Vxlan1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/Vxlan2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file Vxlan2.dat");

	timeval time;
	gettimeofday(&time, NULL);
	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet vxlanPacket(&rawPacket1);

	// test vxlan parsing
	VxlanLayer* vxlanLayer = vxlanPacket.getLayerOfType<VxlanLayer>();
	PACKETPP_ASSERT(vxlanLayer != NULL, "VXLAN layer doesn't exist");
	PACKETPP_ASSERT(vxlanLayer->getVNI() == 3000001, "VNI isn't 3000001");
	PACKETPP_ASSERT(vxlanLayer->getVxlanHeader()->groupPolicyID == htons(100), "Group policy ID isn't 100");
	PACKETPP_ASSERT(vxlanLayer->getVxlanHeader()->dontLearnFlag == 1, "Don't learn flag isn't set");
	PACKETPP_ASSERT(vxlanLayer->getVxlanHeader()->gbpFlag == 1, "GBP flag isn't set");
	PACKETPP_ASSERT(vxlanLayer->getVxlanHeader()->vniPresentFlag == 1, "VNI present flag isn't set");
	PACKETPP_ASSERT(vxlanLayer->getVxlanHeader()->policyAppliedFlag == 1, "Policy applied flag isn't set");
	PACKETPP_ASSERT(vxlanLayer->getNextLayer() != NULL, "Layer next to VXLAN is NULL");
	PACKETPP_ASSERT(vxlanLayer->getNextLayer()->getProtocol() == Ethernet, "Layer next to VXLAN isn't Ethernet");

	// edit vxlan fields
	vxlanLayer->getVxlanHeader()->gbpFlag = 0;
	vxlanLayer->getVxlanHeader()->dontLearnFlag = 0;
	vxlanLayer->getVxlanHeader()->groupPolicyID = htons(32639);
	vxlanLayer->setVNI(300);

	vxlanPacket.computeCalculateFields();

	// verify edited fields
	PACKETPP_ASSERT(buffer2Length == vxlanPacket.getRawPacket()->getRawDataLen(), "Edited packet len (%d) is different than read packet len (%d)", vxlanPacket.getRawPacket()->getRawDataLen(), buffer2Length);
	PACKETPP_ASSERT(memcmp(vxlanPacket.getRawPacket()->getRawData(), buffer2, vxlanPacket.getRawPacket()->getRawDataLen()) == 0, "Edited raw packet data after edit is different than expected");

	// remove vxlan layer
	PACKETPP_ASSERT(vxlanPacket.removeLayer(vxlanLayer) == true, "Couldn't remove vxlan layer");
	vxlanPacket.computeCalculateFields();

	// create new vxlan layer
	VxlanLayer newVxlanLayer(3000001, 100, true, true, true);
	PACKETPP_ASSERT(vxlanPacket.insertLayer(vxlanPacket.getLayerOfType<UdpLayer>(), &newVxlanLayer) == true, "Couldn't insert new vxlan layer");

	// verify new vxlan layer
	PACKETPP_ASSERT(buffer1Length == vxlanPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", vxlanPacket.getRawPacket()->getRawDataLen(), buffer1Length);
	PACKETPP_ASSERT(memcmp(vxlanPacket.getRawPacket()->getRawData(), buffer1, vxlanPacket.getRawPacket()->getRawDataLen()) == 0, "Generated raw packet data after edit is different than expected");

	delete [] buffer2;

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SipRequestLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/sip_req1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file sip_req1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/sip_req2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file sip_req2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/sip_req3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file sip_req3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/sip_req4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file sip_req4.dat");

	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet sipReqPacket1(&rawPacket1);
	Packet sipReqPacket2(&rawPacket2);
	Packet sipReqPacket3(&rawPacket3);
	Packet sipReqPacket4(&rawPacket4);

	PACKETPP_ASSERT(sipReqPacket1.isPacketOfType(SIP) == true, "sipReqPacket1 isn't of type SIP");
	PACKETPP_ASSERT(sipReqPacket1.isPacketOfType(SIPRequest) == true, "sipReqPacket1 isn't of type SIP request");

	PACKETPP_ASSERT(sipReqPacket2.isPacketOfType(SIP) == true, "sipReqPacket2 isn't of type SIP");
	PACKETPP_ASSERT(sipReqPacket2.isPacketOfType(SIPRequest) == true, "sipReqPacket2 isn't of type SIP request");

	PACKETPP_ASSERT(sipReqPacket3.isPacketOfType(SIP) == true, "sipReqPacket3 isn't of type SIP");
	PACKETPP_ASSERT(sipReqPacket3.isPacketOfType(SIPRequest) == true, "sipReqPacket3 isn't of type SIP request");

	PACKETPP_ASSERT(sipReqPacket4.isPacketOfType(SIP) == true, "sipReqPacket4 isn't of type SIP");
	PACKETPP_ASSERT(sipReqPacket4.isPacketOfType(SIPRequest) == true, "sipReqPacket4 isn't of type SIP request");

	SipRequestLayer* sipReqLayer = sipReqPacket1.getLayerOfType<SipRequestLayer>();

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getMethod() == SipRequestLayer::SipINVITE, "SIP request1: method isn't INVITE, it's %d", sipReqLayer->getFirstLine()->getMethod());
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getUri() == "sip:francisco@bestel.com:55060", "SIP request1: URI is not as expected");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP request1: version is not as expected");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getSize() == 47, "SIP request1: first line size isn't 47");

	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD) != NULL, "SIP request1: Cannot find field 'From'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->getFieldValue() == "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", "SIP request1: Value of 'From' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD) != NULL, "SIP request1: Cannot find field 'Contact'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD, 1) == NULL, "SIP request1: Found second instance of field 'Contact'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD)->getFieldValue() == "<sip:200.57.7.195:5060>", "SIP request1: Value of 'From' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD) != NULL, "SIP request1: Cannot find field 'Via'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->getFieldValue() == "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290", "SIP request1: Value of first 'Via' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1) != NULL, "SIP request1: Cannot find second field 'Via'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->getFieldValue() == "SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0", "SIP request1: Value of second 'Via' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 2) == NULL, "SIP request1: Found third instance of field 'Via'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 100) == NULL, "SIP request1: Found 101 instance of field 'Via'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName("BlaBla") == NULL, "SIP request1: Found a field which doesn't exist");
	PACKETPP_ASSERT(sipReqLayer->getFieldCount() == 9, "SIP request1: Field count isn't 9");

	PACKETPP_ASSERT(sipReqLayer->getFirstField()->getFieldName() == "Via", "SIP request1: First field isn't 'Via'");

	PACKETPP_ASSERT(sipReqLayer->getHeaderLen() == 469, "SIP request1: Header len isn't 469, it's %d", (int)sipReqLayer->getHeaderLen());
	PACKETPP_ASSERT(sipReqLayer->getLayerPayloadSize() == 229, "SIP request1: Layer payload size isn't 229, its %d", (int)sipReqLayer->getLayerPayloadSize());
	PACKETPP_ASSERT(sipReqLayer->getContentLength() == 229, "SIP request1: Content length isn't 229");


	sipReqLayer = sipReqPacket2.getLayerOfType<SipRequestLayer>();

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getMethod() == SipRequestLayer::SipCANCEL, "SIP request2: method isn't CANCEL, it's %d", sipReqLayer->getFirstLine()->getMethod());
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getUri() == "sip:echo@iptel.org", "SIP request2: URI is not as expected");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getSize() == 35, "SIP request2: first line size isn't 35");

	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD) != NULL, "SIP request2: Cannot find field 'Max-Forwards'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->getFieldValue() == "70", "SIP request2: Value of 'Max-Forwards' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD))->isEndOfHeader() == true, "SIP request2: field after 'Max-Forwards' isn't marked as end of header");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD) != NULL, "SIP request2: Cannot find field 'CSeq'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->getFieldValue() == "2 CANCEL", "SIP request2: Value of 'CSeq' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD) != NULL, "SIP request2: Cannot find field 'To'");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD)->getFieldValue() == "<sip:echo@iptel.org>", "SIP request2: Value of 'To' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD, 2) == NULL, "SIP request2: mistkaely found a second 'To' field");
	PACKETPP_ASSERT(sipReqLayer->isHeaderComplete() == true, "SIP request2: header is not complete");


	sipReqLayer = sipReqPacket3.getLayerOfType<SipRequestLayer>();

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getMethod() == SipRequestLayer::SipACK, "SIP request3: method isn't ACK, it's %d", sipReqLayer->getFirstLine()->getMethod());
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getUri() == "sip:admind@178.45.73.241", "SIP request3: URI is not as expected");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getSize() == 38, "SIP request3: first line size isn't 38, it's %d", sipReqLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipReqLayer->isHeaderComplete() == false, "SIP request3: header marked as complete");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1) != NULL, "SIP request3: Cannot find second 'Via' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->getFieldValue() == "SIP/2.0/UDP 213.192.59.78:5080;rport=5080;branch=z9hG4bKjBiNGaOX", "SIP request3: Value of second 'Via' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD) != NULL, "SIP request3: Cannot find 'CAll-ID' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD)->getFieldValue() == "2091060b-146f-e011-809a-0019cb53db77@admind-desktop", "SIP request3: Value of 'Call-ID' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName("P-hint") != NULL, "SIP request3: Cannot find 'P-hint' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName("P-hint")->getFieldValue() == "rr-enforced", "SIP request3: Value of 'P-hint' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getNextField(sipReqLayer->getFieldByName("P-hint")) == NULL, "SIP request3: field next of 'P-hint' isn't NULL");
	PACKETPP_ASSERT(sipReqLayer->getContentLength() == 0, "SIP request3: Content length isn't 0");
	PACKETPP_ASSERT(sipReqLayer->getFieldCount() == 9, "SIP request3: Field count isn't 9");


	sipReqLayer = sipReqPacket4.getLayerOfType<SipRequestLayer>();

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getMethod() == SipRequestLayer::SipBYE, "SIP request4: method isn't BYE, it's %d", sipReqLayer->getFirstLine()->getMethod());
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getUri() == "sip:sipp@10.0.2.20:5060", "SIP request4: URI is not as expected");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->getSize() == 37, "SIP request4: first line size isn't 37, it's %d", sipReqLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipReqLayer->isHeaderComplete() == false, "SIP request4: header marked as complete");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_USER_AGENT_FIELD) != NULL, "SIP request4: Cannot find 'User-Agent' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_USER_AGENT_FIELD)->getFieldValue() == "FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit", "SIP request4: Value of 'User-Agent' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD) != NULL, "SIP request4: Cannot find 'Reason' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD)->getFieldValue() == "Q.850;cause=16;text=\"NORMAL_CLEARING\"", "SIP request4: Value of 'Reason' is different than expected");
	PACKETPP_ASSERT(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD))->getFieldName() == "Content-Lengt", "SIP request4: name of last malformed field isn't as expected");
	PACKETPP_ASSERT(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD))->getFieldValue() == "", "SIP request4: value of last malformed field isn't empty");
	PACKETPP_ASSERT(sipReqLayer->getFieldCount() == 11, "SIP request4: Field count isn't 11");
//
//	for (HeaderField* field = sipReqLayer->getFirstField(); field != NULL; field = sipReqLayer->getNextField(field))
//	{
//		printf("!!!%s!!!: !!!%s!!!\n", field->getFieldName().c_str(), field->getFieldValue().c_str());
//	}

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SipRequestLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/sip_req1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file sip_req1.dat");

	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet sipReqSamplePacket(&rawPacket1);

	Packet newSipPacket;

	EthLayer ethLayer(*sipReqSamplePacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Layer ip4Layer;
	ip4Layer = *(sipReqSamplePacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	UdpLayer udpLayer = *(sipReqSamplePacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&udpLayer), "Adding UDP layer failed");

	SipRequestLayer sipReqLayer(SipRequestLayer::SipINVITE, "sip:francisco@bestel.com:55060");

	PACKETPP_ASSERT(sipReqLayer.addField(PCPP_SIP_CALL_ID_FIELD, "12013223@200.57.7.195") != NULL, "Couldn't add 'Call-ID' field");
	PACKETPP_ASSERT(sipReqLayer.addField(PCPP_SIP_CONTENT_TYPE_FIELD, "application/sdp") != NULL, "Couldn't add 'Content-Type' field");
	PACKETPP_ASSERT(sipReqLayer.addEndOfHeader(), "Couldn't add end-of-header field");
	PACKETPP_ASSERT(sipReqLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0") != NULL, "Couldn't add 2nd 'Via' field");
	PACKETPP_ASSERT(sipReqLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290") != NULL, "Couldn't add 1st 'Via' field");
	HeaderField* callIDField = sipReqLayer.getFieldByName(PCPP_SIP_CALL_ID_FIELD);
	PACKETPP_ASSERT(callIDField != NULL, "Couldn't find 'Call-ID' field");
	HeaderField* newField = sipReqLayer.insertField(callIDField, PCPP_SIP_CSEQ_FIELD, "1 INVITE");
	PACKETPP_ASSERT(newField != NULL, "Couldn't add 'CSeq' field");
	newField = sipReqLayer.insertField(newField, PCPP_SIP_CONTACT_FIELD, "<sip:200.57.7.195:5060>");
	PACKETPP_ASSERT(newField != NULL, "Couldn't add 'Contact' field");
	HeaderField* secondViaField = sipReqLayer.getFieldByName(PCPP_SIP_VIA_FIELD, 0);
	PACKETPP_ASSERT(secondViaField != NULL, "Couldn't find second 'Via' field");
	newField = sipReqLayer.insertField(secondViaField, PCPP_SIP_FROM_FIELD, "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34");
	PACKETPP_ASSERT(newField != NULL, "Couldn't add 'From' field");
	newField = sipReqLayer.insertField(newField, PCPP_SIP_TO_FIELD, "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>");
	PACKETPP_ASSERT(newField != NULL, "Couldn't add 'To' field");
	HeaderField* contentLengthField = sipReqLayer.setContentLength(229, PCPP_SIP_CONTENT_TYPE_FIELD);
	PACKETPP_ASSERT(contentLengthField != NULL, "Couldn't set content length");
	contentLengthField->setFieldValue("  229");


	PACKETPP_ASSERT(newSipPacket.addLayer(&sipReqLayer), "Adding SIP request layer failed");

	SipRequestLayer* samplePacketSipLayer = sipReqSamplePacket.getLayerOfType<SipRequestLayer>();
	PayloadLayer payloadLayer(samplePacketSipLayer->getLayerPayload(), samplePacketSipLayer->getLayerPayloadSize(), true);
	PACKETPP_ASSERT(newSipPacket.addLayer(&payloadLayer), "Adding SDP data failed");

	newSipPacket.computeCalculateFields();

	PACKETPP_ASSERT(buffer1Length == newSipPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", newSipPacket.getRawPacket()->getRawDataLen(), buffer1Length);
	PACKETPP_ASSERT(memcmp(newSipPacket.getRawPacket()->getRawData(), buffer1, newSipPacket.getRawPacket()->getRawDataLen()) == 0, "Generated raw packet data after edit is different than expected");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SipRequestLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/sip_req2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file sip_req2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/sip_req3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file sip_req3.dat");

	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);

	Packet secondSipPacket(&rawPacket2);
	Packet editedPacket(&rawPacket3);

	SipRequestLayer* sipReqLayer = editedPacket.getLayerOfType<SipRequestLayer>();

	PACKETPP_ASSERT(sipReqLayer != NULL, "Cannot find SIP request layer");

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setMethod(SipRequestLayer::SipBYE) == true, "Couldn't set method to BYE");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setMethod(SipRequestLayer::SipREGISTER) == true, "Couldn't set method to REGISTER");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setMethod(SipRequestLayer::SipCANCEL) == true, "Couldn't set method to CANCEL");

	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setUri("sip:francisco@bestel.com:55060") == true, "Couldn't set URI - 1st change");
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setUri("sip:echo@iptel.org") == true, "Couldn't set URI - 2nd change");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(sipReqLayer->getFirstLine()->setUri("") == false, "Managed to set an empty URL");
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->setFieldValue("SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bKb26f2c0b-146f-e011-809a-0019cb53db77;rport") == true,
			"Couldn't change the value of 2nd 'Via' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->setFieldValue("70") == true, "Couldn't change the value of 2nd 'Max-Forwards' field");
	PACKETPP_ASSERT(sipReqLayer->removeField(PCPP_SIP_VIA_FIELD, 0) == true, "Couldn't remove 1st 'Via' field");
	PACKETPP_ASSERT(sipReqLayer->removeField(PCPP_SIP_RECORD_ROUTE_FIELD) == true, "Couldn't remove 'Record-Route' field");
	PACKETPP_ASSERT(sipReqLayer->removeField("P-hint") == true, "Couldn't remove 'P-hint' field");
	PACKETPP_ASSERT(sipReqLayer->addEndOfHeader() != NULL, "Couldn't add end-of-header");
	PACKETPP_ASSERT(sipReqLayer->setContentLength(0, PCPP_SIP_TO_FIELD) != NULL, "Cannot set content-length field");
	PACKETPP_ASSERT(sipReqLayer->removeField(PCPP_SIP_CALL_ID_FIELD) == true, "Couldn't remove 'Call-ID' field");
	PACKETPP_ASSERT(sipReqLayer->removeField(PCPP_SIP_CSEQ_FIELD) == true, "Couldn't remove 'CSeq' field");
	PACKETPP_ASSERT(sipReqLayer->insertField(PCPP_SIP_FROM_FIELD, PCPP_SIP_CALL_ID_FIELD, "2091060b-146f-e011-809a-0019cb53db77@admind-desktop") != NULL, "Couldn't re-add 'Call-ID' field");
	PACKETPP_ASSERT(sipReqLayer->insertField("", PCPP_SIP_CSEQ_FIELD, "2 CANCEL") != NULL, "Couldn't re-add 'CSeq' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->setFieldValue("\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77") == true, "Couldn't change the value of 'From' field");
	PACKETPP_ASSERT(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD)->setFieldValue("<sip:echo@iptel.org>") == true, "Couldn't change the value of 'To' field");

	editedPacket.computeCalculateFields();

	SipRequestLayer* secondSipReqLayer = secondSipPacket.getLayerOfType<SipRequestLayer>();
	secondSipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->setFieldValue(" 70");

	PACKETPP_ASSERT(secondSipReqLayer->getHeaderLen() == sipReqLayer->getHeaderLen(), "Edited layer len (%d) isn't as expected (%d)", (int)sipReqLayer->getHeaderLen(), (int)secondSipReqLayer->getHeaderLen());
	PACKETPP_ASSERT(secondSipReqLayer->getFirstLine()->getSize() == sipReqLayer->getFirstLine()->getSize(), "Edited first line length (%d) isn't as expected (%d)", sipReqLayer->getFirstLine()->getSize(), secondSipReqLayer->getFirstLine()->getSize());
	PACKETPP_ASSERT(secondSipReqLayer->getFirstLine()->getMethod() == sipReqLayer->getFirstLine()->getMethod(), "Method of edited packet is different than expected");
	PACKETPP_ASSERT(secondSipReqLayer->getFirstLine()->getUri() == sipReqLayer->getFirstLine()->getUri(), "URI of edited packet is different than expected");
	PACKETPP_ASSERT(secondSipReqLayer->getFirstLine()->getVersion() == sipReqLayer->getFirstLine()->getVersion(), "Version of edited packet is different than expected");
	PACKETPP_ASSERT(secondSipReqLayer->getFieldCount() == sipReqLayer->getFieldCount(), "Number of header fields in edited packet is not as expected");
	PACKETPP_ASSERT(memcmp(secondSipReqLayer->getData(), sipReqLayer->getData(), secondSipReqLayer->getHeaderLen()) == 0, "Edited raw data is different than expected");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(SipResponseLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/sip_resp1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file sip_resp1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/sip_resp2.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file sip_resp2.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/sip_resp3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file sip_resp3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/sip_resp4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file sip_resp4.dat");

	int buffer7Length = 0;
	uint8_t* buffer7 = readFileIntoBuffer("PacketExamples/sip_resp7.dat", buffer7Length);
	PACKETPP_ASSERT(!(buffer7 == NULL), "cannot read file sip_resp7.dat");

	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket7((const uint8_t*)buffer7, buffer7Length, time, true);

	Packet sipRespPacket1(&rawPacket1);
	Packet sipRespPacket2(&rawPacket2);
	Packet sipRespPacket3(&rawPacket3);
	Packet sipRespPacket4(&rawPacket4);
	Packet sipRespPacket7(&rawPacket7);

	PACKETPP_ASSERT(sipRespPacket1.isPacketOfType(SIP) == true, "sipRespPacket1 isn't of type SIP");
	PACKETPP_ASSERT(sipRespPacket1.isPacketOfType(SIPResponse) == true, "sipRespPacket1 isn't of type SIP response");

	PACKETPP_ASSERT(sipRespPacket2.isPacketOfType(SIP) == true, "sipRespPacket2 isn't of type SIP");
	PACKETPP_ASSERT(sipRespPacket2.isPacketOfType(SIPResponse) == true, "sipRespPacket2 isn't of type SIP response");

	PACKETPP_ASSERT(sipRespPacket3.isPacketOfType(SIP) == true, "sipRespPacket3 isn't of type SIP");
	PACKETPP_ASSERT(sipRespPacket3.isPacketOfType(SIPResponse) == true, "sipRespPacket3 isn't of type SIP response");

	PACKETPP_ASSERT(sipRespPacket4.isPacketOfType(SIP) == true, "sipRespPacket4 isn't of type SIP");
	PACKETPP_ASSERT(sipRespPacket4.isPacketOfType(SIPResponse) == true, "sipRespPacket4 isn't of type SIP response");

	PACKETPP_ASSERT(sipRespPacket7.isPacketOfType(SIP) == true, "sipRespPacket7 isn't of type SIP");
	PACKETPP_ASSERT(sipRespPacket7.isPacketOfType(SIPResponse) == true, "sipRespPacket7 isn't of type SIP response");

	SipResponseLayer* sipRespLayer = sipRespPacket1.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip100Trying, "SIP response1: status code isn't 100 Trying, it's %d", sipRespLayer->getFirstLine()->getStatusCode());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeAsInt() == 100, "SIP response1: status code as int isn't 100");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeString() == "Trying", "SIP response1: status code as string isn't 'Trying', it's '%s'", sipRespLayer->getFirstLine()->getStatusCodeString().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP response1: protocol version isn't 'SIP/2.0', it's '%s'", sipRespLayer->getFirstLine()->getVersion().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 20, "SIP response1: first line size isn't 20, it's %d", sipRespLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD) != NULL, "SIP response1: Cannot find field 'From'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->getFieldValue() == "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", "SIP response1: Value of 'From' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD) != NULL, "SIP response1: Cannot find field 'Call-ID'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD)->getFieldValue() == "12013223@200.57.7.195", "SIP response1: Value of 'Call-ID' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_SERVER_FIELD) != NULL, "SIP response1: Cannot find field 'Server'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_SERVER_FIELD)->getFieldValue() == "X-Lite release 1103m", "SIP response1: Value of 'Server' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD) != NULL, "SIP response1: Cannot find field 'Content-Length'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD)->getFieldValue() == "0", "SIP response1: Value of 'Content-Length' isn't '0'");
	PACKETPP_ASSERT(sipRespLayer->getContentLength() == 0, "SIP response1: content length isn't 0");


	sipRespLayer = sipRespPacket2.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip180Ringing, "SIP response2: status code isn't 180 Ringing, it's %d", sipRespLayer->getFirstLine()->getStatusCode());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeAsInt() == 180, "SIP response2: status code as int isn't 180");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeString() == "Ringing", "SIP response2: status code as string isn't 'Ringing', it's '%s'", sipRespLayer->getFirstLine()->getStatusCodeString().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP response2: protocol version isn't 'SIP/2.0', it's '%s'", sipRespLayer->getFirstLine()->getVersion().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 21, "SIP response2: first line size isn't 21, it's %d", sipRespLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipRespLayer->getFirstField()->getFieldName() == PCPP_SIP_VIA_FIELD, "SIP response2: first field isn't 'Via'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD) != NULL, "SIP response2: Cannot find field 'Via'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->getFieldValue() == "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290", "SIP response2: Value of first 'Via' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD) != NULL, "SIP response2: Cannot find field 'CSeq'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->getFieldValue() == "1 INVITE", "SIP response2: Value of 'CSeq' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getContentLength() == 0, "SIP response2: content length isn't 0");



	sipRespLayer = sipRespPacket3.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip200OK, "SIP response3: status code isn't 200 OK, it's %d", sipRespLayer->getFirstLine()->getStatusCode());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeAsInt() == 200, "SIP response3: status code as int isn't 200");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeString() == "Ok", "SIP response3: status code as string isn't 'Ok', it's '%s'", sipRespLayer->getFirstLine()->getStatusCodeString().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP response3: protocol version isn't 'SIP/2.0', it's '%s'", sipRespLayer->getFirstLine()->getVersion().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 16, "SIP response3: first line size isn't 16, it's %d", sipRespLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD) != NULL, "SIP response3: Cannot find field 'Content-Type'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD)->getFieldValue() == "application/sdp", "SIP response3: Value of first 'Content-Type' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getContentLength() == 298, "SIP response3: content length isn't 298");


	sipRespLayer = sipRespPacket4.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip401Unauthorized, "SIP response4: status code isn't 401 Unauthorized, it's %d", sipRespLayer->getFirstLine()->getStatusCode());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeAsInt() == 401, "SIP response4: status code as int isn't 401");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeString() == "Unauthorized", "SIP response4: status code as string isn't 'Unauthorized', it's '%s'", sipRespLayer->getFirstLine()->getStatusCodeString().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP response4: protocol version isn't 'SIP/2.0', it's '%s'", sipRespLayer->getFirstLine()->getVersion().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 26, "SIP response4: first line size isn't 26, it's %d", sipRespLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_WWW_AUTHENTICATE_FIELD) != NULL, "SIP response4: Cannot find field 'WWW-Authenticate'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_WWW_AUTHENTICATE_FIELD)->getFieldValue() == "Digest  realm=\"ims.hom\",nonce=\"021fa2db5ff06518\",opaque=\"627f7bb95d5e2dcd\",algorithm=MD5,qop=\"auth\"", "SIP response4: Value of first 'WWW-Authenticate' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getContentLength() == 0, "SIP response4: content length isn't 0");


	sipRespLayer = sipRespPacket7.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip503ServiceUnavailable, "SIP response7: status code isn't 503 Service Unavailable, it's %d", sipRespLayer->getFirstLine()->getStatusCode());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeAsInt() == 503, "SIP response7: status code as int isn't 503");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCodeString() == "Service Unavailable", "SIP response7: status code as string isn't 'Service Unavailable', it's '%s'", sipRespLayer->getFirstLine()->getStatusCodeString().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getVersion() == "SIP/2.0", "SIP response7: protocol version isn't 'SIP/2.0', it's '%s'", sipRespLayer->getFirstLine()->getVersion().c_str());
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 33, "SIP response7: first line size isn't 33, it's %d", sipRespLayer->getFirstLine()->getSize());

	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_RETRY_AFTER_FIELD) != NULL, "SIP response7: Cannot find field 'Retry-After'");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_RETRY_AFTER_FIELD)->getFieldValue() == "0", "SIP response7: Value of first 'Retry-After' is different than expected");
	PACKETPP_ASSERT(sipRespLayer->getContentLength() == 0, "SIP response7: content length isn't 0");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SipResponseLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer6Length = 0;
	uint8_t* buffer6 = readFileIntoBuffer("PacketExamples/sip_resp6.dat", buffer6Length);
	PACKETPP_ASSERT(!(buffer6 == NULL), "cannot read file sip_resp6.dat");

	RawPacket rawPacket((const uint8_t*)buffer6, buffer6Length, time, true);

	Packet sipRespSamplePacket(&rawPacket);

	Packet newSipPacket;

	EthLayer ethLayer(*sipRespSamplePacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Layer ip4Layer;
	ip4Layer = *(sipRespSamplePacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	UdpLayer udpLayer = *(sipRespSamplePacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(newSipPacket.addLayer(&udpLayer), "Adding UDP layer failed");

	SipResponseLayer sipRespLayer(SipResponseLayer::Sip504ServerTimeout);

	PACKETPP_ASSERT(sipRespLayer.addField(PCPP_SIP_FROM_FIELD, "<sip:user103@ims.hom>;tag=2054531660") != NULL, "Couldn't add 'From' field");
	PACKETPP_ASSERT(sipRespLayer.addField(PCPP_SIP_CSEQ_FIELD, "1 REGISTER") != NULL, "Couldn't add 'CSeq' field");
	HeaderField* contentLengthField = sipRespLayer.setContentLength(0, PCPP_SIP_CSEQ_FIELD);
	PACKETPP_ASSERT(contentLengthField != NULL, "Couldn't set content length");
	contentLengthField->setFieldValue(" 0");
	PACKETPP_ASSERT(sipRespLayer.addEndOfHeader() != NULL, "Couldn't set end-of-header");
	PACKETPP_ASSERT(sipRespLayer.insertField(NULL, PCPP_SIP_CALL_ID_FIELD, "93803593") != NULL, "Couldn't add 'Call-ID' field");
	PACKETPP_ASSERT(sipRespLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 10.3.160.214:5060;rport=5060;received=10.3.160.214;branch=z9hG4bK19266132") != NULL, "Couldn't add 'Via' field");
	HeaderField* fromField = sipRespLayer.getFieldByName(PCPP_SIP_FROM_FIELD);
	PACKETPP_ASSERT(fromField != NULL, "Couldn't find recently added 'From' field");
	PACKETPP_ASSERT(sipRespLayer.insertField(fromField, PCPP_SIP_TO_FIELD, "<sip:user103@ims.hom>;tag=z9hG4bKPjoKb0QlsN0Z-v4iW63WRm5UfjLn.Gm81V") != NULL, "Couldn't add 'To' field");

	PACKETPP_ASSERT(newSipPacket.addLayer(&sipRespLayer), "Adding SIP response layer failed");

	newSipPacket.computeCalculateFields();

	newSipPacket.getLayerOfType<UdpLayer>()->getUdpHeader()->headerChecksum = 0xced8;


	PACKETPP_ASSERT(buffer6Length == newSipPacket.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", newSipPacket.getRawPacket()->getRawDataLen(), buffer6Length);
	PACKETPP_ASSERT(memcmp(newSipPacket.getRawPacket()->getRawData(), buffer6, newSipPacket.getRawPacket()->getRawDataLen()) == 0, "Generated raw packet data after edit is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SipResponseLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/sip_resp3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file sip_resp3.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/sip_resp4.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file sip_resp4.dat");

	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);

	Packet editedPacket(&rawPacket3);
	Packet secondSipPacket(&rawPacket4);

	SipResponseLayer* sipRespLayer = editedPacket.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(sipRespLayer != NULL, "Cannot find SIP response layer");

	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::Sip202Accepted) == true, "Couldn't set status code to 202");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip202Accepted, "Status code is not really 202");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 22, "First line length after changing to 202 isn't 22");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::Sip415UnsupportedMediaType) == true, "Couldn't set status code to 415");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip415UnsupportedMediaType, "Status code is not really 415");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 36, "First line length after changing to 415 isn't 36");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::Sip603Decline) == true, "Couldn't set method to 603");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip603Decline, "Status code is not really 603");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 21, "First line length after changing to 603 isn't 21");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::Sip603Decline, "Some other string") == true, "Couldn't set method to 603 with other string");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip603Decline, "Status code is not really 603");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 31, "First line length after changing to 603 other string isn't 31");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::Sip401Unauthorized) == true, "Couldn't set method to 401");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getStatusCode() == SipResponseLayer::Sip401Unauthorized, "Status code is not really 401");
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->getSize() == 26, "First line length after changing to 401 isn't 26");

	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(sipRespLayer->getFirstLine()->setStatusCode(SipResponseLayer::SipStatusCodeUnknown) == false, "Managed to set an unknown status code");
	LoggerPP::getInstance().enableErrors();

	PACKETPP_ASSERT(sipRespLayer->removeField(PCPP_SIP_VIA_FIELD, 1) == true, "Couldn't remove 2nd 'Via' field");
	PACKETPP_ASSERT(sipRespLayer->removeField(PCPP_SIP_CONTACT_FIELD) == true, "Couldn't remove 'Contact' field");
	PACKETPP_ASSERT(sipRespLayer->removeField(PCPP_SIP_CALL_ID_FIELD) == true, "Couldn't remove 'Call-ID' field");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->setFieldValue("SIP/2.0/UDP 10.3.160.214:5060;rport=5060;received=10.3.160.214;branch=z9hG4bK758266975") == true, "Couldn't set value for 'Via' field");
	PACKETPP_ASSERT(sipRespLayer->removeField(PCPP_SIP_CONTENT_TYPE_FIELD) == true, "Couldn't remove 'Content-Type' field");
	PACKETPP_ASSERT(sipRespLayer->removeField(PCPP_SIP_SERVER_FIELD) == true, "Couldn't remove 'Server' field");
	PACKETPP_ASSERT(sipRespLayer->setContentLength(0) != NULL, "Couldn't set content-length to 0");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->setFieldValue("<sip:user3@ims.hom>;tag=1597735002") == true, "Cannot update 'From' field value");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_TO_FIELD)->setFieldValue("<sip:user3@ims.hom>;tag=z9hG4bKPjNwtzXu2EwWIjxR8qftv00jzO9arV-iyh") == true, "Cannot update 'To' field value");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->setFieldValue("1 REGISTER") == true, "Cannot update 'CSeq' field value");
	PACKETPP_ASSERT(sipRespLayer->insertField(PCPP_SIP_CSEQ_FIELD, PCPP_SIP_WWW_AUTHENTICATE_FIELD,
			"Digest  realm=\"ims.hom\",nonce=\"021fa2db5ff06518\",opaque=\"627f7bb95d5e2dcd\",algorithm=MD5,qop=\"auth\"") != NULL, "Can't add 'WWW-Authenticate' field");
	PACKETPP_ASSERT(sipRespLayer->insertField(PCPP_SIP_VIA_FIELD, PCPP_SIP_CALL_ID_FIELD, "434981653") != NULL, "Can't add 'Call-ID' field");
	PACKETPP_ASSERT(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD)->setFieldValue(" 0") == true, "Couldn't set 'Content-Length' field value to ' 0'");

	SipResponseLayer* secondSipRespLayer = secondSipPacket.getLayerOfType<SipResponseLayer>();

	PACKETPP_ASSERT(secondSipRespLayer->getHeaderLen() == sipRespLayer->getHeaderLen(), "Edited layer len (%d) isn't as expected (%d)", (int)sipRespLayer->getHeaderLen(), (int)secondSipRespLayer->getHeaderLen());
	PACKETPP_ASSERT(secondSipRespLayer->getFirstLine()->getSize() == sipRespLayer->getFirstLine()->getSize(), "Edited first line length (%d) isn't as expected (%d)", sipRespLayer->getFirstLine()->getSize(), secondSipRespLayer->getFirstLine()->getSize());
	PACKETPP_ASSERT(secondSipRespLayer->getFirstLine()->getStatusCode() == sipRespLayer->getFirstLine()->getStatusCode(), "Status code of edited packet is different than expected");
	PACKETPP_ASSERT(secondSipRespLayer->getFieldCount() == sipRespLayer->getFieldCount(), "Number of header fields in edited packet is not as expected");
	PACKETPP_ASSERT(memcmp(secondSipRespLayer->getData(), sipRespLayer->getData(), secondSipRespLayer->getHeaderLen()) == 0, "Edited raw data is different than expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SdpLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/sip_req1.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file sip_req1.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/sdp.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file sdp.dat");

	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);

	Packet sdpPacket(&rawPacket1);
	Packet sdpPacket2(&rawPacket2);

	PACKETPP_ASSERT(sdpPacket.isPacketOfType(SDP) == true, "Packet is not of type SDP");
	SdpLayer* sdpLayer = sdpPacket.getLayerOfType<SdpLayer>();
	PACKETPP_ASSERT(sdpLayer != NULL, "SDP layer is null");

	PACKETPP_ASSERT(sdpLayer->getFieldCount() == 11, "SDP field count isn't 11");

	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_PROTOCOL_VERSION_FIELD) != NULL, "Cannot find v= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_PROTOCOL_VERSION_FIELD)->getFieldValue() == "0", "Protocol version isn't 0");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD) != NULL, "Cannot find o= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD)->getFieldValue() == "Clarent 120386 120387 IN IP4 200.57.7.196", "Wrong originator value");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD) != NULL, "Cannot find m= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD)->getFieldValue() == "audio 40376 RTP/AVP 8 18 4 0", "Wrong media name value");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD) != NULL, "Cannot find 1st a= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD)->getFieldValue() == "rtpmap:8 PCMA/8000", "Wrong 1st media attr value");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 2) != NULL, "Cannot find 3rd a= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 2)->getFieldValue() == "rtpmap:4 G723/8000", "Wrong 3rd media attr value");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 4) != NULL, "Cannot find 4th a= field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 4)->getFieldValue() == "SendRecv", "Wrong 5th media attr value");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 5) == NULL, "Falsly found 6th a= field");

	PACKETPP_ASSERT(sdpLayer->getOwnerIPv4Address() == IPv4Address(std::string("200.57.7.196")), "Owner IP address isn't 200.57.7.196");
	PACKETPP_ASSERT(sdpLayer->getMediaPort("audio") == 40376, "Audio port isn't 40376");

	PACKETPP_ASSERT(sdpPacket2.isPacketOfType(SDP) == true, "Packet2 is not of type SDP");
	sdpLayer = sdpPacket2.getLayerOfType<SdpLayer>();
	PACKETPP_ASSERT(sdpLayer != NULL, "SDP layer is null in packet2");

	PACKETPP_ASSERT(sdpLayer->getFieldCount() == 18, "SDP field count isn't 18 in packet2");

	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD) != NULL, "Cannot find c= field in packet2");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD)->getFieldValue() == "IN IP4 10.33.6.100", "Wrong connection info value in packet2");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_TIME_FIELD) != NULL, "Cannot find t= field in packet2");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_TIME_FIELD)->getFieldValue() == "0 0", "Wrong time value in packet2");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD) != NULL, "Cannot find s= field in packet2");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD)->getFieldValue() == "Phone-Call", "Wrong session name in packet2");

	PACKETPP_ASSERT(sdpLayer->getOwnerIPv4Address() == IPv4Address(std::string("10.33.6.100")), "Owner IP address isn't 10.33.6.100 in packet2");
	PACKETPP_ASSERT(sdpLayer->getMediaPort("audio") == 6010, "Audio port isn't 6010 in packet2");
	PACKETPP_ASSERT(sdpLayer->getMediaPort("image") == 6012, "Image port isn't 6012 in packet2");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SdpLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/sdp.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file sdp.dat");

	RawPacket rawPacket((const uint8_t*)buffer1, buffer1Length, time, true);

	Packet sdpPacket(&rawPacket);

	Packet newSdpPacket;

	EthLayer ethLayer(*sdpPacket.getLayerOfType<EthLayer>());
	PACKETPP_ASSERT(newSdpPacket.addLayer(&ethLayer), "Adding ethernet layer failed");

	IPv4Layer ip4Layer;
	ip4Layer = *(sdpPacket.getLayerOfType<IPv4Layer>());
	PACKETPP_ASSERT(newSdpPacket.addLayer(&ip4Layer), "Adding IPv4 layer failed");

	UdpLayer udpLayer = *(sdpPacket.getLayerOfType<UdpLayer>());
	PACKETPP_ASSERT(newSdpPacket.addLayer(&udpLayer), "Adding UDP layer failed");

	SipResponseLayer sipLayer = *(sdpPacket.getLayerOfType<SipResponseLayer>());
	PACKETPP_ASSERT(newSdpPacket.addLayer(&sipLayer), "Adding SIP layer failed");

	SdpLayer newSdpLayer("IPP", 782647527, 782647407, IPv4Address(std::string("10.33.6.100")), "Phone-Call", 0, 0);

	std::vector<std::string> audioAttributes;
	audioAttributes.push_back("rtpmap:8 PCMA/8000");
	audioAttributes.push_back("rtpmap:96 telephone-event/8000");
	audioAttributes.push_back("fmtp:96 0-15,16");
	audioAttributes.push_back("ptime:20");
	audioAttributes.push_back("sendrecv");
	PACKETPP_ASSERT(newSdpLayer.addMediaDescription("audio", 6010, "RTP/AVP", "8 96", audioAttributes) == true,
			"Failed adding audio media description");

	std::vector<std::string> imageAttributes;
	imageAttributes.push_back("T38FaxVersion:0");
	imageAttributes.push_back("T38MaxBitRate:14400");
	imageAttributes.push_back("T38FaxMaxBuffer:1024");
	imageAttributes.push_back("T38FaxMaxDatagram:238");
	imageAttributes.push_back("T38FaxRateManagement:transferredTCF");
	imageAttributes.push_back("T38FaxUdpEC:t38UDPRedundancy");
	PACKETPP_ASSERT(newSdpLayer.addMediaDescription("image", 6012, "udptl", "t38", imageAttributes) == true,
			"Failed adding image media description");

	PACKETPP_ASSERT(newSdpPacket.addLayer(&newSdpLayer), "Adding SDP layer failed");

	newSdpPacket.computeCalculateFields();

	PACKETPP_ASSERT(newSdpPacket.isPacketOfType(SDP) == true, "New packet isn't of type SDP");

	SdpLayer* sdpLayerPtr = newSdpPacket.getLayerOfType<SdpLayer>();

	PACKETPP_ASSERT(sdpLayerPtr != NULL, "Cannot find newly added SDP layer");
	PACKETPP_ASSERT(sdpLayerPtr->getFieldCount() == 18, "Number of header fields isn't 18");
	PACKETPP_ASSERT(sdpLayerPtr->getHeaderLen() == 406, "SDP message len isn't 406");

	SdpLayer* sdpLayerPtr2 = sdpPacket.getLayerOfType<SdpLayer>();
	PACKETPP_ASSERT(memcmp(sdpLayerPtr2->getData(), sdpLayerPtr->getData(), sdpLayerPtr2->getHeaderLen()) == 0, "Created raw data is different from expected");

	SdpLayer copiedSdpLayer = *sdpLayerPtr;
	PACKETPP_ASSERT(copiedSdpLayer.getFieldCount() == 18, "Number of header fields in copied layer isn't 18");
	PACKETPP_ASSERT(copiedSdpLayer.getHeaderLen() == 406, "SDP copied message len isn't 406");
	PACKETPP_ASSERT(memcmp(copiedSdpLayer.getData(), sdpLayerPtr->getData(), sdpLayerPtr->getHeaderLen()) == 0, "Copied data is different from expected");

	PACKETPP_TEST_PASSED;
}

PACKETPP_TEST(SdpLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/sip_resp3.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file sip_resp3.dat");

	int bufferLength = 0;
	uint8_t* buffer = readFileIntoBuffer("PacketExamples/sdp.dat", bufferLength);
	PACKETPP_ASSERT(!(buffer == NULL), "cannot read file sdp.dat");

	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket((const uint8_t*)buffer, bufferLength, time, true);

	Packet sourceSdpPacket(&rawPacket3);
	Packet targetSdpPacket(&rawPacket);

	SdpLayer* sdpLayer = sourceSdpPacket.getLayerOfType<SdpLayer>();
	PACKETPP_ASSERT(sdpLayer != NULL, "Cannot find SDP layer in source packet");

	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD)->setFieldValue("IPP 782647527 782647407 IN IP4 10.33.6.100") == true, "Cannot change originator field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD)->setFieldValue("Phone-Call") == true, "Cannot change session-name field");
	PACKETPP_ASSERT(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD)->setFieldValue("IN IP4 10.33.6.100") == true, "Cannot change connection-info field");
	PACKETPP_ASSERT(sdpLayer->removeField(PCPP_SDP_MEDIA_NAME_FIELD) == true, "Cannot remove media field");
	while (sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD) != NULL)
	{
		sdpLayer->removeField(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD);
	}

	std::vector<std::string> audioAttributes;
	audioAttributes.push_back("rtpmap:8 PCMA/8000");
	audioAttributes.push_back("rtpmap:96 telephone-event/8000");
	audioAttributes.push_back("fmtp:96 0-15,16");
	audioAttributes.push_back("ptime:20");
	audioAttributes.push_back("sendrecv");
	PACKETPP_ASSERT(sdpLayer->addMediaDescription("audio", 6010, "RTP/AVP", "8 96", audioAttributes) == true,
			"Failed adding audio media description");

	std::vector<std::string> imageAttributes;
	imageAttributes.push_back("T38FaxVersion:0");
	imageAttributes.push_back("T38MaxBitRate:14400");
	imageAttributes.push_back("T38FaxMaxBuffer:1024");
	imageAttributes.push_back("T38FaxMaxDatagram:238");
	imageAttributes.push_back("T38FaxRateManagement:transferredTCF");
	imageAttributes.push_back("T38FaxUdpEC:t38UDPRedundancy");
	PACKETPP_ASSERT(sdpLayer->addMediaDescription("image", 6012, "udptl", "t38", imageAttributes) == true,
			"Failed adding image media description");

	sourceSdpPacket.computeCalculateFields();

	SdpLayer* targetSdpLayer = targetSdpPacket.getLayerOfType<SdpLayer>();

	PACKETPP_ASSERT(sdpLayer->getFieldCount() == targetSdpLayer->getFieldCount(), "Different field count in edited and target SDP layers");
	PACKETPP_ASSERT(sdpLayer->getHeaderLen() == targetSdpLayer->getHeaderLen(), "Different header length in edited and target SDP layers");
	PACKETPP_ASSERT(sdpLayer->getOwnerIPv4Address() == targetSdpLayer->getOwnerIPv4Address(), "Different owner IP in edited and target SDP layers");
	PACKETPP_ASSERT(sdpLayer->getMediaPort("audio") == targetSdpLayer->getMediaPort("audio"), "Different audio port in edited and target SDP layers");
	PACKETPP_ASSERT(sdpLayer->getMediaPort("image") == targetSdpLayer->getMediaPort("image"), "Different image port in edited and target SDP layers");
	PACKETPP_ASSERT(memcmp(sdpLayer->getData(), targetSdpLayer->getData(), targetSdpLayer->getHeaderLen()) == 0, "Edited SDP data is different from target SDP data");

	PACKETPP_TEST_PASSED;
}


PACKETPP_TEST(PacketTrailerTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	int buffer1Length = 0;
	uint8_t* buffer1 = readFileIntoBuffer("PacketExamples/packet_trailer_arp.dat", buffer1Length);
	PACKETPP_ASSERT(!(buffer1 == NULL), "cannot read file packet_trailer_arp.dat");

	int buffer2Length = 0;
	uint8_t* buffer2 = readFileIntoBuffer("PacketExamples/packet_trailer_ipv4.dat", buffer2Length);
	PACKETPP_ASSERT(!(buffer2 == NULL), "cannot read file packet_trailer_ipv4.dat.dat");

	int buffer3Length = 0;
	uint8_t* buffer3 = readFileIntoBuffer("PacketExamples/packet_trailer_ipv6.dat", buffer3Length);
	PACKETPP_ASSERT(!(buffer3 == NULL), "cannot read file packet_trailer_ipv6.dat");

	int buffer4Length = 0;
	uint8_t* buffer4 = readFileIntoBuffer("PacketExamples/packet_trailer_pppoed.dat", buffer4Length);
	PACKETPP_ASSERT(!(buffer4 == NULL), "cannot read file packet_trailer_pppoed.dat");

	int buffer5Length = 0;
	uint8_t* buffer5 = readFileIntoBuffer("PacketExamples/packet_trailer_ipv6.dat", buffer5Length);
	PACKETPP_ASSERT(!(buffer5 == NULL), "cannot read file packet_trailer_ipv6.dat second time");


	RawPacket rawPacket1((const uint8_t*)buffer1, buffer1Length, time, true);
	RawPacket rawPacket2((const uint8_t*)buffer2, buffer2Length, time, true);
	RawPacket rawPacket3((const uint8_t*)buffer3, buffer3Length, time, true);
	RawPacket rawPacket4((const uint8_t*)buffer4, buffer4Length, time, true);
	RawPacket rawPacket5((const uint8_t*)buffer5, buffer5Length, time, true);

	Packet trailerArpPacket(&rawPacket1);
	Packet trailerIPv4Packet(&rawPacket2);
	Packet trailerIPv6Packet(&rawPacket3);
	Packet trailerPPPoEDPacket(&rawPacket4);
	Packet trailerIPv6Packet2(&rawPacket5);

	PACKETPP_ASSERT(trailerArpPacket.isPacketOfType(PacketTrailer) == true, "trailerArpPacket isn't of type PacketTrailer");
	PACKETPP_ASSERT(trailerIPv4Packet.isPacketOfType(PacketTrailer) == true, "trailerIPv4Packet isn't of type PacketTrailer");
	PACKETPP_ASSERT(trailerIPv6Packet.isPacketOfType(PacketTrailer) == true, "trailerIPv6Packet isn't of type PacketTrailer");
	PACKETPP_ASSERT(trailerPPPoEDPacket.isPacketOfType(PacketTrailer) == true, "trailerPPPoEDPacket isn't of type PacketTrailer");

	PACKETPP_ASSERT(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen() == 18, "trailerArpPacket - trailer len isn't 18");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen() == 6, "trailerIPv4Packet - trailer len isn't 6");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerLen() == 4, "trailerIPv6Packet - trailer len isn't 4");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerLen() == 28, "trailerPPPoEDPacket - trailer len isn't 28");

	PACKETPP_ASSERT(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString() ==  "742066726f6d2062726964676500203d3d20", "trailerArpPacket - wrong trailer string");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString() ==  "0101080a0000", "trailerIPv4Packet - wrong trailer string");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString() ==  "cdfcf105", "trailerIPv6Packet - wrong trailer string");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerDataAsHexString() ==  "00000000000000000000000000000000000000000000000000000000", "trailerPPPoEDPacket - wrong trailer string");

	PACKETPP_ASSERT(trailerArpPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[3] == 0x72, "trailerArpPacket - wrong data");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[2] == 0x8, "trailerIPv4Packet - wrong data");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[1] == 0xfc, "trailerIPv6Packet - wrong data");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getTrailerData()[12] == 0, "trailerPPPoEDPacket - wrong data");

	EthLayer* ethLayer = trailerIPv4Packet.getLayerOfType<EthLayer>();
	IPv4Layer* ip4Layer = trailerIPv4Packet.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ethLayer != NULL, "trailerIPv4Packet isn't of type Ethernet");
	PACKETPP_ASSERT(ip4Layer != NULL, "trailerIPv4Packet isn't of type IPv4");
	PACKETPP_ASSERT(ethLayer->getDataLen() - ethLayer->getHeaderLen() > ip4Layer->getDataLen(), "trailerIPv4Packet - eth data isn't larger than ip4 data");
	PACKETPP_ASSERT(ip4Layer->getDataLen() == ntohs(ip4Layer->getIPv4Header()->totalLength), "trailerIPv4Packet - dataLen != totalLength");

	ethLayer = trailerIPv6Packet.getLayerOfType<EthLayer>();
	IPv6Layer* ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
	PACKETPP_ASSERT(ethLayer != NULL, "trailerIPv6Packet isn't of type Ethernet");
	PACKETPP_ASSERT(ip6Layer != NULL, "trailerIPv6Packet isn't of type IPv6");
	PACKETPP_ASSERT(ethLayer->getDataLen() - ethLayer->getHeaderLen() > ip6Layer->getDataLen(), "trailerIPv6Packet - eth data isn't larger than ip6 data");
	PACKETPP_ASSERT(ip6Layer->getDataLen() == ntohs(ip6Layer->getIPv6Header()->payloadLength) + ip6Layer->getHeaderLen(), "trailerIPv6Packet - dataLen != totalLength");

	// add layer before trailer
	VlanLayer newVlanLayer(123, true, 1, PCPP_ETHERTYPE_IPV6);
	PACKETPP_ASSERT(trailerIPv6Packet.insertLayer(ethLayer, &newVlanLayer) == true, "trailerIPv6Packet - couldn't add VLAN layer");
	trailerIPv6Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen() == 468, "trailerIPv6Packet add layer - eth layer len isn't 468");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen() == 454, "trailerIPv6Packet add layer - vlan layer len isn't 454d");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen() == 446, "trailerIPv6Packet add layer - ipv6 layer len isn't 446");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen() == 406, "trailerIPv6Packet add layer - udp layer len isn't 406");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen() == 398, "trailerIPv6Packet add layer - dns layer len isn't 398");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 4, "trailerIPv6Packet add layer - trailer layer len isn't 4");

	// add layer just before trailer
	HttpRequestLayer httpReq(HttpRequestLayer::HttpGET, "/main.html", OneDotOne);
	httpReq.addEndOfHeader();
	TcpLayer* tcpLayer = trailerIPv4Packet.getLayerOfType<TcpLayer>();
	PACKETPP_ASSERT(tcpLayer != NULL, "Couldn't find TCP layer for trailerIPv4Packet");
	trailerIPv4Packet.insertLayer(tcpLayer, &httpReq);
	trailerIPv4Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen() == 87, "trailerIPv4Packet add layer - eth layer len isn't 87");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen() == 67, "trailerIPv4Packet add layer - ipv4 layer len isn't 67");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen() == 47, "trailerIPv4Packet add layer - tcp layer len isn't 47");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen() == 27, "trailerIPv4Packet add layer - http layer len isn't 27");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 6, "trailerIPv4Packet add layer - trailer layer len isn't 6");

	// add layer after trailer (result with an error)
	uint8_t payload[4] = { 0x1, 0x2, 0x3, 0x4 };
	PayloadLayer newPayloadLayer(payload, 4, false);
	LoggerPP::getInstance().supressErrors();
	PACKETPP_ASSERT(trailerIPv4Packet.addLayer(&newPayloadLayer) == false, "Wrongly succeeded to add a layer after packet trailer");
	LoggerPP::getInstance().enableErrors();

	// remove layer before trailer
	tcpLayer = trailerIPv4Packet.getLayerOfType<TcpLayer>();
	PACKETPP_ASSERT(tcpLayer != NULL, "Couldn't find TCP layer for trailerIPv4Packet");
	trailerIPv4Packet.removeLayer(tcpLayer);
	trailerIPv4Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen() == 67, "trailerIPv4Packet remove layer - eth layer len isn't 67");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen() == 47, "trailerIPv4Packet remove layer - ipv4 layer len isn't 47");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<HttpRequestLayer>()->getDataLen() == 27, "trailerIPv4Packet remove layer - http layer len isn't 27");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 6, "trailerIPv4Packet remove layer - trailer layer len isn't 6");

	// remove layer just before trailer
	HttpRequestLayer* httpReqPtr = trailerIPv4Packet.getLayerOfType<HttpRequestLayer>();
	PACKETPP_ASSERT(httpReqPtr != NULL, "Couldn't find HTTP request layer for trailerIPv4Packet");
	trailerIPv4Packet.removeLayer(httpReqPtr);
	trailerIPv4Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen() == 40, "trailerIPv4Packet remove layer - eth layer len isn't 67");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen() == 20, "trailerIPv4Packet remove layer - ipv4 layer len isn't 47");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 6, "trailerIPv4Packet remove layer - trailer layer len isn't 6");

	// remove trailer
	ethLayer = trailerIPv6Packet2.getLayerOfType<EthLayer>();
	VlanLayer newVlanLayer2(456, true, 1, PCPP_ETHERTYPE_IPV6);
	PACKETPP_ASSERT(trailerIPv6Packet2.insertLayer(ethLayer, &newVlanLayer2) == true, "trailerIPv6Packet2 - couldn't add VLAN layer");
	PacketTrailerLayer* packetTrailer = trailerIPv6Packet2.getLayerOfType<PacketTrailerLayer>();
	PACKETPP_ASSERT(packetTrailer != NULL, "Couldn't find trailer layer for trailerIPv6Packet2");
	trailerIPv6Packet2.removeLayer(packetTrailer);
	trailerIPv6Packet2.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv6Packet2.getLayerOfType<EthLayer>()->getDataLen() == 464, "trailerIPv6Packet2 remove trailer - eth layer len isn't 468");
	PACKETPP_ASSERT(trailerIPv6Packet2.getLayerOfType<VlanLayer>()->getDataLen() == 450, "trailerIPv6Packet2 remove trailer - vlan layer len isn't 454d");
	PACKETPP_ASSERT(trailerIPv6Packet2.getLayerOfType<IPv6Layer>()->getDataLen() == 446, "trailerIPv6Packet2 remove trailer - ipv6 layer len isn't 446");
	PACKETPP_ASSERT(trailerIPv6Packet2.getLayerOfType<UdpLayer>()->getDataLen() == 406, "trailerIPv6Packet2 remove trailer - udp layer len isn't 406");
	PACKETPP_ASSERT(trailerIPv6Packet2.getLayerOfType<DnsLayer>()->getDataLen() == 398, "trailerIPv6Packet2 remove trailer - dns layer len isn't 398");

	// remove all layers but the trailer
	ethLayer = trailerIPv4Packet.getLayerOfType<EthLayer>();
	PACKETPP_ASSERT(ethLayer != NULL, "Couldn't find eth layer for trailerIPv4Packet");
	trailerIPv4Packet.removeLayer(ethLayer);
	trailerIPv4Packet.computeCalculateFields();
	ip4Layer = trailerIPv4Packet.getLayerOfType<IPv4Layer>();
	PACKETPP_ASSERT(ip4Layer != NULL, "Couldn't find ipv4 layer for trailerIPv4Packet");
	trailerIPv4Packet.removeLayer(ip4Layer);
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 6, "trailerIPv4Packet remove all layers but trailer - trailer layer len isn't 6");

	// rebuild packet starting from trailer
	EthLayer newEthLayer(MacAddress("30:46:9a:23:fb:fa"), MacAddress("6c:f0:49:b2:de:6e"), PCPP_ETHERTYPE_IP);
	trailerIPv4Packet.insertLayer(NULL, &newEthLayer);
	IPv4Layer newIp4Layer(IPv4Address(std::string("173.194.78.104")), IPv4Address(std::string("10.0.0.1")));
	newIp4Layer.getIPv4Header()->ipId = htons(40382);
	newIp4Layer.getIPv4Header()->timeToLive = 46;
	trailerIPv4Packet.insertLayer(&newEthLayer, &newIp4Layer);
	TcpLayer newTcpLayer(443, 55194);
	newTcpLayer.getTcpHeader()->ackNumber = htonl(0x807df56c);
	newTcpLayer.getTcpHeader()->sequenceNumber = htonl(0x46529f28);
	newTcpLayer.getTcpHeader()->ackFlag = 1;
	newTcpLayer.getTcpHeader()->windowSize = htons(344);
	trailerIPv4Packet.insertLayer(&newIp4Layer, &newTcpLayer);
	trailerIPv4Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<EthLayer>()->getDataLen() == 60, "trailerIPv4Packet rebuild - eth layer len isn't 60");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<IPv4Layer>()->getDataLen() == 40, "trailerIPv4Packet rebuild - ipv4 layer len isn't 40");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<TcpLayer>()->getDataLen() == 20, "trailerIPv4Packet rebuild - tcp layer len isn't 20");
	PACKETPP_ASSERT(trailerIPv4Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 6, "trailerIPv4Packet rebuild - trailer layer len isn't 6");

	// extend layer before trailer
	ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
	IPv6RoutingHeader routingExt(4, 3, NULL, 0);
	ip6Layer->addExtension<IPv6RoutingHeader>(routingExt);
	trailerIPv6Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen() == 476, "trailerIPv6Packet extend layer - eth layer len isn't 476");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen() == 462, "trailerIPv6Packet extend layer - vlan layer len isn't 462");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen() == 454, "trailerIPv6Packet extend layer - ipv6 layer len isn't 454");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen() == 406, "trailerIPv6Packet extend layer - udp layer len isn't 406");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen() == 398, "trailerIPv6Packet extend layer - dns layer len isn't 398");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 4, "trailerIPv6Packet extend layer - trailer layer len isn't 4");

	// extend layer just before trailer
	PPPoEDiscoveryLayer* pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
	PACKETPP_ASSERT(pppoeDiscovery != NULL, "Couldn't find PPPoE discovery layer for trailerPPPoEDPacket");
	uint8_t pppoedTagData[4] = { 0x42, 0x52, 0x41, 0x53 };
	PACKETPP_ASSERT(pppoeDiscovery->addTag(PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, (uint16_t)4, pppoedTagData) != NULL, "Could add pppoed tag");
	trailerPPPoEDPacket.computeCalculateFields();
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen() == 68, "trailerPPPoEDPacket extend layer - eth layer len isn't 68");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen() == 26, "trailerPPPoEDPacket extend layer - pppoed layer len isn't 26");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 28, "trailerPPPoEDPacket extend layer - trailer layer len isn't 28");

	// shorten layer before trailer
	ip6Layer = trailerIPv6Packet.getLayerOfType<IPv6Layer>();
	ip6Layer->removeAllExtensions();
	trailerIPv6Packet.computeCalculateFields();
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<EthLayer>()->getDataLen() == 468, "trailerIPv6Packet shorten layer - eth layer len isn't 468");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<VlanLayer>()->getDataLen() == 454, "trailerIPv6Packet shorten layer - vlan layer len isn't 454d");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<IPv6Layer>()->getDataLen() == 446, "trailerIPv6Packet shorten layer - ipv6 layer len isn't 446");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<UdpLayer>()->getDataLen() == 406, "trailerIPv6Packet shorten layer - udp layer len isn't 406");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<DnsLayer>()->getDataLen() == 398, "trailerIPv6Packet shorten layer - dns layer len isn't 398");
	PACKETPP_ASSERT(trailerIPv6Packet.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 4, "trailerIPv6Packet shorten layer - trailer layer len isn't 4");

	// shorten layer just before trailer
	pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>();
	PACKETPP_ASSERT(pppoeDiscovery->removeAllTags() == true, "couldn't remove all tags for pppoed layer");
	trailerPPPoEDPacket.computeCalculateFields();
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<EthLayer>()->getDataLen() == 48, "trailerPPPoEDPacket shorten layer - eth layer len isn't 48");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PPPoEDiscoveryLayer>()->getDataLen() == 6, "trailerPPPoEDPacket shorten layer - pppoed layer len isn't 6");
	PACKETPP_ASSERT(trailerPPPoEDPacket.getLayerOfType<PacketTrailerLayer>()->getDataLen() == 28, "trailerPPPoEDPacket shorten layer - trailer layer len isn't 28");

	PACKETPP_TEST_PASSED;
}


int main(int argc, char* argv[]) {
	start_leak_check();

	printf("PcapPlusPlus version: %s\n", getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	printf("Starting tests...\n\n");

	PACKETPP_START_RUNNING_TESTS;

	PACKETPP_RUN_TEST(EthPacketCreation);
	PACKETPP_RUN_TEST(EthAndArpPacketParsing);
	PACKETPP_RUN_TEST(ArpPacketCreation);
	PACKETPP_RUN_TEST(VlanParseAndCreation);
	PACKETPP_RUN_TEST(Ipv4PacketCreation);
	PACKETPP_RUN_TEST(Ipv4PacketParsing);
	PACKETPP_RUN_TEST(Ipv4FragmentationTest);
	PACKETPP_RUN_TEST(Ipv4OptionsParsingTest);
	PACKETPP_RUN_TEST(Ipv4OptionsEditTest);
	PACKETPP_RUN_TEST(Ipv4UdpChecksum);
	PACKETPP_RUN_TEST(Ipv6UdpPacketParseAndCreate);
	PACKETPP_RUN_TEST(Ipv6FragmentationTest);
	PACKETPP_RUN_TEST(Ipv6ExtensionsTest);
	PACKETPP_RUN_TEST(TcpPacketNoOptionsParsing);
	PACKETPP_RUN_TEST(TcpPacketWithOptionsParsing);
	PACKETPP_RUN_TEST(TcpPacketWithOptionsParsing2);
	PACKETPP_RUN_TEST(TcpPacketCreation);
	PACKETPP_RUN_TEST(TcpPacketCreation2);
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
	PACKETPP_RUN_TEST(IcmpParsingTest);
	PACKETPP_RUN_TEST(IcmpCreationTest);
	PACKETPP_RUN_TEST(IcmpEditTest);
	PACKETPP_RUN_TEST(GreParsingTest);
	PACKETPP_RUN_TEST(GreCreationTest);
	PACKETPP_RUN_TEST(GreEditTest);
	PACKETPP_RUN_TEST(SSLClientHelloParsingTest);
	PACKETPP_RUN_TEST(SSLAppDataParsingTest);
	PACKETPP_RUN_TEST(SSLAlertParsingTest);
	PACKETPP_RUN_TEST(SSLMultipleRecordParsingTest);
	PACKETPP_RUN_TEST(SSLMultipleRecordParsing2Test);
	PACKETPP_RUN_TEST(SSLMultipleRecordParsing3Test);
	PACKETPP_RUN_TEST(SSLMultipleRecordParsing4Test);
	PACKETPP_RUN_TEST(SSLPartialCertificateParseTest);
	PACKETPP_RUN_TEST(SSLNewSessionTicketParseTest);
	PACKETPP_RUN_TEST(SllPacketParsingTest);
	PACKETPP_RUN_TEST(SllPacketCreationTest);
	PACKETPP_RUN_TEST(DhcpParsingTest);
	PACKETPP_RUN_TEST(DhcpCreationTest);
	PACKETPP_RUN_TEST(DhcpEditTest);
	PACKETPP_RUN_TEST(NullLoopbackTest);
	PACKETPP_RUN_TEST(IgmpParsingTest);
	PACKETPP_RUN_TEST(IgmpCreateAndEditTest);
	PACKETPP_RUN_TEST(Igmpv3ParsingTest);
	PACKETPP_RUN_TEST(Igmpv3QueryCreateAndEditTest);
	PACKETPP_RUN_TEST(Igmpv3ReportCreateAndEditTest);
	PACKETPP_RUN_TEST(ParsePartialPacketTest);
	PACKETPP_RUN_TEST(VxlanParsingAndCreationTest);
	PACKETPP_RUN_TEST(SipRequestLayerParsingTest);
	PACKETPP_RUN_TEST(SipRequestLayerCreationTest);
	PACKETPP_RUN_TEST(SipRequestLayerEditTest);
	PACKETPP_RUN_TEST(SipResponseLayerParsingTest);
	PACKETPP_RUN_TEST(SipResponseLayerCreationTest);
	PACKETPP_RUN_TEST(SipResponseLayerEditTest);
	PACKETPP_RUN_TEST(SdpLayerParsingTest);
	PACKETPP_RUN_TEST(SdpLayerCreationTest);
	PACKETPP_RUN_TEST(SdpLayerEditTest);
	PACKETPP_RUN_TEST(PacketTrailerTest);
	PACKETPP_END_RUNNING_TESTS;
}
