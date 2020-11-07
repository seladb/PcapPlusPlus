#include <stdio.h> 
#include <stdlib.h>
#include <getopt.h>
#include "PcapPlusPlusVersion.h"
#include "../PcppTestFramework/PcppTestFrameworkRun.h"
#include "TestDefinition.h"


static struct option PacketTestOptions[] =
{
	{"tags",  required_argument, 0, 't'},
	{"show-skipped-tests", no_argument, 0, 'w' },
	{"mem-verbose", no_argument, 0, 'm' },
	{"verbose", no_argument, 0, 'v' },
	{"skip-mem-leak-check", no_argument, 0, 's' },
	{"help", no_argument, 0, 'h' },
	{0, 0, 0, 0}
};

void printUsage()
{
    printf("Usage: Packet++Test [-t tags] [-m] [-s] [-v] [-h]\n\n"
			"Flags:\n"
			"-t --tags                A list of semicolon separated tags for tests to run\n"
			"-w --show-skipped-tests  Show tests that are skipped. Default is to hide them in tests results\n"
			"-v --verbose             Run in verbose mode (emits more output in several tests)\n"
			"-m --mem-verbose         Output information about each memory allocation and deallocation\n"
			"-s --skip-mem-leak-check Skip memory leak check\n"
			"-h --help                Display this help message and exit\n"
		);
}


int main(int argc, char* argv[]) 
{

	int optionIndex = 0;
	char opt = 0;
	std::string userTags = "", configTags = "";
	bool memVerbose = false;
	bool skipMemLeakCheck = false;

	while((opt = getopt_long(argc, argv, "msvwht:", PacketTestOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
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
			case 'w':
				PTF_SHOW_SKIPPED_TESTS(true);
				break;
			case 'v':
				PTF_SET_VERBOSE_MODE(true);
				break;
			case 'h':
				printUsage();
				exit(0);
			default:
				printUsage();
				exit(-1);
		}
	}

	printf("PcapPlusPlus version: %s\n", pcpp::getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", pcpp::getBuildDateTime().c_str());
	printf("Built from: %s\n", pcpp::getGitInfo().c_str());

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

	PTF_START_RUNNING_TESTS(userTags, configTags);

	PTF_RUN_TEST(EthPacketCreation, "eth2;eth");
	PTF_RUN_TEST(EthPacketPointerCreation, "eth2;eth");
	PTF_RUN_TEST(EthAndArpPacketParsing, "eth2;eth;arp");
	PTF_RUN_TEST(ArpPacketCreation, "arp");
	PTF_RUN_TEST(EthDot3LayerParsingTest, "eth_dot3;eth");
	PTF_RUN_TEST(EthDot3LayerCreateEditTest, "eth_dot3;eth");

	PTF_RUN_TEST(VlanParseAndCreation, "vlan");
	PTF_RUN_TEST(MplsLayerTest, "mpls");
	PTF_RUN_TEST(VxlanParsingAndCreationTest, "vxlan");

	PTF_RUN_TEST(IPv4PacketCreation, "ipv4");
	PTF_RUN_TEST(IPv4PacketParsing, "ipv4");
	PTF_RUN_TEST(IPv4FragmentationTest, "ipv4");
	PTF_RUN_TEST(IPv4OptionsParsingTest, "ipv4");
	PTF_RUN_TEST(IPv4OptionsEditTest, "ipv4");
	PTF_RUN_TEST(IPv4UdpChecksum, "ipv4");

	PTF_RUN_TEST(IPv6UdpPacketParseAndCreate, "ipv6");
	PTF_RUN_TEST(IPv6FragmentationTest, "ipv6");
	PTF_RUN_TEST(IPv6ExtensionsTest, "ipv6");

	PTF_RUN_TEST(TcpPacketNoOptionsParsing, "tcp");
	PTF_RUN_TEST(TcpPacketWithOptionsParsing, "tcp");
	PTF_RUN_TEST(TcpPacketWithOptionsParsing2, "tcp");
	PTF_RUN_TEST(TcpPacketCreation, "tcp");
	PTF_RUN_TEST(TcpPacketCreation2, "tcp");
	PTF_RUN_TEST(TcpMalformedPacketParsing, "tcp");

	PTF_RUN_TEST(PacketUtilsHash5TupleUdp, "udp");
	PTF_RUN_TEST(PacketUtilsHash5TupleTcp, "tcp");
	PTF_RUN_TEST(PacketUtilsHash5TupleIPv6, "ipv6");

	PTF_RUN_TEST(InsertDataToPacket, "packet;insert");
	PTF_RUN_TEST(InsertVlanToPacket, "packet;vlan;insert");
	PTF_RUN_TEST(RemoveLayerTest, "packet;remove_layer");
	PTF_RUN_TEST(CopyLayerAndPacketTest, "packet;copy_layer");
	PTF_RUN_TEST(PacketLayerLookupTest, "packet");
	PTF_RUN_TEST(RawPacketTimeStampSetterTest, "packet");
	PTF_RUN_TEST(ParsePartialPacketTest, "packet;partial_packet");
	PTF_RUN_TEST(PacketTrailerTest, "packet;packet_trailer");
	PTF_RUN_TEST(ResizeLayerTest, "packet;resize");

	PTF_RUN_TEST(HttpRequestLayerParsingTest, "http");
	PTF_RUN_TEST(HttpRequestLayerCreationTest, "http");
	PTF_RUN_TEST(HttpRequestLayerEditTest, "http");
	PTF_RUN_TEST(HttpResponseLayerParsingTest, "http");
	PTF_RUN_TEST(HttpResponseLayerCreationTest, "http");
	PTF_RUN_TEST(HttpResponseLayerEditTest, "http");

	PTF_RUN_TEST(PPPoESessionLayerParsingTest, "pppoe");
	PTF_RUN_TEST(PPPoESessionLayerCreationTest, "pppoe");
	PTF_RUN_TEST(PPPoEDiscoveryLayerParsingTest, "pppoe");
	PTF_RUN_TEST(PPPoEDiscoveryLayerCreateTest, "pppoe");

	PTF_RUN_TEST(DnsLayerParsingTest, "dns");
	PTF_RUN_TEST(DnsLayerQueryCreationTest, "dns");
	PTF_RUN_TEST(DnsLayerResourceCreationTest, "dns");
	PTF_RUN_TEST(DnsLayerEditTest, "dns");
	PTF_RUN_TEST(DnsLayerRemoveResourceTest, "dns");

	PTF_RUN_TEST(IcmpParsingTest, "icmp");
	PTF_RUN_TEST(IcmpCreationTest, "icmp");
	PTF_RUN_TEST(IcmpEditTest, "icmp");
	
	PTF_RUN_TEST(GreParsingTest, "gre");
	PTF_RUN_TEST(GreCreationTest, "gre");
	PTF_RUN_TEST(GreEditTest, "gre");

	PTF_RUN_TEST(SSLClientHelloParsingTest, "ssl");
	PTF_RUN_TEST(SSLAppDataParsingTest, "ssl");
	PTF_RUN_TEST(SSLAlertParsingTest, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsingTest, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing2Test, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing3Test, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing4Test, "ssl");
	PTF_RUN_TEST(SSLPartialCertificateParseTest, "ssl");
	PTF_RUN_TEST(SSLNewSessionTicketParseTest, "ssl");
	PTF_RUN_TEST(SSLMalformedPacketParsing, "ssl");
	PTF_RUN_TEST(TLS1_3ParsingTest, "ssl");
	PTF_RUN_TEST(TLSCipherSuiteTest, "ssl");

	PTF_RUN_TEST(SllPacketParsingTest, "sll");
	PTF_RUN_TEST(SllPacketCreationTest, "sll");
	PTF_RUN_TEST(NullLoopbackTest, "null_loopback");

	PTF_RUN_TEST(DhcpParsingTest, "dhcp");
	PTF_RUN_TEST(DhcpCreationTest, "dhcp");
	PTF_RUN_TEST(DhcpEditTest, "dhcp");

	PTF_RUN_TEST(IgmpParsingTest, "igmp");
	PTF_RUN_TEST(IgmpCreateAndEditTest, "igmp");
	PTF_RUN_TEST(Igmpv3ParsingTest, "igmp");
	PTF_RUN_TEST(Igmpv3QueryCreateAndEditTest, "igmp");
	PTF_RUN_TEST(Igmpv3ReportCreateAndEditTest, "igmp");
	
	PTF_RUN_TEST(SipRequestLayerParsingTest, "sip");
	PTF_RUN_TEST(SipRequestLayerCreationTest, "sip");
	PTF_RUN_TEST(SipRequestLayerEditTest, "sip");
	PTF_RUN_TEST(SipResponseLayerParsingTest, "sip");
	PTF_RUN_TEST(SipResponseLayerCreationTest, "sip");
	PTF_RUN_TEST(SipResponseLayerEditTest, "sip");
	PTF_RUN_TEST(SdpLayerParsingTest, "sdp");
	PTF_RUN_TEST(SdpLayerCreationTest, "sdp");
	PTF_RUN_TEST(SdpLayerEditTest, "sdp");

	PTF_RUN_TEST(RadiusLayerParsingTest, "radius");
	PTF_RUN_TEST(RadiusLayerCreationTest, "radius");
	PTF_RUN_TEST(RadiusLayerEditTest, "radius");

	PTF_RUN_TEST(GtpLayerParsingTest, "gtp");
	PTF_RUN_TEST(GtpLayerCreationTest, "gtp");
	PTF_RUN_TEST(GtpLayerEditTest, "gtp");

	PTF_RUN_TEST(BgpLayerParsingTest, "bgp");
	PTF_RUN_TEST(BgpLayerCreationTest, "bgp");
	PTF_RUN_TEST(BgpLayerEditTest, "bgp");

	PTF_RUN_TEST(SSHParsingTest, "ssh");
	PTF_RUN_TEST(SSHMalformedParsingTest, "ssh");

	PTF_END_RUNNING_TESTS;
}
