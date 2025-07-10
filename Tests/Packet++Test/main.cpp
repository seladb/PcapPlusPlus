#include <getopt.h>
#include "PcapPlusPlusVersion.h"
#include "PcppTestFrameworkRun.h"
#include "TestDefinition.h"
#include "Logger.h"
#include "../../Tests/Packet++Test/Utils/TestUtils.h"

static struct option PacketTestOptions[] = {
	{ "include-tags",        required_argument, nullptr, 't' },
	{ "exclude-tags",        required_argument, nullptr, 'x' },
	{ "show-skipped-tests",  no_argument,       nullptr, 'w' },
	{ "mem-verbose",         no_argument,       nullptr, 'm' },
	{ "verbose",             no_argument,       nullptr, 'v' },
	{ "skip-mem-leak-check", no_argument,       nullptr, 's' },
	// clang-format off
	{ "help",                no_argument,       nullptr, 'h' },
	{ nullptr,               0,                 nullptr, 0   }
	// clang-format on
};

void printUsage()
{
	std::cout << "Usage: Packet++Test [-t tags] [-m] [-s] [-v] [-h]\n\n"
	          << "Flags:\n"
	          << "-t --include-tags        A list of semicolon separated tags for tests to run\n"
	          << "-x --exclude-tags        A list of semicolon separated tags for tests to exclude\n"
	          << "-w --show-skipped-tests  Show tests that are skipped. Default is to hide them in tests results\n"
	          << "-v --verbose             Run in verbose mode (emits more output in several tests)\n"
	          << "-m --mem-verbose         Output information about each memory allocation and deallocation\n"
	          << "-s --skip-mem-leak-check Skip memory leak check\n"
	          << "-h --help                Display this help message and exit\n";
}

int main(int argc, char* argv[])
{
	int optionIndex = 0;
	int opt = 0;
	std::string userTagsInclude = "", userTagsExclude = "", configTags = "";
	bool memVerbose = false;
	bool skipMemLeakCheck = false;

	while ((opt = getopt_long(argc, argv, "msvwht:x:", PacketTestOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 't':
			userTagsInclude = optarg;
			break;
		case 'x':
			userTagsExclude = optarg;
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

	std::cout << "PcapPlusPlus version: " << pcpp::getPcapPlusPlusVersionFull() << std::endl
	          << "Built: " << pcpp::getBuildDateTime() << std::endl
	          << "Built from: " << pcpp::getGitInfo() << std::endl;

#ifdef NDEBUG
	skipMemLeakCheck = true;
	std::cout
	    << "Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks like a memory leak:"
	    << std::endl
	    << "     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958" << std::endl;
#endif

	// The logger singleton looks like a memory leak. Invoke it before starting the memory check
	// Disables context pooling to avoid false positives in the memory leak check, as the contexts persist in the pool.
	pcpp::Logger::getInstance().useContextPooling(false);

	// cppcheck-suppress knownConditionTrueFalse
	if (skipMemLeakCheck)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "skip_mem_leak_check";
		std::cout << "Skipping memory leak check for all test cases" << std::endl;
	}

	if (memVerbose)
	{
		if (configTags != "")
			configTags += ";";

		configTags += "mem_leak_check_verbose";
		std::cout << "Turning on verbose information on memory allocations" << std::endl;
	}

	PTF_START_RUNNING_TESTS(userTagsInclude, userTagsExclude, configTags);

	pcpp_tests::testSetUp();

	PTF_RUN_TEST(OUILookup, "eth2;eth;oui");
	PTF_RUN_TEST(EthPacketCreation, "eth2;eth");
	PTF_RUN_TEST(EthPacketPointerCreation, "eth2;eth");
	PTF_RUN_TEST(EthAndArpPacketParsing, "eth2;eth;arp");
	PTF_RUN_TEST(ArpPacketCreation, "arp");
	PTF_RUN_TEST(EthDot3LayerParsingTest, "eth_dot3;eth");
	PTF_RUN_TEST(EthDot3LayerCreateEditTest, "eth_dot3;eth");

	PTF_RUN_TEST(VlanParseAndCreation, "vlan");
	PTF_RUN_TEST(QinQ802_1adParse, "vlan");
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
	PTF_RUN_TEST(TcpPacketWithAccurateEcnParsing, "tcp");
	PTF_RUN_TEST(TcpPacketWithOptionsParsing, "tcp");
	PTF_RUN_TEST(TcpPacketWithOptionsParsing2, "tcp");
	PTF_RUN_TEST(TcpPacketCreation, "tcp");
	PTF_RUN_TEST(TcpPacketCreation2, "tcp");
	PTF_RUN_TEST(TcpMalformedPacketParsing, "tcp");
	PTF_RUN_TEST(TcpChecksumInvalidRead, "tcp");
	PTF_RUN_TEST(TcpChecksumMultiBuffer, "tcp");

	PTF_RUN_TEST(PacketUtilsHash5TupleUdp, "udp");
	PTF_RUN_TEST(PacketUtilsHash5TupleTcp, "tcp");
	PTF_RUN_TEST(PacketUtilsHash5TupleIPv6, "ipv6");

	PTF_RUN_TEST(InsertDataToPacket, "packet;insert");
	PTF_RUN_TEST(CreatePacketFromBuffer, "packet");
	PTF_RUN_TEST(InsertVlanToPacket, "packet;vlan;insert");
	PTF_RUN_TEST(RemoveLayerTest, "packet;remove_layer");
	PTF_RUN_TEST(CopyLayerAndPacketTest, "packet;copy_layer");
	PTF_RUN_TEST(PacketLayerLookupTest, "packet");
	PTF_RUN_TEST(RawPacketTimeStampSetterTest, "packet");
	PTF_RUN_TEST(ParsePartialPacketTest, "packet;partial_packet");
	PTF_RUN_TEST(PacketTrailerTest, "packet;packet_trailer");
	PTF_RUN_TEST(ResizeLayerTest, "packet;resize");
	PTF_RUN_TEST(PrintPacketAndLayersTest, "packet;print");
	PTF_RUN_TEST(ProtocolFamilyMembershipTest, "packet");
	PTF_RUN_TEST(PacketParseLayerLimitTest, "packet");

	PTF_RUN_TEST(HttpRequestParseMethodTest, "http");
	PTF_RUN_TEST(HttpRequestLayerParsingTest, "http");
	PTF_RUN_TEST(HttpRequestLayerCreationTest, "http");
	PTF_RUN_TEST(HttpRequestLayerEditTest, "http");
	PTF_RUN_TEST(HttpResponseParseStatusCodeTest, "http");
	PTF_RUN_TEST(HttpResponseParseVersionTest, "http");
	PTF_RUN_TEST(HttpResponseLayerParsingTest, "http");
	PTF_RUN_TEST(HttpResponseLayerCreationTest, "http");
	PTF_RUN_TEST(HttpResponseLayerEditTest, "http");
	PTF_RUN_TEST(HttpMalformedResponseTest, "http");

	PTF_RUN_TEST(PPPoESessionLayerParsingTest, "pppoe");
	PTF_RUN_TEST(PPPoESessionLayerCreationTest, "pppoe");
	PTF_RUN_TEST(PPPoEDiscoveryLayerParsingTest, "pppoe");
	PTF_RUN_TEST(PPPoEDiscoveryLayerCreateTest, "pppoe");

	PTF_RUN_TEST(DnsLayerParsingTest, "dns");
	PTF_RUN_TEST(DnsLayerQueryCreationTest, "dns");
	PTF_RUN_TEST(DnsLayerResourceCreationTest, "dns");
	PTF_RUN_TEST(DnsLayerEditTest, "dns");
	PTF_RUN_TEST(DnsLayerRemoveResourceTest, "dns");
	PTF_RUN_TEST(DnsOverTcpParsingTest, "dns");
	PTF_RUN_TEST(DnsOverTcpCreationTest, "dns");
	PTF_RUN_TEST(DnsLayerAddDnsKeyTest, "dns");

	PTF_RUN_TEST(IcmpParsingTest, "icmp");
	PTF_RUN_TEST(IcmpCreationTest, "icmp");
	PTF_RUN_TEST(IcmpEditTest, "icmp");

	PTF_RUN_TEST(GreParsingTest, "gre");
	PTF_RUN_TEST(GreCreationTest, "gre");
	PTF_RUN_TEST(GreEditTest, "gre");

	PTF_RUN_TEST(SSLClientHelloParsingTest, "ssl");
	PTF_RUN_TEST(SSLExtensionWithZeroSizeTest, "ssl");
	PTF_RUN_TEST(SSLAppDataParsingTest, "ssl");
	PTF_RUN_TEST(SSLAlertParsingTest, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsingTest, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing2Test, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing3Test, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing4Test, "ssl");
	PTF_RUN_TEST(SSLMultipleRecordParsing5Test, "ssl");
	PTF_RUN_TEST(SSLPartialCertificateParseTest, "ssl");
	PTF_RUN_TEST(SSLNewSessionTicketParseTest, "ssl");
	PTF_RUN_TEST(SSLMalformedPacketParsing, "ssl");
	PTF_RUN_TEST(TLS1_3ParsingTest, "ssl");
	PTF_RUN_TEST(TLSCipherSuiteTest, "ssl");
	PTF_RUN_TEST(ClientHelloTLSFingerprintTest, "ssl");
	PTF_RUN_TEST(ServerHelloTLSFingerprintTest, "ssl");

	PTF_RUN_TEST(SllPacketParsingTest, "sll");
	PTF_RUN_TEST(SllPacketCreationTest, "sll");

	PTF_RUN_TEST(NullLoopbackTest, "null_loopback");

	PTF_RUN_TEST(Sll2PacketParsingTest, "sll2");
	PTF_RUN_TEST(Sll2PacketCreationTest, "sll2");

	PTF_RUN_TEST(NflogPacketParsingTest, "nflog");

	PTF_RUN_TEST(DhcpParsingTest, "dhcp");
	PTF_RUN_TEST(DhcpCreationTest, "dhcp");
	PTF_RUN_TEST(DhcpEditTest, "dhcp");

	PTF_RUN_TEST(IgmpParsingTest, "igmp");
	PTF_RUN_TEST(IgmpCreateAndEditTest, "igmp");
	PTF_RUN_TEST(Igmpv3ParsingTest, "igmp");
	PTF_RUN_TEST(Igmpv3QueryCreateAndEditTest, "igmp");
	PTF_RUN_TEST(Igmpv3ReportCreateAndEditTest, "igmp");

	PTF_RUN_TEST(SipRequestParseMethodTest, "sip");
	PTF_RUN_TEST(SipRequestLayerParsingTest, "sip");
	PTF_RUN_TEST(SipRequestLayerCreationTest, "sip");
	PTF_RUN_TEST(SipRequestLayerEditTest, "sip");
	PTF_RUN_TEST(SipResponseParseStatusCodeTest, "sip");
	PTF_RUN_TEST(SipResponseParseVersionCodeTest, "sip");
	PTF_RUN_TEST(SipResponseLayerParsingTest, "sip");
	PTF_RUN_TEST(SipResponseLayerCreationTest, "sip");
	PTF_RUN_TEST(SipResponseLayerEditTest, "sip");
	PTF_RUN_TEST(SipNotSdpLayerParsingTest, "sip");
	PTF_RUN_TEST(SdpLayerParsingTest, "sdp");
	PTF_RUN_TEST(SdpLayerCreationTest, "sdp");
	PTF_RUN_TEST(SdpLayerEditTest, "sdp");

	PTF_RUN_TEST(RadiusLayerParsingTest, "radius");
	PTF_RUN_TEST(RadiusLayerCreationTest, "radius");
	PTF_RUN_TEST(RadiusLayerEditTest, "radius");

	PTF_RUN_TEST(GtpV1LayerParsingTest, "gtp");
	PTF_RUN_TEST(GtpV1LayerCreationTest, "gtp");
	PTF_RUN_TEST(GtpV1LayerEditTest, "gtp");
	PTF_RUN_TEST(GtpV2LayerParsingTest, "gtp");
	PTF_RUN_TEST(GtpV2LayerCreationTest, "gtp");
	PTF_RUN_TEST(GtpV2LayerEditTest, "gtp");

	PTF_RUN_TEST(BgpLayerParsingTest, "bgp");
	PTF_RUN_TEST(BgpLayerCreationTest, "bgp");
	PTF_RUN_TEST(BgpLayerEditTest, "bgp");

	PTF_RUN_TEST(SSHParsingTest, "ssh");
	PTF_RUN_TEST(SSHMalformedParsingTest, "ssh");

	PTF_RUN_TEST(IPSecParsingTest, "ipsec");

	PTF_RUN_TEST(DhcpV6ParsingTest, "dhcp;dhcpv6");
	PTF_RUN_TEST(DhcpV6CreationTest, "dhcp;dhcpv6");
	PTF_RUN_TEST(DhcpV6EditTest, "dhcp;dhcpv6");

	PTF_RUN_TEST(NtpMethodsTests, "ntp");
	PTF_RUN_TEST(NtpParsingV3Tests, "ntp");
	PTF_RUN_TEST(NtpParsingV4Tests, "ntp");
	PTF_RUN_TEST(NtpCreationTests, "ntp");

	PTF_RUN_TEST(TelnetCommandParsingTests, "telnet");
	PTF_RUN_TEST(TelnetDataParsingTests, "telnet");

	PTF_RUN_TEST(TpktLayerTest, "tpkt");

	PTF_RUN_TEST(IcmpV6ParsingTest, "icmpv6");
	PTF_RUN_TEST(IcmpV6CreationTest, "icmpv6");
	PTF_RUN_TEST(IcmpV6EditTest, "icmpv6");

	PTF_RUN_TEST(FtpParsingTests, "ftp");
	PTF_RUN_TEST(FtpCreationTests, "ftp");
	PTF_RUN_TEST(FtpEditTests, "ftp");

	PTF_RUN_TEST(LLCParsingTests, "llc");
	PTF_RUN_TEST(LLCCreationTests, "llc");

	PTF_RUN_TEST(StpConfigurationParsingTests, "stp");
	PTF_RUN_TEST(StpConfigurationCreationTests, "stp");
	PTF_RUN_TEST(StpConfigurationEditTests, "stp");
	PTF_RUN_TEST(StpTopologyChangeParsingTests, "stp");
	PTF_RUN_TEST(StpTopologyChangeCreationTests, "stp");
	PTF_RUN_TEST(StpTopologyChangeEditTests, "stp");
	PTF_RUN_TEST(RapidStpParsingTests, "stp");
	PTF_RUN_TEST(RapidStpCreationTests, "stp");
	PTF_RUN_TEST(RapidStpEditTests, "stp");
	PTF_RUN_TEST(MultipleStpParsingTests, "stp");
	PTF_RUN_TEST(MultipleStpCreationTests, "stp");
	PTF_RUN_TEST(MultipleStpEditTests, "stp");

	PTF_RUN_TEST(SomeIpPortTest, "someip");
	PTF_RUN_TEST(SomeIpParsingTest, "someip");
	PTF_RUN_TEST(SomeIpCreationTest, "someip");
	PTF_RUN_TEST(SomeIpTpParsingTest, "someip");
	PTF_RUN_TEST(SomeIpTpCreationTest, "someip");
	PTF_RUN_TEST(SomeIpTpEditTest, "someip");

	PTF_RUN_TEST(SomeIpSdParsingTest, "someipsd");
	PTF_RUN_TEST(SomeIpSdCreationTest, "someipsd");

	PTF_RUN_TEST(WakeOnLanParsingTests, "wol");
	PTF_RUN_TEST(WakeOnLanCreationTests, "wol");
	PTF_RUN_TEST(WakeOnLanEditTests, "wol");

	PTF_RUN_TEST(VrrpParsingTest, "vrrp");
	PTF_RUN_TEST(VrrpCreateAndEditTest, "vrrp");

	PTF_RUN_TEST(CotpLayerTest, "cotp");

	PTF_RUN_TEST(S7CommLayerParsingTest, "s7comm");
	PTF_RUN_TEST(S7CommLayerCreationTest, "s7comm");

	PTF_RUN_TEST(SmtpParsingTests, "smtp");
	PTF_RUN_TEST(SmtpCreationTests, "smtp");
	PTF_RUN_TEST(SmtpEditTests, "smtp");

	PTF_RUN_TEST(Asn1DecodingTest, "asn1");
	PTF_RUN_TEST(Asn1EncodingTest, "asn1");
	PTF_RUN_TEST(Asn1ObjectIdentifierTest, "asn1");

	PTF_RUN_TEST(LdapParsingTest, "ldap");
	PTF_RUN_TEST(LdapCreationTest, "ldap");

	PTF_RUN_TEST(WireGuardHandshakeInitParsingTest, "wg");
	PTF_RUN_TEST(WireGuardHandshakeRespParsingTest, "wg");
	PTF_RUN_TEST(WireGuardCookieReplyParsingTest, "wg");
	PTF_RUN_TEST(WireGuardTransportDataParsingTest, "wg");
	PTF_RUN_TEST(WireGuardCreationTest, "wg");
	PTF_RUN_TEST(WireGuardEditTest, "wg");

	PTF_RUN_TEST(CiscoHdlcParsingTest, "chdlc");
	PTF_RUN_TEST(CiscoHdlcLayerCreationTest, "chdlc");
	PTF_RUN_TEST(CiscoHdlcLayerEditTest, "chdlc");

	PTF_END_RUNNING_TESTS;
}
