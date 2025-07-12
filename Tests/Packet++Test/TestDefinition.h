#pragma once

#include "PcppTestFramework.h"

// Implemented in EthAndArpTests.cpp
PTF_TEST_CASE(OUILookup);
PTF_TEST_CASE(EthPacketCreation);
PTF_TEST_CASE(EthPacketPointerCreation);
PTF_TEST_CASE(EthAndArpPacketParsing);
PTF_TEST_CASE(ArpPacketCreation);
PTF_TEST_CASE(EthDot3LayerParsingTest);
PTF_TEST_CASE(EthDot3LayerCreateEditTest);

// Implemented in VlanMplsTests.cpp
PTF_TEST_CASE(VlanParseAndCreation);
PTF_TEST_CASE(QinQ802_1adParse);
PTF_TEST_CASE(MplsLayerTest);
PTF_TEST_CASE(VxlanParsingAndCreationTest);

// Implemented in IPv4Tests.cpp
PTF_TEST_CASE(IPv4PacketCreation);
PTF_TEST_CASE(IPv4PacketParsing);
PTF_TEST_CASE(IPv4FragmentationTest);
PTF_TEST_CASE(IPv4OptionsParsingTest);
PTF_TEST_CASE(IPv4OptionsEditTest);
PTF_TEST_CASE(IPv4UdpChecksum);

// Implemented in IPv6Tests.cpp
PTF_TEST_CASE(IPv6UdpPacketParseAndCreate);
PTF_TEST_CASE(IPv6FragmentationTest);
PTF_TEST_CASE(IPv6ExtensionsTest);

// Implemented in TcpTests.cpp
PTF_TEST_CASE(TcpPacketNoOptionsParsing);
PTF_TEST_CASE(TcpPacketWithOptionsParsing);
PTF_TEST_CASE(TcpPacketWithAccurateEcnParsing);
PTF_TEST_CASE(TcpPacketWithOptionsParsing2);
PTF_TEST_CASE(TcpMalformedPacketParsing);
PTF_TEST_CASE(TcpPacketCreation);
PTF_TEST_CASE(TcpPacketCreation2);
PTF_TEST_CASE(TcpChecksumInvalidRead);
PTF_TEST_CASE(TcpChecksumMultiBuffer);

// Implemented in PacketUtilsTests.cpp
PTF_TEST_CASE(PacketUtilsHash5TupleUdp);
PTF_TEST_CASE(PacketUtilsHash5TupleTcp);
PTF_TEST_CASE(PacketUtilsHash5TupleIPv6);

// Implemented in PacketTests.cpp
PTF_TEST_CASE(InsertDataToPacket);
PTF_TEST_CASE(CreatePacketFromBuffer);
PTF_TEST_CASE(InsertVlanToPacket);
PTF_TEST_CASE(RemoveLayerTest);
PTF_TEST_CASE(CopyLayerAndPacketTest);
PTF_TEST_CASE(PacketLayerLookupTest);
PTF_TEST_CASE(RawPacketTimeStampSetterTest);
PTF_TEST_CASE(ParsePartialPacketTest);
PTF_TEST_CASE(PacketTrailerTest);
PTF_TEST_CASE(ResizeLayerTest);
PTF_TEST_CASE(PrintPacketAndLayersTest);
PTF_TEST_CASE(ProtocolFamilyMembershipTest);
PTF_TEST_CASE(PacketParseLayerLimitTest);

// Implemented in HttpTests.cpp
PTF_TEST_CASE(HttpRequestParseMethodTest);
PTF_TEST_CASE(HttpRequestLayerParsingTest);
PTF_TEST_CASE(HttpRequestLayerCreationTest);
PTF_TEST_CASE(HttpRequestLayerEditTest);
PTF_TEST_CASE(HttpResponseParseStatusCodeTest);
PTF_TEST_CASE(HttpResponseParseVersionTest);
PTF_TEST_CASE(HttpResponseLayerParsingTest);
PTF_TEST_CASE(HttpResponseLayerCreationTest);
PTF_TEST_CASE(HttpResponseLayerEditTest);
PTF_TEST_CASE(HttpMalformedResponseTest);

// Implemented in PPPoETests.cpp
PTF_TEST_CASE(PPPoESessionLayerParsingTest);
PTF_TEST_CASE(PPPoESessionLayerCreationTest);
PTF_TEST_CASE(PPPoEDiscoveryLayerParsingTest);
PTF_TEST_CASE(PPPoEDiscoveryLayerCreateTest);

// Implemented in DnsTests.cpp
PTF_TEST_CASE(DnsLayerParsingTest);
PTF_TEST_CASE(DnsLayerQueryCreationTest);
PTF_TEST_CASE(DnsLayerResourceCreationTest);
PTF_TEST_CASE(DnsLayerEditTest);
PTF_TEST_CASE(DnsLayerRemoveResourceTest);
PTF_TEST_CASE(DnsOverTcpParsingTest);
PTF_TEST_CASE(DnsOverTcpCreationTest);
PTF_TEST_CASE(DnsLayerAddDnsKeyTest);

// Implemented in IcmpTests.cpp
PTF_TEST_CASE(IcmpParsingTest);
PTF_TEST_CASE(IcmpCreationTest);
PTF_TEST_CASE(IcmpEditTest);

// Implemented in SllNullLoopbackTests.cpp
PTF_TEST_CASE(SllPacketParsingTest);
PTF_TEST_CASE(SllPacketCreationTest);
PTF_TEST_CASE(NullLoopbackTest);

// Implemented in Sll2Tests.cpp
PTF_TEST_CASE(Sll2PacketParsingTest);
PTF_TEST_CASE(Sll2PacketCreationTest);

// Implemented in NflogTests.cpp
PTF_TEST_CASE(NflogPacketParsingTest);

// Implemented in GreTests.cpp
PTF_TEST_CASE(GreParsingTest);
PTF_TEST_CASE(GreCreationTest);
PTF_TEST_CASE(GreEditTest);

// Implemented in DhcpTests.cpp
PTF_TEST_CASE(DhcpParsingTest);
PTF_TEST_CASE(DhcpCreationTest);
PTF_TEST_CASE(DhcpEditTest);

// Implemented in SSLTests.cpp
PTF_TEST_CASE(SSLClientHelloParsingTest);
PTF_TEST_CASE(SSLExtensionWithZeroSizeTest);
PTF_TEST_CASE(SSLAppDataParsingTest);
PTF_TEST_CASE(SSLAlertParsingTest);
PTF_TEST_CASE(SSLMultipleRecordParsingTest);
PTF_TEST_CASE(SSLMultipleRecordParsing2Test);
PTF_TEST_CASE(SSLMultipleRecordParsing3Test);
PTF_TEST_CASE(SSLMultipleRecordParsing4Test);
PTF_TEST_CASE(SSLMultipleRecordParsing5Test);
PTF_TEST_CASE(SSLPartialCertificateParseTest);
PTF_TEST_CASE(SSLNewSessionTicketParseTest);
PTF_TEST_CASE(SSLMalformedPacketParsing);
PTF_TEST_CASE(TLS1_3ParsingTest);
PTF_TEST_CASE(TLSCipherSuiteTest);
PTF_TEST_CASE(ClientHelloTLSFingerprintTest);
PTF_TEST_CASE(ServerHelloTLSFingerprintTest);

// Implemented in IgmpTests.cpp
PTF_TEST_CASE(IgmpParsingTest);
PTF_TEST_CASE(IgmpCreateAndEditTest);
PTF_TEST_CASE(Igmpv3ParsingTest);
PTF_TEST_CASE(Igmpv3QueryCreateAndEditTest);
PTF_TEST_CASE(Igmpv3ReportCreateAndEditTest);

// Implemented in SipSdpTests.cpp
PTF_TEST_CASE(SipRequestParseMethodTest);
PTF_TEST_CASE(SipRequestLayerParsingTest);
PTF_TEST_CASE(SipRequestLayerCreationTest);
PTF_TEST_CASE(SipRequestLayerEditTest);
PTF_TEST_CASE(SipResponseParseStatusCodeTest);
PTF_TEST_CASE(SipResponseParseVersionCodeTest);
PTF_TEST_CASE(SipResponseLayerParsingTest);
PTF_TEST_CASE(SipResponseLayerCreationTest);
PTF_TEST_CASE(SipResponseLayerEditTest);
PTF_TEST_CASE(SdpLayerParsingTest);
PTF_TEST_CASE(SipNotSdpLayerParsingTest);
PTF_TEST_CASE(SdpLayerCreationTest);
PTF_TEST_CASE(SdpLayerEditTest);

// Implemented in RadiusTests.cpp
PTF_TEST_CASE(RadiusLayerParsingTest);
PTF_TEST_CASE(RadiusLayerCreationTest);
PTF_TEST_CASE(RadiusLayerEditTest);

// Implemented in GtpTests.cpp
PTF_TEST_CASE(GtpV1LayerParsingTest);
PTF_TEST_CASE(GtpV1LayerCreationTest);
PTF_TEST_CASE(GtpV1LayerEditTest);
PTF_TEST_CASE(GtpV2LayerParsingTest);
PTF_TEST_CASE(GtpV2LayerCreationTest);
PTF_TEST_CASE(GtpV2LayerEditTest);

// Implemented in BgpTests.cpp
PTF_TEST_CASE(BgpLayerParsingTest);
PTF_TEST_CASE(BgpLayerCreationTest);
PTF_TEST_CASE(BgpLayerEditTest);

// Implemented in SSHTests.cpp
PTF_TEST_CASE(SSHParsingTest);
PTF_TEST_CASE(SSHMalformedParsingTest);

// Implemented in IPSecTests.cpp
PTF_TEST_CASE(IPSecParsingTest);

// Implemented in DhcpV6Tests.cpp
PTF_TEST_CASE(DhcpV6ParsingTest);
PTF_TEST_CASE(DhcpV6CreationTest);
PTF_TEST_CASE(DhcpV6EditTest);

// Implemented in NtpTests.cpp
PTF_TEST_CASE(NtpMethodsTests);
PTF_TEST_CASE(NtpParsingV3Tests);
PTF_TEST_CASE(NtpParsingV4Tests);
PTF_TEST_CASE(NtpCreationTests);

// Implemented in TelnetTests.cpp
PTF_TEST_CASE(TelnetCommandParsingTests);
PTF_TEST_CASE(TelnetDataParsingTests);

// Implemented in IcmpV6Tests.cpp
PTF_TEST_CASE(IcmpV6ParsingTest);
PTF_TEST_CASE(IcmpV6CreationTest);
PTF_TEST_CASE(IcmpV6EditTest);

// Implemented in FtpTests.cpp
PTF_TEST_CASE(FtpParsingTests);
PTF_TEST_CASE(FtpCreationTests);
PTF_TEST_CASE(FtpEditTests);

// Implemented in LLCTests.cpp
PTF_TEST_CASE(LLCParsingTests);
PTF_TEST_CASE(LLCCreationTests);

// Implemented in StpTests.cpp
PTF_TEST_CASE(StpConfigurationParsingTests);
PTF_TEST_CASE(StpConfigurationCreationTests);
PTF_TEST_CASE(StpConfigurationEditTests);
PTF_TEST_CASE(StpTopologyChangeParsingTests);
PTF_TEST_CASE(StpTopologyChangeCreationTests);
PTF_TEST_CASE(StpTopologyChangeEditTests);
PTF_TEST_CASE(RapidStpParsingTests);
PTF_TEST_CASE(RapidStpCreationTests);
PTF_TEST_CASE(RapidStpEditTests);
PTF_TEST_CASE(MultipleStpParsingTests);
PTF_TEST_CASE(MultipleStpCreationTests);
PTF_TEST_CASE(MultipleStpEditTests);

// Implemented in SomeIpTests.cpp
PTF_TEST_CASE(SomeIpPortTest);
PTF_TEST_CASE(SomeIpParsingTest);
PTF_TEST_CASE(SomeIpCreationTest);
PTF_TEST_CASE(SomeIpTpParsingTest);
PTF_TEST_CASE(SomeIpTpCreationTest);
PTF_TEST_CASE(SomeIpTpEditTest);

// Implemented in SomeIpSdTests.cpp
PTF_TEST_CASE(SomeIpSdParsingTest);
PTF_TEST_CASE(SomeIpSdCreationTest);

// Implemented in WakeOnLanTests.cpp
PTF_TEST_CASE(WakeOnLanParsingTests);
PTF_TEST_CASE(WakeOnLanCreationTests);
PTF_TEST_CASE(WakeOnLanEditTests);

// Implemented in TpktTests.cpp
PTF_TEST_CASE(TpktLayerTest);

// Implemented in VrrpTests.cpp
PTF_TEST_CASE(VrrpParsingTest);
PTF_TEST_CASE(VrrpCreateAndEditTest);

// Implemented in CotpTests.cpp
PTF_TEST_CASE(CotpLayerTest);

// Implemented in S7commTests.cpp
PTF_TEST_CASE(S7CommLayerParsingTest);
PTF_TEST_CASE(S7CommLayerCreationTest);

// Implemented in SmtpTests.cpp
PTF_TEST_CASE(SmtpParsingTests);
PTF_TEST_CASE(SmtpCreationTests);
PTF_TEST_CASE(SmtpEditTests);

// Implemented in Asn1Tests.cpp
PTF_TEST_CASE(Asn1DecodingTest);
PTF_TEST_CASE(Asn1EncodingTest);
PTF_TEST_CASE(Asn1ObjectIdentifierTest);

// Implemented in LdapTests.cpp
PTF_TEST_CASE(LdapParsingTest);
PTF_TEST_CASE(LdapCreationTest);

// Implemented in WireGuardTests.cpp
PTF_TEST_CASE(WireGuardHandshakeInitParsingTest);
PTF_TEST_CASE(WireGuardHandshakeRespParsingTest);
PTF_TEST_CASE(WireGuardCookieReplyParsingTest);
PTF_TEST_CASE(WireGuardTransportDataParsingTest);
PTF_TEST_CASE(WireGuardCreationTest);
PTF_TEST_CASE(WireGuardEditTest);

// Implemented in CiscoHdlcTests.cpp
PTF_TEST_CASE(CiscoHdlcParsingTest);
PTF_TEST_CASE(CiscoHdlcLayerCreationTest);
PTF_TEST_CASE(CiscoHdlcLayerEditTest);
