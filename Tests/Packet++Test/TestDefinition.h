#pragma once

#include "PcppTestFramework.h"

// Implemented in EthAndArpTests.cpp
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
PTF_TEST_CASE(TcpPacketWithOptionsParsing2);
PTF_TEST_CASE(TcpMalformedPacketParsing);
PTF_TEST_CASE(TcpPacketCreation);
PTF_TEST_CASE(TcpPacketCreation2);

// Implemented in PacketUtilsTests.cpp
PTF_TEST_CASE(PacketUtilsHash5TupleUdp);
PTF_TEST_CASE(PacketUtilsHash5TupleTcp);
PTF_TEST_CASE(PacketUtilsHash5TupleIPv6);

// Implemented in PacketTests.cpp
PTF_TEST_CASE(InsertDataToPacket);
PTF_TEST_CASE(InsertVlanToPacket);
PTF_TEST_CASE(RemoveLayerTest);
PTF_TEST_CASE(CopyLayerAndPacketTest);
PTF_TEST_CASE(PacketLayerLookupTest);
PTF_TEST_CASE(RawPacketTimeStampSetterTest);
PTF_TEST_CASE(ParsePartialPacketTest);
PTF_TEST_CASE(PacketTrailerTest);
PTF_TEST_CASE(ResizeLayerTest);

// Implemented in HttpTests.cpp
PTF_TEST_CASE(HttpRequestLayerParsingTest);
PTF_TEST_CASE(HttpRequestLayerCreationTest);
PTF_TEST_CASE(HttpRequestLayerEditTest);
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

// Implemented in IcmpTests.cpp
PTF_TEST_CASE(IcmpParsingTest);
PTF_TEST_CASE(IcmpCreationTest);
PTF_TEST_CASE(IcmpEditTest);

// Implemented in SllNullLoopbackTests.cpp
PTF_TEST_CASE(SllPacketParsingTest);
PTF_TEST_CASE(SllPacketCreationTest);
PTF_TEST_CASE(NullLoopbackTest);

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
PTF_TEST_CASE(SSLAppDataParsingTest);
PTF_TEST_CASE(SSLAlertParsingTest);
PTF_TEST_CASE(SSLMultipleRecordParsingTest);
PTF_TEST_CASE(SSLMultipleRecordParsing2Test);
PTF_TEST_CASE(SSLMultipleRecordParsing3Test);
PTF_TEST_CASE(SSLMultipleRecordParsing4Test);
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
PTF_TEST_CASE(SipRequestLayerParsingTest);
PTF_TEST_CASE(SipRequestLayerCreationTest);
PTF_TEST_CASE(SipRequestLayerEditTest);
PTF_TEST_CASE(SipResponseLayerParsingTest);
PTF_TEST_CASE(SipResponseLayerCreationTest);
PTF_TEST_CASE(SipResponseLayerEditTest);
PTF_TEST_CASE(SdpLayerParsingTest);
PTF_TEST_CASE(SdpLayerCreationTest);
PTF_TEST_CASE(SdpLayerEditTest);

// Implemented in RadiusTests.cpp
PTF_TEST_CASE(RadiusLayerParsingTest);
PTF_TEST_CASE(RadiusLayerCreationTest);
PTF_TEST_CASE(RadiusLayerEditTest);

// Implemented in GtpTests.cpp
PTF_TEST_CASE(GtpLayerParsingTest);
PTF_TEST_CASE(GtpLayerCreationTest);
PTF_TEST_CASE(GtpLayerEditTest);

// Implemented in BgpTests.cpp
PTF_TEST_CASE(BgpLayerParsingTest);
PTF_TEST_CASE(BgpLayerCreationTest);
PTF_TEST_CASE(BgpLayerEditTest);

// Implemented in SSHTests.cpp
PTF_TEST_CASE(SSHParsingTest);
PTF_TEST_CASE(SSHMalformedParsingTest);

// Implemented in IPSec.cpp
PTF_TEST_CASE(IPSecParsingTest);
