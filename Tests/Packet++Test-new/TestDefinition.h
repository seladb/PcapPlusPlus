#pragma once

#include "../PcppTestFramework2/PcppTestFramework.h"

// Implemented in EthAndArpTests.cpp
PTF_TEST_CASE(EthPacketCreation);
PTF_TEST_CASE(EthPacketPointerCreation);
PTF_TEST_CASE(EthAndArpPacketParsing);
PTF_TEST_CASE(ArpPacketCreation);

// Implemented in VlanTests.cpp
PTF_TEST_CASE(VlanParseAndCreation);

// Implemented in IPv4Tests.cpp
PTF_TEST_CASE(Ipv4PacketCreation);
PTF_TEST_CASE(Ipv4PacketParsing);
PTF_TEST_CASE(Ipv4FragmentationTest);
PTF_TEST_CASE(Ipv4OptionsParsingTest);
PTF_TEST_CASE(Ipv4OptionsEditTest);
PTF_TEST_CASE(Ipv4UdpChecksum);

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

// Implemented in PacketTests.cpp
PTF_TEST_CASE(InsertDataToPacket);
PTF_TEST_CASE(InsertVlanToPacket);
PTF_TEST_CASE(RemoveLayerTest);

// Implemented in HttpTests.cpp
PTF_TEST_CASE(HttpRequestLayerParsingTest);
PTF_TEST_CASE(HttpRequestLayerCreationTest);
PTF_TEST_CASE(HttpRequestLayerEditTest);
PTF_TEST_CASE(HttpResponseLayerParsingTest);
PTF_TEST_CASE(HttpResponseLayerCreationTest);
PTF_TEST_CASE(HttpResponseLayerEditTest);
