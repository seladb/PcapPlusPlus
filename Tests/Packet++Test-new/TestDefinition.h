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
