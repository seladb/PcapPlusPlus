#pragma once

#include "../PcppTestFramework2/PcppTestFramework.h"

// Implemented in EthAndArpTests.cpp
PTF_TEST_CASE(EthPacketCreation);
PTF_TEST_CASE(EthPacketPointerCreation);
PTF_TEST_CASE(EthAndArpPacketParsing);
PTF_TEST_CASE(ArpPacketCreation);

// Implemented in BlanTests.cpp
PTF_TEST_CASE(VlanParseAndCreation);