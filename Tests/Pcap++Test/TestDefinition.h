#pragma once

#include "../PcppTestFramework/PcppTestFramework.h"

// Implemented in IpMac.cpp
PTF_TEST_CASE(TestIPAddress);
PTF_TEST_CASE(TestMacAddress);

// Implemented in FileTests.cpp
PTF_TEST_CASE(TestPcapFileReadWrite);
PTF_TEST_CASE(TestPcapSllFileReadWrite);
PTF_TEST_CASE(TestPcapRawIPFileReadWrite);
PTF_TEST_CASE(TestPcapFileAppend);
PTF_TEST_CASE(TestPcapNgFileReadWrite);
PTF_TEST_CASE(TestPcapNgFileReadWriteAdv);

