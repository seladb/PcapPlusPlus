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

// Implemented in LiveDeviceTests.cpp
PTF_TEST_CASE(TestPcapLiveDeviceList);
PTF_TEST_CASE(TestPcapLiveDeviceListSearch);
PTF_TEST_CASE(TestPcapLiveDevice);
PTF_TEST_CASE(TestPcapLiveDeviceNoNetworking);
PTF_TEST_CASE(TestPcapLiveDeviceStatsMode);
PTF_TEST_CASE(TestPcapLiveDeviceBlockingMode);
PTF_TEST_CASE(TestPcapLiveDeviceSpecialCfg);
PTF_TEST_CASE(TestWinPcapLiveDevice);

// Implemented in FilterTests.cpp
PTF_TEST_CASE(TestPcapFiltersLive);
PTF_TEST_CASE(TestPcapFilters_General_BPFStr);
PTF_TEST_CASE(TestPcapFiltersOffline);
