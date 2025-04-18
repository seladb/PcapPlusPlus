#pragma once

#include "PcppTestFramework.h"

// Implemented in IpMac.cpp
PTF_TEST_CASE(TestIPAddress);
PTF_TEST_CASE(TestMacAddress);
PTF_TEST_CASE(TestLRUList);
PTF_TEST_CASE(TestGeneralUtils);
PTF_TEST_CASE(TestGetMacAddress);
PTF_TEST_CASE(TestIPv4Network);
PTF_TEST_CASE(TestIPv6Network);
PTF_TEST_CASE(TestIPNetwork);

// Implemented in ObjectPoolTests.cpp
PTF_TEST_CASE(TestObjectPool);

// Implemented in LoggerTests.cpp
PTF_TEST_CASE(TestLogger);
PTF_TEST_CASE(TestLoggerMultiThread);

// Implemented in FileTests.cpp
PTF_TEST_CASE(TestPcapFileReadWrite);
PTF_TEST_CASE(TestPcapFilePrecision);
PTF_TEST_CASE(TestPcapSllFileReadWrite);
PTF_TEST_CASE(TestPcapSll2FileReadWrite);
PTF_TEST_CASE(TestPcapRawIPFileReadWrite);
PTF_TEST_CASE(TestPcapFileAppend);
PTF_TEST_CASE(TestPcapNgFileReadWrite);
PTF_TEST_CASE(TestPcapNgFileReadWriteAdv);
PTF_TEST_CASE(TestPcapNgFileTooManyInterfaces);
PTF_TEST_CASE(TestPcapFileReadLinkTypeIPv6);
PTF_TEST_CASE(TestPcapFileReadLinkTypeIPv4);
PTF_TEST_CASE(TestSolarisSnoopFileRead);
PTF_TEST_CASE(TestPcapNgFilePrecision);
PTF_TEST_CASE(TestPcapFileWriterDeviceDestructor);

// Implemented in LiveDeviceTests.cpp
PTF_TEST_CASE(TestPcapLiveDeviceList);
PTF_TEST_CASE(TestPcapLiveDeviceListSearch);
PTF_TEST_CASE(TestPcapLiveDevice);
PTF_TEST_CASE(TestPcapLiveDeviceClone);
PTF_TEST_CASE(TestPcapLiveDeviceNoNetworking);
PTF_TEST_CASE(TestPcapLiveDeviceStatsMode);
PTF_TEST_CASE(TestPcapLiveDeviceBlockingMode);
PTF_TEST_CASE(TestPcapLiveDeviceWithLambda);
PTF_TEST_CASE(TestPcapLiveDeviceBlockingModeWithLambda);
PTF_TEST_CASE(TestPcapLiveDeviceSpecialCfg);
PTF_TEST_CASE(TestWinPcapLiveDevice);
PTF_TEST_CASE(TestSendPacket);
PTF_TEST_CASE(TestSendPackets);
PTF_TEST_CASE(TestMtuSize);
PTF_TEST_CASE(TestRemoteCapture);

// Implemented in FilterTests.cpp
PTF_TEST_CASE(TestPcapFilters_MatchStatic);
PTF_TEST_CASE(TestPcapFiltersLive);
PTF_TEST_CASE(TestPcapFilters_General_BPFStr);
PTF_TEST_CASE(TestPcapFiltersOffline);
PTF_TEST_CASE(TestPcapFilters_LinkLayer);

// Implemented in PacketParsingTests.cpp
PTF_TEST_CASE(TestHttpRequestParsing);
PTF_TEST_CASE(TestHttpResponseParsing);
PTF_TEST_CASE(TestPrintPacketAndLayers);
PTF_TEST_CASE(TestDnsParsing);

// Implemented in TcpReassemblyTests.cpp
PTF_TEST_CASE(TestTcpReassemblySanity);
PTF_TEST_CASE(TestTcpReassemblyRetran);
PTF_TEST_CASE(TestTcpReassemblyMissingData);
PTF_TEST_CASE(TestTcpReassemblyOutOfOrder);
PTF_TEST_CASE(TestTcpReassemblyOOOWithManualClose);
PTF_TEST_CASE(TestTcpReassemblyWithFIN_RST);
PTF_TEST_CASE(TestTcpReassemblyMalformedPkts);
PTF_TEST_CASE(TestTcpReassemblyMultipleConns);
PTF_TEST_CASE(TestTcpReassemblyIPv6);
PTF_TEST_CASE(TestTcpReassemblyIPv6MultConns);
PTF_TEST_CASE(TestTcpReassemblyIPv6_OOO);
PTF_TEST_CASE(TestTcpReassemblyCleanup);
PTF_TEST_CASE(TestTcpReassemblyMaxOOOFrags);
PTF_TEST_CASE(TestTcpReassemblyMaxSeq);
PTF_TEST_CASE(TestTcpReassemblyDisableOOOCleanup);
PTF_TEST_CASE(TestTcpReassemblyTimeStamps);
PTF_TEST_CASE(TestTcpReassemblyFinReset);
PTF_TEST_CASE(TestTcpReassemblyHighPrecision);

// Implemented in IPFragmentationTests.cpp
PTF_TEST_CASE(TestIPFragmentationSanity);
PTF_TEST_CASE(TestIPFragOutOfOrder);
PTF_TEST_CASE(TestIPFragPartialData);
PTF_TEST_CASE(TestIPFragMultipleFrags);
PTF_TEST_CASE(TestIPFragMapOverflow);
PTF_TEST_CASE(TestIPFragRemove);
PTF_TEST_CASE(TestIPFragWithPadding);

// Implemented in PfRingTests.cpp
PTF_TEST_CASE(TestPfRingDevice);
PTF_TEST_CASE(TestPfRingDeviceSingleChannel);
PTF_TEST_CASE(TestPfRingMultiThreadAllCores);
PTF_TEST_CASE(TestPfRingMultiThreadSomeCores);
PTF_TEST_CASE(TestPfRingSendPacket);
PTF_TEST_CASE(TestPfRingSendPackets);
PTF_TEST_CASE(TestPfRingFilters);

// Implemented in DpdkTests.cpp
PTF_TEST_CASE(TestDpdkInitDevice);
PTF_TEST_CASE(TestDpdkDevice);
PTF_TEST_CASE(TestDpdkMultiThread);
PTF_TEST_CASE(TestDpdkDeviceSendPackets);
PTF_TEST_CASE(TestDpdkDeviceWorkerThreads);
PTF_TEST_CASE(TestDpdkMbufRawPacket);

// Implemented in KniTests.cpp
PTF_TEST_CASE(TestKniDevice);
PTF_TEST_CASE(TestKniDeviceSendReceive);

// Implemented in RawSocketTests.cpp
PTF_TEST_CASE(TestRawSockets);

// Implemented in SystemUtilsTests.cpp
PTF_TEST_CASE(TestSystemCoreUtils);

// Implemented in XdpTest.cpp
PTF_TEST_CASE(TestXdpDeviceReceivePackets);
PTF_TEST_CASE(TestXdpDeviceSendPackets);
PTF_TEST_CASE(TestXdpDeviceNonDefaultConfig);
PTF_TEST_CASE(TestXdpDeviceInvalidConfig);
