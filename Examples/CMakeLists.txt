cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlusExamples)

add_subdirectory(Arping)
add_subdirectory(ArpSpoofing)
add_subdirectory(DNSResolver)
add_subdirectory(DnsSpoofing)
add_subdirectory(HttpAnalyzer)
add_subdirectory(IcmpFileTransfer)
add_subdirectory(IPDefragUtil)
add_subdirectory(IPFragUtil)
add_subdirectory(PcapPlusPlus-benchmark)
add_subdirectory(PcapPrinter)
add_subdirectory(PcapSearch)
add_subdirectory(PcapSplitter)
add_subdirectory(SSLAnalyzer)
add_subdirectory(TcpReassembly)
add_subdirectory(TLSFingerprinting)

add_subdirectory(Tutorials)

if(PCAPPP_USE_DPDK)
	add_subdirectory(DpdkExample-FilterTraffic)
	add_subdirectory(DpdkBridge)
	add_subdirectory(KniPong)
endif()

if(PCAPPP_USE_PF_RING)
	add_subdirectory(PfRingExample-FilterTraffic)
endif()


