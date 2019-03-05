cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlusExamples)

add_subdirectory(HttpAnalyzer)
add_subdirectory(PcapSplitter)
add_subdirectory(IPDefragUtil)
add_subdirectory(Tutorials)
add_subdirectory(PcapSearch)
add_subdirectory(PcapPlusPlus-benchmark)
add_subdirectory(DNSResolver)
add_subdirectory(IcmpFileTransfer)
add_subdirectory(PcapPrinter)
add_subdirectory(TcpReassembly)
add_subdirectory(DnsSpoofing)
add_subdirectory(Arping)
add_subdirectory(ArpSpoofing)
add_subdirectory(SSLAnalyzer)
add_subdirectory(IPFragUtil)

if(PCAPPP_USE_DPDK)
    add_subdirectory(DpdkExample-FilterTraffic)
    add_subdirectory(DpdkBridge)
endif()

if(PCAPPP_USE_PF_RING)
    add_subdirectory(PfRingExample-FilterTraffic)
endif()

#add_subdirectory(Tutorials/Tutorial-DpdkL2Fwd
#add_subdirectory(Tutorials/Tutorial-PacketCraftAndEdit
#add_subdirectory(Tutorials/Tutorial-PacketParsing
#add_subdirectory(Tutorials/Tutorial-PcapFiles
#add_subdirectory(Tutorials/Tutorial-HelloWorld
#add_subdirectory(Tutorials/Tutorial-LiveTraffic
