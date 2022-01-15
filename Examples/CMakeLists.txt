cmake_minimum_required(VERSION 3.12)

project(PcapPlusPlusExamples)

set(CMAKE_PROJECT_HOMEPAGE_URL "https://pcapplusplus.github.io/")

if(TARGET PcapPP)
  # Are we building from the PcapPP project ??
  message(STATUS "Building Example from Pcap++ project")
  # Alias the project to make it compatible with imported package
  add_library(PcapPlusPlus::PcapPP ALIAS PcapPP)
else()
  find_package(PcapPlusPlus CONFIG REQUIRED)
  message(STATUS "Using Pcap++ ${PcapPlusPlus_VERSION}")
  message(STATUS "Include dir: ${PcapPlusPlus_INCLUDE_DIR}")
endif()

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

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
