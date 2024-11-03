cmake_minimum_required(VERSION 3.14)

project(PcapPlusPlusExamples)

set(CMAKE_PROJECT_HOMEPAGE_URL "https://pcapplusplus.github.io/")

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

if(TARGET Pcap++)
  # Are we building from the PcapPlusPlus project ??
  message(STATUS "Building Example from PcapPlusPlus project")
  # Alias the project to make it compatible with imported package
  add_library(PcapPlusPlus::Pcap++ ALIAS Pcap++)
else()
  find_package(PcapPlusPlus CONFIG REQUIRED)
  message(STATUS "Using Pcap++ ${PcapPlusPlus_VERSION}")
  message(STATUS "Include dir: ${PcapPlusPlus_INCLUDE_DIR}")
endif()

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

if(PCAPPP_BUILD_TUTORIALS)
  set(PCAPPP_BINARY_TUTORIAL_DIR ${CMAKE_BINARY_DIR}/tutorials_bin)
  add_subdirectory(Tutorials)
endif()

if(PCAPPP_USE_DPDK)
  add_subdirectory(DpdkExample-FilterTraffic)
  add_subdirectory(DpdkBridge)
  if(PCAPPP_USE_DPDK_KNI)
    add_subdirectory(KniPong)
  endif()
endif()

if(PCAPPP_USE_PF_RING)
  add_subdirectory(PfRingExample-FilterTraffic)
endif()

if(PCAPPP_USE_XDP)
  add_subdirectory(XdpExample-FilterTraffic)
endif()
