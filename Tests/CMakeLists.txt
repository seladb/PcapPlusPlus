add_subdirectory(Packet++Test)
add_subdirectory(Pcap++Test)
add_subdirectory(PcppTestFramework)

if(PCAPPP_BUILD_EXAMPLES)
  add_subdirectory(ExamplesTest)
endif()

if(PCAPPP_BUILD_FUZZERS)
  add_subdirectory(Fuzzers)
endif()
