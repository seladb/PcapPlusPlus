if(PCAPPP_BUILD_TESTS)
  add_subdirectory(Packet++Test)
  add_subdirectory(Pcap++Test)
  add_subdirectory(PcppTestFramework)
endif()

if(PCAPPP_BUILD_FUZZERS)
  add_subdirectory(Fuzzers)
endif()
