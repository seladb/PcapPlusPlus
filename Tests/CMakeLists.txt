if(PCAPPP_BUILD_TESTS)
  add_subdirectory(PcppTestFramework)
  add_subdirectory(Packet++Test)

  if(PCAPPP_BUILD_PCAPPP)
    add_subdirectory(Pcap++Test)
  endif()
endif()

if(PCAPPP_BUILD_FUZZERS)
  add_subdirectory(Fuzzers)
endif()
