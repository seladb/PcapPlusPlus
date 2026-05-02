if(PCAPPP_BUILD_TESTS)
  add_subdirectory(PcppTestFramework)
  add_subdirectory(PcppTestUtilities)
  add_subdirectory(Packet++Test)

  if(PCAPPP_BUILD_PCAPPP)
    # Only building Logger++ if Pcap++ is also being built since the logger requires Threads package.
    add_subdirectory(Logger++Test)
    add_subdirectory(Pcap++Test)
  endif()
endif()

if(PCAPPP_BUILD_FUZZERS)
  add_subdirectory(Fuzzers)
endif()
