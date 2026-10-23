add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(hash-library)
add_subdirectory(json)
add_subdirectory(LightPcapNg)

if(PCAPPP_BUILD_TESTS OR PCAPPP_BUILD_FUZZERS OR PCAPPP_BUILD_EXAMPLES)
  # Only used in examples and tests
  add_subdirectory(MemPlumber/MemPlumber)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
  )
endif()
