add_executable(IPDefragUtil main.cpp)

target_link_libraries(IPDefragUtil PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(IPDefragUtil PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IPDefragUtil PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS IPDefragUtil EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
