add_executable(IPFragUtil main.cpp)

target_link_libraries(IPFragUtil PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(IPFragUtil PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IPFragUtil PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS IPFragUtil EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
