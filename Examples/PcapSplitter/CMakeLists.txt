add_executable(PcapSplitter main.cpp)

target_link_libraries(PcapSplitter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(PcapSplitter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapSplitter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS PcapSplitter EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
