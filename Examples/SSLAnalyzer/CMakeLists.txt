add_executable(SSLAnalyzer main.cpp)

target_link_libraries(SSLAnalyzer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(SSLAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(SSLAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS SSLAnalyzer EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
