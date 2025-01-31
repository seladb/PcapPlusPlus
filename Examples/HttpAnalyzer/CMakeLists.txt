add_executable(HttpAnalyzer main.cpp)

target_link_libraries(HttpAnalyzer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(HttpAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(HttpAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS HttpAnalyzer EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
