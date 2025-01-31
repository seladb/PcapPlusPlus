add_executable(PcapPrinter main.cpp)

target_link_libraries(PcapPrinter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(PcapPrinter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapPrinter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS PcapPrinter EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
