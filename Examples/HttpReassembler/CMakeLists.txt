add_executable(HttpReassembler main.cpp)

target_link_libraries(HttpReassembler PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(HttpReassembler PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(HttpReassembler PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(
    TARGETS HttpReassembler
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
