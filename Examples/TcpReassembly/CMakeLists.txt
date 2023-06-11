add_executable(TcpReassembly main.cpp)

target_link_libraries(TcpReassembly PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(TcpReassembly PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(TcpReassembly PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS TcpReassembly EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
