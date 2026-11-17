add_executable(PcapSerializer main.cpp)

target_link_libraries(PcapSerializer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(PcapSerializer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapSerializer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS PcapSerializer EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
