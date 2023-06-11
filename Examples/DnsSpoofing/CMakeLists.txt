add_executable(DnsSpoofing main.cpp)

target_link_libraries(DnsSpoofing PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(DnsSpoofing PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(DnsSpoofing PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS DnsSpoofing EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
