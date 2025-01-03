add_executable(Arping main.cpp)

target_link_libraries(Arping PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Arping PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(Arping PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS Arping EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
