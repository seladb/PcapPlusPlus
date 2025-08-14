add_executable(X509Toolkit main.cpp)

target_link_libraries(X509Toolkit PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(X509Toolkit PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  X509Toolkit
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}" RUNTIME_OUTPUT_NAME "X509Toolkit"
)

if(PCAPPP_INSTALL)
  install(TARGETS X509Toolkit EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
