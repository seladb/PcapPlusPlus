add_executable(IcmpFileTransfer-catcher Common.cpp IcmpFileTransfer-catcher.cpp)

target_link_libraries(IcmpFileTransfer-catcher PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(IcmpFileTransfer-catcher PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IcmpFileTransfer-catcher PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS IcmpFileTransfer-catcher EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()

add_executable(IcmpFileTransfer-pitcher Common.cpp IcmpFileTransfer-pitcher.cpp)

target_link_libraries(IcmpFileTransfer-pitcher PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(IcmpFileTransfer-pitcher PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IcmpFileTransfer-pitcher PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS IcmpFileTransfer-pitcher EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
