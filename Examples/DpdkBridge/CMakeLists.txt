add_executable(DpdkBridge main.cpp)

target_link_libraries(DpdkBridge PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(DpdkBridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS DpdkBridge EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
