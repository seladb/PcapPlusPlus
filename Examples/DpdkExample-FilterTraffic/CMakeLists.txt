add_executable(DpdkTrafficFilter main.cpp)

target_link_libraries(DpdkTrafficFilter PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(DpdkTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS DpdkTrafficFilter EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
