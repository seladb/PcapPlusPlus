add_executable(XdpTrafficFilter main.cpp)

target_link_libraries(XdpTrafficFilter PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(XdpTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS XdpTrafficFilter EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
