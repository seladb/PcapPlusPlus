add_executable(KniPong main.cpp)

target_link_libraries(KniPong PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(KniPong PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(TARGETS KniPong EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
