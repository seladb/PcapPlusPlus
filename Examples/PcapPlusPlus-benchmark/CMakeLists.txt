add_executable(benchmark benchmark.cpp)

target_link_libraries(benchmark PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(benchmark PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(
    TARGETS benchmark
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
