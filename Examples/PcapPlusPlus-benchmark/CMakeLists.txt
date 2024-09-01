add_executable(BenchmarkExample benchmark.cpp)

target_link_libraries(BenchmarkExample PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(BenchmarkExample PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_INSTALL)
  install(
    TARGETS BenchmarkExample
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
