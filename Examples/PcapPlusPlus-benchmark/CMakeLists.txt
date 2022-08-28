add_executable(benchmark benchmark.cpp)

target_link_libraries(benchmark PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(benchmark PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
