add_executable(PfRingTrafficFilter main.cpp)

target_link_libraries(PfRingTrafficFilter PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(PfRingTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
