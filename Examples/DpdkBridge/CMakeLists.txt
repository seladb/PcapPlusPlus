add_executable(DpdkBridge main.cpp)

target_link_libraries(DpdkBridge PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(DpdkBridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            "${PCAPPP_BINARY_EXAMPLES_DIR}")
