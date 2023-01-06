add_executable(Tutorial-LiveTraffic main.cpp)

target_link_libraries(Tutorial-LiveTraffic PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-LiveTraffic PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
