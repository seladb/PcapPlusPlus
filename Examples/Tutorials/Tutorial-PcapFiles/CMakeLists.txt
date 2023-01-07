add_executable(Tutorial-PcapFiles main.cpp)

target_link_libraries(Tutorial-PcapFiles PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-PacketParsing PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
