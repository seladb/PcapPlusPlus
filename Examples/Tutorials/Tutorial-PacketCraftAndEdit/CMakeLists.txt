add_executable(Tutorial-PacketCraftAndEdit main.cpp)

target_link_libraries(Tutorial-PacketCraftAndEdit PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-PacketCraftAndEdit PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/1_http_packet.pcap" DESTINATION "${PCAPPP_BINARY_TUTORIAL_DIR}")
