add_executable(Tutorial-HelloWorld main.cpp)

target_link_libraries(Tutorial-HelloWorld PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-HelloWorld PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/1_packet.pcap" DESTINATION "${PCAPPP_BINARY_TUTORIAL_DIR}")
