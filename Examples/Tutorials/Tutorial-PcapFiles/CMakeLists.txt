add_executable(Tutorial-PcapFiles main.cpp)

target_link_libraries(Tutorial-PcapFiles PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-PcapFiles PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/input.pcap" DESTINATION "${PCAPPP_BINARY_TUTORIAL_DIR}")
