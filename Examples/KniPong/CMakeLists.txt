add_executable(KniPong main.cpp)

target_link_libraries(KniPong PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(KniPong PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         "${CMAKE_BINARY_DIR}/examples_bin")
