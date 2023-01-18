add_executable(Fuzzer FuzzTarget.cpp)

target_link_libraries(Fuzzer PUBLIC PcapPlusPlus::Pcap++)
