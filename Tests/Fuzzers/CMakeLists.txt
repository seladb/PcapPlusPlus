find_package(Fuzzer REQUIRED)

add_executable(FuzzTarget FuzzTarget.cpp)

target_link_libraries(FuzzTarget PRIVATE Pcap++ Fuzzer::Fuzzer)
