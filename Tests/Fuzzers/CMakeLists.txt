add_executable(Fuzzer FuzzTarget.cpp)

target_link_libraries(Fuzzer PRIVATE Pcap++ -fsanitize=fuzzer,address)
