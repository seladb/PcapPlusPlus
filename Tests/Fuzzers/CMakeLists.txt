add_executable(FuzzTarget FuzzTarget.cpp)

target_link_libraries(FuzzTarget PRIVATE Pcap++ -fsanitize=fuzzer)
