add_executable(FuzzPacketParse FuzzPacketParse.cpp)

target_compile_options(FuzzPacketParse PRIVATE -fsanitize=fuzzer,address)
target_link_options(FuzzPacketParse PRIVATE -fsanitize=fuzzer,address)
target_link_libraries(FuzzPacketParse PRIVATE Pcap++)
