add_executable(FuzzTarget FuzzTarget.cpp)
target_link_libraries(FuzzTarget PRIVATE Pcap++ -fsanitize=fuzzer)
target_compile_definitions(FuzzTarget PUBLIC FILE_EXT=".pcap")
target_include_directories(FuzzTarget PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

add_executable(FuzzTargetNg FuzzTarget.cpp)
target_link_libraries(FuzzTargetNg PRIVATE Pcap++ -fsanitize=fuzzer)
target_compile_definitions(FuzzTargetNg PUBLIC FILE_EXT=".pcapng")
target_include_directories(FuzzTargetNg PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

add_executable(FuzzTargetSnoop FuzzTarget.cpp)
target_link_libraries(FuzzTargetSnoop PRIVATE Pcap++ -fsanitize=fuzzer)
target_compile_definitions(FuzzTargetSnoop PUBLIC FILE_EXT=".snoop")
target_include_directories(FuzzTargetSnoop PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

add_executable(FuzzWriter FuzzWriter.cpp)
target_link_libraries(FuzzWriter PRIVATE Pcap++ -fsanitize=fuzzer)
target_compile_definitions(FuzzWriter PUBLIC FILE_EXT=".pcap" NG_WRITER)

add_executable(FuzzWriterNg FuzzWriter.cpp)
target_link_libraries(FuzzWriterNg PRIVATE Pcap++ -fsanitize=fuzzer)
target_compile_definitions(FuzzWriterNg PUBLIC FILE_EXT=".pcapng")
