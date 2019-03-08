cmake_minimum_required (VERSION 3.0)

add_executable(PcapPP-Test
    main.cpp
)

target_link_libraries(PcapPP-Test PUBLIC
    PcapPP
    debug-new
)

set_property(TARGET PcapPP-Test PROPERTY CXX_STANDARD 11)
set_property(TARGET PcapPP-Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Tests/bin")
set_property(TARGET PcapPP-Test PROPERTY CXX_EXTENSIONS OFF)

add_test(
    NAME Pcap++-Test
    COMMAND $<TARGET_FILE:PcapPP-Test> -n
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
)
