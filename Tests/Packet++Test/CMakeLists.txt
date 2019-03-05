cmake_minimum_required (VERSION 3.0)

add_executable(PacketPP-Test
	main.cpp
)

target_link_libraries(PacketPP-Test PUBLIC
	PcapPP
    debug-new
)

set_property(TARGET PacketPP-Test PROPERTY CXX_STANDARD 11)
set_property(TARGET PacketPP-Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Tests/bin")
set_property(TARGET PacketPP-Test PROPERTY CXX_EXTENSIONS OFF)

add_test(
    NAME Packet++-Test
    COMMAND $<TARGET_FILE:PacketPP-Test>
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
)
