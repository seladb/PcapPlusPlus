cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-PacketParsing
	main.cpp
)

target_link_libraries(Tutorial-PacketParsing PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-PacketParsing PROPERTY CXX_STANDARD 11)
set_property(TARGET Tutorial-PacketParsing PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET Tutorial-PacketParsing PROPERTY CXX_EXTENSIONS OFF)

