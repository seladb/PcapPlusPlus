cmake_minimum_required (VERSION 3.0)

add_executable(IPDefragUtil
	main.cpp
)

target_link_libraries(IPDefragUtil PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET IPDefragUtil PROPERTY CXX_STANDARD 11)
set_property(TARGET IPDefragUtil PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")

