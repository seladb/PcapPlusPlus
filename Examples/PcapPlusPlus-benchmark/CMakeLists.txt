cmake_minimum_required (VERSION 3.0)

add_executable(benchmark 
	benchmark.cpp
)

target_link_libraries(benchmark PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET benchmark PROPERTY CXX_STANDARD 11)
set_property(TARGET benchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


