cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-LiveTraffic
	main.cpp
)

target_link_libraries(Tutorial-LiveTraffic PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-LiveTraffic PROPERTY CXX_STANDARD 11)
set_property(TARGET Tutorial-LiveTraffic PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


