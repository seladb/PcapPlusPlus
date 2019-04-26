cmake_minimum_required (VERSION 3.0)

add_executable(IPFragUtil
	main.cpp
)

target_link_libraries(IPFragUtil PUBLIC
	PcapPP
)

set_property(TARGET IPFragUtil PROPERTY CXX_STANDARD 14)
set_property(TARGET IPFragUtil PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET IPFragUtil PROPERTY CXX_EXTENSIONS OFF)

