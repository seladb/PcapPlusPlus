cmake_minimum_required (VERSION 3.0)

add_executable(PcapSearch 
	main.cpp
)

target_link_libraries(PcapSearch PUBLIC
	PcapPP
)

set_property(TARGET PcapSearch PROPERTY CXX_STANDARD 14)
set_property(TARGET PcapSearch PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET PcapSearch PROPERTY CXX_EXTENSIONS OFF)

