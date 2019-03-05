cmake_minimum_required (VERSION 3.0)

add_executable(ArpSpoofing 
	main.cpp
)

target_link_libraries(ArpSpoofing PUBLIC
	PcapPP
)

set_property(TARGET ArpSpoofing PROPERTY CXX_STANDARD 11)
set_property(TARGET ArpSpoofing PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


