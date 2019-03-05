cmake_minimum_required (VERSION 3.0)

add_executable(DnsSpoofing 
	main.cpp
)

target_link_libraries(DnsSpoofing PUBLIC
	PcapPP
)

set_property(TARGET DnsSpoofing PROPERTY CXX_STANDARD 11)
set_property(TARGET DnsSpoofing PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


