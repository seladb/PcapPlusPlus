cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-PcapFiles
	main.cpp
)

target_link_libraries(Tutorial-PcapFiles PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-PcapFiles PROPERTY CXX_STANDARD 11)
set_property(TARGET Tutorial-PcapFiles PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


