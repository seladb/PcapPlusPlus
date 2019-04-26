cmake_minimum_required (VERSION 3.0)

add_executable(TcpReassembly 
	main.cpp
)

target_link_libraries(TcpReassembly PUBLIC
	PcapPP
)

set_property(TARGET TcpReassembly PROPERTY CXX_STANDARD 14)
set_property(TARGET TcpReassembly PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET TcpReassembly PROPERTY CXX_EXTENSIONS OFF)

