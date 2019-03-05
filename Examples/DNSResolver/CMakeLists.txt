cmake_minimum_required (VERSION 3.0)

add_executable(DNSResolver
	main.cpp
)

target_link_libraries(DNSResolver PUBLIC
	PcapPP
)

set_property(TARGET DNSResolver PROPERTY CXX_STANDARD 11)
set_property(TARGET DNSResolver PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET DNSResolver PROPERTY CXX_EXTENSIONS OFF)
