cmake_minimum_required (VERSION 3.0)

add_executable(PcapSplitter 
	ConnectionSplitters.h
	IPPortSplitters.h
	main.cpp
	SimpleSplitters.h
	Splitters.h
)

target_link_libraries(PcapSplitter PUBLIC
	PcapPP
)

set_property(TARGET PcapSplitter PROPERTY CXX_STANDARD 11)
set_property(TARGET PcapSplitter PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


