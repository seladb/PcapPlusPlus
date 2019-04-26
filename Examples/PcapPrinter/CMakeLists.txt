cmake_minimum_required (VERSION 3.0)

add_executable(PcapPrinter 
	main.cpp
)

target_link_libraries(PcapPrinter PUBLIC
	PcapPP
)

set_property(TARGET PcapPrinter PROPERTY CXX_STANDARD 14)
set_property(TARGET PcapPrinter PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET PcapPrinter PROPERTY CXX_EXTENSIONS OFF)

