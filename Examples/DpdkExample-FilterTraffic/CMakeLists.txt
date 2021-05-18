cmake_minimum_required (VERSION 3.0)

add_executable(DpdkTrafficFilter
	main.cpp
)

target_link_libraries(DpdkTrafficFilter PUBLIC
	PcapPP
)

set_property(TARGET DpdkTrafficFilter PROPERTY CXX_STANDARD 11)
set_property(TARGET DpdkTrafficFilter PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET DpdkTrafficFilter PROPERTY CXX_EXTENSIONS OFF)

