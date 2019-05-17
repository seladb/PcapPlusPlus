cmake_minimum_required (VERSION 3.0)

add_executable(Arping 
	main.cpp
)

target_link_libraries(Arping PUBLIC
	PcapPP
)

set_property(TARGET Arping PROPERTY CXX_STANDARD 11)
set_property(TARGET Arping PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET Arping PROPERTY CXX_EXTENSIONS OFF)

