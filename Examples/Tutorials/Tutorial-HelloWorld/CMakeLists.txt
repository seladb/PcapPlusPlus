cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-HelloWorld
	main.cpp
)

target_link_libraries(Tutorial-HelloWorld PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-HelloWorld PROPERTY CXX_STANDARD 14)
set_property(TARGET Tutorial-HelloWorld PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET Tutorial-HelloWorld PROPERTY CXX_EXTENSIONS OFF)

