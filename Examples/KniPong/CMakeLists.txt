cmake_minimum_required (VERSION 3.0)

add_executable(KniPong
	main.cpp
)

target_link_libraries(KniPong PUBLIC
	PcapPP
)

set_property(TARGET KniPong PROPERTY CXX_STANDARD 11)
set_property(TARGET KniPong PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET KniPong PROPERTY CXX_EXTENSIONS OFF)

