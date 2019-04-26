cmake_minimum_required (VERSION 3.0)

add_executable(HttpAnalyzer
	HttpStatsCollector.h
	main.cpp
)

target_link_libraries(HttpAnalyzer PUBLIC
	PcapPP
)

set_property(TARGET HttpAnalyzer PROPERTY CXX_STANDARD 14)
set_property(TARGET HttpAnalyzer PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET HttpAnalyzer PROPERTY CXX_EXTENSIONS OFF)

