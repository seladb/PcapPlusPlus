cmake_minimum_required (VERSION 3.0)

add_executable(HttpAnalyzer
	HttpStatsCollector.h
	main.cpp
)

target_link_libraries(HttpAnalyzer PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET HttpAnalyzer PROPERTY CXX_STANDARD 11)



