cmake_minimum_required (VERSION 3.0)

add_executable(SSLAnalyzer 
	SSLStatsCollector.h
	main.cpp
)

target_link_libraries(SSLAnalyzer PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET SSLAnalyzer PROPERTY CXX_STANDARD 11)



