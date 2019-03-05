cmake_minimum_required (VERSION 3.0)

add_executable(PfRingTrafficFilter 
	Common.h
	main.cpp
	PacketMatchingEngine.h
)

target_link_libraries(PfRingTrafficFilter PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET PfRingTrafficFilter PROPERTY CXX_STANDARD 11)



