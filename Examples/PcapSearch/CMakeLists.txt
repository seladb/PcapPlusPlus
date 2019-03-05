cmake_minimum_required (VERSION 3.0)

add_executable(PcapSearch 
	main.cpp
)

target_link_libraries(PcapSearch PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET PcapSearch PROPERTY CXX_STANDARD 11)



