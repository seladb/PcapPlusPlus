cmake_minimum_required (VERSION 3.0)

add_executable(Arping 
	main.cpp
)

target_link_libraries(Arping PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET Arping PROPERTY CXX_STANDARD 11)



