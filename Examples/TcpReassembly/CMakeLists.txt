cmake_minimum_required (VERSION 3.0)

add_executable(TcpReassembly 
	main.cpp
)

target_link_libraries(TcpReassembly PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET TcpReassembly PROPERTY CXX_STANDARD 11)



