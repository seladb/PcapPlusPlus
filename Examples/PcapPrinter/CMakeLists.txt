cmake_minimum_required (VERSION 3.0)

add_executable(PcapPrinter 
	main.cpp
)

target_link_libraries(PcapPrinter PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET PcapPrinter PROPERTY CXX_STANDARD 11)



