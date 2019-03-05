cmake_minimum_required (VERSION 3.0)

add_executable(DpdkBridge
	AppWorkerThread.h
	Common.h
	main.cpp
)

target_link_libraries(DpdkBridge PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET DpdkBridge PROPERTY CXX_STANDARD 11)



