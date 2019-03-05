cmake_minimum_required (VERSION 3.0)

add_executable(DpdkTrafficFilter 
	AppWorkerThread.h
	Common.h
	main.cpp
	PacketMatchingEngine.h
)

target_link_libraries(DpdkTrafficFilter PUBLIC
	PcapPP
	CommonPP
	PacketPP
)

set_property(TARGET DpdkTrafficFilter PROPERTY CXX_STANDARD 11)
set_property(TARGET DpdkTrafficFilter PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


