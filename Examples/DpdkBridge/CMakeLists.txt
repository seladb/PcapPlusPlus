cmake_minimum_required (VERSION 3.0)

add_executable(DpdkBridge
	AppWorkerThread.h
	Common.h
	main.cpp
)

target_link_libraries(DpdkBridge PUBLIC
	PcapPP
)

set_property(TARGET DpdkBridge PROPERTY CXX_STANDARD 11)
set_property(TARGET DpdkBridge PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET DpdkBridge PROPERTY CXX_EXTENSIONS OFF)
