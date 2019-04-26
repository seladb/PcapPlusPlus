cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-DpdkL2Fwd
    main.cpp
    WorkerThread.cpp
    WorkerThread.h
)

target_link_libraries(Tutorial-DpdkL2Fwd PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-DpdkL2Fwd PROPERTY CXX_STANDARD 14)
set_property(TARGET Tutorial-DpdkL2Fwd PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET Tutorial-DpdkL2Fwd PROPERTY CXX_EXTENSIONS OFF)

