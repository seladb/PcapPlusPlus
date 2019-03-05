cmake_minimum_required (VERSION 3.0)

add_executable(IcmpFileTransfer-catcher
	Common.cpp
	Common.h
	IcmpFileTransfer-catcher.cpp
)

target_link_libraries(IcmpFileTransfer-catcher PUBLIC
	PcapPP
)

set_property(TARGET IcmpFileTransfer-catcher PROPERTY CXX_STANDARD 11)
set_property(TARGET IcmpFileTransfer-catcher PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET IcmpFileTransfer-catcher PROPERTY CXX_EXTENSIONS OFF)

add_executable(IcmpFileTransfer-pitcher
	Common.cpp
	Common.h
	IcmpFileTransfer-pitcher.cpp
)

target_link_libraries(IcmpFileTransfer-pitcher PUBLIC
	PcapPP
)

set_property(TARGET IcmpFileTransfer-pitcher PROPERTY CXX_STANDARD 11)
set_property(TARGET IcmpFileTransfer-pitcher PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")
set_property(TARGET IcmpFileTransfer-pitcher PROPERTY CXX_EXTENSIONS OFF)
