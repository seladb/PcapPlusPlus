cmake_minimum_required (VERSION 3.0)

add_executable(Tutorial-PacketCraftAndEdit
	main.cpp
)

target_link_libraries(Tutorial-PacketCraftAndEdit PUBLIC
	PcapPP
)

set_property(TARGET Tutorial-PacketCraftAndEdit PROPERTY CXX_STANDARD 11)
set_property(TARGET Tutorial-PacketCraftAndEdit PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Examples/bin")


