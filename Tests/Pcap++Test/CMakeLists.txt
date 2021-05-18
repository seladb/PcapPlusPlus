cmake_minimum_required (VERSION 3.0)

add_executable(Pcap++Test
	main.cpp
	Common/TestUtils.cpp
	Tests/DpdkTests.cpp
	Tests/FileTests.cpp
	Tests/FilterTests.cpp
	Tests/IPFragmentationTests.cpp
	Tests/IpMacTests.cpp
	Tests/KniTests.cpp
	Tests/LiveDeviceTests.cpp
	Tests/PacketParsingTests.cpp
	Tests/PfRingTests.cpp
	Tests/RawSocketTests.cpp
	Tests/TcpReassemblyTests.cpp
)

target_link_libraries(Pcap++Test PUBLIC
	memplumber
	PcapPP
	PcppTestFramework
)

set_property(TARGET Pcap++Test PROPERTY CXX_STANDARD 11)
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY CXX_EXTENSIONS OFF)

add_test(
	NAME Pcap++Test
	COMMAND $<TARGET_FILE:Pcap++Test> -n
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
)
