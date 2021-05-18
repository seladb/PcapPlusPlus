cmake_minimum_required (VERSION 3.0)

add_executable(Packet++Test
	main.cpp
	Tests/BgpTests.cpp
	Tests/DhcpTests.cpp
	Tests/DnsTests.cpp
	Tests/EthAndArpTests.cpp
	Tests/GreTests.cpp
	Tests/GtpTests.cpp
	Tests/HttpTests.cpp
	Tests/IcmpTests.cpp
	Tests/IgmpTests.cpp
	Tests/IPSecTests.cpp
	Tests/IPv4Tests.cpp
	Tests/IPv6Tests.cpp
	Tests/PacketTests.cpp
	Tests/PacketUtilsTests.cpp
	Tests/PPPoETests.cpp
	Tests/RadiusTests.cpp
	Tests/SipSdpTests.cpp
	Tests/SllNullLoopbackTests.cpp
	Tests/SSHTests.cpp
	Tests/SSLTests.cpp
	Tests/TcpTests.cpp
	Tests/VlanMplsTests.cpp
	Utils/TestUtils.cpp
)

target_link_libraries(Packet++Test PUBLIC
	memplumber
	PcapPP
	PcppTestFramework
)

set_property(TARGET Packet++Test PROPERTY CXX_STANDARD 11)
set_property(TARGET Packet++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test PROPERTY CXX_EXTENSIONS OFF)

add_test(
	NAME Packet++Test
	COMMAND $<TARGET_FILE:Packet++Test>
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
)
