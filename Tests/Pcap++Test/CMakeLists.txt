add_executable(
  Pcap++Test
  Common/TestUtils.cpp
  main.cpp
  Tests/DpdkTests.cpp
  Tests/FileTests.cpp
  Tests/FilterTests.cpp
  Tests/IPFragmentationTests.cpp
  Tests/IpMacTests.cpp
  Tests/KniTests.cpp
  Tests/LiveDeviceTests.cpp
  Tests/LoggerTests.cpp
  Tests/ObjectPoolTests.cpp
  Tests/PacketParsingTests.cpp
  Tests/PfRingTests.cpp
  Tests/RawSocketTests.cpp
  Tests/SystemUtilsTests.cpp
  Tests/TcpReassemblyTests.cpp
  Tests/XdpTests.cpp
)

target_link_libraries(Pcap++Test PUBLIC memplumber Pcap++ PcppTestFramework EndianPortable)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Pcap++Test PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")

add_test(NAME Pcap++Test COMMAND $<TARGET_FILE:Pcap++Test> -n WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
