add_executable(
  Pcap++Test
  main.cpp
  Common/TestUtils.cpp
  $<$<BOOL:${PCAPPP_USE_DPDK}>:Tests/DpdkTests.cpp>
  Tests/LoggerTests.cpp
  Tests/FileTests.cpp
  Tests/FilterTests.cpp
  Tests/IPFragmentationTests.cpp
  Tests/IpMacTests.cpp
  $<$<BOOL:${PCAPPP_USE_DPDK}>:Tests/KniTests.cpp>
  Tests/LiveDeviceTests.cpp
  Tests/PacketParsingTests.cpp
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:Tests/PfRingTests.cpp>
  Tests/RawSocketTests.cpp
  Tests/TcpReassemblyTests.cpp)

target_link_libraries(Pcap++Test PUBLIC memplumber Pcap++ PcppTestFramework
                                        EndianPortable)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(Pcap++Test PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY
                                        "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG
                                        "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE
                                        "${CMAKE_CURRENT_SOURCE_DIR}/Bin")

add_test(
  NAME Pcap++Test
  COMMAND $<TARGET_FILE:Pcap++Test> -n
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
