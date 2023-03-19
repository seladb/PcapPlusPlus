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
  Tests/PacketParsingTests.cpp
  Tests/PfRingTests.cpp
  Tests/RawSocketTests.cpp
  Tests/SystemUtilsTests.cpp
  Tests/TcpReassemblyTests.cpp)

target_link_libraries(
  Pcap++Test
  PUBLIC memplumber
         Pcap++
         PcppTestFramework
         EndianPortable)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Pcap++Test PRIVATE Getopt-for-Visual-Studio)
endif()

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(
    TARGET Pcap++Test
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:Pcap++Test> $<TARGET_FILE_DIR:Pcap++Test>
    COMMAND_EXPAND_LISTS)
endif()

set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Pcap++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")

add_test(
  NAME Pcap++Test
  COMMAND $<TARGET_FILE:Pcap++Test> -n
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
