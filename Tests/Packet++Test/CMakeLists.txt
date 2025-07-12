add_executable(
  Packet++Test
  main.cpp
  Tests/Asn1Tests.cpp
  Tests/BgpTests.cpp
  Tests/CiscoHdlcTests.cpp
  Tests/CotpTests.cpp
  Tests/DhcpTests.cpp
  Tests/DhcpV6Tests.cpp
  Tests/DnsTests.cpp
  Tests/EthAndArpTests.cpp
  Tests/FtpTests.cpp
  Tests/GreTests.cpp
  Tests/GtpTests.cpp
  Tests/HttpTests.cpp
  Tests/IcmpTests.cpp
  Tests/IcmpV6Tests.cpp
  Tests/IgmpTests.cpp
  Tests/IPSecTests.cpp
  Tests/IPv4Tests.cpp
  Tests/IPv6Tests.cpp
  Tests/LdapTests.cpp
  Tests/LLCTests.cpp
  Tests/NflogTests.cpp
  Tests/NtpTests.cpp
  Tests/PacketTests.cpp
  Tests/PacketUtilsTests.cpp
  Tests/PPPoETests.cpp
  Tests/RadiusTests.cpp
  Tests/S7CommTests.cpp
  Tests/SipSdpTests.cpp
  Tests/Sll2Tests.cpp
  Tests/SllNullLoopbackTests.cpp
  Tests/SmtpTests.cpp
  Tests/SomeIpSdTests.cpp
  Tests/SomeIpTests.cpp
  Tests/SSHTests.cpp
  Tests/SSLTests.cpp
  Tests/StpTests.cpp
  Tests/TcpTests.cpp
  Tests/TelnetTests.cpp
  Tests/TpktTests.cpp
  Tests/VlanMplsTests.cpp
  Tests/VrrpTest.cpp
  Tests/WakeOnLanTests.cpp
  Tests/WireGuardTests.cpp
  Tests/X509Tests.cpp
  Utils/TestUtils.cpp
)

target_link_libraries(Packet++Test PUBLIC memplumber Packet++ PcppTestFramework EndianPortable)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Packet++Test PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Packet++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Packet++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
add_test(NAME Packet++Test COMMAND $<TARGET_FILE:Packet++Test> WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
