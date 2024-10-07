add_library(
  Packet++
  $<TARGET_OBJECTS:hash-library>
  src/ArpLayer.cpp
  src/Asn1Codec.cpp
  src/BgpLayer.cpp
  src/CotpLayer.cpp
  src/DhcpLayer.cpp
  src/DhcpV6Layer.cpp
  src/DnsLayer.cpp
  src/DnsResource.cpp
  src/DnsResourceData.cpp
  src/EthDot3Layer.cpp
  src/EthLayer.cpp
  src/FtpLayer.cpp
  src/GreLayer.cpp
  src/GtpLayer.cpp
  src/HttpLayer.cpp
  src/IcmpLayer.cpp
  src/IcmpV6Layer.cpp
  src/IgmpLayer.cpp
  src/IPReassembly.cpp
  src/IPSecLayer.cpp
  src/IPv4Layer.cpp
  src/IPv6Extensions.cpp
  src/IPv6Layer.cpp
  src/Layer.cpp
  src/LdapLayer.cpp
  src/LLCLayer.cpp
  src/MplsLayer.cpp
  src/NdpLayer.cpp
  src/NflogLayer.cpp
  src/NtpLayer.cpp
  src/NullLoopbackLayer.cpp
  src/Packet.cpp
  src/PacketTrailerLayer.cpp
  src/PacketUtils.cpp
  src/PayloadLayer.cpp
  src/PPPoELayer.cpp
  src/RadiusLayer.cpp
  src/RawPacket.cpp
  src/S7CommLayer.cpp
  src/SdpLayer.cpp
  src/SingleCommandTextProtocol.cpp
  src/SipLayer.cpp
  src/Sll2Layer.cpp
  src/SllLayer.cpp
  src/SmtpLayer.cpp
  src/SomeIpLayer.cpp
  src/SomeIpSdLayer.cpp
  src/SSHLayer.cpp
  src/SSLCommon.cpp
  src/SSLHandshake.cpp
  src/SSLLayer.cpp
  src/StpLayer.cpp
  src/TcpLayer.cpp
  src/TcpReassembly.cpp
  src/TelnetLayer.cpp
  src/TextBasedProtocol.cpp
  src/TLVData.cpp
  src/TpktLayer.cpp
  src/UdpLayer.cpp
  src/VlanLayer.cpp
  src/VrrpLayer.cpp
  src/VxlanLayer.cpp
  src/WakeOnLanLayer.cpp
  src/WireGuardLayer.cpp
  # Force hash-library pcapng to be link fully static
)

set(public_headers
    header/pcapplusplus/ArpLayer.h
    header/pcapplusplus/Asn1Codec.h
    header/pcapplusplus/BgpLayer.h
    header/pcapplusplus/CotpLayer.h
    header/pcapplusplus/DhcpLayer.h
    header/pcapplusplus/DhcpV6Layer.h
    header/pcapplusplus/DnsLayerEnums.h
    header/pcapplusplus/DnsLayer.h
    header/pcapplusplus/DnsResourceData.h
    header/pcapplusplus/DnsResource.h
    header/pcapplusplus/EthDot3Layer.h
    header/pcapplusplus/EthLayer.h
    header/pcapplusplus/FtpLayer.h
    header/pcapplusplus/GreLayer.h
    header/pcapplusplus/GtpLayer.h
    header/pcapplusplus/HttpLayer.h
    header/pcapplusplus/IcmpLayer.h
    header/pcapplusplus/IcmpV6Layer.h
    header/pcapplusplus/IgmpLayer.h
    header/pcapplusplus/IPLayer.h
    header/pcapplusplus/IPReassembly.h
    header/pcapplusplus/IPSecLayer.h
    header/pcapplusplus/IPv4Layer.h
    header/pcapplusplus/IPv6Extensions.h
    header/pcapplusplus/IPv6Layer.h
    header/pcapplusplus/Layer.h
    header/pcapplusplus/LdapLayer.h
    header/pcapplusplus/LLCLayer.h
    header/pcapplusplus/MplsLayer.h
    header/pcapplusplus/NullLoopbackLayer.h
    header/pcapplusplus/NdpLayer.h
    header/pcapplusplus/NflogLayer.h
    header/pcapplusplus/NtpLayer.h
    header/pcapplusplus/Packet.h
    header/pcapplusplus/PacketTrailerLayer.h
    header/pcapplusplus/PacketUtils.h
    header/pcapplusplus/PayloadLayer.h
    header/pcapplusplus/PPPoELayer.h
    header/pcapplusplus/ProtocolType.h
    header/pcapplusplus/RadiusLayer.h
    header/pcapplusplus/RawPacket.h
    header/pcapplusplus/S7CommLayer.h
    header/pcapplusplus/SdpLayer.h
    header/pcapplusplus/SingleCommandTextProtocol.h
    header/pcapplusplus/SipLayer.h
    header/pcapplusplus/SllLayer.h
    header/pcapplusplus/Sll2Layer.h
    header/pcapplusplus/SmtpLayer.h
    header/pcapplusplus/SomeIpLayer.h
    header/pcapplusplus/SomeIpSdLayer.h
    header/pcapplusplus/SSHLayer.h
    header/pcapplusplus/SSLCommon.h
    header/pcapplusplus/SSLHandshake.h
    header/pcapplusplus/SSLLayer.h
    header/pcapplusplus/StpLayer.h
    header/pcapplusplus/TcpLayer.h
    header/pcapplusplus/TcpReassembly.h
    header/pcapplusplus/TelnetLayer.h
    header/pcapplusplus/TextBasedProtocol.h
    header/pcapplusplus/TLVData.h
    header/pcapplusplus/TpktLayer.h
    header/pcapplusplus/UdpLayer.h
    header/pcapplusplus/VlanLayer.h
    header/pcapplusplus/VrrpLayer.h
    header/pcapplusplus/VxlanLayer.h
    header/pcapplusplus/WakeOnLanLayer.h
    header/pcapplusplus/WireGuardLayer.h)

# Don't use set_target_properties CMake limit to 50 elements
set_property(TARGET Packet++ PROPERTY PUBLIC_HEADER ${public_headers})

target_include_directories(
  Packet++
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header> $<INSTALL_INTERFACE:include>
  # Don't link with hash-library nor EndianPortable as they won't be exported
  PRIVATE $<TARGET_PROPERTY:hash-library,INCLUDE_DIRECTORIES>
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

target_link_libraries(Packet++ PUBLIC Common++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Packet++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()

set_property(TARGET Packet++ PROPERTY OUTPUT_NAME "Packet++")
set_property(TARGET Packet++ PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET Packet++ PROPERTY COMPILE_WARNING_AS_ERROR ON)
