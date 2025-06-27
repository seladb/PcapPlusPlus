add_library(
  Packet++
  $<TARGET_OBJECTS:hash-library>
  src/ArpLayer.cpp
  src/Asn1Codec.cpp
  src/BgpLayer.cpp
  src/CiscoHdlcLayer.cpp
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
  src/IPLayer.cpp
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
  src/X509Decoder.cpp
  # Force hash-library pcapng to be link fully static
)

set(
  public_headers
  header/ArpLayer.h
  header/Asn1Codec.h
  header/BgpLayer.h
  header/CiscoHdlcLayer.h
  header/CotpLayer.h
  header/DhcpLayer.h
  header/DhcpV6Layer.h
  header/DnsLayerEnums.h
  header/DnsLayer.h
  header/DnsResourceData.h
  header/DnsResource.h
  header/EthDot3Layer.h
  header/EthLayer.h
  header/FtpLayer.h
  header/GreLayer.h
  header/GtpLayer.h
  header/HttpLayer.h
  header/IcmpLayer.h
  header/IcmpV6Layer.h
  header/IgmpLayer.h
  header/IPLayer.h
  header/IPReassembly.h
  header/IPSecLayer.h
  header/IPv4Layer.h
  header/IPv6Extensions.h
  header/IPv6Layer.h
  header/Layer.h
  header/LdapLayer.h
  header/LLCLayer.h
  header/MplsLayer.h
  header/NullLoopbackLayer.h
  header/NdpLayer.h
  header/NflogLayer.h
  header/NtpLayer.h
  header/Packet.h
  header/PacketTrailerLayer.h
  header/PacketUtils.h
  header/PayloadLayer.h
  header/PPPoELayer.h
  header/ProtocolType.h
  header/RadiusLayer.h
  header/RawPacket.h
  header/S7CommLayer.h
  header/SdpLayer.h
  header/SingleCommandTextProtocol.h
  header/SipLayer.h
  header/SllLayer.h
  header/Sll2Layer.h
  header/SmtpLayer.h
  header/SomeIpLayer.h
  header/SomeIpSdLayer.h
  header/SSHLayer.h
  header/SSLCommon.h
  header/SSLHandshake.h
  header/SSLLayer.h
  header/StpLayer.h
  header/TcpLayer.h
  header/TcpReassembly.h
  header/TelnetLayer.h
  header/TextBasedProtocol.h
  header/TLVData.h
  header/TpktLayer.h
  header/UdpLayer.h
  header/VlanLayer.h
  header/VrrpLayer.h
  header/VxlanLayer.h
  header/WakeOnLanLayer.h
  header/WireGuardLayer.h
  header/X509Decoder.h
)

# Don't use set_target_properties CMake limit to 50 elements
set_property(TARGET Packet++ PROPERTY PUBLIC_HEADER ${public_headers})

target_compile_features(Packet++ PUBLIC cxx_std_14)

target_include_directories(
  Packet++
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header>
    $<INSTALL_INTERFACE:include/pcapplusplus>
    $<INSTALL_INTERFACE:include>
  # Don't link with hash-library nor EndianPortable as they won't be exported
  PRIVATE $<TARGET_PROPERTY:hash-library,INCLUDE_DIRECTORIES>
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(Packet++ PUBLIC Common++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Packet++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()

set_property(TARGET Packet++ PROPERTY OUTPUT_NAME "Packet++")
set_property(TARGET Packet++ PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET Packet++ PROPERTY COMPILE_WARNING_AS_ERROR ON)
