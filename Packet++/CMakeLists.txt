add_library(PacketPP
	src/ArpLayer.cpp
	src/BgpLayer.cpp
	src/DhcpLayer.cpp
	src/DnsLayer.cpp
	src/DnsResource.cpp
	src/DnsResourceData.cpp
	src/EthDot3Layer.cpp
	src/EthLayer.cpp
	src/GreLayer.cpp
	src/GtpLayer.cpp
	src/HttpLayer.cpp
	src/IcmpLayer.cpp
	src/IgmpLayer.cpp
	src/IPReassembly.cpp
	src/IPSecLayer.cpp
	src/IPv4Layer.cpp
	src/IPv6Extensions.cpp
	src/IPv6Layer.cpp
	src/Layer.cpp
	src/MplsLayer.cpp
	src/NullLoopbackLayer.cpp
	src/Packet.cpp
	src/PacketTrailerLayer.cpp
	src/PacketUtils.cpp
	src/PayloadLayer.cpp
	src/PPPoELayer.cpp
	src/RadiusLayer.cpp
	src/RawPacket.cpp
	src/SdpLayer.cpp
	src/SipLayer.cpp
	src/SllLayer.cpp
	src/SSHLayer.cpp
	src/SSLCommon.cpp
	src/SSLHandshake.cpp
	src/SSLLayer.cpp
	src/TcpLayer.cpp
	src/TcpReassembly.cpp
	src/TextBasedProtocol.cpp
	src/TLVData.cpp
	src/UdpLayer.cpp
	src/VlanLayer.cpp
	src/VxlanLayer.cpp
)

target_include_directories(PacketPP
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header
)

target_link_libraries(PacketPP PUBLIC
	CommonPP
	EndianPortable
	hash-library
)

set_property(TARGET PacketPP PROPERTY CXX_STANDARD 11)
set_property(TARGET PacketPP PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET PacketPP PROPERTY ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set_property(TARGET PacketPP PROPERTY OUTPUT_NAME "Packet++")
