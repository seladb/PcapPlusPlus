cmake_minimum_required(VERSION 3.0)

option(USE_DPDK    "Setup PcapPlusPlus with DPDK. In this case you must also set DPDK_HOME")
option(USE_PF_RING "Setup PcapPlusPlus with PF_RING. In this case you must also set PF_RING_HOME")

if(USE_DPDK)
	add_definitions(-DUSE_DPDK)
	set(DPDK_HOME "" CACHE STRING "Sets DPDK home directoy." FORCE)
endif()

if(USE_PF_RING)
	add_definitions(-DUSE_PF_RING)
	set(PF_RING_HOME "" CACHE STRING "Sets PF_RING home directory." FORCE)
endif()

add_library(PcapPP
	src/DpdkDevice.cpp
	src/DpdkDeviceList.cpp
	src/NetworkUtils.cpp
	src/PcapDevice.cpp
	src/PcapFileDevice.cpp
	src/PcapFilter.cpp
	src/PcapLiveDevice.cpp
	src/PcapLiveDeviceList.cpp
	src/PcapRemoteDevice.cpp
	src/PcapRemoteDeviceList.cpp
	src/PfRingDevice.cpp
	src/PfRingDeviceList.cpp
	src/RawSocketDevice.cpp
	src/WinPcapLiveDevice.cpp
	
	header/Device.h
	header/DpdkDevice.h
	header/DpdkDeviceList.h
	header/NetworkUtils.h
	header/PcapDevice.h
	header/PcapFileDevice.h
	header/PcapFilter.h
	header/PcapLiveDevice.h
	header/PcapLiveDeviceList.h
	header/PcapRemoteDevice.h
	header/PcapRemoteDeviceList.h
	header/PfRingDevice.h
	header/PfRingDeviceList.h
	header/RawSocketDevice.h
	header/WinPcapLiveDevice.h

)

target_include_directories(PcapPP
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(PcapPP LINK_PUBLIC
	CommonPP
	PacketPP
	EndianPortable
	light_pcapng
	${PCAP_LIBRARIES}

)

set_property(TARGET PcapPP PROPERTY CXX_STANDARD 14)
set_property(TARGET PcapPP PROPERTY CXX_EXTENSIONS ON)
set_property(TARGET PcapPP PROPERTY ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set_property(TARGET PcapPP PROPERTY OUTPUT_NAME "Pcap++")
