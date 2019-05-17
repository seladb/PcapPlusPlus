cmake_minimum_required(VERSION 3.0)

find_package (Threads)

option(PCAPPP_HAS_PCAP_IMMEDIATE_MODE "Enable Pcap Has Immediate Mode (supported on libpcap>=1.5)")

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

if(PCAPPP_USE_PF_RING)
	target_link_libraries(PcapPP
		PUBLIC PF_RING::PF_RING
	)
endif()

if(PCAPPP_USE_DPDK)
	target_link_libraries(PcapPP
		PUBLIC DPDK::DPDK
	)
endif()

target_link_libraries(PcapPP PUBLIC
	CommonPP
	PacketPP
	EndianPortable
	light_pcapng
	${PCAP_LIBRARIES}
	Threads::Threads
)

if(PCAPPP_HAS_PCAP_IMMEDIATE_MODE)
    target_compile_definitions(PcapPP
        PUBLIC -DHAS_PCAP_IMMEDIATE_MODE
    )
endif()

set_property(TARGET PcapPP PROPERTY CXX_STANDARD 11)
set_property(TARGET PcapPP PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET PcapPP PROPERTY ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set_property(TARGET PcapPP PROPERTY OUTPUT_NAME "Pcap++")
