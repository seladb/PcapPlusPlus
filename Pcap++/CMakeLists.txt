include(DetectOS)

if (TARGET_PLATFORM_WINDOWS)
	set(THREADS_USE_PTHREADS_WIN32 true)
	find_package (Threads REQUIRED)
	include_directories(${THREADS_PTHREADS_INCLUDE_DIR})

	include( CheckStructHasMember )
	check_struct_has_member("struct timespec" "tv_sec" "time.h" HAVE_STRUCT_TIMESPEC)
	# HAVE_STRUCT_TIMESPEC must be defined for windows pthreads on newer MSVC
	if (HAVE_STRUCT_TIMESPEC)
		add_definitions(-DHAVE_STRUCT_TIMESPEC=1)
	endif()
else()
	find_package (Threads REQUIRED)
endif()

find_package (PCAP REQUIRED)

option(PCAPPP_HAS_PCAP_IMMEDIATE_MODE "Enable Pcap Has Immediate Mode (supported on libpcap>=1.5)")

add_library(PcapPP
	src/DpdkDevice.cpp
	src/DpdkDeviceList.cpp
	src/KniDevice.cpp
	src/KniDeviceList.cpp
	src/LinuxNicInformationSocket.cpp
	src/MBufRawPacket.cpp
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
)

target_include_directories(PcapPP
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header
	PUBLIC ${PCAP_INCLUDE_DIR}
)

if(TARGET_PLATFORM_MACOS)
	find_package(MACOS)
	target_link_libraries(PcapPP PUBLIC
		${MACOS_CORE_FOUNDATION_LIBRARY}
		${MACOS_SYSTEM_CONFIGURATION_LIBRARY}
	)
elseif(TARGET_PLATFORM_WINDOWS)
	target_compile_definitions(PcapPP
		PUBLIC -DHAVE_REMOTE
	)
	target_compile_definitions(PcapPP
		PUBLIC -DWPCAP
	)
endif()

if(PCAPPP_USE_PF_RING)
	target_link_libraries(PcapPP
		PUBLIC PF_RING::PF_RING dl
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
	${PCAP_LIBRARY}
	${PACKET_LIBRARY}
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
