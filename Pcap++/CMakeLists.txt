add_library(
  Pcap++
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/KniDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/KniDeviceList.cpp>
  $<$<BOOL:${PCAPPP_TARGET_PLATFORM_LINUX}>:src/LinuxNicInformationSocket.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/MBufRawPacket.cpp>
  src/NetworkUtils.cpp
  src/PcapFileDevice.cpp
  src/PcapDevice.cpp
  src/PcapFilter.cpp
  src/PcapLiveDevice.cpp
  src/PcapLiveDeviceList.cpp
  $<$<BOOL:${PCAPPP_TARGET_PLATFORM_WINDOWS}>:src/PcapRemoteDevice.cpp>
  $<$<BOOL:${PCAPPP_TARGET_PLATFORM_WINDOWS}>:src/PcapRemoteDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDeviceList.cpp>
  src/RawSocketDevice.cpp
  $<$<BOOL:${PCAPPP_TARGET_PLATFORM_WINDOWS}>:src/WinPcapLiveDevice.cpp>
  # Force light pcapng to be link fully static
  $<TARGET_OBJECTS:light_pcapng>)

set(public_headers
    header/Device.h
    header/NetworkUtils.h
    header/PcapDevice.h
    header/PcapFileDevice.h
    header/PcapFilter.h
    header/PcapLiveDevice.h
    header/PcapLiveDeviceList.h
    header/RawSocketDevice.h)

if(PCAPPP_USE_DPDK)
  list(
    APPEND
    public_headers
    header/KniDevice.h
    header/DpdkDeviceList.h
    header/KniDeviceList.h
    header/DpdkDevice.h
    header/MBufRawPacket.h)
endif()

if(PCAPPP_USE_PF_RING)
  list(
    APPEND
    public_headers
    header/PfRingDevice.h
    header/PfRingDeviceList.h)
endif()

if(PCAPPP_TARGET_PLATFORM_LINUX)
  list(APPEND public_headers header/LinuxNicInformationSocket.h)
endif()

if(PCAPPP_TARGET_PLATFORM_WINDOWS)
  list(
    APPEND
    public_headers
    header/WinPcapLiveDevice.h
    header/PcapRemoteDevice.h
    header/PcapRemoteDeviceList.h)
endif()

set_property(TARGET Pcap++ PROPERTY PUBLIC_HEADER ${public_headers})

if(PCAPPP_TARGET_PLATFORM_MACOS)
  find_package(MACOS)
  target_link_libraries(Pcap++ PUBLIC ${MACOS_CORE_FOUNDATION_LIBRARY} ${MACOS_SYSTEM_CONFIGURATION_LIBRARY})
elseif(PCAPPP_TARGET_PLATFORM_WINDOWS)
  target_compile_definitions(Pcap++ PUBLIC -DHAVE_REMOTE)
  target_compile_definitions(Pcap++ PUBLIC -DWPCAP)
  target_link_libraries(Pcap++ PUBLIC ws2_32 iphlpapi)
  target_link_libraries(Pcap++ PUBLIC ${Packet_LIBRARY})
endif()

target_include_directories(
  Pcap++
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header> $<INSTALL_INTERFACE:include/pcapplusplus>
  # Don't link with EndianPortable nor Light_PcapNG as they won't be exported
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>
          $<TARGET_PROPERTY:light_pcapng,INTERFACE_INCLUDE_DIRECTORIES>)

target_link_libraries(
  Pcap++
  PUBLIC Common++
         Packet++
         $<$<BOOL:${PCAPPP_USE_PF_RING}>:PF_RING::PF_RING>
         $<$<BOOL:${PCAPPP_USE_DPDK}>:DPDK::DPDK>
         PCAP::PCAP
         Threads::Threads)

if(LIGHT_PCAPNG_ZSTD)
  target_link_libraries(Pcap++ PRIVATE light_pcapng)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Pcap++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR})
endif()

set_property(TARGET Pcap++ PROPERTY OUTPUT_NAME "Pcap++")
set_property(TARGET Pcap++ PROPERTY VERSION ${PCAPPP_VERSION})
