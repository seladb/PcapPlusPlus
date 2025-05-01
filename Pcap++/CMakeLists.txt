add_library(
  Pcap++
  src/DeviceUtils.cpp
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK_KNI}>:src/KniDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK_KNI}>:src/KniDeviceList.cpp>
  $<$<BOOL:${LINUX}>:src/LinuxNicInformationSocket.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/MBufRawPacket.cpp>
  src/PcapUtils.cpp
  src/NetworkUtils.cpp
  src/PcapFileDevice.cpp
  src/PcapDevice.cpp
  src/PcapFilter.cpp
  src/PcapLiveDevice.cpp
  src/PcapLiveDeviceList.cpp
  $<$<BOOL:${WIN32}>:src/PcapRemoteDevice.cpp>
  $<$<BOOL:${WIN32}>:src/PcapRemoteDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_XDP}>:src/XdpDevice.cpp>
  src/RawSocketDevice.cpp
  $<$<BOOL:${WIN32}>:src/WinPcapLiveDevice.cpp>
  # Force light pcapng to be link fully static
  $<TARGET_OBJECTS:light_pcapng>
)

set(
  public_headers
  header/Device.h
  header/DeviceListBase.h
  header/NetworkUtils.h
  header/PcapDevice.h
  header/PcapFileDevice.h
  header/PcapFilter.h
  header/PcapLiveDevice.h
  header/PcapLiveDeviceList.h
  header/RawSocketDevice.h
)

if(PCAPPP_USE_DPDK)
  list(APPEND public_headers header/DpdkDevice.h header/DpdkDeviceList.h header/MBufRawPacket.h)
endif()

if(PCAPPP_USE_DPDK_KNI)
  list(APPEND public_headers header/KniDevice.h header/KniDeviceList.h)
endif()

if(PCAPPP_USE_PF_RING)
  list(APPEND public_headers header/PfRingDevice.h header/PfRingDeviceList.h)
endif()

if(PCAPPP_USE_XDP)
  list(APPEND public_headers header/XdpDevice.h)
endif()

if(LINUX)
  list(APPEND public_headers header/LinuxNicInformationSocket.h)
endif()

if(WIN32)
  list(APPEND public_headers header/PcapRemoteDevice.h header/PcapRemoteDeviceList.h header/WinPcapLiveDevice.h)
endif()

set_property(TARGET Pcap++ PROPERTY PUBLIC_HEADER ${public_headers})

target_compile_features(Pcap++ PUBLIC cxx_std_11)

if(APPLE)
  target_link_libraries(Pcap++ PRIVATE "-framework CoreFoundation" "-framework SystemConfiguration")
elseif(WIN32)
  target_compile_definitions(Pcap++ PUBLIC -DHAVE_REMOTE)
  target_compile_definitions(Pcap++ PUBLIC -DWPCAP)
  target_link_libraries(Pcap++ PRIVATE ws2_32 iphlpapi)
  target_link_libraries(Pcap++ PUBLIC Packet::Packet)
endif()

target_include_directories(
  Pcap++
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header>
    $<INSTALL_INTERFACE:include/pcapplusplus>
    $<INSTALL_INTERFACE:include>
  # Don't link with EndianPortable nor Light_PcapNG as they won't be exported
  PRIVATE
    $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:light_pcapng,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(
  Pcap++
  PUBLIC
    Common++
    Packet++
    $<$<BOOL:${PCAPPP_USE_PF_RING}>:PF_RING::PF_RING>
    $<$<BOOL:${PCAPPP_USE_DPDK}>:DPDK::DPDK>
    $<$<BOOL:${PCAPPP_USE_XDP}>:BPF::BPF>
    PCAP::PCAP
    Threads::Threads
)

if(LIGHT_PCAPNG_ZSTD)
  target_link_libraries(Pcap++ PRIVATE light_pcapng)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Pcap++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()

set_property(TARGET Pcap++ PROPERTY OUTPUT_NAME "Pcap++")
set_property(TARGET Pcap++ PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET Pcap++ PROPERTY COMPILE_WARNING_AS_ERROR ON)
