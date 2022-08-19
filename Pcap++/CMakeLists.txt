add_library(
  Pcap++
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/DpdkDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/KniDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/KniDeviceList.cpp>
  $<$<BOOL:${TARGET_PLATFORM_LINUX}>:src/LinuxNicInformationSocket.cpp>
  $<$<BOOL:${PCAPPP_USE_DPDK}>:src/MBufRawPacket.cpp>
  src/NetworkUtils.cpp
  src/PcapDevice.cpp
  src/PcapFileDevice.cpp
  src/PcapFilter.cpp
  src/PcapLiveDevice.cpp
  src/PcapLiveDeviceList.cpp
  $<$<BOOL:${TARGET_PLATFORM_WINDOWS}>:src/PcapRemoteDevice.cpp>
  $<$<BOOL:${TARGET_PLATFORM_WINDOWS}>:src/PcapRemoteDeviceList.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDevice.cpp>
  $<$<BOOL:${PCAPPP_USE_PF_RING}>:src/PfRingDeviceList.cpp>
  src/RawSocketDevice.cpp
  $<$<BOOL:${TARGET_PLATFORM_WINDOWS}>:src/WinPcapLiveDevice.cpp>
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
  set(public_headers
      ${public_headers} header/DpdkDevice.h header/DpdkDeviceList.h
      header/KniDevice.h header/KniDeviceList.h header/MBufRawPacket.h)
endif()

if(PCAPPP_USE_PF_RING)
  set(public_headers ${public_headers} header/PfRingDevice.h
                     header/PfRingDeviceList.h)
endif()

if(TARGET_PLATFORM_LINUX)
  set(public_headers ${public_headers} header/LinuxNicInformationSocket.h)
endif()

if(TARGET_PLATFORM_WINDOWS)
  set(public_headers ${public_headers} header/WinPcapLiveDevice.h
                     header/PcapRemoteDevice.h header/PcapRemoteDeviceList.h)
endif()

set_property(TARGET Pcap++ PROPERTY PUBLIC_HEADER ${public_headers})

if(TARGET_PLATFORM_MACOS)
  find_package(MACOS)
  target_link_libraries(Pcap++ PUBLIC ${MACOS_CORE_FOUNDATION_LIBRARY}
                                      ${MACOS_SYSTEM_CONFIGURATION_LIBRARY})
elseif(TARGET_PLATFORM_WINDOWS)
  target_compile_definitions(Pcap++ PUBLIC -DHAVE_REMOTE)
  target_compile_definitions(Pcap++ PUBLIC -DWPCAP)
  # pthreads-win32's pthread.h doesn't have the valid include guards for this
  # case (shame on them!). pthreads tries to declare it because it needs it
  # internally, but since it's possible it won't need the entire time.h, it
  # tries to declare only the timespec if possible.
  target_compile_definitions(Pcap++ PUBLIC -DHAVE_STRUCT_TIMESPEC)
  target_link_libraries(Pcap++ PUBLIC ws2_32 iphlpapi)
  target_link_libraries(Pcap++ PUBLIC ${Packet_LIBRARY})
endif()

target_include_directories(
  Pcap++
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header>
         $<INSTALL_INTERFACE:include/pcapplusplus>
  # Don't link with EndianPortable nor Light_PcapNG as they won't be exported
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>
          $<TARGET_PROPERTY:light_pcapng,INTERFACE_INCLUDE_DIRECTORIES>)

target_link_libraries(
  Pcap++
  PUBLIC Common++ Packet++ $<$<BOOL:${PCAPPP_USE_PF_RING}>:PF_RING::PF_RING>
         $<$<BOOL:${PCAPPP_USE_DPDK}>:dpdk::dpdk> PCAP::PCAP ${_PCAPP_THREADS})

if(LIGHT_PCAPNG_ZSTD)
  target_link_libraries(Pcap++ PRIVATE light_pcapng)
endif()

# Static linking GCC/Threads for minGW (Windows + GNU)
if(TARGET_PLATFORM_WINDOWS AND TARGET_COMPILER_GCC)
  target_link_libraries(Pcap++ PUBLIC -static-libgcc -static-libstdc++)
  target_link_libraries(Pcap++ PUBLIC -static ${_PCAPP_THREADS})
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Pcap++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPP_INSTALL_INCLUDEDIR})
endif()

set_property(TARGET Pcap++ PROPERTY OUTPUT_NAME "pcap++")
set_property(TARGET Pcap++ PROPERTY VERSION ${VERSION_MAJOR}.${VERSION_MINOR})
