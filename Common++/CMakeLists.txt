add_library(
  CommonPP
  src/GeneralUtils.cpp
  src/IpAddress.cpp
  src/IpUtils.cpp
  src/Logger.cpp
  src/MacAddress.cpp
  src/PcapPlusPlusVersion.cpp
  src/SystemUtils.cpp
  src/TablePrinter.cpp)

set(public_headers
    header/GeneralUtils.h
    header/IpAddress.h
    header/IpUtils.h
    header/Logger.h
    header/LRUList.h
    header/MacAddress.h
    header/PcapPlusPlusVersion.h
    header/PointerVector.h
    header/SystemUtils.h
    header/TablePrinter.h
    header/TimespecTimeval.h)

set_property(TARGET CommonPP PROPERTY PUBLIC_HEADER ${public_headers})

target_include_directories(
  CommonPP
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header>
         $<INSTALL_INTERFACE:include/pcapplusplus>
  # Don't link with EndianPortable as it won't be exported
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

if(TARGET_PLATFORM_WINDOWS)
  target_link_libraries(CommonPP PUBLIC ws2_32 iphlpapi)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS CommonPP
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pcapplusplus)
endif()

set_property(TARGET CommonPP PROPERTY OUTPUT_NAME "common++")
set_property(TARGET CommonPP PROPERTY VERSION ${VERSION_MAJOR}.${VERSION_MINOR})
