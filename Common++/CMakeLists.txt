add_library(
  Common++
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

set_property(TARGET Common++ PROPERTY PUBLIC_HEADER ${public_headers})

target_include_directories(
  Common++
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header>
         $<INSTALL_INTERFACE:include/pcapplusplus>
  # Don't link with EndianPortable as it won't be exported
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>)

if(TARGET_PLATFORM_WINDOWS)
  target_link_libraries(Common++ PUBLIC ws2_32 iphlpapi)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Common++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPP_INSTALL_INCLUDEDIR})
endif()

set_property(TARGET Common++ PROPERTY OUTPUT_NAME "common++")
set_property(TARGET Common++ PROPERTY VERSION ${VERSION_MAJOR}.${VERSION_MINOR})
