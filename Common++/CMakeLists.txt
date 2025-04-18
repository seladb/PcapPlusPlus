add_library(
  Common++
  src/GeneralUtils.cpp
  src/IpAddress.cpp
  src/IpAddressUtils.cpp
  src/IpUtils.cpp
  src/Logger.cpp
  src/MacAddress.cpp
  src/OUILookup.cpp
  src/PcapPlusPlusVersion.cpp
  src/SystemUtils.cpp
  src/TablePrinter.cpp
)

set(
  public_headers
  header/pcapplusplus/DeprecationUtils.h
  header/pcapplusplus/GeneralUtils.h
  header/pcapplusplus/IpAddress.h
  header/pcapplusplus/IpAddressUtils.h
  header/pcapplusplus/IpUtils.h
  header/pcapplusplus/Logger.h
  header/pcapplusplus/LRUList.h
  header/pcapplusplus/MacAddress.h
  header/pcapplusplus/ObjectPool.h
  header/pcapplusplus/OUILookup.h
  header/pcapplusplus/PcapPlusPlusVersion.h
  header/pcapplusplus/PointerVector.h
  header/pcapplusplus/SystemUtils.h
  header/pcapplusplus/TablePrinter.h
  header/pcapplusplus/TimespecTimeval.h
)

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${generated_dir})

set(generated_transition_headers)
foreach(header IN LISTS public_headers)
  file(RELATIVE_PATH relative_path "${CMAKE_CURRENT_SOURCE_DIR}/header" "${CMAKE_CURRENT_SOURCE_DIR}/${header}")

  get_filename_component(filename "${relative_path}" NAME)

  set(PCAPPP_INTERNAL_INCLUDE_LINK_FILE "${relative_path}")
  set(output_file "${generated_dir}/${filename}")

  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/TransitionHeaderTemplate.h.in" "${output_file}" @ONLY)

  list(APPEND generated_transition_headers "${output_file}")
endforeach()

# Set the public header that will be installed
set_property(TARGET Common++ PROPERTY PUBLIC_HEADER ${public_headers})

target_compile_features(Common++ PUBLIC cxx_std_11)

target_include_directories(
  Common++
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/header> $<INSTALL_INTERFACE:include>
  # Don't link with EndianPortable and json as it won't be exported
  PRIVATE $<TARGET_PROPERTY:EndianPortable,INTERFACE_INCLUDE_DIRECTORIES>
  PRIVATE $<TARGET_PROPERTY:json,INTERFACE_INCLUDE_DIRECTORIES>
)

if(WIN32)
  target_link_libraries(Common++ PRIVATE ws2_32 iphlpapi)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Common++
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )

  install(DIRECTORY "${generated_dir}/" DESTINATION "${PCAPPP_INSTALL_INCLUDEDIR_LEGACY}")
endif()

set_property(TARGET Common++ PROPERTY OUTPUT_NAME "Common++")
set_property(TARGET Common++ PROPERTY VERSION ${PCAPPP_VERSION})
set_property(TARGET Common++ PROPERTY COMPILE_WARNING_AS_ERROR ON)
