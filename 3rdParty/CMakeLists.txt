add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(hash-library)
add_subdirectory(json)
add_subdirectory(MemPlumber/MemPlumber)

include(FetchContent)

set(LIGHT_PCAPNG_BUILD_TYPE OBJECT CACHE STRING "" FORCE)

FetchContent_Declare(
  LightPcapNg
  GIT_REPOSITORY https://github.com/PcapPlusPlus/LightPcapNg
  GIT_TAG copy-from-pcapplusplus  # TODO: Replace with master
)

FetchContent_MakeAvailable(LightPcapNg)

# TODO: do we still need it?
#if(PCAPPP_INSTALL)
#  install(
#    TARGETS light_pcapng
#    EXPORT PcapPlusPlusTargets
#    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
#    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
#    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
#  )
#endif()
