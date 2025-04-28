add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(hash-library)
add_subdirectory(json)
add_subdirectory(MemPlumber/MemPlumber)

# Find CMake module for ExternalProject
include(ExternalProject)

ExternalProject_Add(
  LightPcapNg
  PREFIX ${CMAKE_BINARY_DIR}/3rdParty
  GIT_REPOSITORY https://github.com/PcapPlusPlus/LightPcapNg
  GIT_TAG copy-from-pcapplusplus  # TODO: Replace with master
  INSTALL_COMMAND ""  # TODO: fix it
)

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
