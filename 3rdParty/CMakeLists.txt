add_subdirectory(dirent-for-Visual-Studio)
add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(LightPcapNg)
add_subdirectory(hash-library)
add_subdirectory(MemPlumber/MemPlumber)

if(PCAPPP_INSTALL)
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    LIBRARY
    ARCHIVE DESTINATION ${PCAPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPP_INSTALL_INCLUDEDIR})
endif()
