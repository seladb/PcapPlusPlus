add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(hash-library)
add_subdirectory(json)
add_subdirectory(LightPcapNg)
add_subdirectory(MemPlumber/MemPlumber)

if(PCAPPP_INSTALL)
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR}
  )
endif()
