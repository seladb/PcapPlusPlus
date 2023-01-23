add_subdirectory(dirent-for-Visual-Studio)
add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(LightPcapNg)
add_subdirectory(hash-library)
if (PCAPPP_USE_SANITIZER STREQUAL "MemorySanitizer")
  message(WARNING "Memplumber conflict with MemorySanitizer, it will not be built!")
else()
  add_subdirectory(MemPlumber/MemPlumber)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${PCAPPP_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${PCAPPP_INSTALL_INCLUDEDIR})
endif()
