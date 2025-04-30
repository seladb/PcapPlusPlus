include(FetchContent)

add_subdirectory(EndianPortable)
add_subdirectory(Getopt-for-Visual-Studio)
add_subdirectory(hash-library)
add_subdirectory(json)
add_subdirectory(MemPlumber/MemPlumber)

FetchContent_Declare(
  LightPcapNg
  GIT_REPOSITORY "https://github.com/PcapPlusPlus/LightPcapNg"
  GIT_TAG "pcpp-copy-for-fetch-content-tests"
)

if(PCAPPP_INSTALL)
  FetchContent_MakeAvailable(LightPcapNg)

  # Needed as Cmake complains about the target not being in an export set for Pcap++ install
  # Does not actually output anything if the target is an OBJECT library.
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    ARCHIVE DESTINATION "${PCAPPP_INSTALL_LIBDIR}/vendor"
    LIBRARY DESTINATION "${PCAPPP_INSTALL_LIBDIR}/vendor"
    PUBLIC_HEADER DESTINATION "${PCAPPP_INSTALL_INCLUDEDIR}/vendor"
  )
endif()
