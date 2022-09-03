add_executable(Tutorial-LiveTraffic main.cpp)

target_link_libraries(Tutorial-LiveTraffic PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-LiveTraffic
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
