add_executable(Tutorial-PcapFiles main.cpp)

target_link_libraries(Tutorial-PcapFiles PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-PcapFiles
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
