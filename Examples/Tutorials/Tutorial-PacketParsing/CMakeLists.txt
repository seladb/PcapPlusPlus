add_executable(Tutorial-PacketParsing main.cpp)

target_link_libraries(Tutorial-PacketParsing PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-PacketParsing
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
