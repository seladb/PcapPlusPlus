add_executable(Tutorial-PacketCraftAndEdit main.cpp)

target_link_libraries(Tutorial-PacketCraftAndEdit PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-PacketCraftAndEdit
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
