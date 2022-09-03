add_executable(Tutorial-DpdkL2Fwd main.cpp WorkerThread.cpp)

target_link_libraries(Tutorial-DpdkL2Fwd PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-DpdkL2Fwd
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
