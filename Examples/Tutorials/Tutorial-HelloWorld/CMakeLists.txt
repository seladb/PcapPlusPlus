add_executable(Tutorial-HelloWorld main.cpp)

target_link_libraries(Tutorial-HelloWorld PUBLIC PcapPlusPlus::Pcap++)

if(PCAPPP_INSTALL)
  install(
    TARGETS Tutorial-HelloWorld
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
endif()
