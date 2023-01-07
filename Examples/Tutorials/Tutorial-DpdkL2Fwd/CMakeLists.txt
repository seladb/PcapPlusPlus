add_executable(Tutorial-DpdkL2Fwd main.cpp WorkerThread.cpp)

target_link_libraries(Tutorial-DpdkL2Fwd PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(Tutorial-DpdkL2Fwd PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
