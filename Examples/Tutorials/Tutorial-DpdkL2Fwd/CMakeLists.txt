add_executable(Tutorial-DpdkL2Fwd main.cpp WorkerThread.cpp)

target_link_libraries(Tutorial-DpdkL2Fwd PUBLIC PcapPlusPlus::Pcap++)
