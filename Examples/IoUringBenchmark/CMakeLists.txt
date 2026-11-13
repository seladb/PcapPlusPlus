cmake_minimum_required(VERSION 3.14)

add_executable(generate_pcap generate_pcap.cpp)
target_link_libraries(generate_pcap PRIVATE Threads::Threads)

if(TARGET Pcap++)
  add_executable(test_io_uring test_io_uring.cpp)
  target_link_libraries(test_io_uring PRIVATE PcapPlusPlus::Pcap++)

  add_executable(benchmark_io_uring benchmark_io_uring.cpp)
  target_link_libraries(benchmark_io_uring PRIVATE PcapPlusPlus::Pcap++)
endif()
