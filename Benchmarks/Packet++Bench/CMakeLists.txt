cmake_minimum_required(VERSION 3.14)

add_executable(Packet++Bench
  "main.cpp"
  "Benchmarks/PortMapperBench.cpp"
)

target_link_libraries(Packet++Bench PUBLIC PcapPlusPlus::Pcap++ benchmark::benchmark)
