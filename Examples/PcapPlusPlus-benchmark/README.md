PcapPlusPlus Benchmark
======================

This folder contains benchmark applications for measuring the performance of PcapPlusPlus. Currently, there are two benchmark applications.

## Compare with other libraries

A benchmark application used for measuring PcapPlusPlus performance can be found in `benchmark.cpp`. It is based on Matias Fontanini's packet-capture-benchmarks project (https://github.com/mfontanini/packet-capture-benchmarks) and allows us to compare PcapPlusPlus with other packet libraries. See this page for more details and result comparisons: https://pcapplusplus.github.io/docs/benchmark

## Directly benchmark PcapPlusPlus

Another application integrates with the Google Benchmark library and can be found in `benchmark-google.cpp`. This application currently consists of four different benchmarks, and each benchmark can be influenced by various factors. These benchmarks aim to utilize different influence factors to provide accurate results for different scenarios. You can check the table below for more information. For performance-critical applications using PcapPlusPlus, it is recommended to run benchmarks in your specific environment for more accurate results. Using larger pcap files and those with diverse protocols and sessions can provide better insights into PcapPlusPlus performance in your setup.

|     Benchmark     |   Operation   |  Influencing factors |
|:-----------------:|:-------------:|:--------------------:|
| BM_PcapFileRead   |     Read      |  CPU + Disk (Read)   |
| BM_PcapFileWrite  |     Write     |  CPU + Disk (Write)  |
| BM_PacketParsing  | Read + Parse  |  CPU + Disk (Read)   |
| BM_PacketCrafting |     Craft     |        CPU           |
