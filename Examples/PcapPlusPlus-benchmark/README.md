PcapPlusPlus Benchmark
======================

This folder contains benchmark applications for measuring the performance of PcapPlusPlus. Currently, there are two benchmark applications.

## Compare with other libraries

A benchmark application used for measuring PcapPlusPlus performance can be found in `benchmark.cpp`. It is based on Matias Fontanini's packet-capture-benchmarks project (https://github.com/mfontanini/packet-capture-benchmarks) and allows us to compare PcapPlusPlus with other packet libraries. See this page for more details and result comparisons: https://pcapplusplus.github.io/docs/benchmark

## Directly benchmark PcapPlusPlus

Another application integrates with the Google Benchmark library and can be found in `benchmark-google.cpp`. This application currently consists of five different benchmarks, and each benchmark can be influenced by various factors. These benchmarks aim to utilize different influence factors to provide accurate results for different scenarios. You can check the table below for more information. For performance-critical applications using PcapPlusPlus, it is recommended to run benchmarks in your specific environment for more accurate results. Using larger pcap files and those with diverse protocols and sessions can provide better insights into PcapPlusPlus performance in your setup.

### Benchmarks and their influencing factors

The supported files column indicates the file formats that can be used for the benchmark.
For Read operations benchmarks that denotes the filetypes that can be used as a data source.
For Write operation benchmarks that denotes the filetypes that will be generated as output.


|     Benchmark        |   Supported files   |   Operation   |  Influencing factors |
|:--------------------:|:-------------------:|:-------------:|:--------------------:|
| BM_FileRead          | pcap, pcapng, snoop |     Read      |  CPU + Disk (Read)   |
| BM_FileWrite         |     pcap, pcapng    |     Write     |  CPU + Disk (Write)  |
| BM_PacketParsing     | pcap, pcapng, snoop | Read + Parse  |  CPU + Disk (Read)   |
| BM_PacketPureParsing | pcap, pcapng, snoop |     Parse     |        CPU           |
| BM_PacketCrafting    |       N/A           |     Craft     |        CPU           |
