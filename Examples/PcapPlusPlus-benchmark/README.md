PcapPlusPlus Benchmark
======================

There is a benchmark application used for measuring PcapPlusPlus performance. It is based on Matias Fontanini's packet-capture-benchmarks project (https://github.com/mfontanini/packet-capture-benchmarks).

See this page for more details: https://pcapplusplus.github.io/docs/benchmark

This application currently compiles on Linux only (where benchmark was running on)

Additionally, there is an integration of Google Benchmark library for benchmarking. For enabling, configure the library with `-DPCAPPP_USE_GOOGLEBENCHMARK=ON`. Each benchmark can be affected from different sources. You can check the table below for more information. If you have performance critical applications which will use PcapPlusPlus, please benchmark it in your environment to get better and more precise results. Also using different pcaps, both in terms of size (larger is better to prevent open/close overhead) and protocol/session variety, can also help to give idea about performance of PcapPlusPlus in your environment.

|     Benchmark     |   Operation   |  Can be affected  |
|:-----------------:|:-------------:|:-----------------:|
| BM_PcapFileRead   |     Read      | CPU + Disk (Read) |
| BM_PcapFileWrite  |     Write     | CPU + Disk (Write)|
| BM_PacketParsing  | Read + Parse  | CPU + Disk (Read) |
| BM_PacketCrafting |     Craft     |       CPU         |
