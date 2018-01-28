PcapPlusPlus
============

[![Build Status](https://travis-ci.org/seladb/PcapPlusPlus.svg?branch=master)](https://travis-ci.org/seladb/PcapPlusPlus)
[![Build status](https://ci.appveyor.com/api/projects/status/4u5ui21ibbevkstc?svg=true)](https://ci.appveyor.com/project/seladb/pcapplusplus)

PcapPlusPlus is a multiplatform C++ network sniffing and packet parsing and crafting framework. PcapPlusPlus is meant to be lightweight, efficient and easy to use.

PcapPlusPlus web-site: http://seladb.github.io/PcapPlusPlus-Doc

### Getting Started ###

Please visit the [Tutorials](http://seladb.github.io/PcapPlusPlus-Doc/tutorials.html) in PcapPlusPlus web-site to learn about PcapPlusPlus and how to use it


### What makes PcapPlusPlus different from similar C++ wrappers for libpcap/WinPcap? ###

- Designed to be lightweight and efficient
- Support for **DPDK** fast packet processing engine which enables packet capturing and transmition in line rate using kernel bypass
- Support for ntop's **PF_RING** packet capturing engine that dramatically improves the packet capture speed
- Support for parsing and editing of many protocols, including L5-7 protocols like HTTP, SSL/TLS and SIP
- Unique implementation of **TCP reassembly** logic which includes support of TCP retransmission, out-of-order TCP packets and missing TCP data
- Support for Remote Capture capabilities on Windows (using RPCAP protocol supported in WinPcap)
- Support for reading and writing **PCAPNG** files (a lot more more than currently supported in WinPcap/libpcap)
- Vast object-oriented filtering mechanism that makes libpcap filters a lot more user-friendly (no need to know the exact filter string to use)

### PcapPlusPlus Is Multi-Platform! ###
PcapPlusPlus is currently supported on **Windows**, **Linux** and **Mac OS X**. It was tested on the following platforms:

- Windows:
    - Microsoft Visual Studio 2015 (32-bit + 64-bit compilation)
    - MinGW32 (32-bit compilation only)
    - MinGW-w64 (32-bit compilation only)

- Linux:
    - Ubuntu (12.04 LTS, 14.04 LTS, 16.04 LTS)
    - Fedora 26
    - CentOS 7
    - It should work on other Linux distributions as well

- Mac OS X:
    - Yosemite (10.10)
    - El Capitan (10.11)
    - Sierra (10.12)

### Supported Engines and Devices ###

PcapPlusPlus currently works with the following devices:

1. libpcap live device (on Linux and Mac OS X)
2. WinPcap live device (on Windows)
3. Vanilla PF_RING device (on Linux)
4. DPDK device (on Linux)
5. Remote live device (on Windows)
6. PCAP and PCAPNG file devices

### Supported Protocols ###

The Packet++ library currently supports parsing, editing and creation of packets of the following protocols:

1. Ethernet
2. SLL (Linux cooked capture)
3. Null/Loopback
4. Raw IP (IPv4 & IPv6)
5. IPv4
6. IPv6
7. ARP
8. VLAN
9. VXLAN
10. MPLS
11. PPPoE
12. GRE
13. TCP
14. UDP
15. ICMP
16. IGMP (IGMPv1, IGMPv2 and IGMPv3 are supported)
17. SIP
18. SDP
19. DNS
20. DHCP
21. HTTP headers (request & response)
22. SSL/TLS - parsing only (no editing capabilities)
23. Generic payload

### Useful Packet And Network Utilities ###

1. TCP reassembly logic
2. IP reassembly logic (a.k.a IP de-fragmentation). Works for both IPv4 and IPv6
3. Packet hash key creation (by 5-tuple and 2-tuple)
4. Retrieve remote machine MAC address using ARP protocol
5. Retrieve host IPv4 address by using DNS protocol
6. Checksum calculation

### Package Content ###

PcapPlusPlus consists of 3 libraries:

1. **Packet++** - a library for parsing, creating and editing packets
2. **Pcap++** - a library for intercepting and sending packets, providing network and NIC info, stats, etc. It is actually a C++ wrapper for packet capturing engines such as libpcap, WinPcap, DPDK and PF_RING
3. **Common++** - a library with some common code utilities used by both Packet++ and Pcap++

In addition it contains many examples, tutorials and utilities documented in the [Examples](http://seladb.github.io/PcapPlusPlus-Doc/examples.html) and in the [Tutorials](http://seladb.github.io/PcapPlusPlus-Doc/tutorials.html) pages in PcapPlusPlus web-site 


# Download #

In order to download PcapPlusPlus, please visit the github [page](https://github.com/seladb/PcapPlusPlus/).

You can also download it using these links:

- [ZIP format](https://github.com/seladb/PcapPlusPlus/archive/master.zip)
- [tat.gz format](https://github.com/seladb/PcapPlusPlus/archive/master.tar.gz)
 
Or clone the git repository by:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

### Compiled Binaries ###

If you want an already compiled version of PcapPlusPlus chekcout the latest release:
[https://github.com/seladb/PcapPlusPlus/releases/latest](https://github.com/seladb/PcapPlusPlus/releases/latest)


### Compile Yourself ###

For compilation instructions of the various platforms please refer to the [Download](http://seladb.github.io/PcapPlusPlus-Doc/download.html) page in PcapPlusPlus web-site

# PcapPlusPlus Documentation #

[PcapPlusPlus web-site](http://seladb.github.io/PcapPlusPlus-Doc/) includes all the relevant documentation.

Also, the entire API of PcapPlusPlus is documented using doxygen. You can find it here: [http://seladb.github.io/PcapPlusPlus-Doc/Documentation/index.html](http://seladb.github.io/PcapPlusPlus-Doc/Documentation/index.html)

If you see any missing information please tell me


# PcapPlusPlus Support #

I'll be very happy to get feedbacks, so feel free to contact me in any of the following ways:

- Open a Github ticket
- PcapPlusPlus Google group: https://groups.google.com/d/forum/pcapplusplus-support
- Send an email to: pcapplusplus@gmail.com


# DPDK & PF_RING Support #

PcapPlusPLus provides a C++ absraction layers over DPDK & PF_RING. For more details please visit PcapPlusPlus web-site:

http://seladb.github.io/PcapPlusPlus-Doc/dpdk-pf_ring.html


# Benchmarks #

I used Matias Fontanini's [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) project to compare the performance of PcapPlusPlus with other similar C++ libraries (libtins and libcrafter). 

The results can eviewed in the [Benchmarks](http://seladb.github.io/PcapPlusPlus-Doc/benchmark.html) page in PcapPlusPlus web-site


# Creating Applications With PcapPlusPlus #

Please refer to the [Tutorials](http://seladb.github.io/PcapPlusPlus-Doc/tutorials.html) section in PcapPlusPlus web-site
