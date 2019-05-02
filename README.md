# PcapPlusPlus &nbsp; [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=PcapPlusPlus%20is%20a%20multiplatform%20cplusplus%20library%20for%20capturing%2C%20parsing%20and%20crafting%20network%20packets&url=http://seladb.github.io/PcapPlusPlus-Doc)

[![Build Status](https://travis-ci.org/seladb/PcapPlusPlus.svg?branch=master)](https://travis-ci.org/seladb/PcapPlusPlus)
[![Build status](https://ci.appveyor.com/api/projects/status/4u5ui21ibbevkstc?svg=true)](https://ci.appveyor.com/project/seladb/pcapplusplus/branch/master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/18137/badge.svg)](https://scan.coverity.com/projects/pcapplusplus)

[PcapPlusPlus](http://seladb.github.io/PcapPlusPlus-Doc) is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use.

PcapPlusPlus enables decoding and forging capabilities for a large variety of network protocols. It also provides easy to use C++ wrappers for the most popular packet processing engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [DPDK](https://www.dpdk.org/) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/).

## Table Of Contents

- [Download](#download)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Multi Platform Support](#multi-platform-support)
- [Package Content](#package-content)
- [Supported Network Protocols](#supported-network-protocols)
- [Supported Packet Capture Engines](#supported-packet-capture-engines)
- [Useful Packet And Network Utilities](#useful-packet-and-network-utilities)
- [DPDK And PF_RING Support](#dpdk-and-pf_ring-support)
- [Benchmarks](#benchmarks)
- [Provide Feedback](#provide-feedback)
- [Contributing](#contributing)
- [License](#license)

## Download

You can choose between downloading pre-compiled binaries and build PcapPlusPlus yourself. For more details please visit the [Download](http://seladb.github.io/PcapPlusPlus-Doc/download.html) page in PcapPlusPlus web-site.

### Pre Compiled Binaries

From [Homebrew](https://formulae.brew.sh/formula/pcapplusplus):

```shell
brew install pcapplusplus
```

From [Conan](https://bintray.com/bincrafters/public-conan/pcapplusplus%3Abincrafters):

```shell
conan remote add public-conan https://api.bintray.com/conan/bincrafters/public-conan
conan install pcapplusplus/19.04@bincrafters/stable -r public-conan
```

From GitHub release page:

<https://github.com/seladb/PcapPlusPlus/releases/latest>

### Build It Yourself

Clone the git repository:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

Follow the build instructions according to your platform in the [Download](http://seladb.github.io/PcapPlusPlus-Doc/download.html) page in PcapPlusPlus web-site.

## Key Features

- __Decoding and forging__ capabilities for a large variety of network protocols (see the full list [here](#supported-network-protocols))
- __Capture and send network packets__ through an easy to use C++ wrapper for [libpcap](https://www.tcpdump.org/) and [WinPcap](https://www.winpcap.org/)
- __Packet processing in line speed__ through an efficient and easy to use C++ wrapper for [DPDK](https://www.dpdk.org/) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)
- __Read and write network packets to/from files__ in both __PCAP__ and __PCAPNG__ formats
- __Multiplatform support__ including Linux, MacOS and Windows
- Unique implementation of __TCP Reassembly__ logic which includes support of TCP retransmission, out-of-order TCP packets and missing TCP data
- Implementation of __IP Fragmentation and Defragmentation__ logic to create and reassemble IPv4 and IPv6 fragments
- __Remote packet capture__ on Windows using RPCAP protocol supported in WinPcap
- __Vast object-oriented packet filtering__ that makes libpcap's BPF filters a lot more user-friendly
- Designed to be __powerful and efficient__

## Getting Started

Writing applications with PcapPlusPlus is very easy and intuitive. Here is a simple application that shows how to read a packet from a PCAP file and parse it:

```cpp
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        printf("Couldn't read the first packet in the file\n");
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();

        // print source and dest IPs
        printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(), destIP.toString().c_str());
    }

    // close the file
    reader.close();

    return 0;
}
```

You can find much more information in the [Tutorials](http://seladb.github.io/PcapPlusPlus-Doc/tutorials.html) section in PcapPlusPlus web-site. These tutorials will walk you through the main concepts and features of PcapPlusPlus and also provide code examples that you can easily download and run.

## API Documentation

You can find an extensive API documentation in the [API documentation section](http://seladb.github.io/PcapPlusPlus-Doc/Documentation) in PcapPlusPlus web-site.
If you see any missing data please [contact us](#provide-feedback) and report it.

## Multi Platform Support

PcapPlusPlus is currently supported on __Windows__, __Linux__ and __MacOS__. It is being continuously tested on the following platforms:

- Windows:
  - Microsoft Visual Studio 2015 (32-bit + 64-bit compilation)
  - MinGW32 (32-bit compilation only)
  - MinGW-w64 (32-bit compilation only)

- Linux:
  - Ubuntu (12.04 LTS, 14.04 LTS, 16.04 LTS, 18.04 LTS)
  - Fedora 26 & 29
  - CentOS 7
  - It should work on other Linux distributions as well

- MacOS:
  - El Capitan (10.11)
  - Sierra (10.12)
  - High Sierra (10.13)
  - Mojave (10.14)

## Package Content

PcapPlusPlus consists of 3 libraries:

1. __Packet++__ - a library for parsing, creating and editing network packets
2. __Pcap++__ - a library for intercepting and sending packets, providing network and NIC info, stats, etc. It is actually a C++ wrapper for packet capturing engines such as libpcap, WinPcap, DPDK and PF_RING
3. **Common++** - a library with some common code utilities used by both Packet++ and Pcap++

## Supported Network Protocols

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
19. Radius
20. DNS
21. DHCP
22. HTTP headers (request & response)
23. SSL/TLS - parsing only (no editing capabilities)
24. Packet trailer (a.k.a footer or padding)
25. Generic payload

## Supported Packet Capture Engines

PcapPlusPlus currently works with the following packet capture engines:

1. libpcap packet capture (on Linux and Mac OS X)
2. WinPcap packet capture (on Windows)
3. Vanilla PF_RING (on Linux)
4. DPDK (on Linux)
5. WinPcap remote capture (on Windows)
6. PCAP and PCAPNG files
7. Raw sockets (on Linux and Windows)

## Useful Packet And Network Utilities

1. TCP reassembly logic
2. IP reassembly logic (a.k.a IP de-fragmentation). Works for both IPv4 and IPv6
3. Packet hash key creation (by 5-tuple and 2-tuple)
4. Retrieve remote machine MAC address using ARP protocol
5. Retrieve host IPv4 address by using DNS protocol
6. Checksum calculation

In addition it contains many examples, tutorials and utilities documented in the [Examples](http://seladb.github.io/PcapPlusPlus-Doc/examples.html) and in the [Tutorials](http://seladb.github.io/PcapPlusPlus-Doc/tutorials.html) pages in PcapPlusPlus web-site.

## DPDK And PF_RING Support

[The Data Plane Development Kit (DPDK)](https://www.dpdk.org/) is a set of data plane libraries and network interface controller drivers for fast packet processing.

[PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/) is a new type of network socket that dramatically improves the packet capture speed.

Both frameworks provide very fast packets processing (up to line speed) and are used in many network applications such as routers, firewalls, load balancers, etc.
PcapPlusPLus provides a C++ abstraction layer over DPDK & PF_RING. This abstraction layer provides an easy to use interface that removes a lot of the boilerplate involved in using these frameworks. You can learn more by visiting the [DPDK & PF_RING support](http://seladb.github.io/PcapPlusPlus-Doc/dpdk-pf_ring.html) page in PcapPlusPlus web-site.

## Benchmarks

We used Matias Fontanini's [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) project to compare the performance of PcapPlusPlus with other similar C++ libraries (such as `libtins` and `libcrafter`).

You can see the results in the [Benchmarks](http://seladb.github.io/PcapPlusPlus-Doc/benchmark.html) page in PcapPlusPlus web-site.

## Provide Feedback

We'd be more than happy to get feedback, please feel free to reach out to us in any of the following ways:

- Open a GitHub ticket
- Post a message in PcapPlusPlus Google group: <https://groups.google.com/d/forum/pcapplusplus-support>
- Send an email to: <pcapplusplus@gmail.com>
- Follow us on Twitter: <https://twitter.com/seladb>

If you like this project please __Star us on GitHub — it helps!__ :star: :star:

## Contributing

Please follow the notes captured in the [contributing](CONTRIBUTING.md) file to contribute to this project.

## License

PcapPlusPlus is released under the [Unlicense license](https://unlicense.org/).
