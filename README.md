![PcapPlusPlus Logo](https://pcapplusplus.github.io/img/logo/logo_color.png)

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/seladb/PcapPlusPlus/Build%20and%20test?logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![Cirrus CI - Base Branch Build Status](https://img.shields.io/cirrus/github/seladb/PcapPlusPlus?logo=cirrusci&style=flat)](https://cirrus-ci.com/github/seladb/PcapPlusPlus)
[![AppVeyor](https://img.shields.io/appveyor/build/seladb/PcapPlusPlus?logo=appveyor&style=flat)](https://ci.appveyor.com/project/seladb/pcapplusplus/branch/master)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/seladb/PcapPlusPlus/CodeQL?label=CodeQL&logo=github)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![Twitter Follow](https://img.shields.io/twitter/follow/seladb?label=Follow%20PcapPlusPlus&style=social)](https://twitter.com/intent/follow?screen_name=seladb)
![GitHub Repo stars](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=social)

[PcapPlusPlus](https://pcapplusplus.github.io/) is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use.

PcapPlusPlus enables decoding and forging capabilities for a large variety of network protocols. It also provides easy to use C++ wrappers for the most popular packet processing engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [DPDK](https://www.dpdk.org/) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/).

## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [Download](#download)
  - [GitHub Release Page](#github-release-page)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [Build It Yourself](#build-it-yourself)
- [Feature Overview](#feature-overview)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Multi Platform Support](#multi-platform-support)
- [Supported Network Protocols](#supported-network-protocols)
  - [Data Link Layer (L2)](#data-link-layer-l2)
  - [Network Layer (L3)](#network-layer-l3)
  - [Transport Layer (L4)](#transport-layer-l4)
  - [Session Layer (L5)](#session-layer-l5)
  - [Presentation Layer (L6)](#presentation-layer-l6)
  - [Application Layer (L7)](#application-layer-l7)
- [DPDK And PF_RING Support](#dpdk-and-pf_ring-support)
- [Benchmarks](#benchmarks)
- [Provide Feedback](#provide-feedback)
- [Contributing](#contributing)
- [License](#license)

## Download

You can choose between downloading from GitHub release page, use a package manager or build PcapPlusPlus yourself. For more details please visit the [Download](https://pcapplusplus.github.io/docs/install) page in PcapPlusPlus web-site.

![GitHub all releases](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?label=Downloads&logo=github)
![homebrew downloads](https://img.shields.io/homebrew/installs/dy/pcapplusplus?label=Downloads&logo=homebrew)

### GitHub Release Page

<https://github.com/seladb/PcapPlusPlus/releases/latest>

### Homebrew

```shell
brew install pcapplusplus
```

Homebrew formulae: <https://formulae.brew.sh/formula/pcapplusplus>

### Vcpkg

Windows:

```text
.\vcpkg install pcapplusplus
```

MacOS/Linux:

```text
vcpkg install pcapplusplus
```

Vcpkg port: <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>

### Conan

```text
conan install "pcapplusplus/[>0]@" -u
```

The package in ConanCenter: <https://conan.io/center/pcapplusplus>

### Build It Yourself

Clone the git repository:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

Follow the build instructions according to your platform in the [Build From Source](https://pcapplusplus.github.io/docs/install#build-from-source) page in PcapPlusPlus web-site.

## Feature Overview

- __Packet capture__ through an easy to use C++ wrapper for popular packet capture engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [Intel DPDK](https://www.dpdk.org/), [ntop’s PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) and [raw sockets](https://en.wikipedia.org/wiki/Network_socket#Raw_socket) [[Learn more](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __Packet parsing and crafting__ including detailed analysis of protocols and layers, packet generation and packet edit for a large variety of [network protocols](https://pcapplusplus.github.io/docs/features#supported-network-protocols) [[Learn more](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __Read and write packets from/to files__ in both __PCAP__ and __PCAPNG__ formats [[Learn more](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __Packet processing in line rate__ through an efficient and easy to use C++ wrapper for [DPDK](https://www.dpdk.org/) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) [[Learn more](https://pcapplusplus.github.io/docs/features#dpdk-support)]
- __Multiplatform support__ - PcapPlusPlus is fully supported on Linux, MacOS, Windows, Android and FreeBSD
- __Packet reassembly__ - unique implementation of __TCP Reassembly__ which includes TCP retransmission, out-of-order TCP packets and missing TCP data, and __IP Fragmentation and Defragmentation__ to create and reassemble IPv4 and IPv6 fragments [[Learn more](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __Packet filtering__ that makes libpcap's BPF filters a lot more user-friendly [[Learn more](https://pcapplusplus.github.io/docs/features#packet-filtering)]
- __TLS Fingerprinting__ - a C++ implementation of [JA3 and JA3S](https://github.com/salesforce/ja3) TLS fingerprinting [[Learn more](https://pcapplusplus.github.io/docs/features#tls-fingerprinting)]

## Getting Started

Writing applications with PcapPlusPlus is very easy and intuitive. Here is a simple application that shows how to read a packet from a PCAP file and parse it:

```cpp
#include <iostream>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "Couldn't read the first packet in the file" << std::endl;
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // print source and dest IPs
        std::cout << "Source IP is '" << srcIP << "'; Dest IP is '" << destIP << "'" << std::endl;
    }

    // close the file
    reader.close();

    return 0;
}
```

You can find much more information in the [Getting Started](https://pcapplusplus.github.io/docs/quickstart) page in PcapPlusPlus web-site. This page will walk you through few easy steps to have an app up and running.

## API Documentation

PcapPlusPlus consists of 3 libraries:

1. __Packet++__ - a library for parsing, creating and editing network packets
2. __Pcap++__ - a library for intercepting and sending packets, providing network and NIC info, stats, etc. It is actually a C++ wrapper for packet capturing engines such as libpcap, WinPcap, Npcap, DPDK and PF_RING
3. __Common++__ - a library with some common code utilities used by both Packet++ and Pcap++

You can find an extensive API documentation in the [API documentation section](https://pcapplusplus.github.io/docs/api) in PcapPlusPlus web-site.
If you see any missing data please [contact us](#provide-feedback).

## Multi Platform Support

PcapPlusPlus is currently supported on __Windows__, __Linux__, __MacOS__, __Android__ and __FreeBSD__. Please visit PcapPlusPlus web-site to see all of the [supported platforms](https://pcapplusplus.github.io/docs/platforms) and refer to the [Download](#download) section to start using PcapPlusPlus on your platform.

![](https://img.shields.io/badge/Windows-%230078D6.svg?&style=flat&logo=windows&logoColor=white)
![](https://img.shields.io/badge/Linux-%23FCC624.svg?&style=flat&logo=linux&logoColor=black)
![](https://img.shields.io/badge/MacOS-%23FFFFFF.svg?&style=flat&logo=macos&logoColor=black)
![](https://img.shields.io/badge/Android-%23000000.svg?&style=flat&logo=android&logoColor=3DDC84)
![](https://img.shields.io/badge/FreeBSD-%23A62B28.svg?&style=flat&logo=freebsd&logoColor=red)

## Supported Network Protocols

PcapPlusPlus currently supports parsing, editing and creation of packets of the following protocols:

### Data Link Layer (L2)

1. Ethernet II
2. IEEE 802.3 Ethernet
3. LLC (Only BPDU supported)
4. Null/Loopback
5. Packet trailer (a.k.a footer or padding)
6. PPPoE
7. SLL (Linux cooked capture)
8. STP - parsing only (no editing capabilities)
9. VLAN
10. VXLAN

### Network Layer (L3)

11. ARP
12. GRE
13. ICMP
14. ICMPv6
15. IGMP (IGMPv1, IGMPv2 and IGMPv3 are supported)
16. IPv4
17. IPv6
18. MPLS
19. NDP
20. Raw IP (IPv4 & IPv6)

### Transport Layer (L4)

21. GTP (v1)
22. IPSec AH & ESP - parsing only (no editing capabilities)
23. TCP
24. UDP

### Session Layer (L5)

25. SDP
26. SIP

### Presentation Layer (L6)

27. SSL/TLS - parsing only (no editing capabilities)

### Application Layer (L7)

28. BGP (v4)
29. DHCP
30. DHCPv6
31. DNS
32. FTP
33. HTTP headers (request & response)
34. NTP (v3, v4)
35. Radius
36. SOME/IP
37. SSH - parsing only (no editing capabilities)
38. Telnet - parsing only (no editing capabilities)
39. Generic payload

## DPDK And PF_RING Support

[The Data Plane Development Kit (DPDK)](https://www.dpdk.org/) is a set of data plane libraries and network interface controller drivers for fast packet processing.

[PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/) is a new type of network socket that dramatically improves the packet capture speed.

Both frameworks provide very fast packets processing (up to line speed) and are used in many network applications such as routers, firewalls, load balancers, etc.
PcapPlusPLus provides a C++ abstraction layer over DPDK & PF_RING. This abstraction layer provides an easy to use interface that removes a lot of the boilerplate involved in using these frameworks. You can learn more by visiting the [DPDK](https://pcapplusplus.github.io/docs/dpdk) & [PF_RING](https://pcapplusplus.github.io/docs/features#pf_ring-support) support pages in PcapPlusPlus web-site.

## Benchmarks

We used Matias Fontanini's [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) project to compare the performance of PcapPlusPlus with other similar C++ libraries (such as `libtins` and `libcrafter`).

You can see the results in the [Benchmarks](https://pcapplusplus.github.io/docs/benchmark) page in PcapPlusPlus web-site.

## Provide Feedback

We'd be more than happy to get feedback, please feel free to reach out to us in any of the following ways:

- Open a GitHub ticket
- Post a message in PcapPlusPlus Google group: <https://groups.google.com/d/forum/pcapplusplus-support>
- Ask a question on Stack Overflow: <https://stackoverflow.com/questions/tagged/pcapplusplus>
- Send an email to: <pcapplusplus@gmail.com>
- Follow us on Twitter: <https://twitter.com/seladb>

If you like this project please __Star us on GitHub — it helps!__ :star: :star:

Please visit the [PcapPlusPlus web-site](https://pcapplusplus.github.io/community) to learn more.

## Contributing

We would very much appreciate any contribution to this project. If you're interested in contributing please visit the [contribution page](https://pcapplusplus.github.io/community#contribute) in PcapPlusPlus web-site.

## License

PcapPlusPlus is released under the [Unlicense license](https://unlicense.org/).
