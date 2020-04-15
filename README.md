![PcapPlusPlus Logo](https://pcapplusplus.github.io/resources/logo_color.png)

[![Build Status](https://travis-ci.org/seladb/PcapPlusPlus.svg?branch=master)](https://travis-ci.org/seladb/PcapPlusPlus)
[![Build status](https://ci.appveyor.com/api/projects/status/4u5ui21ibbevkstc/branch/master?svg=true)](https://ci.appveyor.com/project/seladb/pcapplusplus/branch/master)
[![Build Status](https://api.cirrus-ci.com/github/seladb/PcapPlusPlus.svg)](https://cirrus-ci.com/github/seladb/PcapPlusPlus)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/seladb/PcapPlusPlus.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/seladb/PcapPlusPlus/context:cpp)
<a href="https://twitter.com/intent/follow?screen_name=seladb">
    <img src="https://img.shields.io/twitter/follow/seladb.svg?label=Follow%20PcapPlusPlus" alt="Follow PcapPlusPlus" />
</a>

[PcapPlusPlus](https://pcapplusplus.github.io/) is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use.

PcapPlusPlus enables decoding and forging capabilities for a large variety of network protocols. It also provides easy to use C++ wrappers for the most popular packet processing engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [DPDK](https://www.dpdk.org/) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/).

## Table Of Contents

- [Download](#download)
- [Feature Overview](#feature-overview)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Multi Platform Support](#multi-platform-support)
- [Supported Network Protocols](#supported-network-protocols)
- [DPDK And PF_RING Support](#dpdk-and-pf_ring-support)
- [Benchmarks](#benchmarks)
- [Provide Feedback](#provide-feedback)
- [Contributing](#contributing)
- [License](#license)

## Download

You can choose between downloading pre-compiled binaries and build PcapPlusPlus yourself. For more details please visit the [Download](https://pcapplusplus.github.io/docs/install) page in PcapPlusPlus web-site.

### Pre Compiled Binaries

From [Homebrew](https://formulae.brew.sh/formula/pcapplusplus):

```shell
brew install pcapplusplus
```

From [Conan](https://bintray.com/bincrafters/public-conan/pcapplusplus%3Abincrafters):

```shell
conan remote add public-conan https://api.bintray.com/conan/bincrafters/public-conan
conan install pcapplusplus/19.12@bincrafters/stable -r public-conan
```

From GitHub release page:

<https://github.com/seladb/PcapPlusPlus/releases/latest>

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
- __Multiplatform support__ - PcapPlusPlus is fully supported on Linux, MacOS, Windows and FreeBSD
- __Packet reassembly__ - unique implementation of __TCP Reassembly__ which includes TCP retransmission, out-of-order TCP packets and missing TCP data, and __IP Fragmentation and Defragmentation__ to create and reassemble IPv4 and IPv6 fragments [[Learn more](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __Packet filtering__ that makes libpcap's BPF filters a lot more user-friendly [[Learn more](https://pcapplusplus.github.io/docs/features#packet-filtering)]

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

You can find much more information in the [Getting Started](https://pcapplusplus.github.io/docs/) page in PcapPlusPlus web-site. This page will walk you through few easy steps to have an app up and running.

## API Documentation

PcapPlusPlus consists of 3 libraries:

1. __Packet++__ - a library for parsing, creating and editing network packets
2. __Pcap++__ - a library for intercepting and sending packets, providing network and NIC info, stats, etc. It is actually a C++ wrapper for packet capturing engines such as libpcap, WinPcap, Npcap, DPDK and PF_RING
3. __Common++__ - a library with some common code utilities used by both Packet++ and Pcap++

You can find an extensive API documentation in the [API documentation section](https://pcapplusplus.github.io/api-docs/) in PcapPlusPlus web-site.
If you see any missing data please [contact us](#provide-feedback).

## Multi Platform Support

PcapPlusPlus is currently supported on __Windows__, __Linux__, __MacOS__ and __FreeBSD__. Please visit PcapPlusPlus web-site to see all of the [supported platforms](https://pcapplusplus.github.io/docs/install/platforms) and refer to the [Download](#download) section to start using PcapPlusPlus on your platform.

## Supported Network Protocols

PcapPlusPlus currently supports parsing, editing and creation of packets of the following protocols:

1. Ethernet II
2. IEEE 802.3 Ethernet
3. SLL (Linux cooked capture)
4. Null/Loopback
5. Raw IP (IPv4 & IPv6)
6. IPv4
7. IPv6
8. ARP
9. VLAN
10. VXLAN
11. MPLS
12. PPPoE
13. GRE
14. TCP
15. UDP
16. GTP (v1)
17. ICMP
18. IGMP (IGMPv1, IGMPv2 and IGMPv3 are supported)
19. SIP
20. SDP
21. Radius
22. DNS
23. DHCP
24. BGP (v4)
25. HTTP headers (request & response)
26. SSL/TLS - parsing only (no editing capabilities)
27. Packet trailer (a.k.a footer or padding)
28. Generic payload

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
- Send an email to: <pcapplusplus@gmail.com>
- Follow us on Twitter: <https://twitter.com/seladb>

If you like this project please __Star us on GitHub — it helps!__ :star: :star:

Please visit the [PcapPlusPlus web-site](https://pcapplusplus.github.io/docs/community) to learn more.

## Contributing

We would very much appreciate any contribution to this project. If you're interested in contributing please visit the [contribution page](https://pcapplusplus.github.io/docs/community#contribute) in PcapPlusPlus web-site.

## License

PcapPlusPlus is released under the [Unlicense license](https://unlicense.org/).
