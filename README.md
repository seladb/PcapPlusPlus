
<div align="center">

[![PcapPlusPlus Logo](https://pcapplusplus.github.io/img/logo/logo_color.png)](https://pcapplusplus.github.io)

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/build_and_test.yml?branch=master&label=Actions&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/codeql.yml?branch=master&label=CodeQL&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![Codecov](https://img.shields.io/codecov/c/github/seladb/PcapPlusPlus?logo=codecov&logoColor=white)](https://app.codecov.io/github/seladb/PcapPlusPlus)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seladb/PcapPlusPlus/badge)](https://scorecard.dev/viewer/?uri=github.com/seladb/PcapPlusPlus)
[![GitHub contributors](https://img.shields.io/github/contributors/seladb/PcapPlusPlus?style=flat&label=Contributors&logo=github)](https://github.com/seladb/PcapPlusPlus/graphs/contributors)

[![X Follow](https://img.shields.io/badge/follow-%40seladb-1DA1F2?logo=x&style=social)](https://x.com/intent/follow?screen_name=seladb)
[![GitHub Repo stars](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=social)]()

</div>

[PcapPlusPlus](https://pcapplusplus.github.io/) is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use.

PcapPlusPlus enables decoding and forging capabilities for a large variety of network protocols. It also provides easy to use C++ wrappers for the most popular packet processing engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/).

Translations: English · [正體中文](./translation/README-zh-tw.md) · [한국어](./translation/README-kor.md)

## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [Download](#download)
  - [GitHub Release Page](#github-release-page)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [Build It Yourself](#build-it-yourself)
  - [Verify your packages](#verify-your-packages)
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

[![GitHub all releases](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=flat&label=Downloads&logo=github)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

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

### Verify your packages

PcapPlusPlus releases which newer than v23.09 are signed with GitHub attestation. All of the attestations can be found [here](https://github.com/seladb/PcapPlusPlus/attestations). You can verify the attestation of these packages with GitHub CLI. To verify packages you can follow the most recent instructions from [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify). For simple instructions you can use the following command:

```shell
gh attestation verify <path-to-package-file> --repository seladb/PcapPlusPlus
```

and you should see the following output in your terminal:

```shell
✓ Verification succeeded!
```

## Feature Overview

- __Packet capture__ through an easy to use C++ wrapper for popular packet capture engines such as [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [Intel DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [ntop’s PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) and [raw sockets](https://en.wikipedia.org/wiki/Network_socket#Raw_socket) [[Learn more](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __Packet parsing and crafting__ including detailed analysis of protocols and layers, packet generation and packet edit for a large variety of [network protocols](https://pcapplusplus.github.io/docs/features#supported-network-protocols) [[Learn more](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __Read and write packets from/to files__ in both __PCAP__ and __PCAPNG__ formats [[Learn more](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __Packet processing in line rate__ through an efficient and easy to use C++ wrapper for [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html) and [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) [[Learn more](https://pcapplusplus.github.io/docs/features#dpdk-support)]
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

PcapPlusPlus is currently supported on
__Windows__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-windows.png" alt="" width="16" height="16"/>
</picture>,
__Linux__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-linux.png" alt="" width="16" height="16"/>
</picture>,
__MacOS__
<picture><source media="(prefers-color-scheme: dark)" srcset="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple-dark.png"/>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple.png" alt="" width="16" height="16"/>
</picture>,
__Android__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-android.png" alt="" width="16" height="16"/>
</picture> and
__FreeBSD__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-freebsd.png" alt="" width="16" height="16"/>
</picture>.
Please visit PcapPlusPlus web-site to see all of the [supported platforms](https://pcapplusplus.github.io/docs/platforms) and refer to the [Download](#download) section to start using PcapPlusPlus on your platform.

## Supported Network Protocols

PcapPlusPlus currently supports parsing, editing and creation of packets of the following protocols:

### Data Link Layer (L2)

1. Cisco HDLC
2. Ethernet II
3. IEEE 802.3 Ethernet
4. LLC (Only BPDU supported)
5. Null/Loopback
6. Packet trailer (a.k.a footer or padding)
7. PPPoE
8. SLL (Linux cooked capture)
9. SLL2 (Linux cooked capture v2)
10. STP
11. VLAN
12. VXLAN
13. Wake on LAN (WoL)
14. NFLOG (Linux Netfilter NFLOG) - parsing only (no editing capabilities)


### Network Layer (L3)

15. ARP
16. GRE
17. ICMP
18. ICMPv6
19. IGMP (IGMPv1, IGMPv2 and IGMPv3 are supported)
20. IPv4
21. IPv6
22. MPLS
23. NDP
24. Raw IP (IPv4 & IPv6)
25. VRRP (IPv4 & IPv6)
26. WireGuard

### Transport Layer (L4)

27. COTP
28. GTP (v1 & v2)
29. IPSec AH & ESP - parsing only (no editing capabilities)
30. TCP
31. TPKT
32. UDP

### Session Layer (L5)

33. SDP
34. SIP

### Presentation Layer (L6)

35. SSL/TLS - parsing only (no editing capabilities)

### Application Layer (L7)

36. ASN.1 decoder and encoder
37. BGP (v4)
38. DHCP
39. DHCPv6
40. DNS
41. FTP
42. HTTP headers (request & response)
43. LDAP
44. NTP (v3, v4)
45. Radius
46. S7 Communication (S7comm)
47. SMTP
48. SOME/IP
49. SSH - parsing only (no editing capabilities)
50. Telnet - parsing only (no editing capabilities)
51. Generic payload

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
- Follow us on X: <https://x.com/seladb>

If you like this project please __Star us on GitHub — it helps!__ :star: :star:

Please visit the [PcapPlusPlus web-site](https://pcapplusplus.github.io/community) to learn more.

## Contributing

We would very much appreciate any contribution to this project. If you're interested in contributing please visit the [contribution page](https://pcapplusplus.github.io/community#contribute) in PcapPlusPlus web-site.

## License

PcapPlusPlus is released under the [Unlicense license](https://choosealicense.com/licenses/unlicense/).

[![GitHub](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=flat&color=blue&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)
