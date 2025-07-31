<div align="center">

[![PcapPlusPlus Logo](https://pcapplusplus.github.io/img/logo/logo_color.png)](https://pcapplusplus.github.io)

<p><strong>⚡ High-Performance Network Packet Processing Library for C++ ⚡</strong></p>

---

<div>

[![🔧 Build Status](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/build_and_test.yml?branch=master&label=Build&logo=github&style=for-the-badge&color=brightgreen)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![🔍 CodeQL](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/codeql.yml?branch=master&label=Security&logo=github&style=for-the-badge&color=blue)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![📊 Coverage](https://img.shields.io/codecov/c/github/seladb/PcapPlusPlus?logo=codecov&logoColor=white&style=for-the-badge&color=purple)](https://app.codecov.io/github/seladb/PcapPlusPlus)

</div>

<div>

[![🏆 Quality Score](https://img.shields.io/ossf-scorecard/github.com/seladb/PcapPlusPlus?label=Security%20Score&style=for-the-badge&color=orange)](https://scorecard.dev/viewer/?uri=github.com/seladb/PcapPlusPlus)
[![👥 Contributors](https://img.shields.io/github/contributors/seladb/PcapPlusPlus?style=for-the-badge&label=Contributors&logo=github&color=red)](https://github.com/seladb/PcapPlusPlus/graphs/contributors)
[![📥 Downloads](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=for-the-badge&label=Downloads&logo=github&color=teal)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

</div>

<div>

[![🐦 Follow](https://img.shields.io/badge/follow-%40seladb-1DA1F2?logo=x&style=for-the-badge)](https://x.com/intent/follow?screen_name=seladb)
[![⭐ Stars](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=for-the-badge&logo=github&color=yellow)](https://github.com/seladb/PcapPlusPlus/stargazers)
[![🍴 Forks](https://img.shields.io/github/forks/seladb/PcapPlusPlus?style=for-the-badge&logo=github&color=lightgrey)](https://github.com/seladb/PcapPlusPlus/network/members)

</div>

</div>

<br>

<div align="center">
<table>
<tr>
<td align="center">

**🌐 Multiplatform**<br>
Linux • Windows • macOS<br>
Android • FreeBSD

</td>
<td align="center">

**⚡ High Performance**<br>
DPDK • PF_RING • eBPF<br>
Line-rate Processing

</td>
<td align="center">

**🔧 Easy to Use**<br>
Modern C++ API<br>
Extensive Documentation

</td>
</tr>
</table>
</div>

---

## About PcapPlusPlus

[**PcapPlusPlus**](https://pcapplusplus.github.io/) is a **multiplatform C++ library** for capturing, parsing and crafting of network packets. It is designed to be **efficient**, **powerful** and **easy to use**.

> 💡 **What makes PcapPlusPlus special?**
>
> PcapPlusPlus enables decoding and forging capabilities for a **large variety of network protocols**. It also provides easy to use C++ wrappers for the most popular packet processing engines such as [**libpcap**](https://www.tcpdump.org/), [**WinPcap**](https://www.winpcap.org/), [**Npcap**](https://nmap.org/npcap/), [**DPDK**](https://www.dpdk.org/), [**eBPF AF_XDP**](https://www.kernel.org/doc/html/next/networking/af_xdp.html) and [**PF_RING**](https://www.ntop.org/products/packet-capture/pf_ring/).

<div align="center">

**🌍 Translations Available**

[**🇺🇸 English**]() · [**🇹🇼 正體中文**](./translation/README-zh-tw.md) · [**🇰🇷 한국어**](./translation/README-kor.md)

</div>

## Table Of Contents

- [About PcapPlusPlus](#about-pcapplusplus)
- [Table Of Contents](#table-of-contents)
- [Download](#download)
  - [GitHub Release Page](#github-release-page)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [Build It Yourself](#build-it-yourself)
  - [Verify your packages](#verify-your-packages)
- [Feature Overview](#feature-overview)
  - [**Packet Capture**](#packet-capture)
  - [**Packet Parsing \& Crafting**](#packet-parsing--crafting)
  - [**File I/O Operations**](#file-io-operations)
  - [**Line-Rate Processing**](#line-rate-processing)
  - [**Packet Reassembly**](#packet-reassembly)
  - [**Advanced Features**](#advanced-features)
- [Getting Started](#getting-started)
- [Packet Capture Backends](#packet-capture-backends)
  - [**libpcap**](#libpcap)
  - [**WinPcap / Npcap**](#winpcap--npcap)
  - [**Remote Capture (rpcapd)**](#remote-capture-rpcapd)
  - [**DPDK KNI**](#dpdk-kni)
- [API Documentation](#api-documentation)
  - [**Packet++**](#packet)
  - [**Pcap++**](#pcap)
  - [**Common++**](#common)
- [Multi Platform Support](#multi-platform-support)
- [Supported Network Protocols](#supported-network-protocols)
  - [Data Link Layer (L2)](#data-link-layer-l2)
  - [Network Layer (L3)](#network-layer-l3)
  - [Transport Layer (L4)](#transport-layer-l4)
  - [Session Layer (L5)](#session-layer-l5)
  - [Presentation Layer (L6)](#presentation-layer-l6)
  - [Application Layer (L7)](#application-layer-l7)
- [High-Performance Packet Processing Support](#high-performance-packet-processing-support)
  - [**DPDK**](#dpdk)
  - [**PF\_RING™**](#pf_ring)
  - [**eBPF XDP**](#ebpf-xdp)
- [Benchmarks](#benchmarks)
- [Provide Feedback](#provide-feedback)
- [Contributing](#contributing)
- [License](#license)

## Download

<div align="center">

**Choose Your Preferred Installation Method**

</div>

You can choose between downloading from GitHub release page, use a package manager or build PcapPlusPlus yourself. For more details please visit the [**📖 Download**](https://pcapplusplus.github.io/docs/install) page in PcapPlusPlus web-site.

### GitHub Release Page

```
https://github.com/seladb/PcapPlusPlus/releases/latest
```

### Homebrew

```shell
brew install pcapplusplus
```

**📎 Homebrew formulae:** <https://formulae.brew.sh/formula/pcapplusplus>

### Vcpkg

**Windows:**
```cmd
.\vcpkg install pcapplusplus
```

**MacOS/Linux:**
```bash
vcpkg install pcapplusplus
```

**📎 Vcpkg port:** <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>

### Conan

```bash
conan install "pcapplusplus/[>0]@" -u
```

**📎 The package in ConanCenter:** <https://conan.io/center/pcapplusplus>

### Build It Yourself

**Clone the repository:**
```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

Follow the build instructions according to your platform in the [**🛠️ Build From Source**](https://pcapplusplus.github.io/docs/install#build-from-source) page in PcapPlusPlus web-site.

### Verify your packages

PcapPlusPlus releases which newer than **v23.09** are signed with **GitHub attestation**. All of the attestations can be found [**here**](https://github.com/seladb/PcapPlusPlus/attestations). You can verify the attestation of these packages with GitHub CLI. To verify packages you can follow the most recent instructions from [**gh attestation verify**](https://cli.github.com/manual/gh_attestation_verify). For simple instructions you can use the following command:

```shell
gh attestation verify <path-to-package-file> --repository seladb/PcapPlusPlus
```

and you should see the following output in your terminal:

```shell
✓ Verification succeeded!
```

## Feature Overview

<div align="center">

**Everything You Need for Network Packet Processing**

</div>

<table>
<tr>
<td width="50%">

### **Packet Capture**
Easy-to-use C++ wrapper for popular engines:
- **libpcap** - Universal packet capture
- **WinPcap/Npcap** - Windows packet capture
- **Intel DPDK** - High-performance processing
- **eBPF AF_XDP** - Kernel bypass networking
- **PF_RING** - High-speed packet processing
- **Raw sockets** - Low-level network access

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#packet-capture)

</td>
<td width="50%">

### **Packet Parsing & Crafting**
Detailed protocol analysis and packet generation:
- **Deep packet inspection**
- **Packet creation and modification**
- **Layer-by-layer analysis**
- **50+ supported protocols**
- **Protocol-specific handling**

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)

</td>
</tr>
<tr>
<td width="50%">

### **File I/O Operations**
Read and write packets from/to files:
- **PCAP format support**
- **PCAPNG format support**
- **Format conversion**
- **Efficient file handling**

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)

</td>
<td width="50%">

### **Line-Rate Processing**
High-performance packet processing:
- **DPDK integration**
- **eBPF AF_XDP support**
- **PF_RING optimization**
- **Scalable architecture**
- **Zero-copy processing**

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#dpdk-support)

</td>
</tr>
<tr>
<td width="50%">

### **Packet Reassembly**
Advanced reconstruction capabilities:
- **TCP Reassembly** - Handle retransmissions & out-of-order
- **IP Fragmentation/Defragmentation** - IPv4 & IPv6
- **Missing data handling**
- **State management**

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#packet-reassembly)

</td>
<td width="50%">

### **Advanced Features**
Specialized networking capabilities:
- **BPF filters made easy**
- **TLS Fingerprinting (JA3/JA3S)**
- **Multi-platform support**
- **User-friendly packet filtering**

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#packet-filtering)

</td>
</tr>
</table>

## Getting Started

<div align="center">

**✨ Writing applications with PcapPlusPlus is very easy and intuitive! ✨**

</div>

Here's a **simple application** that shows how to read a packet from a PCAP file and parse it:

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

<div align="center">

**Want to learn more?**

Visit our comprehensive [**📚 Getting Started**](https://pcapplusplus.github.io/docs/quickstart) guide! This page will walk you through **few easy steps** to have an app up and running.

</div>

## Packet Capture Backends

<div align="center">

**Multiple Capture Engines Supported!**

</div>

PcapPlusPlus provides a **unified C++ interface** for multiple packet capture backends, making it easy to switch between different capture engines based on your platform and requirements.

<table>
<tr>
<td width="25%" align="center">

### **libpcap**
<img src="https://img.shields.io/badge/Backend-libpcap-blue?style=for-the-badge" alt="libpcap">

**🐧 Universal Packet Capture**

The standard packet capture library for **Unix-like systems**. Cross-platform support for Linux, macOS, and BSD.

</td>
<td width="25%" align="center">

### **WinPcap / Npcap**
<img src="https://img.shields.io/badge/Backend-WinPcap%2FNpcap-red?style=for-the-badge" alt="WinPcap/Npcap">

**🖥️ Windows Packet Capture**

**WinPcap** and **Npcap** provide packet capture capabilities on Windows systems with advanced filtering.

</td>
<td width="25%" align="center">

### **Remote Capture (rpcapd)**
<img src="https://img.shields.io/badge/Backend-rpcapd-green?style=for-the-badge" alt="rpcapd">

**📡 Network-Based Capture**

**Remote packet capture** using rpcapd daemon for capturing packets from remote machines over the network.

</td>
<td width="25%" align="center">

### **DPDK KNI**
<img src="https://img.shields.io/badge/Backend-KNI-purple?style=for-the-badge" alt="KNI">

**🌉 Kernel Network Interface**

DPDK's **Kernel Network Interface** for seamless integration between kernel space and DPDK userspace applications.

</td>
</tr>
</table>

> 💡 **Why multiple backends?**
>
> Different capture backends are optimized for different use cases. **libpcap** provides broad compatibility, **WinPcap/Npcap** offers Windows integration, **rpcapd** enables remote monitoring, and **DPDK KNI** bridges high-performance DPDK with kernel networking.
>
> **PcapPlusPlus** abstracts these differences, providing a **consistent API** regardless of the underlying capture engine!

## API Documentation

<div align="center">

**PcapPlusPlus Architecture Overview**

</div>

PcapPlusPlus consists of **3 powerful libraries**:

<table>
<tr>
<td width="33%" align="center">

### **Packet++**
<img src="https://img.shields.io/badge/Library-Packet%2B%2B-blue?style=for-the-badge" alt="Packet++">

**🔍 Packet Processing Engine**

A library for **parsing**, **creating** and **editing** network packets with support for 50+ protocols.

</td>
<td width="33%" align="center">

### **Pcap++**
<img src="https://img.shields.io/badge/Library-Pcap%2B%2B-green?style=for-the-badge" alt="Pcap++">

**📡 Capture & Send Engine**

C++ wrapper for packet engines like **libpcap**, **WinPcap**, **Npcap**, **DPDK** and **PF_RING**.

</td>
<td width="33%" align="center">

### **Common++**
<img src="https://img.shields.io/badge/Library-Common%2B%2B-orange?style=for-the-badge" alt="Common++">

**⚙️ Utilities Library**

Common utilities and helper functions used by both **Packet++** and **Pcap++**.

</td>
</tr>
</table>

<div align="center">

**📚 Comprehensive Documentation Available**

You can find extensive API documentation in the [**📖 API Documentation**](https://pcapplusplus.github.io/docs/api) section.

</div>

## Multi Platform Support

<div align="center">

**Runs Everywhere You Need It!**

</div>

<div align="center">
<table style="table-layout: fixed;">
<tr>
<td align="center" width="20%" style="vertical-align: top; height: 180px;">

<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-windows.png" alt="Windows" width="48" height="48"/>
</picture>

**🪟 Windows**

<div style="min-height: 80px; display: flex; flex-direction: column; justify-content: center;">

*Visual Studio 16+*<br>
*MinGW 32*<br>
*MinGW 64*

</div>

</td>
<td align="center" width="20%" style="vertical-align: top; height: 180px;">

<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-linux.png" alt="Linux" width="48" height="48"/>
</picture>

**🐧 Linux**

<div style="min-height: 80px; display: flex; flex-direction: column; justify-content: center;">

*Ubuntu 20.04+*<br>
*Alpine 3.20*<br>
*Fedora 42*<br>
*Red Hat EL 9.4*

</div>

</td>
<td align="center" width="20%" style="vertical-align: top; height: 180px;">

<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple-dark.png"/>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple.png" alt="macOS" width="48" height="48"/>
</picture>

**🍎 macOS**

<div style="min-height: 80px; display: flex; flex-direction: column; justify-content: center;">

*MacOS 13+ x86*<br>
*MacOS 13+ arm64*<br>
*&nbsp;*

</div>

</td>
<td align="center" width="20%" style="vertical-align: top; height: 180px;">

<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-android.png" alt="Android" width="48" height="48"/>
</picture>

**🤖 Android**

<div style="min-height: 80px; display: flex; flex-direction: column; justify-content: center;">

*API version 35+*<br>
*&nbsp;*<br>
*&nbsp;*<br>
*&nbsp;*

</div>

</td>
<td align="center" width="20%" style="vertical-align: top; height: 180px;">

<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-freebsd.png" alt="FreeBSD" width="48" height="48"/>
</picture>

**😈 FreeBSD**

<div style="min-height: 80px; display: flex; flex-direction: column; justify-content: center;">

*FreeBSD 13.4*<br>
*FreeBSD 14.1*<br>
*&nbsp;*<br>
*&nbsp;*

</div>

</td>
</tr>
</table>
</div>

<div align="center">

</div>

## Supported Network Protocols

<div align="center">

**50+ Network Protocols Supported!**

*PcapPlusPlus supports **parsing**, **editing** and **creation** of packets for the following protocols:*

</div>

### Data Link Layer (L2)

<div style="columns: 2; column-gap: 20px;">

- **Cisco HDLC**
- **Ethernet II**
- **IEEE 802.3 Ethernet**
- **LLC** (BPDU supported)
- **Null/Loopback**
- **Packet trailer** (footer/padding)
- **PPPoE**
- **SLL** (Linux cooked capture)
- **SLL2** (Linux cooked capture v2)
- **STP**
- **VLAN**
- **VXLAN**
- **Wake on LAN (WoL)**
- **NFLOG** *(parsing only)*

</div>

### Network Layer (L3)

<div style="columns: 2; column-gap: 20px;">

- **ARP**
- **GRE**
- **ICMP**
- **ICMPv6**
- **IGMP** (v1, v2, v3)
- **IPv4**
- **IPv6**
- **MPLS**
- **NDP**
- **Raw IP** (IPv4 & IPv6)
- **VRRP** (IPv4 & IPv6)
- **WireGuard**

</div>

### Transport Layer (L4)

<div style="columns: 2; column-gap: 20px;">

- **COTP**
- **GTP** (v1 & v2)
- **IPSec AH & ESP** *(parsing only)*
- **TCP**
- **TPKT**
- **UDP**

</div>

### Session Layer (L5)

<div style="columns: 2; column-gap: 20px;">

- **SDP**
- **SIP**

</div>

### Presentation Layer (L6)

<div style="columns: 2; column-gap: 20px;">

- **SSL/TLS** *(parsing only)*

</div>

### Application Layer (L7)

<div style="columns: 2; column-gap: 20px;">

- **ASN.1** decoder/encoder
- **BGP** (v4)
- **DHCP**
- **DHCPv6**
- **DNS**
- **FTP**
- **HTTP** headers
- **LDAP**
- **NTP** (v3, v4)
- **Radius**
- **S7 Communication**
- **SMTP**
- **SOME/IP**
- **SSH** *(parsing only)*
- **Telnet** *(parsing only)*
- **X509 certificates** *(parsing only)*
- **Generic payload**

</div>

## High-Performance Packet Processing Support

<div align="center">

**Unleash Line-Rate Performance!**

</div>

<table>
<tr>
<td width="33%" align="center">

### **DPDK**
<img src="https://img.shields.io/badge/Framework-DPDK-blue?style=for-the-badge&logo=intel" alt="DPDK">

**⚡ Data Plane Development Kit**

Set of data plane libraries and drivers for **ultra-fast packet processing**. Perfect for routers, firewalls, and load balancers.

[**📖 Learn more**](https://pcapplusplus.github.io/docs/dpdk)

</td>
<td width="33%" align="center">

### **PF_RING™**
<img src="https://img.shields.io/badge/Framework-PF_RING-red?style=for-the-badge" alt="PF_RING">

**⚡ High-Speed Network Socket**

Revolutionary network socket that **dramatically improves** packet capture speed for real-time processing.

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#pf_ring-support)

</td>
<td width="33%" align="center">

###  **eBPF XDP**
<img src="https://img.shields.io/badge/Framework-XDP-green?style=for-the-badge" alt="XDP">

**⚡ eXpress Data Path**

Linux kernel's **ultra-fast** packet processing framework using eBPF for **zero-copy** performance.

[**📖 Learn more**](https://pcapplusplus.github.io/docs/features#af_xdp-support)

</td>
</tr>
</table>

> 💡 **Why use these high-performance frameworks?**
>
> All these frameworks provide **very fast packet processing** (up to **line speed**) and are used in many network applications such as **routers**, **firewalls**, **load balancers**, etc.
>
> **PcapPlusPlus** provides a **C++ abstraction layer** over DPDK, PF_RING & XDP that removes the boilerplate and makes these powerful frameworks **easy to use**!

## Benchmarks

<div align="center">

**Performance Matters!**

</div>

We used **Matias Fontanini's** [**packet-capture-benchmarks**](https://github.com/mfontanini/packet-capture-benchmarks) project to compare the performance of **PcapPlusPlus** with other similar C++ libraries (such as `libtins` and `libcrafter`).

<div align="center">

**See The Results**

Check out our comprehensive [**📊 Benchmarks**](https://pcapplusplus.github.io/docs/benchmark) page to see how **PcapPlusPlus** performs!

</div>

## Provide Feedback

<div align="center">

**We'd Love to Hear From You!**

</div>

<div align="center">
<table>
<tr>
<td align="center" width="20%">

**🐛 Issues**

[GitHub Issues](https://github.com/seladb/PcapPlusPlus/issues)

*Bug reports & feature requests*

</td>
<td align="center" width="20%">

**💬 Discussion**

[Google Groups](https://groups.google.com/d/forum/pcapplusplus-support)

*Community support*

</td>
<td align="center" width="20%">

**❓ Q&A**

[Stack Overflow](https://stackoverflow.com/questions/tagged/pcapplusplus)

*Technical questions*

</td>
<td align="center" width="20%">

**📧 Email**

[pcapplusplus@gmail.com](mailto:pcapplusplus@gmail.com)

*Direct contact*

</td>
<td align="center" width="20%">

**🐦 Social**

[Follow @seladb](https://x.com/seladb)

*Updates & news*

</td>
</tr>
</table>
</div>

<div align="center">

**⭐ Show Your Support ⭐**

If you like this project please **Star us on GitHub** — it helps! 🌟

[![GitHub stars](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=for-the-badge&logo=github&color=yellow)](https://github.com/seladb/PcapPlusPlus/stargazers)

</div>

<div align="center">

**🌐 Learn More**

Visit the [**PcapPlusPlus Community**](https://pcapplusplus.github.io/community) page to learn more.

</div>

## Contributing

<div align="center">

**Join Our Community of Contributors!**

</div>

We would **very much appreciate** any contribution to this project! Whether you're:

<div align="center">
<table>
<tr>
<td align="center" width="25%">

**🐛 Bug Hunter**

Found a bug?<br>
*Help us fix it!*

</td>
<td align="center" width="25%">

**✨ Feature Developer**

Got a cool idea?<br>
*Let's build it together!*

</td>
<td align="center" width="25%">

**📚 Documentation Writer**

Love clear docs?<br>
*Help us improve them!*

</td>
<td align="center" width="25%">

**🧪 Tester**

Testing enthusiast?<br>
*Help us ensure quality!*

</td>
</tr>
</table>
</div>

<div align="center">

**Get Started Contributing**

Visit our [**🤝 Contributing Guide**](https://pcapplusplus.github.io/community#contribute) to learn how you can help make PcapPlusPlus even better!

</div>

## License

<div align="center">

**Free and Open Source**

</div>

PcapPlusPlus is released under the [**Unlicense**](https://choosealicense.com/licenses/unlicense/) - meaning it's completely **free** for any use!

<div align="center">

[![License: Unlicense](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=for-the-badge&color=brightgreen&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)

**✅ Commercial Use** • **✅ Modification** • **✅ Distribution** • **✅ Private Use**

</div>

---

<div align="center">

**🎉 Thank you for using PcapPlusPlus! 🎉**

<img src="https://img.shields.io/badge/Made%20with-❤️-ff1744?style=for-the-badge&labelColor=ff1744&color=white" alt="Made with Love">

</div>
