<div align="center">

[![PcapPlusPlus 標誌](https://pcapplusplus.github.io/img/logo/logo_color.png)](https://pcapplusplus.github.io)

[![GitHub 工作流程狀態](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/build_and_test.yml?branch=master&label=Actions&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![GitHub 工作流程狀態](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/codeql.yml?branch=master&label=CodeQL&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![Codecov](https://img.shields.io/codecov/c/github/seladb/PcapPlusPlus?logo=codecov&logoColor=white)](https://app.codecov.io/github/seladb/PcapPlusPlus)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seladb/PcapPlusPlus/badge)](https://scorecard.dev/viewer/?uri=github.com/seladb/PcapPlusPlus)
[![GitHub 貢獻者](https://img.shields.io/github/contributors/seladb/PcapPlusPlus?style=flat&label=Contributors&logo=github)](https://github.com/seladb/PcapPlusPlus/graphs/contributors)

[![X 關注](https://img.shields.io/badge/follow-%40seladb-1DA1F2?logo=x&style=social)](https://x.com/intent/follow?screen_name=seladb)
[![GitHub Repo 星星](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=social)]()

</div>

[PcapPlusPlus](https://pcapplusplus.github.io/) 是一個跨平台的 C++ 函式庫，提供高效、強大且易於使用的功能，來進行網路封包的擷取、解析和生成。

PcapPlusPlus 支援對多種網路協議進行解析和建構，並對常見的封包處理函式庫（如 [libpcap](https://www.tcpdump.org/)、[WinPcap](https://www.winpcap.org/)、[Npcap](https://nmap.org/npcap/)、[DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html) 和 [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)）提供 C++ 的封裝函式。

翻譯: [English](../README.md) · 正體中文 · [한국어](./README-kor.md)

## 目錄

- [目錄](#目錄)
- [下載](#下載)
  - [GitHub 發佈頁面](#github-發佈頁面)
  - [Homebrew](#Homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [自行建置](#自行建置])
  - [驗證您的套件](#驗證您的套件)
- [功能概述](#功能概述)
- [快速入門](#快速入門)
- [API 文件](#api-文件)
- [跨平台支援](#跨平台支援)
- [支援的網路協定](#支援的網路協定)
  - [資料連接層 (L2)](#資料鏈路層-l2)
  - [網路層 (L3)](#網路層-l3)
  - [傳輸層 (L4)](#傳輸層-l4)
  - [對話層 (L5)](#對話層-l5)
  - [表現層 (L6)](#表現層-l6)
  - [應用層 (L7)](#應用層-l7)
- [DPDK 與 PF_RING 支援](#dpdk-和-pf_ring-支援)
- [基準測試](#基準測試)
- [提供回饋](#提供回饋)
- [貢獻](#貢獻)
- [授權條款](#授權條款)

## 下載

您可以從 GitHub 發佈頁面下載，使用套件管理器來下載，或自行建構 PcapPlusPlus。更多詳情請參考 [下載](https://pcapplusplus.github.io/docs/install) 頁面。

[![GitHub 全部下載](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=flat&label=Downloads&logo=github)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

### GitHub 發佈頁面

<https://github.com/seladb/PcapPlusPlus/releases/latest>

### Homebrew

```shell
brew install pcapplusplus
```

Homebrew 套件頁面: <https://formulae.brew.sh/formula/pcapplusplus>

### Vcpkg

Windows:

```shell
.\vcpkg install pcapplusplus
```

MacOS/Linux:

```shell
vcpkg install pcapplusplus
```

Vcpkg 套件頁面: <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>


### Conan

```shell
conan install "pcapplusplus/[>0]@" -u
```

Conan 套件頁面: <https://conan.io/center/pcapplusplus>

### 自行建置

取得 git repo：

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

根據您的平台，請遵循 [從原始碼建置](https://pcapplusplus.github.io/docs/install#build-from-source) 頁面中的指示進行建置。

### 驗證您的套件

PcapPlusPlus 發佈的版本自 v23.09 以後都已通過 GitHub 驗證簽署。所有的驗證文件都可以在 [這裡](https://github.com/seladb/PcapPlusPlus/attestations) 找到。您可以使用 GitHub CLI 驗證這些套件的簽署。要驗證套件，您可以參考 [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify) 的最新說明。以下是簡單的操作命令：

```shell
gh attestation verify <path-to-package-file> --repository seladb/PcapPlusPlus
```

執行後，您應該會在終端機中看到以下輸出：

```shell
✓ Verification succeeded!
```

## 功能概述

- __封包捕獲__：提供簡單易用的 C++ 封裝函式來使用常見的封包捕獲引擎，如 [libpcap](https://www.tcpdump.org/)、[WinPcap](https://www.winpcap.org/)、[Npcap](https://nmap.org/npcap/)、[Intel DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html)、[ntop 的 PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) 以及 [raw sockets](https://en.wikipedia.org/wiki/Network_socket#Raw_socket) [[了解更多](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __解析與建構__：包含網路協定解析、網路封包建構與編輯，支援各種類型的 [網路協定](https://pcapplusplus.github.io/docs/features#supported-network-protocols) [[了解更多](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __從檔案讀寫封包__：支援 __PCAP__ 和 __PCAPNG__ 格式 [[了解更多](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __封包處理__：以線性速度提供高效且易用的 C++ 封裝函式來使用 [DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html) 和 [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) [[了解更多](https://pcapplusplus.github.io/docs/features#dpdk-support)]
- __多平台支援__：PcapPlusPlus 完全支援 Linux、MacOS、Windows、Android 和 FreeBSD
- __封包重組__：包含 __TCP 重組__ 的獨特實現，處理 TCP 重傳、亂序的 TCP 封包及遺失的 TCP 資料，並支援 __IP 分片與重組__，可生成並重組 IPv4 和 IPv6 的分片 [[了解更多](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __封包過濾__：讓 libpcap 的 BPF 過濾器變得更加易用 [[了解更多](https://pcapplusplus.github.io/docs/features#packet-filtering)]
- __TLS 指紋識別__：C++ 實現的 [JA3 和 JA3S](https://github.com/salesforce/ja3) TLS 指紋識別 [[了解更多](https://pcapplusplus.github.io/docs/features#tls-fingerprinting)]

## 快速入門

使用 PcapPlusPlus 編寫應用程式非常簡單且直觀。以下是一個簡單的應用程式，展示了如何從 PCAP 檔案讀取封包並解析它：

```cpp
#include <iostream>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // 打開一個 pcap 檔案進行讀取
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        std::cerr << "打開 pcap 檔案時出錯" << std::endl;
        return 1;
    }

    // 從檔案中讀取第一個（也是唯一的）封包
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "無法讀取檔案中的第一個封包" << std::endl;
        return 1;
    }

    // 將原始封包解析為已解析的封包
    pcpp::Packet parsedPacket(&rawPacket);

    // 確認封包是 IPv4 封包
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // 提取源 IP 和目的 IP
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // 輸出源 IP 和目的 IP
        std::cout << "來源 IP: '" << srcIP << "'; 目的 IP: '" << destIP << "'" << std::endl;
    }

    // 關閉檔案
    reader.close();

    return 0;
}
```

您可以在 PcapPlusPlus 網站的 [快速入門指南](https://pcapplusplus.github.io/docs/quickstart) 中找到更多資訊。該頁面會帶您通過幾個簡單的步驟，讓您的應用程式快速運行起來。

## API 文件

PcapPlusPlus 包含三個函式庫：

1. __Packet++__ - 用於解析、創建和編輯網路封包的函式庫
2. __Pcap++__ - 用於攔截和發送封包、提供網路和網卡資訊、統計等功能的函式庫。實際上是對封包擷取引擎（如 libpcap、WinPcap、Npcap、DPDK 和 PF_RING）的 C++ 封裝
3. __Common++__ - 包含 Packet++ 和 Pcap++ 共用的一些通用程式碼工具函式庫

您可以在 PcapPlusPlus 網站的 [API 文件區](https://pcapplusplus.github.io/docs/api) 找到詳細的 API 文件。如果您發現有任何遺漏的資料，請[聯繫我們](#provide-feedback)。

## 跨平台支援

PcapPlusPlus 目前支援以下平台：
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
</picture> 和
__FreeBSD__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-freebsd.png" alt="" width="16" height="16"/>
</picture>。
請訪問 PcapPlusPlus 網站查看所有[支援的平台](https://pcapplusplus.github.io/docs/platforms)，並參考[下載](#download)區開始在您的平台上使用 PcapPlusPlus。

## 支援的網路協定

PcapPlusPlus 目前支援解析、編輯和建構以下網路協定的封包：

### 資料連接層 (L2)

1. Ethernet II
2. IEEE 802.3 Ethernet
3. LLC（僅支援 BPDU）
4. Null/Loopback
5. Packet trailer（又稱 footer 或 padding）
6. PPPoE
7. SLL（Linux 擷取協定）
8. SLL2（Linux 擷取協定 v2）
9. STP
10. VLAN
11. VXLAN
12. Wake on LAN (WoL)
13. NFLOG（Linux Netfilter NFLOG）- 僅支援解析（不支援編輯）

### 網路層 (L3)

14. ARP
15. GRE
16. ICMP
17. ICMPv6
18. IGMP（支援 IGMPv1、IGMPv2 和 IGMPv3）
19. IPv4
20. IPv6
21. MPLS
22. NDP
23. Raw IP（IPv4 和 IPv6）
24. VRRP（IPv4 和 IPv6）
25. WireGuard

### 傳輸層 (L4)

26. COTP
27. GTP (v1 & v2)
28. IPSec AH 和 ESP - 僅支援解析（不支援編輯）
29. TCP
30. TPKT
31. UDP

### 對話層 (L5)

32. SDP
33. SIP

### 表示層 (L6)

34. SSL/TLS - 僅支援解析（不支援編輯）

### 應用層 (L7)

35. ASN.1 編碼器與解碼器
36. BGP (v4)
37. DHCP
38. DHCPv6
39. DNS
40. FTP
41. HTTP 標頭（請求和響應）
42. LDAP
43. NTP (v3, v4)
44. Radius
45. S7 通訊（S7comm）
46. SMTP
47. SOME/IP
48. SSH - 僅支援解析（不支援編輯）
49. Telnet - 僅支援解析（不支援編輯）
50. 通用酬載（Generic Payload）

## DPDK 和 PF_RING 支援

[DPDK (The Data Plane Development Kit)](https://www.dpdk.org/) 是一套用於高速封包處理的資料平面函式庫和網路介面卡驅動。

[PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/) 是一種新型網路套接字，能顯著提升封包擷取速度。

這兩個框架提供了非常快速的封包處理（幾乎是線性的），並廣泛應用於路由器、防火牆、負載平衡器等網路應用中。PcapPlusPlus 提供了對 DPDK 和 PF_RING 的 C++ 抽象層，這個抽象層簡化了使用這些框架的繁瑣流程。您可以在 PcapPlusPlus 網站的 [DPDK](https://pcapplusplus.github.io/docs/dpdk) 和 [PF_RING](https://pcapplusplus.github.io/docs/features#pf_ring-support) 支援頁面了解更多資訊。

## 基準測試

我們使用了 Matias Fontanini 的 [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) 專案來比較 PcapPlusPlus 與其他類似的 C++ 函式庫（如 `libtins` 和 `libcrafter`）的效能。

您可以在 PcapPlusPlus 網站的 [基準測試](https://pcapplusplus.github.io/docs/benchmark) 頁面查看測試結果。

## 提供回饋

我們非常樂意收到您的回饋，請通過以下任一方式與我們聯繫：

- 在 GitHub 上提交問題
- 在 PcapPlusPlus 的 Google 群組發佈訊息: <https://groups.google.com/d/forum/pcapplusplus-support>
- 在 Stack Overflow 上提問: <https://stackoverflow.com/questions/tagged/pcapplusplus>
- 發送電子郵件至: <pcapplusplus@gmail.com>
- 在 X 平台關注我們: <https://x.com/seladb>

如果您喜歡這個專案，請在 GitHub 上為我們按下星星 — 這對我們非常有幫助！ :star: :star:

請訪問 [PcapPlusPlus 網站](https://pcapplusplus.github.io/community) 瞭解更多資訊。

## 貢獻

我們非常感謝您對此專案的任何貢獻。如果您有興趣參與貢獻，請訪問 PcapPlusPlus 網站上的 [貢獻頁面](https://pcapplusplus.github.io/community#contribute)。

## 授權條款

PcapPlusPlus 是根據 [Unlicense 授權條款](https://choosealicense.com/licenses/unlicense/) 發佈的。

[![GitHub](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=flat&color=blue&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)
