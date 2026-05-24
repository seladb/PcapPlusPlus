> ⚠️ **注意:** この翻訳は AI を使用して維持・同期されており、最新の英語版と差異がある可能性があります。誤りを見つけられた場合は、GitHub の Issue を作成するか、PR を提出してください。

<div align="center">

[![PcapPlusPlus ロゴ](https://pcapplusplus.github.io/img/logo/logo_color.png)](https://pcapplusplus.github.io)

[![GitHub Workflow ステータス](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/build_and_test.yml?branch=master&label=Actions&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![GitHub Workflow ステータス](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/codeql.yml?branch=master&label=CodeQL&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![Codecov](https://img.shields.io/codecov/c/github/seladb/PcapPlusPlus?logo=codecov&logoColor=white)](https://app.codecov.io/github/seladb/PcapPlusPlus)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seladb/PcapPlusPlus/badge)](https://scorecard.dev/viewer/?uri=github.com/seladb/PcapPlusPlus)
[![GitHub コントリビューター](https://img.shields.io/github/contributors/seladb/PcapPlusPlus?style=flat&label=Contributors&logo=github)](https://github.com/seladb/PcapPlusPlus/graphs/contributors)

[![X フォロー](https://img.shields.io/badge/follow-%40seladb-1DA1F2?logo=x&style=social)](https://x.com/intent/follow?screen_name=seladb)
[![GitHub Repo スター](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=social)]()

</div>

[PcapPlusPlus](https://pcapplusplus.github.io/) は、ネットワークパケットのキャプチャ、解析、生成を行うためのマルチプラットフォーム C++ ライブラリです。効率的かつ強力で、使いやすく設計されています。

PcapPlusPlus は、多種多様なネットワークプロトコルのデコードと生成機能を提供します。また、[libpcap](https://www.tcpdump.org/)、[WinPcap](https://www.winpcap.org/)、[Npcap](https://nmap.org/npcap/)、[DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html)、[WinDivert](https://reqrypt.org/windivert.html)、[PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) など、最も人気のあるパケット処理エンジンに対する使いやすい C++ ラッパーも提供します。

翻訳: [English](../README.md) · [正體中文](./README-zh-tw.md) · [한국어](./README-kor.md) · 日本語 · [Русский](./README-rus.md)

## 目次

- [目次](#目次)
- [ダウンロード](#ダウンロード)
  - [GitHub リリースページ](#github-リリースページ)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [自分でビルドする](#自分でビルドする)
  - [パッケージの検証](#パッケージの検証)
- [機能概要](#機能概要)
- [はじめに](#はじめに)
- [API ドキュメント](#api-ドキュメント)
- [マルチプラットフォーム対応](#マルチプラットフォーム対応)
- [サポートされるネットワークプロトコル](#サポートされるネットワークプロトコル)
  - [データリンク層 (L2)](#データリンク層-l2)
  - [ネットワーク層 (L3)](#ネットワーク層-l3)
  - [トランスポート層 (L4)](#トランスポート層-l4)
  - [セッション層 (L5)](#セッション層-l5)
  - [プレゼンテーション層 (L6)](#プレゼンテーション層-l6)
  - [アプリケーション層 (L7)](#アプリケーション層-l7)
- [DPDK と PF_RING のサポート](#dpdk-と-pf_ring-のサポート)
- [ベンチマーク](#ベンチマーク)
- [フィードバックの提供](#フィードバックの提供)
- [コントリビューション](#コントリビューション)
- [ライセンス](#ライセンス)

## ダウンロード

GitHub のリリースページからダウンロードするか、パッケージマネージャーを使用するか、PcapPlusPlus を自分でビルドすることができます。詳細については、PcapPlusPlus ウェブサイトの [ダウンロード](https://pcapplusplus.github.io/docs/install) ページをご覧ください。

[![GitHub 全リリースのダウンロード数](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=flat&label=Downloads&logo=github)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

### GitHub リリースページ

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

Vcpkg ポート: <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>

### Conan

```text
conan install "pcapplusplus/[>0]@" -u
```

ConanCenter のパッケージ: <https://conan.io/center/pcapplusplus>

### 自分でビルドする

git リポジトリをクローンします:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

PcapPlusPlus ウェブサイトの [ソースからビルド](https://pcapplusplus.github.io/docs/install#build-from-source) ページで、お使いのプラットフォームに応じたビルド手順に従ってください。

### パッケージの検証

v23.09 より新しい PcapPlusPlus のリリースは、GitHub の attestation で署名されています。すべての attestation は [こちら](https://github.com/seladb/PcapPlusPlus/attestations) で確認できます。GitHub CLI を使ってこれらのパッケージの attestation を検証できます。パッケージを検証するには、[gh attestation verify](https://cli.github.com/manual/gh_attestation_verify) の最新の手順に従ってください。シンプルな手順としては、次のコマンドを使用できます:

```shell
gh attestation verify <path-to-package-file> --repository seladb/PcapPlusPlus
```

ターミナルに次の出力が表示されるはずです:

```shell
✓ Verification succeeded!
```

## 機能概要

- __パケットキャプチャ__: [libpcap](https://www.tcpdump.org/)、[WinPcap](https://www.winpcap.org/)、[Npcap](https://nmap.org/npcap/)、[Intel DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html)、[WinDivert](https://reqrypt.org/windivert.html)、[ntop の PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)、[raw socket](https://en.wikipedia.org/wiki/Network_socket#Raw_socket) といった人気のパケットキャプチャエンジンに対する、使いやすい C++ ラッパーによるパケットキャプチャ [[詳細](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __パケット解析と生成__: 幅広い [ネットワークプロトコル](https://pcapplusplus.github.io/docs/features#supported-network-protocols) について、プロトコルとレイヤーの詳細な解析、パケット生成、パケット編集を含みます [[詳細](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __ファイルからのパケットの読み書き__: __PCAP__ と __PCAPNG__ の両形式をサポート [[詳細](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __ラインレートでのパケット処理__: [DPDK](https://www.dpdk.org/)、[eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html)、[PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) に対する効率的で使いやすい C++ ラッパー [[詳細](https://pcapplusplus.github.io/docs/features#dpdk-support)]
- __マルチプラットフォーム対応__: PcapPlusPlus は Linux、MacOS、Windows、Android、FreeBSD で完全にサポートされています
- __パケット再構成__: TCP の再送、順序が乱れた TCP パケット、欠落した TCP データを扱う独自の __TCP 再構成__ 実装、および IPv4 と IPv6 のフラグメントを生成・再構成する __IP フラグメント化・デフラグメント化__ [[詳細](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __パケットフィルタリング__: libpcap の BPF フィルタを非常に使いやすくします [[詳細](https://pcapplusplus.github.io/docs/features#packet-filtering)]
- __TLS フィンガープリンティング__: [JA3 と JA3S](https://github.com/salesforce/ja3) の TLS フィンガープリンティングの C++ 実装 [[詳細](https://pcapplusplus.github.io/docs/features#tls-fingerprinting)]

## はじめに

PcapPlusPlus でアプリケーションを書くことは非常に簡単で直感的です。以下は、PCAP ファイルからパケットを読み込んで解析する方法を示す簡単なアプリケーションです:

```cpp
#include <iostream>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // 読み取り用に pcap ファイルを開く
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        std::cerr << "pcap ファイルを開く際にエラーが発生しました" << std::endl;
        return 1;
    }

    // ファイルから最初の(かつ唯一の)パケットを読み込む
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "ファイル内の最初のパケットを読み込めませんでした" << std::endl;
        return 1;
    }

    // raw パケットを解析済みパケットに変換する
    pcpp::Packet parsedPacket(&rawPacket);

    // パケットが IPv4 であることを確認する
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // 送信元 IP と宛先 IP を抽出する
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // 送信元 IP と宛先 IP を出力する
        std::cout << "送信元 IP: '" << srcIP << "'; 宛先 IP: '" << destIP << "'" << std::endl;
    }

    // ファイルを閉じる
    reader.close();

    return 0;
}
```

詳細は PcapPlusPlus ウェブサイトの [はじめに](https://pcapplusplus.github.io/docs/quickstart) ページで確認できます。このページでは、いくつかの簡単なステップを通じて、アプリケーションを起動するまでの流れを案内します。

## API ドキュメント

PcapPlusPlus は 3 つのライブラリで構成されています:

1. __Packet++__ - ネットワークパケットを解析・生成・編集するためのライブラリ
2. __Pcap++__ - パケットの傍受と送信、ネットワークと NIC の情報、統計情報などを提供するライブラリ。実体は libpcap、WinPcap、Npcap、DPDK、AF_XDP、WinDivert、PF_RING といったパケットキャプチャエンジンの C++ ラッパーです
3. __Common++__ - Packet++ と Pcap++ の両方で使用される共通のコードユーティリティを含むライブラリ

PcapPlusPlus ウェブサイトの [API ドキュメントセクション](https://pcapplusplus.github.io/docs/api) で詳細な API ドキュメントを確認できます。
不足しているデータがあれば、[ご連絡ください](#フィードバックの提供)。

## マルチプラットフォーム対応

PcapPlusPlus は現在
__Windows__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-windows.png" alt="" width="16" height="16"/>
</picture>、
__Linux__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-linux.png" alt="" width="16" height="16"/>
</picture>、
__MacOS__
<picture><source media="(prefers-color-scheme: dark)" srcset="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple-dark.png"/>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-apple.png" alt="" width="16" height="16"/>
</picture>、
__Android__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-android.png" alt="" width="16" height="16"/>
</picture>、そして
__FreeBSD__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-freebsd.png" alt="" width="16" height="16"/>
</picture>
でサポートされています。
PcapPlusPlus ウェブサイトで [サポートされているすべてのプラットフォーム](https://pcapplusplus.github.io/docs/platforms) を確認し、[ダウンロード](#ダウンロード) セクションを参照してお使いのプラットフォームで PcapPlusPlus を使い始めてください。

## サポートされるネットワークプロトコル

PcapPlusPlus は現在、以下のプロトコルのパケットの解析、編集、生成をサポートしています:

### データリンク層 (L2)

1. Cisco HDLC
2. Ethernet II
3. IEEE 802.3 Ethernet
4. LLC (BPDU のみサポート)
5. Null/Loopback
6. Packet trailer (footer または padding とも呼ばれる)
7. PPPoE
8. SLL (Linux cooked capture)
9. SLL2 (Linux cooked capture v2)
10. STP
11. VLAN
12. VXLAN
13. Wake on LAN (WoL)
14. NFLOG (Linux Netfilter NFLOG) - 解析のみ (編集機能なし)


### ネットワーク層 (L3)

15. ARP
16. GRE
17. ICMP
18. ICMPv6
19. IGMP (IGMPv1、IGMPv2、IGMPv3 をサポート)
20. IPv4
21. IPv6
22. MPLS
23. NDP
24. Raw IP (IPv4 と IPv6)
25. VRRP (IPv4 と IPv6)
26. WireGuard

### トランスポート層 (L4)

27. COTP
28. GTP (v1 と v2)
29. IPSec AH と ESP - 解析のみ (編集機能なし)
30. TCP
31. TPKT
32. UDP

### セッション層 (L5)

33. SDP
34. SIP

### プレゼンテーション層 (L6)

35. SSL/TLS - 解析のみ (編集機能なし)

### アプリケーション層 (L7)

36. ASN.1 デコーダおよびエンコーダ
37. BGP (v4)
38. 暗号鍵デコーダ
39. DHCP
40. DHCPv6
41. DNS
42. DoIP
43. FTP
44. HTTP ヘッダ (リクエストとレスポンス)
45. LDAP
46. Modbus
47. MySQL - 解析のみ (編集機能なし)
48. NTP (v3, v4)
49. PEM デコーダおよびエンコーダ
50. PostgreSQL Wire Protocol (PGWire) - 解析のみ (編集機能なし)
51. Radius
52. S7 Communication (S7comm)
53. SMTP
54. SOME/IP
55. SSH - 解析のみ (編集機能なし)
56. Telnet - 解析のみ (編集機能なし)
57. X509 証明書 - 解析のみ (編集機能なし)
58. 汎用ペイロード

## DPDK と PF_RING のサポート

[The Data Plane Development Kit (DPDK)](https://www.dpdk.org/) は、高速パケット処理のためのデータプレーンライブラリとネットワークインターフェースコントローラドライバ群です。

[PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/) は、パケットキャプチャ速度を劇的に向上させる新しいタイプのネットワークソケットです。

どちらのフレームワークも非常に高速なパケット処理 (ラインスピードまで) を提供し、ルーター、ファイアウォール、ロードバランサーなど多くのネットワークアプリケーションで使用されています。
PcapPlusPlus は DPDK と PF_RING の上に C++ の抽象化レイヤーを提供します。この抽象化レイヤーは、これらのフレームワークを利用する際に発生する多くのボイラープレートを取り除き、使いやすいインターフェースを提供します。詳細は、PcapPlusPlus ウェブサイトの [DPDK](https://pcapplusplus.github.io/docs/dpdk) と [PF_RING](https://pcapplusplus.github.io/docs/features#pf_ring-support) のサポートページで確認できます。

## ベンチマーク

PcapPlusPlus と他の類似 C++ ライブラリ (`libtins` や `libcrafter` など) のパフォーマンスを比較するために、Matias Fontanini 氏の [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) プロジェクトを使用しました。

結果は PcapPlusPlus ウェブサイトの [ベンチマーク](https://pcapplusplus.github.io/docs/benchmark) ページで確認できます。

## フィードバックの提供

フィードバックを大歓迎いたします。以下のいずれかの方法でお気軽にご連絡ください:

- GitHub の Issue を作成する
- PcapPlusPlus の Google グループにメッセージを投稿する: <https://groups.google.com/d/forum/pcapplusplus-support>
- Stack Overflow で質問する: <https://stackoverflow.com/questions/tagged/pcapplusplus>
- メールを送る: <pcapplusplus@gmail.com>
- X でフォローする: <https://x.com/seladb>

このプロジェクトを気に入っていただけたら、__GitHub でスターをお願いします — 大きな助けになります!__ :star: :star:

詳細は [PcapPlusPlus ウェブサイト](https://pcapplusplus.github.io/community) をご覧ください。

## コントリビューション

このプロジェクトへの貢献を心より歓迎します。貢献にご興味があれば、PcapPlusPlus ウェブサイトの [コントリビューションページ](https://pcapplusplus.github.io/community#contribute) をご覧ください。

## ライセンス

PcapPlusPlus は [Unlicense ライセンス](https://choosealicense.com/licenses/unlicense/) の下で公開されています。

[![GitHub](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=flat&color=blue&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)
