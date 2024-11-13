<div align="center">

[![PcapPlusPlus 로고](https://pcapplusplus.github.io/img/logo/logo_color.png)](https://pcapplusplus.github.io)

[![GitHub Workflow 상태](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/build_and_test.yml?branch=master&label=Actions&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22Build+and+test%22)
[![GitHub Workflow 상태](https://img.shields.io/github/actions/workflow/status/seladb/PcapPlusPlus/codeql.yml?branch=master&label=CodeQL&logo=github&style=flat)](https://github.com/seladb/PcapPlusPlus/actions?query=workflow%3A%22CodeQL%22)
[![Codecov](https://img.shields.io/codecov/c/github/seladb/PcapPlusPlus?logo=codecov&logoColor=white)](https://app.codecov.io/github/seladb/PcapPlusPlus)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seladb/PcapPlusPlus/badge)](https://scorecard.dev/viewer/?uri=github.com/seladb/PcapPlusPlus)
[![GitHub 기여자](https://img.shields.io/github/contributors/seladb/PcapPlusPlus?style=flat&label=Contributors&logo=github)](https://github.com/seladb/PcapPlusPlus/graphs/contributors)

[![X 팔로우](https://img.shields.io/badge/follow-%40seladb-1DA1F2?logo=x&style=social)](https://x.com/intent/follow?screen_name=seladb)
[![GitHub 리포지토리 별표](https://img.shields.io/github/stars/seladb/PcapPlusPlus?style=social)]()

</div>

[PcapPlusPlus](https://pcapplusplus.github.io/)는 네트워크 패킷을 캡처, 분석 및 생성하기 위한 멀티 플랫폼 C++ 라이브러리입니다. 이 라이브러리는 효율적이고 강력하며 사용이 용이하도록 설계되었습니다.

PcapPlusPlus는 다양한 네트워크 프로토콜을 디코딩하고 생성할 수 있는 기능을 제공하며, [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) 등과 같은 유용한 패킷 처리 엔진을 위한 손쉬운 C++ 래퍼를 지원합니다.

번역: [English](../README.md) · [正體中文](./README-zh-tw.md) · 한국어

## 목차

- [목차](#목차)
- [다운로드](#다운로드)
  - [GitHub 릴리스 페이지](#github-릴리스-페이지)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [직접 빌드하기](#직접-빌드하기)
  - [패키지 검증](#패키지-검증)
- [기능 개요](#기능-개요)
- [시작하기](#시작하기)
- [API 문서](#api-문서)
- [멀티 플랫폼 지원](#멀티-플랫폼-지원)
- [지원되는 네트워크 프로토콜](#지원되는-네트워크-프로토콜)
  - [데이터 링크 계층 (L2)](#데이터-링크-계층-l2)
  - [네트워크 계층 (L3)](#네트워크-계층-l3)
  - [전송 계층 (L4)](#전송-계층-l4)
  - [세션 계층 (L5)](#세션-계층-l5)
  - [프레젠테이션 계층 (L6)](#프레젠테이션-계층-l6)
  - [응용 계층 (L7)](#응용-계층-l7)
- [DPDK 및 PF_RING 지원](#dpdk-및-pf_ring-지원)
- [벤치마크](#벤치마크)
- [피드백 제공](#피드백-제공)
- [기여](#기여)
- [라이센스](#라이센스)

## 다운로드

GitHub 릴리스 페이지에서 다운로드하거나 패키지 관리자를 사용할 수 있으며, 직접 PcapPlusPlus를 빌드할 수도 있습니다. 자세한 내용은 PcapPlusPlus 웹사이트의 [다운로드](https://pcapplusplus.github.io/docs/install) 페이지를 방문하세요.

[![GitHub 모든 릴리스](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=flat&label=Downloads&logo=github)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

### GitHub 릴리스 페이지

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

Vcpkg 포트: <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>

### Conan

```text
conan install "pcapplusplus/[>0]@" -u
```

ConanCenter의 패키지: <https://conan.io/center/pcapplusplus>

### 직접 빌드하기

git 리포지토리 클론:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

PcapPlusPlus 웹사이트의 [소스에서 빌드](https://pcapplusplus.github.io/docs/install#build-from-source) 페이지에서 플랫폼에 맞는 빌드 지침을 따르세요.

### 패키지 검증

v23.09 이상의 PcapPlusPlus 릴리스는 GitHub 증명을 통해 서명됩니다. 모든 증명은 [여기](https://github.com/seladb/PcapPlusPlus/attestations)에서 확인할 수 있습니다. GitHub CLI를 통해 이러한 패키지의 증명을 검증할 수 있습니다. 패키지 검증을 위해 다음 명령어를 사용할 수 있습니다:

```shell
gh attestation verify <패키지 파일 경로> --repository seladb/PcapPlusPlus
```

터미널에 다음과 같은 출력이 나타납니다:

```shell
✓ Verification succeeded!
```

## 기능 개요

- __패킷 캡처__: [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [Intel DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [ntop의 PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) 및 [raw 소켓](https://en.wikipedia.org/wiki/Network_socket#Raw_socket)을 위한 손쉬운 C++ 래퍼를 통한 패킷 캡처 [[더 알아보기](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __패킷 분석 및 생성__: 다양한 [네트워크 프로토콜](https://pcapplusplus.github.io/docs/features#supported-network-protocols)에 대한 분석, 생성 및 편집을 지원 [[더 알아보기](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __파일로 패킷 읽기 및 쓰기__: __PCAP__ 및 __PCAPNG__ 형식의 파일을 지원 [[더 알아보기](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __라인 속도에서의 패킷 처리__: [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)을 위한 효율적이고 쉬운 C++ 래퍼 [[더 알아보기](https://pcapplusplus.github.io/docs/features#dpdk-support)]
- __멀티 플랫폼 지원__: Linux, MacOS, Windows, Android 및 FreeBSD에서 완전 지원
- __패킷 재조합__: __TCP 재조합__ 및 __IP 단편화와 재조합__ [[더 알아보기](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __패킷 필터링__: libpcap의 BPF 필터를 더 간편하게 사용 [[더 알아보기](https://pcapplusplus.github.io/docs/features#packet-filtering)]

## 시작하기

PcapPlusPlus로 애플리케이션을 작성하는 것은 매우 쉽고 직관적입니다. 아래는 PCAP 파일에서 패킷을 읽고 이를 파싱하는 간단한 예제 애플리케이션입니다:

```cpp
#include <iostream>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // PCAP 파일을 읽기 모드로 열기
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        std::cerr << "PCAP 파일을 여는 중 오류 발생" << std::endl;
        return 1;
    }

    // 파일에서 첫 번째 (단일) 패킷 읽기
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "파일에서 첫 번째 패킷을 읽을 수 없음" << std::endl;
        return 1;
    }

    // raw 패킷을 파싱된 패킷으로 변환
    pcpp::Packet parsedPacket(&rawPacket);

    // 패킷이 IPv4인지 확인
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // 소스 및 대상 IP 추출
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // 소스 및 대상 IP 출력
        std::cout << "Source IP is '" << srcIP << "'; Dest IP is '" << destIP << "'" << std::endl;
    }

    // 파일 닫기
    reader.close();

    return 0;
}
```

자세한 내용은 PcapPlusPlus 웹사이트의 [시작하기](https://pcapplusplus.github.io/docs/quickstart) 페이지에서 확인할 수 있습니다. 이 페이지는 애플리케이션을 빠르게 시작할 수 있는 단계별 안내를 제공합니다.

## API 문서

PcapPlusPlus는 다음의 세 가지 라이브러리로 구성됩니다:

1. __Packet++__ - 네트워크 패킷을 파싱하고 생성 및 편집하는 라이브러리
2. __Pcap++__ - 패킷을 캡처하고 전송하며 네트워크 및 NIC 정보, 통계를 제공하는 라이브러리 (libpcap, WinPcap, Npcap, DPDK, PF_RING 등과 같은 패킷 캡처 엔진을 위한 C++ 래퍼)
3. __Common++__ - Packet++ 및 Pcap++에서 사용하는 일반적인 코드 유틸리티를 포함한 라이브러리

PcapPlusPlus 웹사이트의 [API 문서 섹션](https://pcapplusplus.github.io/docs/api)에서 자세한 API 문서를 확인할 수 있습니다.

## 멀티 플랫폼 지원

PcapPlusPlus는 현재 __Windows__, __Linux__, __MacOS__, __Android__, __FreeBSD__에서 지원됩니다. PcapPlusPlus 웹사이트에서 [지원 플랫폼](https://pcapplusplus.github.io/docs/platforms) 전체 목록을 확인할 수 있으며, [다운로드](#download) 섹션을 참조하여 해당 플랫폼에서 PcapPlusPlus를 시작하세요.

## 지원되는 네트워크 프로토콜

PcapPlusPlus는 현재 다음 프로토콜의 패킷을 파싱, 편집 및 생성할 수 있습니다:

### 데이터 링크 계층 (L2)

1. Ethernet II
2. IEEE 802.3 Ethernet
3. LLC (BPDU만 지원)
4. Null/Loopback
5. Packet trailer (패킷 패딩)
6. PPPoE
7. SLL (Linux cooked capture)
8. SLL2 (Linux cooked capture v2)
9. STP
10. VLAN
11. VXLAN
12. Wake on LAN (WoL)
13. NFLOG (Linux Netfilter NFLOG) - 파싱만 가능 (편집 불가)

### 네트워크 계층 (L3)

14. ARP
15. GRE
16. ICMP
17. ICMPv6
18. IGMP (IGMPv1, IGMPv2, IGMPv3 지원)
19. IPv4
20. IPv6
21. MPLS
22. NDP
23. Raw IP (IPv4 & IPv6)
24. VRRP (IPv4 & IPv6)
25. WireGuard

### 전송 계층 (L4)

26. COTP
27. GTP (v1 & v2)
28. IPSec AH & ESP - 파싱만 가능 (편집 불가)
29. TCP
30. TPKT
31. UDP

### 세션 계층 (L5)

32. SDP
33. SIP

### 표현 계층 (L6)

34. SSL/TLS - 파싱만 가능 (편집 불가)

### 응용 계층 (L7)

35. ASN.1 인코더 및 디코더
36. BGP (v4)
37. DHCP
38. DHCPv6
39. DNS
40. FTP
41. HTTP 헤더 (요청 및 응답)
42. LDAP
43. NTP (v3, v4)
44. Radius
45. S7 Communication (S7comm)
46. SMTP
47. SOME/IP
48. SSH - 파싱만 가능 (편집 불가)
49. Telnet - 파싱만 가능 (편집 불가)
50. 일반 페이로드

## DPDK 및 PF_RING 지원

[DPDK](https://www.dpdk.org/)는 빠른 패킷 처리를 위한 데이터 플레인 라이브러리 세트이며, [PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/)은 패킷 캡처 속도를 대폭 향상시키는 새로운 유형의 네트워크 소켓입니다. PcapPlusPlus는 DPDK 및 PF_RING에 대한 C++ 추상화 계층을 제공합니다. 자세한 내용은 PcapPlusPlus 웹사이트의 [DPDK](https://pcapplusplus.github.io/docs/dpdk) 및 [PF_RING](https://pcapplusplus.github.io/docs/features#pf_ring-support) 지원 페이지에서 확인하세요.

## 성능 벤치마크

PcapPlusPlus는 다른 C++ 라이브러리(`libtins`, `libcrafter` 등)와 성능을 비교하기 위해 Matias Fontanini의 [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) 프로젝트를 사용했습니다. 성능 결과는 PcapPlusPlus 웹사이트의 [벤치마크](https://pcapplusplus.github.io/docs/benchmark) 페이지에서 확인할 수 있습니다.

## 피드백 제공

피드백을 환영합니다. 다음 방법을 통해 연락해 주세요:

- GitHub 이슈 작성
- PcapPlusPlus Google 그룹에 메시지 게시: <https://groups.google.com/d/forum/pcapplusplus-support>
- Stack Overflow에서 질문하기: <https://stackoverflow.com/questions/tagged/pcapplusplus>
- 이메일 보내기: <pcapplusplus@gmail.com>
- X 팔로우하기: <https://x.com/seladb>

이 프로젝트가 마음에 드시면 __GitHub에서 Star를 눌러 주세요__ :star: :star:

자세한 내용은 [PcapPlusPlus 웹사이트](https://pcapplusplus.github.io/community)를 방문하여 확인할 수 있습니다.

## 기여하기

이 프로젝트에 기여해 주신다면 감사하겠습니다. 기여에 관심이 있으시면 PcapPlusPlus 웹사이트의 [기여 페이지](https://pcapplusplus.github.io/community#contribute)를 방문해 주세요.

## 라이선스

PcapPlusPlus는 [Unlicense 라이선스](https://choosealicense.com/licenses/unlicense/)로 제공됩니다.

[![GitHub](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=flat&color=blue&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)
