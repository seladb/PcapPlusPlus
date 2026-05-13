> ⚠️ **Внимание:** Этот перевод поддерживается и синхронизируется с помощью AI. Он может отличаться от последней английской версии. Если вы обнаружите ошибки, пожалуйста, создайте GitHub issue или отправьте PR.

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

[PcapPlusPlus](https://pcapplusplus.github.io/) — это кроссплатформенная C++ библиотека для захвата, анализа и формирования сетевых пакетов. Она разработана, чтобы быть эффективной, мощной и простой в использовании.

PcapPlusPlus поддерживает возможности декодирования и создания для большого количества сетевых протоколов. Она также предоставляет удобные C++ обертки для самых популярных движков обработки пакетов, таких как [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [WinDivert](https://reqrypt.org/windivert.html) и [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/).

Переводы: [English](../README.md) · [正體中文](./translation/README-zh-tw.md) · [한국어](./translation/README-kor.md) · Русский

## Содержание

- [Содержание](#table-of-contents)
- [Установка](#download)
  - [Страница релизов GitHub](#github-release-page)
  - [Homebrew](#homebrew)
  - [Vcpkg](#vcpkg)
  - [Conan](#conan)
  - [Самостоятельная сборка](#build-it-yourself)
  - [Проверка пакетов](#verify-your-packages)
- [Обзор возможностей](#feature-overview)
- [Начало работы](#getting-started)
- [Документация API](#api-documentation)
- [Поддержка платформ](#multi-platform-support)
- [Поддерживаемые сетевые протоколы](#supported-network-protocols)
  - [Канальный уровень (L2)](#data-link-layer-l2)
  - [Сетевой уровень (L3)](#network-layer-l3)
  - [Транспортный уровень (L4)](#transport-layer-l4)
  - [Сеансовый уровень (L5)](#session-layer-l5)
  - [Уровень представления (L6)](#presentation-layer-l6)
  - [Прикладной уровень (L7)](#application-layer-l7)
- [Поддержка DPDK и PF_RING](#dpdk-and-pf_ring-support)
- [Бенчмарки](#benchmarks)
- [Обратная связь](#provide-feedback)
- [Участие в разработке](#contributing)
- [Лицензия](#license)

## Установка

Вы можете выбрать между загрузкой со страницы релизов GitHub, использованием пакетного менеджера или самостоятельной сборкой PcapPlusPlus. Для получения подробной информации посетите страницу [Download](https://pcapplusplus.github.io/docs/install) на веб-сайте PcapPlusPlus.

[![GitHub all releases](https://img.shields.io/github/downloads/seladb/PcapPlusPlus/total?style=flat&label=Downloads&logo=github)](https://tooomm.github.io/github-release-stats/?username=seladb&repository=PcapPlusPlus)

### Страница релизов GitHub

<https://github.com/seladb/PcapPlusPlus/releases/latest>

### Homebrew

```shell
brew install pcapplusplus
```

Формула Homebrew: <https://formulae.brew.sh/formula/pcapplusplus>

### Vcpkg

Windows:

```text
.\vcpkg install pcapplusplus
```

MacOS/Linux:

```text
vcpkg install pcapplusplus
```

Порт Vcpkg: <https://github.com/microsoft/vcpkg/tree/master/ports/pcapplusplus>

### Conan

```text
conan install "pcapplusplus/[>0]@" -u
```

Пакет в ConanCenter: <https://conan.io/center/pcapplusplus>

### Самостоятельная сборка

Клонируйте git-репозиторий:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

Следуйте инструкциям по сборке для вашей платформы на странице [Build From Source](https://pcapplusplus.github.io/docs/install#build-from-source) веб-сайта PcapPlusPlus.

### Проверка пакетов

Релизы PcapPlusPlus новее v23.09 подписаны с помощью GitHub attestation. Все аттестации можно найти [здесь](https://github.com/seladb/PcapPlusPlus/attestations). Вы можете проверить подлинность этих пакетов с помощью GitHub CLI. Для проверки следуйте актуальным инструкциям [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify). Краткая команда для проверки:

```shell
gh attestation verify <path-to-package-file> --repository seladb/PcapPlusPlus
```

в терминале должен появиться следующий вывод:

```shell
✓ Verification succeeded!
```

## Обзор возможностей

- __Захват пакетов__ через удобную C++ обертку для популярных движков, таких как [libpcap](https://www.tcpdump.org/), [WinPcap](https://www.winpcap.org/), [Npcap](https://nmap.org/npcap/), [Intel DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html), [WinDivert](https://reqrypt.org/windivert.html), [ntop’s PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) и [raw sockets](https://en.wikipedia.org/wiki/Network_socket#Raw_socket) [[Узнать больше](https://pcapplusplus.github.io/docs/features#packet-capture)]
- __Анализ и формирование пакетов__, включая детальный разбор протоколов и уровней, генерацию и редактирование пакетов для множества [сетевых протоколов](https://pcapplusplus.github.io/docs/features#supported-network-protocols) [[Узнать больше](https://pcapplusplus.github.io/docs/features#packet-parsing-and-crafting)]
- __Чтение и запись пакетов в файлы__ в форматах PCAP и PCAPNG [[Узнать больше](https://pcapplusplus.github.io/docs/features#read-and-write-packets-fromto-files)]
- __Обработка пакетов на скорости линии__ благодаря эффективной C++ обертке для [DPDK](https://www.dpdk.org/), [eBPF AF_XDP](https://www.kernel.org/doc/html/next/networking/af_xdp.html) и [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) [[Узнать больше](https://pcapplusplus.github.io/docs/features#dpdk-support)]
- __Мультиплатформенная поддержка__ - PcapPlusPlus полностью поддерживается на Linux, MacOS, Windows, Android и FreeBSD
- __Сборка пакетов__ — уникальная реализация TCP Reassembly, которая включает обработку ретрансляции TCP, пакетов вне очереди и отсутствующих данных, а также IP Fragmentation and Defragmentation для создания и сборки фрагментов IPv4 и IPv6 [[Узнать больше](https://pcapplusplus.github.io/docs/features#packet-reassembly)]
- __Фильтрация пакетов__, которая делает BPF-фильтры libpcap намного более удобными для пользователя [[Узнать больше](https://pcapplusplus.github.io/docs/features#packet-filtering)]
- __TLS Fingerprinting__ — реализация на C++ алгоритмов [JA3 и JA3S](https://github.com/salesforce/ja3) для создания отпечатков TLS [[Узнать больше](https://pcapplusplus.github.io/docs/features#tls-fingerprinting)]

## Начало работы

Писать приложения с PcapPlusPlus очень просто и интуитивно понятно. Вот пример простого приложения, которое показывает, как прочитать пакет из PCAP-файла и разобрать его:

```cpp
#include <iostream>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // открыть pcap-файл для чтения
    pcpp::PcapFileReaderDevice reader("1_packet.pcap");
    if (!reader.open())
    {
        std::cerr << "Ошибка при открытии pcap-файла" << std::endl;
        return 1;
    }

    // прочитать первый (и единственный) пакет из файла
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "Не удалось прочитать первый пакет в файле" << std::endl;
        return 1;
    }

    // преобразовать необработанный пакет в разобранный (parsed) пакет
    pcpp::Packet parsedPacket(&rawPacket);

    // проверить, является ли пакет пакетом IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // извлечь IP-адреса источника и назначения
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // напечатать IP-адреса источника и назначения
        std::cout << "IP-адрес источника: '" << srcIP << "'; IP-адрес назначения: '" << destIP << "'" << std::endl;
    }

    // закрыть файл
    reader.close();

    return 0;
}
```

Вы можете найти гораздо больше информации на странице [Getting Started](https://pcapplusplus.github.io/docs/quickstart) веб-сайта PcapPlusPlus. Эта страница проведет вас через несколько простых шагов для запуска вашего приложения.

## Документация API

PcapPlusPlus состоит из 3 библиотек:

1. __Packet++__ — библиотека для анализа, создания и редактирования сетевых пакетов
2. __Pcap++__ — библиотека для перехвата и отправки пакетов, предоставления информации о сети и сетевых картах, статистики и т.д. По сути, это C++ обертка для движков захвата пакетов, таких как libpcap, WinPcap, Npcap, DPDK, AF_XDP, WinDivert и PF_RING
3. __Common++__ — библиотека с общими вспомогательными утилитами, используемыми в Packet++ и Pcap++

Обширную документацию API можно найти в [разделе документации API](https://pcapplusplus.github.io/docs/api) на веб-сайте PcapPlusPlus.
Если вы заметили недостающие данные, пожалуйста, [свяжитесь с нами](#provide-feedback).

## Поддержка платформ

На данный момент PcapPlusPlus поддерживается на:
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
</picture> и
__FreeBSD__
<picture>
  <img src="https://github.com/PcapPlusPlus/pcapplusplus.github.io/raw/master/static/img/os-logos/logo-freebsd.png" alt="" width="16" height="16"/>
</picture>.
Пожалуйста, посетите веб-сайт PcapPlusPlus, чтобы увидеть все [поддерживаемые платформы](https://pcapplusplus.github.io/docs/platforms) и обратитесь к разделу [Загрузка](#download), чтобы начать использование PcapPlusPlus на вашей платформе.

## Поддерживаемые сетевые протоколы

PcapPlusPlus в настоящее время поддерживает анализ, редактирование и создание пакетов следующих протоколов:

### Канальный уровень (L2)

1. Cisco HDLC
2. Ethernet II
3. IEEE 802.3 Ethernet
4. LLC (поддерживается только BPDU)
5. Null/Loopback
6. Трейлер пакета (также известный как футер или паддинг)
7. PPPoE
8. SLL (Linux cooked capture)
9. SLL2 (Linux cooked capture v2)
10. STP
11. VLAN
12. VXLAN
13. Wake on LAN (WoL)
14. NFLOG (Linux Netfilter NFLOG) — только анализ (без возможностей редактирования)


### Сетевой уровень (L3)

15. ARP
16. GRE
17. ICMP
18. ICMPv6
19. IGMP (поддерживаются IGMPv1, IGMPv2 и IGMPv3)
20. IPv4
21. IPv6
22. MPLS
23. NDP
24. Raw IP (IPv4 и IPv6)
25. VRRP (IPv4 и IPv6)
26. WireGuard

### Транспортный уровень (L4)

27. COTP
28. GTP (v1 и v2)
29. IPSec AH и ESP — только анализ (без возможностей редактирования)
30. TCP
31. TPKT
32. UDP

### Сеансовый уровень (L5)

33. SDP
34. SIP

### Уровень представления (L6)

35. SSL/TLS — только анализ (без возможностей редактирования)

### Прикладной уровень (L7)

36. Декодер и энкодер ASN.1
37. BGP (v4)
38. Декодеры криптографических ключей
39. DHCP
40. DHCPv6
41. DNS
42. DoIP
43. FTP
44. Заголовки HTTP (запрос и ответ)
45. LDAP
46. Modbus
47. MySQL — только анализ (без возможностей редактирования)
48. NTP (v3, v4)
49. Декодер и энкодер PEM
50. PostgreSQL Wire Protocol (PGWire) — только анализ (без возможностей редактирования)
51. Radius
52. S7 Communication (S7comm)
53. SMTP
54. SOME/IP
55. SSH — только анализ (без возможностей редактирования)
56. Telnet — только анализ (без возможностей редактирования)
57. Сертификаты X509 — только анализ (без возможностей редактирования)
58. Generic payload

## Поддержка DPDK и PF_RING

[The Data Plane Development Kit (DPDK)](https://www.dpdk.org/) — это набор библиотек плоскости данных и драйверов контроллеров сетевых интерфейсов для быстрой обработки пакетов.

[PF_RING™](https://www.ntop.org/products/packet-capture/pf_ring/) — это новый тип сетевого сокета, который значительно повышает скорость захвата пакетов.

Оба фреймворка обеспечивают очень быструю обработку пакетов (вплоть до скорости линии) и используются во многих сетевых приложениях, таких как маршрутизаторы, межсетевые экраны, балансировщики нагрузки и т.д.
PcapPlusPlus предоставляет уровень абстракции C++ над DPDK и PF_RING. Этот уровень абстракции предоставляет простой в использовании интерфейс, который избавляет от написания большого количества шаблонного кода, необходимого для использования этих фреймворков. Вы можете узнать больше, посетив страницы поддержки [DPDK](https://pcapplusplus.github.io/docs/dpdk) и [PF_RING](https://pcapplusplus.github.io/docs/features#pf_ring-support) на веб-сайте PcapPlusPlus.

## Бенчмарки

Мы использовали проект Матиаса Фонтанини [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) для сравнения производительности PcapPlusPlus с другими аналогичными C++ библиотеками (такими как `libtins` и `libcrafter`).

Результаты вы можете увидеть на странице [Benchmarks](https://pcapplusplus.github.io/docs/benchmark) веб-сайта PcapPlusPlus.

## Обратная связь

Мы будем очень рады обратной связи, пожалуйста, свяжитесь с нами любым из следующих способов:

- Откройте тикет на GitHub
- Опубликуйте сообщение в группе Google PcapPlusPlus: <https://groups.google.com/d/forum/pcapplusplus-support>
- Задайте вопрос на Stack Overflow: <https://stackoverflow.com/questions/tagged/pcapplusplus>
- Отправьте письмо на: <pcapplusplus@gmail.com>
- Подпишитесь на нас в X: <https://x.com/seladb>

Если вам нравится этот проект, пожалуйста, __поставьте нам звезду — это помогает!__ :star: :star:

Пожалуйста, посетите [PcapPlusPlus веб-сайт](https://pcapplusplus.github.io/community) чтобы узнать больше.

## Участие в разработке

Мы будем очень признательны за любой вклад в этот проект. Если вы заинтересованы, пожалуйста, посетите [страницу участия](https://pcapplusplus.github.io/community#contribute) на веб-сайте PcapPlusPlus.

## Лицензия

PcapPlusPlus выпущен под лицензией [Unlicense](https://choosealicense.com/licenses/unlicense/).

[![GitHub](https://img.shields.io/github/license/seladb/PcapPlusPlus?style=flat&color=blue&logo=unlicense)](https://choosealicense.com/licenses/unlicense/)
