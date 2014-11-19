PcapPlusPlus
============

PcapPlusPlus is a multiplatform C++ network sniffing and packet parsing and manipulation framework. PcapPlusPlus is meant to be lightweight, efficient and easy to use.

PcapPlusPlus is currently supported on Windows and Linux operating systems.
It was tested on Windows (32bit and 64bit), Ubuntu and Fedora, but it should work on other Linux distributions as well.
Other opeating systems such as FreeBSD and Mac OS were never tested and compilation on those platform would probably fail

## Package Content ##

The PcapPlusPlus package contains several libraries, unit-tests and example utilities:

1. **Packet++ library** - a library for parsing, creating and editing packets
2. **Pcap++ library** - a library for intercepting and sending packets. This library is actually a C++ wrapper for the libPcap and WinPcap libraries
3. **Common++ library** - a library with some common code utilities used both by Packet++ and Pcap++
4. **Packet++Test unit-test** - a unit-test application for testing the Packet++ library
5. **Pcap++Test unit-test** - a unit-test application for testing the Pcap++ library
6. **Example applications:**
  1. **Packet Parsing** - a short guide for parsing packets using Pcap++ and Packet++
  2. **Break Pcap FileTo Streams** - an application that takes a pcap file and breaks it into several pcap files, each containing one stream
  3. **ARP Spoofing** - an application that does ARP spoofing using Packet++ and Pcap++

#### Supported Protocols ####

The Packet++ library currently supports parsing, editing and creation of packets of the following protocols:

1. Ethernet
2. IPv4
3. IPv6
4. ARP
5. VLAN
6. TCP
7. UDP
8. HTTP request header
9. HTTP response header
10. Generic payload

#### Supported Engines ####

PcapPlusPlus currently works with the following engines:

1. libPcap (on Linux)
2. WinPcap (on Windows)


## Download ##

In order to download PcapPlusPlus, please visit the github [page](https://github.com/seladb/PcapPlusPlus/).

You can also download it using these links:

- [ZIP format](https://github.com/seladb/PcapPlusPlus/archive/master.zip)
- [tat.gz format](https://github.com/seladb/PcapPlusPlus/archive/master.tar.gz)
 
Or clone the git repository by:

```shell
git clone https://github.com/seladb/PcapPlusPlus.git
```

## Compiling ##

#### Prerequisutes - Windows ####

In order to compile PcapPlusPlus on Windows you need the following components:

1. The MinGW environment and compiler - this is the only environment currently supported for PcapPlusPlus. You can download and install is from www.mingw.org/
2. Winpcap developer's pack - containing the wpcap library PcapPlusPlus is linking with plus relevant h files. You can download it from https://www.winpcap.org/devel.htm

#### Prerequisutes - Linux ####

In order to compile PcapPlusPlus on Linux you need the following components:

1. libPcap developers pack - containing the libpcap library PcapPlusPlus is linking with plus relevant h files. You can download it from http://www.tcpdump.org/#latest-release or through package management engines 
such as apt-get:
  ```shell
  sudo apt-get install libpcap-dev
  ```

  or yum:
  ```shell
  sudo yum install libpcap-devel
  ```
  
2. Make sure you have the libstdc++-static package. If not, you can install it via *yum* or *apt-get*

#### Configuration and Compilation ####

*On Windows:*

1. run the **configure-windows.bat** batch file from PcapPlusPlus main directory. The script will ask you for WinPcap developer's pack location and MinGW location
2. run **mingw32-make.exe all** from PcapPlusPlus main directory
3. This should compile all libraries, unit-tests and examples

*On Linux:*

1. run the **configure-linux.sh** script from PcapPlusPlus main directory
2. Run **make all** from PcapPlusPlus main directory
3. This should compile all libraries, unit-tests and examples
 
#### Simple Testing ####

To ensure configuration and compilation went smoothly, you can run the unit-test applications for both Packet++ and Pcap++:

```shell
elad@elad:~/home/PcapPlusPlus/Packet++Test$ Bin/Packet++Test.exe
EthPacketCreation             : PASSED
EthAndArpPacketParsing        : PASSED
ArpPacketCreation             : PASSED
VlanParseAndCreation          : PASSED
Ipv4PacketCreation            : PASSED
Ipv4PacketParsing             : PASSED
Ipv4UdpChecksum               : PASSED
Ipv6UdpPacketParseAndCreate   : PASSED
TcpPacketNoOptionsParsing     : PASSED
TcpPacketWithOptionsParsing   : PASSED
TcpPacketWithOptionsParsing2  : PASSED
TcpPacketCreation             : PASSED
InsertDataToPacket            : PASSED
InsertVlanToPacket            : PASSED
RemoveLayerTest               : PASSED
HttpRequestLayerParsingTest   : PASSED
HttpRequestLayerCreationTest  : PASSED
HttpRequestLayerEditTest      : PASSED
HttpResponseLayerParsingTest  : PASSED
HttpResponseLayerCreationTest : PASSED
HttpResponseLayerEditTest     : PASSED
ALL TESTS PASSED!!

elad@elad:~/PcapPlusPlus/Pcap++Test$ sudo Bin/Pcap++Test.exe -i 10.0.0.1
Using ip: 10.0.0.1
Debug mode: off
Starting tests...
TestIPAddress                 : PASSED
TestMacAddress                : PASSED
TestPcapFileReadWrite         : PASSED
TestPcapLiveDeviceList        : PASSED
TestPcapLiveDeviceListSearch  : PASSED
TestPcapLiveDevice            : PASSED
TestPcapLiveDeviceStatsMode   : PASSED
TestWinPcapLiveDevice         : PASSED
TestPcapFilters               : PASSED
TestSendPacket                : PASSED
TestSendPackets               : PASSED
TestRemoteCaptue              : PASSED
TestHttpRequestParsing        : PASSED
TestHttpResponseParsing       : PASSED
ALL TESTS PASSED!!
```

*Notice:* Pcap++Test must be run with **sudo** on Linux to have access to all NICs
