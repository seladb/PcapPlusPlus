PcapPlusPlus
============

PcapPlusPlus is a multiplatform C++ network sniffing and packet parsing and manipulation framework. PcapPlusPlus is meant to be lightweight, efficient and easy to use.

**What makes PcapPlusPlus different from similar C++ wrappers for libpcap/WinPcap?**
- Designed to be lightweight and efficient
- Support for ntop's **PF_RING** packet capturing engine that dramatically improves the packet capture speed
- Support for many protocols, including HTTP protocol parsing and editing
- Support for Remote Capture capabilities on Windows (using RPCAP protocol supported in WinPcap)
- Vast object-oriented filtering mechanism that makes libpcap filters a lot more user-friendly (no need to know the exact filter string to use)

PcapPlusPlus is currently supported on Windows and Linux operating systems.
It was tested on Windows (32bit and 64bit), Ubuntu and Fedora, but it should work on other Linux distributions as well.
Other opeating systems such as FreeBSD and Mac OS were never tested and compilation on those platform would probably fail

For more information including detailed class documentation, please visit PcapPlusPlus web-site:

http://seladb.github.io/PcapPlusPlus-Doc

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
  4. **ARP Spoofing with simple Windows makefile** - same code as ARP spoofing but with simple Windows makefile (see "Creating Applications With PcapPlusPlus" section)
  5. **ARP Spoofing with simple Linux makefile** - same code as ARP spoofing but with simple Linux makefile (see "Creating Applications With PcapPlusPlus" section)
  6. **Arping** - an implementation of the arping utility using PcapPlusPlus

After compilation you can find the libraries, examples, header files and helpful makefiles under the **Dist/** directory

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

#### Supported Engines and Devices ####

PcapPlusPlus currently works with the following devices:

1. libpcap live device (on Linux)
2. WinPcap live device (on Windows)
3. Vanilla PF_RING device (on Linux)
4. Remote live device (on Windows)
5. File devices


#### PF_RING support ####

PcapPlusPlus provides a clean and simple C++ wrapper API for Vanilla PF_RING. Currently only Vanilla PF_RING is supported which provides significant performance improvement in comparison to libpcap or Linux kernel, but PF_RING DNA or ZC (which allows kernel bypass and zero-copy of packets from NIC to user-space) isn't supported yet. I hope I'll be able to add this support in the future.

You can read more about PF_RING in ntop web-site: [http://www.ntop.org/products/pf_ring/](http://www.ntop.org/products/pf_ring/) and in PF_RING user guide: [https://svn.ntop.org/svn/ntop/trunk/PF_RING/doc/UsersGuide.pdf](https://svn.ntop.org/svn/ntop/trunk/PF_RING/doc/UsersGuide.pdf)

In order to compile PcapPlusPlus with PF_RING you need to:

1. Download PF_RING from ntop's web-site: [http://www.ntop.org/get-started/download/#PF_RING](http://www.ntop.org/get-started/download/#PF_RING)
2. Note that I used PcapPlusPlus with PF_RING version 6.0.2. I can't guarantee it'll work with previous versions
3. Once PF_RING is compiled successfully, you need to run PcapPlusPlus **configure-linux.sh** and type "y" in "Compile PcapPlusPlus with PF_RING?"
4. Then you can compile PcapPlusPlus as usual (using make, see below)
5. Before you activate any PcapPlusPlus program that uses PF_RING, don't forget to enable PF_RING kernel module. If you forget to do that, PcapPlusPlus will output an appropriate error on startup which will remind you:
```shell
sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko
```


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
2. If you'd like to compile it with PF_RING please follow the instructions in the "PF_RING support" section above and type "y" in "Compile PcapPlusPlus with PF_RING?"
2. Run **make all** from PcapPlusPlus main directory
3. This should compile all libraries, unit-tests and examples
 
#### Simple Testing ####

To ensure configuration and compilation went smoothly, you can run the unit-test applications for both Packet++ and Pcap++:

```shell
seladb@seladb:~/home/PcapPlusPlus/Packet++Test$ Bin/Packet++Test.exe
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
CopyLayerAndPacketTest        : PASSED
ALL TESTS PASSED!!

seladb@seladb:~/PcapPlusPlus/Pcap++Test$ sudo Bin/Pcap++Test.exe -i 10.0.0.1
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
TestPrintPacketAndLayers      : PASSED
TestPfRingDevice              : PASSED
TestPfRingDeviceSingleChannel : PASSED
TestPfRingMultiThreadAllCores : PASSED
TestPfRingMultiThreadSomeCores: PASSED
TestPfRingSendPacket          : PASSED
TestPfRingSendPackets         : PASSED
TestPfRingFilters             : PASSED
ALL TESTS PASSED!!
```

*Notice:* Pcap++Test must be run with **sudo** on Linux to have access to all NICs


## Creating Applications With PcapPlusPlus ##

Creating applications that uses PcapPlusPlus is rather easy. To do this, please follow these steps:

1. First make sure PcapPlusPlus is configured and compiles successfully
2. All you need is under the **Dist/** directory. You can find the PcapPlusPlus libraries, header files, code examples and helpful makefiles
3. In order to compile your application with PcapPlusPlus libraries you should use the makefiles under the **mk/** directory. There are 2 makefiles there:
  1. *platform.mk* - contains mainly platform-dependent variables such as MinGW and WinPcap directory in Windows, binary files extensions (.lib/.exe for Windows, .a/none for Linux), compile utilities names (g++/g++.exe, ar/ar.exe), etc. 
  2. *PcapPlusPlus.mk* - contains variables that encapsulate all you need in order to compile your application with PcapPlusPlus:
    1. *PCAPPP_INCLUDES* - all includes needed
    2. *PCAPPP_LIBS_DIR* - location of all libraries needed for compiling and linking with PcapPlusPlus
    3. *PCAPPP_LIBS* - all libraries needed for compiling and linking with PcapPlusPlus
    4. *PCAPPP_POST_BUILD* - all post-build actions needed after compiling with PcapPlusPlus
    5. *PCAPPLUSPLUS_HOME* - PcapPlusPlus home directory
4. As an example, here is a simple Makefile needed for compiling the ArpSpoofing example on Windows (you can find this example under the **Examples/ArpSpoofing-SimpleMakefile-Windows** directory):
  ```makefile
  -include ../../Dist/mk/platform.mk
  -include ../../Dist/mk/PcapPlusPlus.mk
  
  # All Target
  all:
  	g++.exe $(PCAPPP_INCLUDES) -c -o main.o main.cpp
  	g++.exe $(PCAPPP_LIBS_DIR) -static-libgcc -static-libstdc++ -o ArpSpoofing.exe main.o $(PCAPPP_LIBS)
  
  # Clean Target
  clean:
  	del main.o
  	del ArpSpoofing.exe
  ```

5. And the same example on Linux (you can find it in **Examples/ArpSpoofing-SimpleMakefile-Linux**):
  ```makefile
  -include ../../Dist/mk/PcapPlusPlus.mk
  
  # All Target
  all:
  	g++ $(PCAPPP_INCLUDES) -c -o main.o main.cpp
  	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o ArpSpoofing main.o $(PCAPPP_LIBS)
  
  # Clean Target
  clean:
  	rm main.o
  	rm ArpSpoofing
  ```
6. Rather easy, isn't it?
