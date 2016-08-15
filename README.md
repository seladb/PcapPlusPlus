PcapPlusPlus
============

[![Build Status](https://travis-ci.org/seladb/PcapPlusPlus.svg?branch=master)](https://travis-ci.org/seladb/PcapPlusPlus)

PcapPlusPlus is a multiplatform C++ network sniffing and packet parsing and manipulation framework. PcapPlusPlus is meant to be lightweight, efficient and easy to use.

**What makes PcapPlusPlus different from similar C++ wrappers for libpcap/WinPcap?**
- Designed to be lightweight and efficient
- Support for **DPDK** fast packet processing engine which enables packet capturing and transmition in line rate using kernel bypass
- Support for ntop's **PF_RING** packet capturing engine that dramatically improves the packet capture speed
- Support for many protocols, including HTTP protocol parsing and editing and SSL/TLS parsing
- Support for Remote Capture capabilities on Windows (using RPCAP protocol supported in WinPcap)
- Vast object-oriented filtering mechanism that makes libpcap filters a lot more user-friendly (no need to know the exact filter string to use)

PcapPlusPlus is currently supported on **Windows**, **Linux** and **Mac OS X**.
It was tested on Windows (32bit and 64bit), Ubuntu and Fedora, but it should work on other Linux distributions as well. Regarding Mac OS X - I tested it on Snow Leopard (10.6) 32bit, Mavericks (10.9.5) and Yosemite (10.10). I hope it would work on other Mac OS X versions as well (>= 10.6).
Other opeating systems such as FreeBSD were never tested and compilation on those platforms would probably fail

For more information including detailed class documentation, please visit PcapPlusPlus web-site:

http://seladb.github.io/PcapPlusPlus-Doc

Also, there is a Google group for questions, suggestions and support:

https://groups.google.com/d/forum/pcapplusplus-support

Or you can send an email to:

pcapplusplus@gmail.com

## Package Content ##

The PcapPlusPlus package contains several libraries, unit-tests and example utilities:

1. **Packet++ library** - a library for parsing, creating and editing packets
2. **Pcap++ library** - a library for intercepting and sending packets. This library is actually a C++ wrapper for packet capturing engines such as libPcap, WinPcap and PF_RING
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
  7. **DpdkExample-FilterTraffic** - a sample application that demonstartes the PcapPlusPlus DPDK APIs
  8. **DNS Spoofing** - a command-line application that does DNS spoofing using Packet++ and Pcap++
  9. **DNS Resolver** - a command-line application that resolves IPv4 address for an hostname using DNS protocol
  10. **HTTP Analyzer** - an application that analyzes HTTP traffic and presents detailed and diverse information about it. Can operate on live traffic or read packets from a pcap file
  11. **SSL Analyzer** - an application that analyzes SSL/TLS traffic and presents detailed and diverse information about it. Can operate on live traffic or read packets from a pcap file
  12. **PfRingExample-FilterTraffic** - a sample application that demonstartes the PcapPlusPlus PF_RING APIs
  13. **Pcap Printer** - a simple application that outputs packets from a pcap file as a readable string
  14. **Pcap Splitter** - an application that splits a pcap file into smaller pcap files by various criteria
  15. **Pcap Search** - an application that search inside pcap files in a directory/ies given by the user and counts how many packet match a user-defined pattern given in a BPF format

After compilation you can find the libraries, examples, header files and helpful makefiles under the **Dist/** directory

#### Supported Protocols ####

The Packet++ library currently supports parsing, editing and creation of packets of the following protocols:

1. Ethernet
2. SLL (Linux cooked capture)
3. IPv4
4. IPv6
5. ARP
6. VLAN
7. MPLS
8. PPPoE
9. GRE
10. TCP
11. UDP
12. ICMP
13. DNS
14. HTTP headers (request & response)
15. SSL/TLS - parsing only (no editing capabilities)
16. Generic payload

#### Supported Engines and Devices ####

PcapPlusPlus currently works with the following devices:

1. libpcap live device (on Linux and Mac OS X)
2. WinPcap live device (on Windows)
3. Vanilla PF_RING device (on Linux)
4. DPDK device (on Linux)
5. Remote live device (on Windows)
6. File devices


#### API Documentation ####

The entire API of PcapPlusPlus is documented using doxygen. You can find the documentation here: [http://seladb.github.io/PcapPlusPlus-Doc/Documentation/index.html](http://seladb.github.io/PcapPlusPlus-Doc/Documentation/index.html)

If you see any missing information please tell me


#### DPDK support ####

The Data Plane Development Kit (DPDK) is a set of data plane libraries and network interface controller drivers for fast packet processing. The DPDK provides a programming framework for Intel x86 processors and enables faster development of high speed data packet networking applications. It is provided and supported under the open source BSD license (taken from [Wikipedia](https://en.wikipedia.org/wiki/Data_Plane_Development_Kit))

DPDK provides packet processing at line rate using kernel bypass for a large range of network interface cards. Notice that not every NIC supports DPDK as the NIC needs to support the kernel bypass feature. You can read more about DPDK in [DPDK's web-site](http://dpdk.org/) and get a list of supported NICs [here](http://dpdk.org/doc/nics).

Also, you can get more details about DPDK and PcapPlusPlus wrapping for DPDK in the documentation of DpdkDevice.h and DpdkDeviceList.h header files.


**_Download and install:_**

Download and install instructions for DPDK are on this page: [http://dpdk.org/download](http://dpdk.org/download)


**_So what does PcapPlusPlus offer for DPDK?_**

- An easy-to-use C++ wrapper (as DPDK is written in C) that encapsulates DPDK's main functionality but doesn't hit packet procssing performance
- Encapsulation of DPDK's initialization process - both outside and inside the application - using simple scripts and methods
- A C++ class wrapper for DPDK's packet structure (mbuf) which offers the most common functionality
- A seamless integration to other PcapPlusPlus capabilities, for example: receivce packets using DPDK, parse them with Packet++ protocol layers and save them to a pcap file


**_PcapPlusPlus configuration for DPDK:_**

1. Download and compile DPDK on your system (see the link above)
2. Note PcapPlusPlus supports DPDK version 2.1. Previous (and most probably newer) versions won't work
3. Once DPDK compiles successfully run PcapPlusPlus' **configure-linux.sh** and type "y" in "Compile PcapPlusPlus with DPDK?"
4. **configure-linux.sh** will ask for DPDK path (i.e /home/user/dpdk-2.1.0) and build path (i.e i686-native-linuxapp-gcc)
5. Then compile PcapPlusPlus as usual (using make, see below)


**_DPDK initialization with PcapPlusPlus:_**

DPDK has 2 steps of initialization: one that configures Linux to support DPDK applications, and other that runs at application startup and configures DPDK. PcapPlusPlus wraps both of them in an easy-to-use interfaces:

*Before application is run* - DPDK requires several Linux configurations to run:
  1. DPDK uses the Linux huge-pages mechanism for faster virtual to physical page conversion resulting in better performance. So huge-pages must be set before a DPDK application is run
  2. DPDK uses a designated kernel module for the kernel-bypass mechanism. This module should be loaded into the kernel
  3. The user needs to state which NICs will move to DPDK control and which will stay under Linux control

PcapPlusPlus offers a simple script that automatically configures all of these. The script is under PcapPlusPlus root directory and is called **setup-dpdk.sh**. The script takes as an input the following parameters:

  1. -p	   : the amount of huge pages to allocate. By default each huge-page size is 2048KB
  2. -n    : a comma-separated list of all NICs that will be unbinded from Linux and move to DPDK control. Only these NICs will be used by DPDK, the others will stay under Linux control. For example: eth0,eth1 will move these 2 interfaces under DPDK control - assuming this NIC is supported by DPDK
You can use the -h switch for help.

If everything went well the system is ready to run a DPDK application and the script output should look like this:

```shell
*******************************
PcapPlusPlus setup DPDK script 
*******************************

1. Reserve huge-pages - DONE!
2. Install kernel module - DONE!
3. Bind network adapters - DONE!

Network devices using DPDK-compatible driver
============================================
0000:00:03.0 '82540EM Gigabit Ethernet Controller' drv=igb_uio unused=e1000
0000:00:08.0 '82545EM Gigabit Ethernet Controller (Copper)' drv=igb_uio unused=e1000

Network devices using kernel driver
===================================
0000:00:09.0 '82545EM Gigabit Ethernet Controller (Copper)' if=eth2 drv=e1000 unused=igb_uio *Active*
0000:00:0a.0 '82545EM Gigabit Ethernet Controller (Copper)' if=eth3 drv=e1000 unused=igb_uio 

Other network devices
=====================
<none>
Setup DPDK completed
```

*At application startup* - before using DPDK inside the application DPDK should be configured on application startup. This configuration includes:
  1. Verify huge-pages, kernel module and NICs are set
  2. Initialize DPDK internal structures and memory, poll-mode-drivers etc.
  3. Prepare CPU cores that will be used by the application
  4. Initialize packet memory pool 
  5. Configure each NIC controlled by DPDK

These steps are wrapped in one static method that should be called once in application startup:
```shell
DpdkDeviceList::initDpdk()
```


**_Tests and limitations:_**
- All unit-tests are in Pcap++Test
- In addition please try the DPDK example application (Examples/DpdkExample-FilterTraffic)
- The only DPDK version supported is 2.1 (currently the latest version)
- So far I managed to test the code on 2 virtual PMDs only: 
  1. VMXNET3 - a VMWare guest driver
  2. E1000/EM - 1GbE Intel NIC but I tested it as virtual NIC in VirtualBox guest
- I hope I'll be able to test it on some more (preferebly non-virtual) NICs soon - I'll update if/when I do
- Operating systems and configurations tested:
  1. Ubuntu 14.04.1 LTS 64bit with kernel 3.x and gcc 4.8.x
  2. Ubuntu 12.04.5 LTS 32bit with kernel 3.x and gcc 4.6.x
  3. CentOS 7.1 64bit with kernel 3.x and gcc 4.8.x


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

#### Compiled Binaries ####

If you want an already compiled version of PcapPlusPlus chekcout the latest release:
[https://github.com/seladb/PcapPlusPlus/releases/latest](https://github.com/seladb/PcapPlusPlus/releases/latest)

It currently contains compiled binaries for Win32, Ubuntu 14.10 32-bit and Mac OSX Snow Leopard 32-bit


## Compiling ##

#### Prerequisutes - Windows ####

In order to compile PcapPlusPlus on Windows you need the following components:

1. The MinGW environment and compiler - this is the only environment currently supported for PcapPlusPlus. You can download and install is from www.mingw.org/
  1. The fastest way I found for installing mingw32 was through this link: http://www.mingw.org/wiki/Getting_Started
  2. Download "mingw-get-setup.exe", run it and follow the instructions
  3. By default the pthreads library is not installed so you need to ask to install it. It can be done during the installation process or afterwards with "mingw-get.exe" (MinGW installation manager)
  4. In the MinGW installation manager go to "MinGW Libraries" and select everything with "POSIX threading library for Win32" description
  5. Choose Installation->Update Catalogue
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

#### Prerequisutes - Mac OS X ####

In order to compile PacpPlusPlus on Mac OS X you need to make sure [Xcode](https://developer.apple.com/xcode/) is installed. Xcode contains all prerequisites required for PcapPlusPlus:

1. gcc/g++ compiler
2. libpcap with all relevant H files

#### Configuration and Compilation ####

*On Windows:*

1. run the **configure-windows.bat** batch file from PcapPlusPlus main directory. The script will ask you for WinPcap developer's pack location and MinGW location
2. run **mingw32-make.exe all** from PcapPlusPlus main directory
3. This should compile all libraries, unit-tests and examples

*On Linux:*

1. run the **configure-linux.sh** script from PcapPlusPlus main directory
2. If you'd like to compile it with PF_RING please follow the instructions in the "PF_RING support" section above and type "y" in "Compile PcapPlusPlus with PF_RING?"
3. If you'd like to compile it with DPDK please follow the instructions in the "DPDK support" section above and type "y" in "Compile PcapPlusPlus with DPDK?"
4. Run **make all** from PcapPlusPlus main directory
5. This should compile all libraries, unit-tests and examples

*On Mac OS X:*

1. run the **configure-mac_os_x.sh** script from PcapPlusPlus main directory
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
PPPoESessionLayerParsingTest  : PASSED
PPPoESessionLayerCreationTest : PASSED
PPPoEDiscoveryLayerParsingTest: PASSED
PPPoEDiscoveryLayerCreateTest : PASSED
DnsLayerParsingTest           : PASSED
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
TestDnsParsing                : PASSED
TestDpdkDevice                : PASSED
TestDpdkMultiThread           : PASSED
TestDpdkDeviceSendPackets     : PASSED
TestDpdkMbufRawPacket         : PASSED
TestDpdkDeviceWorkerThreads   : PASSED
ALL TESTS PASSED!!
```

*Notice:* Pcap++Test must be run with **sudo** on Linux to have access to all NICs


## Benchmarks ##

I used Matias Fontanini's [packet-capture-benchmarks](https://github.com/mfontanini/packet-capture-benchmarks) project to compare the performance of PcapPlusPlus with other similar C++ libraries (libtins and libcrafter)

#### Testing Environment ####
 
I ran all benchmarks on the following environment:
- Linux Ubuntu 12.04 32-bit running as a VirtualBox VM
- Compiler is GCC 4.6.3
- Host platform is a dual-core Intel Core i5 760 2.8GHz with 4GB RAM system running Windows 7 32-bit

#### Tested Libraries ####

I decided to compare PcapPlusPlus only to similar C++ libraries such as [libtins](http://libtins.github.io/) and [libcrafter](https://code.google.com/archive/p/libcrafter/). That's because Python or Java libraries cannot compete with native code libraries in terms of performance. Tests results are as follows:


#### Benchmark #1 - Interpretting TCP ###

|     Library      | Time taken(seconds) | Packets per second |
|------------------|--------------------:|-------------------:|
| libpcap          | 0.208               | 2403846            |
| **PcapPlusPlus** | **0.661**           | **756429**         |
| libtins          | 0.844               | 592417             |
| libcrafter       | 21.627              | 23119              | 	
---------------------------------------------------------------

As you can see PcapPlusPlus is **~27% faster** than libtins and **~x32 faster** than libcrafter


#### Benchmark #2 - Interpretting TCP + TCP Options ###

|     Library      | Time taken(seconds) | Packets per second |
|------------------|--------------------:|-------------------:|
| libpcap          | 0.252               | 1984126            |
| **PcapPlusPlus** | **0.869**           | **575373**         |
| libtins          | 1.862               | 268528             |
| libcrafter       | 35.142              | 14227              | 	
---------------------------------------------------------------

As you can see PcapPlusPlus is **~x2 faster** than libtins and **~x40 faster** than libcrafter


#### Benchmark #3 - Interpretting DNS ###

|     Library      | Time taken(seconds) | Packets per second |
|------------------|--------------------:|-------------------:|
| libpcap          | 0.076               | 6578947            |
| **PcapPlusPlus** | **0.976**           | **512295**         |
| libtins          | 1.109               | 450856             |
| libcrafter       | 23.289              | 21469              | 	
---------------------------------------------------------------

As you can see PcapPlusPlus is **~13% faster** than libtins and **~x24 faster** than libcrafter


#### Run the Benchmark Yourself ####

You can find PcapPlusPlus benchmark application under **Examples/PcapPlusPlus-benchmark**. If you want to run it with packet-capture-benchmarks please follow the directions in **Examples/PcapPlusPlus-benchmark/benchmark.cpp** (top section)

In addition you can see libtins tests result using the same benchmark platform here: [libtins](http://libtins.github.io/benchmark/)


#### Conclusions ####

As you can see PcapPlusPlus is quite faster than similar libraries. For my opinion the exact numbers aren't important as they may vary in other environments and platforms. The important thing this benchmark shows is where each library is located in terms of perfromance. It can be determined unequivocally that libcrafter has the poorest performance (in significant gap compared to the others), and libtins and PcapPlusPlus are quite fast, with ~15%-50% advantage to PcapPlusPlus


## Creating Applications With PcapPlusPlus ##

Creating applications that uses PcapPlusPlus is rather easy. To do this, please follow these steps:

1. First make sure PcapPlusPlus is configured and compiled successfully
2. All you need is under the **Dist/** directory. You can find the PcapPlusPlus libraries, header files, code examples and helpful makefiles
3. In order to compile your application with PcapPlusPlus libraries you should use the makefiles under the **Dist/mk/** directory. There are 2 makefiles there:
  1. *platform.mk* - contains mainly platform-dependent variables such as MinGW and WinPcap directory in Windows, binary files extensions (.lib/.exe for Windows, .a/none for Linux and Mac OS X), compile utilities names (g++/g++.exe, ar/ar.exe), etc. 
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
