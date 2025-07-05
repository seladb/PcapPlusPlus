
PcapPlusPlus web-site:  https://pcapplusplus.github.io/

GitHub page:            https://github.com/seladb/PcapPlusPlus


This package contains:
----------------------

 - PcapPlusPlus compiled libraries for Visual Studio (under `lib\`)
    - Common++.lib
    - Packet++.lib
    - Pcap++.lib
 - PcapPlusPlus header files (under `include\pcapplusplus`)
 - Compiled examples (under `bin\`)
 - Code example with a simple CMake file showing how to build applications with PcapPlusPlus (under `example-app\`)
 - CMake files required to build your application with PcapPlusPlus (under `lib\cmake\pcapplusplus`)


In order to compile your application with these binaries you need to:
---------------------------------------------------------------------

 - Make sure that Microsoft Visual Studio version installed on your machine matches the package (VS 2019 / VS 2022)
 - In addition make sure that the package you downloaded matches the configuration you need: Win32 / x64 and Debug / Release
 - Make sure you have WinPcap or Npcap Developer's pack installed (WinPcap Dev Pack can be downloaded from https://www.winpcap.org/devel.htm, Npcap SDK can be downloaded from https://nmap.org/npcap/#download)
 - If your application uses CMake, you can add `PcapPlusPlus_ROOT=<PACKAGE_DIR>`, `PCAP_ROOT=<WinPcap_OR_Npcap_DIR>` and `Packet_ROOT=<WinPcap_OR_Npcap_DIR>``
   when running CMake. For example: if you downloaded the package for VS 2022, x64 and Release, you need to run the following commands:
   - `cmake -A x64 -G "Visual Studio 17 2022"  -S . -B build -DPcapPlusPlus_ROOT=<PACKAGE_DIR> -DPCAP_ROOT=<WinPcap_OR_Npcap_DIR> -DPacket_ROOT=<WinPcap_OR_Npcap_DIR>`
   - `cmake --build build --config Release`


Running the examples:
---------------------

 - Make sure you have WinPcap, Npcap or Wireshark installed
 - Make sure you have Visual C++ Redistributable for Visual Studio installed
 - If examples still don't run, install Visual C++ Redistributable for Visual Studio 2010 also
