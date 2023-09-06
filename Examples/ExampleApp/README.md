PcapPlusPlus Example Application
================================

This folder contains the source code and a CMake file of a simple application that uses PcapPlusPlus.

The code is based on the "Hello World" application in PcapPlusPlus Tutorials (https://pcapplusplus.github.io/docs/tutorials/intro#writing-a-simple-app-including-a-makefile).

In order to build the application please use the following parameters in CMake command:

 - `-DPcapPlusPlus_ROOT=<PACKAGE_DIR>` - where `PACKAGE_DIR` is PcapPlusPlus package path
 - `-DPCAP_ROOT=<WinPcap_OR_Npcap_DIR>` - ONLY REQUIRED ON WINDOWS, `WinPcap_OR_Npcap_DIR` is WinPcap/Npcap SDK path
 - `-DPacket_ROOT=<WinPcap_OR_Npcap_DIR>` - ONLY REQUIRED ON WINDOWS, `WinPcap_OR_Npcap_DIR` is WinPcap/Npcap SDK path
