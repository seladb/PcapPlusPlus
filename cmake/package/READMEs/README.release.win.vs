
PcapPlusPlus web-site:  https://pcapplusplus.github.io/

GitHub page:            https://github.com/seladb/PcapPlusPlus


This package contains:
----------------------

 - PcapPlusPlus compiled libraries
    - Common++.lib
    - Packet++.lib
    - Pcap++.lib
 - These libraries are compiled in 4 different configurations (each containing all libraries above):
    - 32bit debug configuration (`x86\Debug`)
    - 32bit release configuration (`x86\Release`)
    - 64bit debug configuration (`x64\Debug`)
    - 64bit release configuration (`x64\Release`)
 - PcapPlusPlus header files (under `header\`)
 - Compiled examples:
    - 32bit executables (under `x86\examples`)
    - 64bit executables (under `x64\examples`)
 - Visual Studio example solution configured to work with PcapPlusPlus compiled binaries (under `ExampleProject\`)


Running the examples:
---------------------

 - Make sure you have WinPcap, Npcap or Wireshark installed
 - Make sure you have Visual C++ Redistributable for Visual Studio installed
 - If examples still don't run, install Visual C++ Redistributable for Visual Studio 2010 also


In order to compile your application with these binaries you need to:
---------------------------------------------------------------------

 - Make sure you have Microsoft Visual Studio installed
 - NOTE for Visual Studio 2019: these binaries were compiled with Visual Studio 2019 version 16.11.5. Older or newer versions of Visual Studio 2019 may not link with these binaries
 - Make sure you have WinPcap or Npcap Developer's pack installed (WinPcap Dev Pack can be downloaded from https://www.winpcap.org/devel.htm, Npcap SDK can be downloaded from https://nmap.org/npcap/#download)
 - You need to add to your project all of the include and binary paths required for PcapPlusPlus. The best option is to copy the configuration of the ExampleProject (under `ExampleProject\` folder). Another option
   is to use the ExampleProject solution, delete all the code from it and start writing your own code
 - Before using the ExampleProject solution please make sure you update the following details in `PcapPlusPlusPropertySheet.props` file (inside `ExampleProject\` folder):
    - Set the value of the `PcapPlusPlusHome` to the folder where PcapPlusPlus binaries package is located (the one you downloaded)
    - Set the value of the `PcapSdkHome` to the folder where WinPcap/Npcap Developer's Pack is located
 - Now you can load the solution and build it. You can switch between Debug/Release and x86/x64 configurations
 - If you get an error of `The Windows SDK version 8.1 is not found` follow these steps:
    - Right click on `ExampleProject` project -> Choose "Properties"
    - Go to "Configuration Properties" -> "General"
    - Open the drop down list next to "Windows SDK version" and choose the version installed on your machine
 - Build result will be in `ExampleProject\Debug` or `ExampleProject\Release` (according to chosen configuration)


