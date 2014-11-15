PcapPlusPlus
============

PcapPlusPlus is a multiplatform C++ network sniffing and packet parsing and manipulation framework. PcapPlusPlus is meant to be lightweight, efficient and easy to use.

PcapPlusPlus is currently supported on Windows and Linux operating systems.
It was tested on Windows (32bit and 64bit), Ubuntu and Fedora, but it should work on other Linux distributions as well.
Other opeating systems such as FreeBSD and Mac OS were never tested but it should theoretically compile and work with no problems

## Compiling ##

### Prerequisutes - Windows ###

In order to compile PcapPlusPlus on Windows you need the following components:

1. The MinGW environment and compiler - this is the only environment currently supported for PcapPlusPlus. You can download and install is from www.mingw.org/
2. Winpcap developer's pack - containing the wpcap library PcapPlusPlus is linking with plus relevant h files. You can download it from https://www.winpcap.org/devel.htm

### Prerequisutes - Linux ###

In order to compile PcapPlusPlus on Linux you need the following components:
