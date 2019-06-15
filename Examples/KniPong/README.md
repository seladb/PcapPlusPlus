KNI Pong
========

This application emulates working of Unix NETCAT utility that run with `-u` key.  
Basically it is a ping/pong client/server channel using user provided input from `stdin`.  
User provided input is sent to KNI device in UDP packets. Application reads this packets and sends them back to Linux kernel with same string so the string will be shown on terminal two times.  
It shows how to work with KNI devices in isolation from DPDK ports.  

Using the utility
-----------------
	Basic usage:
		KniPong -i <kni_ipv4> [-n <kni_device_name>] [-p <port>] [-v] [-h]
	Options:
		-i --ip <kni_ipv4>            : IP to assign to created KNI device. Must not be odd in last byte
		-n --name <kni_device_name>   : Name for KNI device
		-p --port <port>              : Port for communication
		-v --version                  : Displays the current version and exits
		-h --help                     : Displays this help message and exits