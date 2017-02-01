ARP Spoofing - Simple Makefile for Linux
========================================

This application has the same code as the ARP spoofing application but with simple Linux makefile that demonstrates how 
to write a working Linux makefile that uses PcapPlusPlus. For more info please see:  
http://seladb.github.io/PcapPlusPlus-Doc/examples.html#simple-application

Using the utility
-----------------
Same as the ARP spoofing application

	Basic usage:
		ArpSpoofing -i <INTERFACE_IP> -v <VICTIM_IP> -g <GATEWAY_IP>

	Options:
		-i INTERFACE_IP : Use the specified interface, identified by its IPv4 address
		-v VICTIM_IP    : The IPv4 address of the victim which will be spoofed
		-g GATEWAY_IP   : The gateway IPv4 address