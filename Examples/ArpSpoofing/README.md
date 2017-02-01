ARP Spoofing
============

This application does ARP spoofing using Packet++ and Pcap++. You can read more about ARP spoofing here: https://en.wikipedia.org/wiki/ARP_spoofing .

The input for the application is the spoof victim IP address, the gateway IP address and the interface IP to send the ARP request from.

Using the utility
-----------------
	Basic usage:
		ArpSpoofing -i <INTERFACE_IP> -v <VICTIM_IP> -g <GATEWAY_IP>

	Options:
		-i INTERFACE_IP : Use the specified interface, identified by its IPv4 address
		-v VICTIM_IP    : The IPv4 address of the victim which will be spoofed
		-g GATEWAY_IP   : The gateway IPv4 address

Limitations
-----------
- Works with IPv4 only
