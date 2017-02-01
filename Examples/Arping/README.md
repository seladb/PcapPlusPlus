Arping
======

This application resolves a target MAC address using its IPv4 address, by sending an ARP request and 
analyzing the ARP response.

It's an implementation of the arping utility (https://en.wikipedia.org/wiki/Arping) but with less options.
Its basic input is the target IP address and the interface name/IP to send the ARP request from.

Using the utility
-----------------
	Basic usage:
		Arping [-hl] [-c count] [-w timeout] [-i interface] [-s mac_sddr] [-S ip_addr] -T ip_addr

	Options:
		-h           : Displays this help message and exits
		-l           : Print the list of interfaces and exists
		-c count     : Send 'count' requests
		-i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address
		-s mac_addr  : Set source MAC address
		-S ip_addr   : Set source IP address
		-T ip_addr   : Set target IP address
		-w timeout   : How long to wait for a reply (in seconds)		

Limitations
-----------
- Works with IPv4 only
- Doesn't have all the options of the original arping utility
