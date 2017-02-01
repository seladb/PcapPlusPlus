DNS Spoofing
============

This application does simple DNS spoofing. It's provided with interface name or IP address and starts capturing DNS requests on that interface. 
Each DNS request that matches is edited and turned into a DNS response with a user-provided IPv4 address as the resolved IP address.
Then it's sent back on the network on the same interface

Using the utility
-----------------
	Basic usage: 
		DnsSpoofing [-hl] [-o HOST1,HOST2,...,HOST_N] [-c IP_ADDRESS] -i INTERFACE -d IP_ADDRESS

	Options:
		-h|--help                              : Displays this help message and exits
		-l|--list                              : Print the list of available interfaces
		-i|--interface            INTERFACE    : The interface name or interface IP address to use. Use the -l switch to see all interfaces
		-d|--spoof-dns-server     IP_ADDRESS   : The IPv4 address of the spoofed DNS server (all responses will be sent with this IP address)
		-c|--client-ip            IP_ADDRESS   : Spoof only DNS requests coming from a specific IPv4 address
		-o|--host-list  HOST1,HOST2,...,HOST_N : A comma-separated list of hosts to spoof. If list is not given, all hosts will be spoofed.
												 If an host contains '*' all sub-domains will be spoofed, for example: if '*.google.com' is given
												 then 'mail.google.com', 'tools.google.com', etc. will be spoofed

Limitations
-----------
- Works with IPv4 only
