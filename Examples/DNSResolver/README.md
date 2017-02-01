DNS Resolver
============

This application resolves the IPv4 address of a hostname by sending a DNS request and analyzing the DNS response.

The basic input for the application is the hostname to be resolved.

Using the utility
-----------------
	Basic usage:
		DNSResolver [-hl] [-t timeout] [-d dns_server] [-g gateway] [-i interface] -s hostname

	Options:
		-h           : Displays this help message and exits
		-l           : Print the list of interfaces and exists
		-s hostname  : Hostname to resolve
		-i interface : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. If not set then
					   one of the interfaces that has a default gateway will be used
		-d dns_server: IPv4 address of DNS server to send the DNS request to. If not set the DNS request will be sent to the gateway
		-g gateway   : IPv4 address of the gateway to send the DNS request to. If not set the default gateway will be chosen
		-t timeout   : How long to wait for a reply (in seconds). Default timeout is 5 seconds

Limitations
-----------
- Works with IPv4 only
