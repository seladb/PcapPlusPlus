SSL/TLS Traffic Analyzer
========================

This application analyzes SSL/TLS traffic and presents detailed and diverse information about it such as:
- Packet count and rate
- Bandwidth
- Flow count and rate
- Average packets and data per flow
- Number of client-hello and server-hello messages
- Number of SSL flows with successful handshake and alert messages
- Hostname histogram
- Cipher suite histogram
- SSL/TLS version histogram
- SSL/TLS ports histogram

It can analyze live traffic or read packets from a pcap/pcap-ng file

The output stats looks as follows:

	STATS SUMMARY
	=============

	General stats
	-------------

	Sample time:                                            5.018 [Seconds]
	Number of SSL packets:                                    130 [Packets]
	Rate of SSL packets:                                   14.409 [Packets/sec]
	Number of SSL flows:                                       26 [Flows]
	Rate of SSL flows:                                      2.882 [Flows/sec]
	Total SSL data:                                        101799 [Bytes]
	Rate of SSL data:                                   11282.986 [Bytes/sec]
	Average packets per flow:                               5.000 [Packets]
	Average data per flow:                               3915.346 [Bytes]
	Client-hello message:                                       3 [Messages]
	Server-hello message:                                       3 [Messages]
	Number of SSL flows with successful handshake:             25 [Flows]
	Number of SSL flows ended with alert:                       1 [Flows]

	SSL/TLS ports count
	-------------------

	-------------------------
	| SSL/TLS ports | Count |
	-------------------------
	| 443           | 26    |
	-------------------------

	SSL/TLS versions count
	----------------------

	----------------------------------------
	| SSL/TLS version              | Count |
	----------------------------------------
	| TLS 1.2                      | 3     |
	----------------------------------------

	Cipher-suite count
	------------------

	--------------------------------------------------------------
	| Cipher-suite                                       | Count |
	--------------------------------------------------------------
	| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              | 3     |
	--------------------------------------------------------------

	Server-name count
	-----------------

	----------------------------------------------------
	| Hostname                                 | Count |
	----------------------------------------------------
	| github.com                               | 1     |
	| avatars3.githubusercontent.com           | 1     |
	| alive.github.com                         | 1     |
	----------------------------------------------------

Using the utility
-----------------
When analyzing SSL/TLS traffic from a pcap/pcap-ng file:

	Basic usage:
		SSLAnalyzer [-h] -f input_file

	Options:
		-f           : The input pcap/pcapng file to analyze. Required argument for this mode
		-h           : Displays this help message and exits

When analyzing SSL/TLS traffic on live traffic:

	Basic usage:
		SSLAnalyzer [-hld] [-o output_file] [-r calc_period] -i interface

	Options:
		-i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address
		-o output_file : Save all captured SSL packets to a pcap file. Notice this may cause performance degradation
		-r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds
		-d             : Disable periodic rates calculation
		-h             : Displays this help message and exits
		-l             : Print the list of interfaces and exists)
