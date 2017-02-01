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
- Client hello version histogram
- SSL/TLS ports histogram

It can analyze live traffic or read packets from a pcap/pcap-ng file

The output stats looks as follows:

	STATS SUMMARY
	=============

	General stats
	--------------------

	Sample time:                                            8.777 [Seconds]
	Number of SSL packets:                                    109 [Packets]
	Rate of SSL packets:                                    9.765 [Packets/sec]
	Number of SSL flows:                                       21 [Flows]
	Rate of SSL flows:                                      1.881 [Flows/sec]
	Total SSL data:                                         60049 [Bytes]
	Rate of SSL data:                                    5379.698 [Bytes/sec]
	Average packets per flow:                               5.190 [Packets]
	Average data per flow:                               2859.476 [Bytes]
	Client-hello message:                                      12 [Messages]
	Server-hello message:                                      12 [Messages]
	Number of SSL flows with successful handshake:             17 [Flows]
	Number of SSL flows ended with alert:                       5 [Flows]

	SSL/TLS ports count
	--------------------

	| SSL/TLS ports | Count |
	-------------------------
	| 443           | 21    |
	-------------------------

	SSL versions count
	--------------------

	| SSL record version           | Count |
	----------------------------------------
	| TLSv1.2                      | 12    |
	----------------------------------------

	Client-hello versions count
	--------------------

	| Client-hello version         | Count |
	----------------------------------------
	| TLSv1.0                      | 12    |
	----------------------------------------

	Cipher-suite count
	--------------------

	| Cipher-suite                                       | Count |
	--------------------------------------------------------------
	| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              | 12    |
	--------------------------------------------------------------

	Server-name count
	--------------------

	| Hostname                                 | Count |
	----------------------------------------------------
	| assets-cdn.github.com                    | 4     |
	| camo.githubusercontent.com               | 2     |
	| api.github.com                           | 1     |
	| avatars0.githubusercontent.com           | 1     |
	| collector.githubapp.com                  | 1     |
	| github.com                               | 1     |
	| live.github.com                          | 1     |
	| www.google-analytics.com                 | 1     |
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