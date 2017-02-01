Filter Traffic DPDK example application
=======================================

This application demonstrates PcapPlusPlus DPDK APIs. 

It listens to one or more DPDK ports (a.k.a DPDK devices), captures all traffic and matches packets by user-defined matching criteria such as source/dest IP, source/dest TCP/UDP port and more. 
Matched packets can be send to another DPDK port and/or be saved to a pcap file. 

In addition the application collects statistics on received and matched packets (such as number of packets per protocol, number of matched flows and number of matched packets).
Matching is done per flow, meaning the first packet received on a flow is matched against the matching criteria and if it's matched then all packets of the same flow will be matched too.


The application uses the concept of worker threads. Number of cores can be set by the user or set to default (default is all machine cores minus one management core). 
Each core is assigned with one worker thread. The application divides the DPDK ports and RX queues equally between worker threads.
For example: if there are 2 DPDK ports to listen to, each one with 6 RX queues and there are 3 worker threads, then worker #1 will get RX queues 1-4 of port 1, worker #2 will get RX queues 5-6 of port 1 
and RX queues 1-2 of port 2, and worker #3 will get RX queues 3-6 of port 2.

Each worker thread does exactly the same work: receiving packets, collecting packet statistics, matching flows and sending/saving matched packets.

Important: 
----------
- This application runs only on Linux (DPDK is not supported on Windows and Mac OS X)
- This application (like all applications using DPDK) should be run as 'sudo'


Using the utility
-----------------
	Basic usage: 
		FilterTraffic [-hl] [-s PORT] [-f FILENAME] [-i IPV4_ADDR] [-I IPV4_ADDR] [-p PORT] [-P PORT] [-r PROTOCOL] [-c CORE_MASK] [-m POOL_SIZE] -d PORT_1,PORT_3,...,PORT_N

	Options:
	    -h|--help                                  : Displays this help message and exits
	    -l|--list                                  : Print the list of DPDK ports and exists
	    -d|--dpdk-ports PORT_1,PORT_3,...,PORT_N   : A comma-separated list of DPDK port numbers to receive packets from.
	                                                 To see all available DPDK ports use the -l switch
	    -s|--send-matched-packets PORT             : DPDK port to send matched packets to
	    -f|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH. Packets matched by core X will be saved under 'FILEPATH/CoreX.pcap'
	    -i|--match-source-ip      IPV4_ADDR        : Match source IPv4 address
	    -I|--match-dest-ip        IPV4_ADDR        : Match destination IPv4 address
	    -p|--match-source-port    PORT             : Match source TCP/UDP port
	    -P|--match-dest-port      PORT             : Match destination TCP/UDP port
	    -r|--match-protocol       PROTOCOL         : Match protocol. Valid values are 'TCP' or 'UDP'
	    -c|--core-mask            CORE_MASK        : Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2.
	                                                 Default is using all cores except management core
	    -m|--mbuf-pool-size       POOL_SIZE        : DPDK mBuf pool size to initialize DPDK with. Default value is 4095);